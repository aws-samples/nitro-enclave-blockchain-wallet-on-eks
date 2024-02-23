#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
import os
from aws_cdk import (
    Stack,
    RemovalPolicy,
    Duration,
    aws_ecr_assets as ecr_assets,
    aws_s3_assets as s3_assets,
    aws_iam as iam,
    aws_ssm as ssm,
    aws_eks as eks,
    aws_kms as kms,
    aws_dynamodb as ddb,
    aws_lambda as _lambda,
    aws_ec2 as ec2,
    aws_logs as logs,
    aws_apigateway as apigateway,
)
from constructs import Construct
from cdk_nag import NagSuppressions, NagPackSuppression

OIDC_PLACEHOLDER_VALUE = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/0123456789abcdef0123456789abcdef"


class NitroWalletAppStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        params = kwargs.pop("params")
        super().__init__(scope, construct_id, **kwargs)

        # default to warning if parameter is provided as constructor argument
        prefix = os.getenv("CDK_PREFIX", "")
        target_architecture = os.getenv("CDK_TARGET_ARCHITECTURE", "linux/amd64")
        target_architecture_config = {
            "linux/amd64": {"platform": ecr_assets.Platform.LINUX_AMD64},
            "linux/arm64": {"platform": ecr_assets.Platform.LINUX_ARM64},
        }
        log_level = params.get("log_level")

        kms_key = kms.Key(
            self,
            "SymmetricalKSMKey",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

        secrets_table = ddb.Table(
            self,
            "SecretsTable",
            partition_key=ddb.Attribute(name="key_id", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PROVISIONED,
            removal_policy=RemovalPolicy.DESTROY,
            encryption=ddb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
        )

        vpc_id = ssm.StringParameter.value_from_lookup(
            self, parameter_name=f"/{prefix}eks/nitro/ethereum/vpc_id"
        )
        vpc = ec2.Vpc.from_lookup(self, "EKSVPC", vpc_id=vpc_id)

        signer_client_sg = ec2.SecurityGroup(
            self,
            "NitroSignerSG",
            vpc=vpc,
            allow_all_outbound=True,
            description="Eth2 signer security group",
        )

        cluster_zone_name = ssm.StringParameter.value_from_lookup(
            self, parameter_name=f"/{prefix}eks/nitro/ethereum/domain"
        )
        invoke_lambda = _lambda.DockerImageFunction(
            self,
            "NitroInvokeLambda",
            code=_lambda.DockerImageCode.from_image_asset(
                directory="./applications/ethereum-signer/",
                file="images/lambda/Dockerfile",
                build_args={
                    "SKIP_TEST_ARG": "true" if os.getenv("CDK_SKIP_TESTS") else "false"
                },
            ),
            timeout=Duration.minutes(2),
            memory_size=256,
            environment={
                "LOG_LEVEL": "DEBUG",
                "SECRETS_TABLE": secrets_table.table_name,
                "KEY_ARN": kms_key.key_arn,
                "NITRO_INSTANCE_PRIVATE_DNS": cluster_zone_name,
            },
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            security_groups=[signer_client_sg],
        )
        kms_key.grant_encrypt(invoke_lambda)
        secrets_table.grant_write_data(invoke_lambda)

        api_access_log_group = logs.LogGroup(
            self, "NitroInvokeAccessLogs", removal_policy=RemovalPolicy.DESTROY
        )

        # api gateway for lambda function
        key_rest_api = apigateway.LambdaRestApi(
            self,
            "NitroInvokeLambdaRestAPI",
            handler=invoke_lambda,
            proxy=False,
            default_method_options=apigateway.MethodOptions(
                authorization_type=apigateway.AuthorizationType.IAM
            ),
            deploy_options=apigateway.StageOptions(
                stage_name=f"{prefix}",
                logging_level=apigateway.MethodLoggingLevel.INFO,
                data_trace_enabled=True,
                tracing_enabled=True,
                access_log_destination=apigateway.LogGroupLogDestination(
                    api_access_log_group
                ),
            ),
            endpoint_configuration=apigateway.EndpointConfiguration(
                types=[apigateway.EndpointType.REGIONAL]
            ),
        )

        key = key_rest_api.root.add_resource("key")

        # allows creation of new key / returns keyID
        key_new = key.add_method("POST")

        key_id_operation = key.add_resource("{key_id}")

        # allows the creation of new user_op signature (message)
        key_user_op_signature_resource = key_id_operation.add_resource(
            "userop_signature"
        )
        key_user_op_signature_new = key_user_op_signature_resource.add_method("POST")

        # allows the creation of new ethereum tx signature
        key_tx_signature_resource = key_id_operation.add_resource("tx_signature")
        key_tx_signature_new = key_tx_signature_resource.add_method("POST")

        key_rest_policy = iam.ManagedPolicy(
            self,
            "NitroInvokeLambdaRestAPIPolicy",
            managed_policy_name=f"{prefix}NitroInvokeLambdaRestAPIPolicy",
            statements=[
                iam.PolicyStatement(
                    actions=["execute-api:Invoke"],
                    effect=iam.Effect.ALLOW,
                    resources=[
                        key_new.method_arn,
                        key_user_op_signature_new.method_arn,
                        key_tx_signature_new.method_arn,
                    ],
                )
            ],
        )

        rest_api_role = iam.Role(
            self,
            "NitroInvokeLambdaRestAPIRole",
            managed_policies=[key_rest_policy],
            role_name=f"{prefix}NitroInvokeLambdaRestAPIRole",
            assumed_by=iam.AccountPrincipal(self.account),
        )

        rest_api_url_ssm_param = ssm.StringParameter(
            self,
            "RestAPIURLParameter",
            parameter_name=f"/{prefix}app/ethereum/rest_url",
            string_value=key_rest_api.url,
        )

        rest_api_role_arn_ssm_param = ssm.StringParameter(
            self,
            "RestAPIRoleArnParameter",
            parameter_name=f"/{prefix}app/ethereum/rest_url_role_arn",
            string_value=rest_api_role.role_arn,
        )

        signer_enclave_image = s3_assets.Asset(
            self,
            "signerEnclaveImage",
            path=f"./applications/ethereum-signer/third_party/eif/{prefix}ethereum-signer_enclave.eif",
        )

        signer_enclave_image_uri_ssm = ssm.StringParameter(
            self,
            "SignerEnclaveURIParameter",
            parameter_name=f"/{prefix}app/ethereum/signer_enclave/eif_uri",
            string_value=signer_enclave_image.s3_object_url,
        )

        generator_enclave_image = s3_assets.Asset(
            self,
            "GeneratorEnclaveImage",
            path=f"./applications/ethereum-signer/third_party/eif/{prefix}ethereum-key-generator_enclave.eif",
        )

        generator_enclave_image_uri_ssm = ssm.StringParameter(
            self,
            "GeneratorEnclaveURIParameter",
            parameter_name=f"/{prefix}app/ethereum/generator_enclave/eif_uri",
            string_value=generator_enclave_image.s3_object_url,
        )

        signer_pod_image = ecr_assets.DockerImageAsset(
            self,
            "SignerPodImage",
            directory="./applications/ethereum-signer",
            file="images/signing_pod/Dockerfile",
            build_args={
                "REGION_ARG": self.region,
                # todo to be sourced from ssm
                "LOG_LEVEL_ARG": "DEBUG",
                "SKIP_TEST_ARG": "true" if os.getenv("CDK_SKIP_TESTS") else "false",
            },
            platform=target_architecture_config[target_architecture]["platform"],
        )
        signer_pod_image.node.add_dependency(signer_enclave_image)

        generator_pod_image = ecr_assets.DockerImageAsset(
            self,
            "GeneratorPodImage",
            directory="./applications/ethereum-signer",
            file="images/key-generator_pod/Dockerfile",
            build_args={
                "REGION_ARG": self.region,
                # todo to be sourced from ssm
                "LOG_LEVEL_ARG": "DEBUG",
                "SKIP_TEST_ARG": "true" if os.getenv("CDK_SKIP_TESTS") else "false",
            },
            platform=target_architecture_config[target_architecture]["platform"],
        )
        generator_pod_image.node.add_dependency(generator_enclave_image)

        cluster_oidc_provider_arn = ssm.StringParameter.value_from_lookup(
            self, parameter_name=f"/{prefix}eks/nitro/ethereum/oidc_provider_arn"
        )

        # workaround to enable cdk synth https://github.com/aws/aws-cdk/issues/8699
        if cluster_oidc_provider_arn.startswith("dummy-value-for"):
            cluster_oidc_provider_arn = OIDC_PLACEHOLDER_VALUE

        cluster_oidc_provider = (
            iam.OpenIdConnectProvider.from_open_id_connect_provider_arn(
                self,
                "NitroEKSClusterOIDCProvider",
                open_id_connect_provider_arn=cluster_oidc_provider_arn,
            )
        )

        cluster_name = ssm.StringParameter.value_from_lookup(
            self, parameter_name=f"/{prefix}eks/nitro/ethereum/cluster_name"
        )
        cluster_kubectl_role_arn = ssm.StringParameter.value_from_lookup(
            self, parameter_name=f"/{prefix}eks/nitro/ethereum/kubectl_role_arn"
        )

        if cluster_kubectl_role_arn.startswith("dummy-value-for"):
            cluster_kubectl_role_arn = (
                "arn:aws:iam::123456789012:role/stack-clusterCreationRole-012345679123"
            )

        # https://github.com/aws/aws-cdk/tree/main/packages/aws-cdk-lib/aws-eks#using-existing-clusters
        cluster = eks.Cluster.from_cluster_attributes(
            self,
            "NitroEKSCluster",
            cluster_name=cluster_name,
            open_id_connect_provider=cluster_oidc_provider,
            kubectl_role_arn=cluster_kubectl_role_arn,
            # kubectl_role_arn="arn:aws:iam::168635352862:role/cw2EksNitroCluster-ConsoleReadOnlyRole0A30C09D-qGG56Yqy9y5u"
            # kubectl_lambda_role=
        )

        generator_service_account = cluster.add_service_account("EKSSAGenerator")
        kms_key.grant_encrypt(generator_service_account)
        secrets_table.grant_write_data(generator_service_account)

        signer_service_account = cluster.add_service_account("EKSSASigner")
        secrets_table.grant_read_data(signer_service_account)

        signing_pod_iam_policy = iam.ManagedPolicy(
            self,
            "SigningPodPolicy",
            document=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        actions=["s3:ListBucket"],
                        resources=[
                            "arn:aws:s3:::{}".format(
                                signer_enclave_image.s3_bucket_name
                            )
                        ],
                    ),
                    iam.PolicyStatement(
                        actions=["s3:GetObject", "s3:GetObjectVersion"],
                        resources=[
                            "arn:aws:s3:::{}/*".format(
                                signer_enclave_image.s3_bucket_name
                            )
                        ],
                    ),
                    iam.PolicyStatement(
                        actions=["ssm:GetParameter"],
                        resources=[signer_enclave_image_uri_ssm.parameter_arn],
                    ),
                ]
            ),
        )
        signer_service_account.role.add_managed_policy(signing_pod_iam_policy)

        generator_pod_iam_policy = iam.ManagedPolicy(
            self,
            "GeneratorPodPolicy",
            document=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        actions=["s3:ListBucket"],
                        resources=[
                            "arn:aws:s3:::{}".format(
                                generator_enclave_image.s3_bucket_name
                            )
                        ],
                    ),
                    iam.PolicyStatement(
                        actions=["s3:GetObject", "s3:GetObjectVersion"],
                        resources=[
                            "arn:aws:s3:::{}/*".format(
                                generator_enclave_image.s3_bucket_name
                            )
                        ],
                    ),
                    iam.PolicyStatement(
                        actions=["ssm:GetParameter"],
                        resources=[generator_enclave_image_uri_ssm.parameter_arn],
                    ),
                ]
            ),
        )
        generator_service_account.role.add_managed_policy(generator_pod_iam_policy)

        ssm.StringParameter(
            self,
            "KMSKeyID",
            parameter_name=f"/{prefix}app/ethereum/key_id",
            string_value=kms_key.key_id,
        )

        ssm.StringParameter(
            self,
            "SecretsTableNameSSMParameter",
            parameter_name=f"/{prefix}app/ethereum/secrets_table",
            string_value=secrets_table.table_name,
        )

        # arn for web3workshop stack
        ssm.StringParameter(
            self,
            "InvokeLambdaNameSSMParameter",
            parameter_name=f"/{prefix}app/ethereum/invoke_lambda",
            string_value=invoke_lambda.function_arn,
        )

        ssm.StringParameter(
            self,
            "SignerPodDockerImageSSMParameter",
            parameter_name=f"/{prefix}app/ethereum/signer_pod/image_uri",
            string_value=signer_pod_image.image_uri,
        )

        ssm.StringParameter(
            self,
            "SignerPodServiceAccountSSMParameter",
            parameter_name=f"/{prefix}app/ethereum/signer_pod/service_account_name",
            string_value=signer_service_account.service_account_name,
        )

        ssm.StringParameter(
            self,
            "SignerPodServiceAccountRoleARNSSMParameter",
            parameter_name=f"/{prefix}app/ethereum/signer_pod/service_account_role_arn",
            string_value=signer_service_account.role.role_arn,
        )

        ssm.StringParameter(
            self,
            "GeneratorPodDockerImageSSMParameter",
            parameter_name=f"/{prefix}app/ethereum/generator_pod/image_uri",
            string_value=generator_pod_image.image_uri,
        )

        ssm.StringParameter(
            self,
            "GeneratorPodServiceAccountSSMParameter",
            parameter_name=f"/{prefix}app/ethereum/generator_pod/service_account_name",
            string_value=generator_service_account.service_account_name,
        )

        ssm.StringParameter(
            self,
            "ApplicationLogLevel",
            parameter_name=f"/{prefix}app/ethereum/log_level",
            string_value=log_level,
        )

        NagSuppressions.add_resource_suppressions(
            construct=self,
            suppressions=[
                NagPackSuppression(
                    id="AwsSolutions-IAM5",
                    reason="Permission to get object and object version on all items in bucket is restrictive enough",
                ),
                NagPackSuppression(
                    id="AwsSolutions-IAM4",
                    reason="AWSLambdaBasicExecutionRole, AWSLambdaVPCAccessExecutionRole, AmazonEKS* are restrictive roles",
                ),
                NagPackSuppression(
                    id="AwsSolutions-COG4",
                    reason="Using sigv4 based authentication for technical integration",
                ),
                NagPackSuppression(
                    id="AwsSolutions-APIG2",
                    reason="Request validation is implemented in Lambda function",
                ),
                NagPackSuppression(
                    id="AwsSolutions-L1",
                    reason="Non-container Lambda function managed by predefined EKS templates for CDK",
                )
            ],
            apply_to_children=True,
        )
