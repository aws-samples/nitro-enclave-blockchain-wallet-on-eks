#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
import json
import os
import yaml
import sys
from git import Repo
from aws_cdk import (
    Stack,
    Fn,
    aws_eks as eks,
    aws_ec2 as ec2,
    aws_route53 as route53,
    aws_iam as iam,
    aws_ssm as ssm,
    aws_ecr_assets as ecr_assets,
    CfnOutput,
)
from constructs import Construct
from cdk_nag import NagSuppressions, NagPackSuppression
from aws_cdk import lambda_layer_kubectl_v27


class EksNitroWalletStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        prefix = os.getenv("CDK_PREFIX", "")
        target_architecture = os.getenv("CDK_TARGET_ARCHITECTURE", "linux/amd64")
        target_architecture_config = {
            "linux/amd64": {
                "ami_type": eks.NodegroupAmiType.AL2_X86_64,
                "instance_type": "m5a.2xlarge",
                "platform": ecr_assets.Platform.LINUX_AMD64,
            },
            "linux/arm64": {
                "ami_type": eks.NodegroupAmiType.AL2_ARM_64,
                "instance_type": "c7g.4xlarge",
                "platform": ecr_assets.Platform.LINUX_ARM64,
            },
        }

        if target_architecture not in target_architecture_config:
            print(
                f"selected target architecture ({target_architecture} not supported, stopping deployment ..."
            )
            sys.exit(1)

        # worker nodes vpc
        vpc = ec2.Vpc(
            self,
            "VPC",
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public", subnet_type=ec2.SubnetType.PUBLIC
                ),
                ec2.SubnetConfiguration(
                    name="private", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                ),
            ],
            enable_dns_support=True,
            enable_dns_hostnames=True,
        )

        zone = route53.PrivateHostedZone(
            self,
            "nitro-enclave-private-zone",
            zone_name="{}.private".format(self.stack_name),
            vpc=vpc,
        )

        self._create_private_link(
            vpc=vpc,
            services=[
                "DYNAMODB",
                "KMS",
                "ECR",
                "S3",
                "CLOUDWATCH_LOGS",
                "CLOUDWATCH_MONITORING",
            ],
        )

        zone_external_dns_updates_iam_policy = iam.ManagedPolicy(
            self,
            "nitro-zone-external-update-policy",
            document=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        actions=["route53:ChangeResourceRecordSets"],
                        resources=[
                            "arn:aws:route53:::hostedzone/{}".format(
                                zone.hosted_zone_id
                            )
                        ],
                    ),
                    iam.PolicyStatement(
                        actions=[
                            "route53:ListHostedZones",
                            "route53:ListResourceRecordSets",
                        ],
                        resources=["*"],
                    ),
                ]
            ),
        )

        eks_cloudwatch_logs_iam_policy = iam.ManagedPolicy(
            self,
            "eks-cloudwatch-logs-iam-policy",
            document=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        actions=[
                            "ec2:DescribeVolumes",
                            "ec2:DescribeTags",
                            "logs:PutLogEvents",
                            "logs:DescribeLogStreams",
                            "logs:DescribeLogGroups",
                            "logs:CreateLogStream",
                            "logs:CreateLogGroup",
                            "logs:PutRetentionPolicy",
                            "logs:DeleteRetentionPolicy",
                        ],
                        resources=["*"],
                    ),
                ],
            ),
        )

        with open("./lib/user_data/user_data.sh") as f:
            user_data_raw = f.read()

        # https://docs.aws.amazon.com/eks/latest/userguide/retrieve-ami-id.html
        nitro_enclave_launch_template = ec2.CfnLaunchTemplate(
            self,
            "nitro-enclave-launch-template",
            launch_template_data=ec2.CfnLaunchTemplate.LaunchTemplateDataProperty(
                enclave_options=ec2.CfnLaunchTemplate.EnclaveOptionsProperty(
                    enabled=True
                ),
                user_data=Fn.base64(user_data_raw),
            ),
        )

        nitro_enclave_launch_template_spec = eks.LaunchTemplateSpec(
            id=nitro_enclave_launch_template.ref,
            version=nitro_enclave_launch_template.attr_latest_version_number,
        )

        kubectl_layer = lambda_layer_kubectl_v27.KubectlV27Layer(
            self, "nitro-eks-kubectl-layer"
        )

        cluster = eks.Cluster(
            self,
            "nitro-eks-cluster",
            # custom kubernetes version requires a region specific custom ami - see launch template definition above
            version=eks.KubernetesVersion.of(version="1.27"),
            kubectl_layer=kubectl_layer,
            vpc=vpc,
            default_capacity=0,
            cluster_logging=[
                eks.ClusterLoggingTypes.API,
                eks.ClusterLoggingTypes.AUDIT,
                eks.ClusterLoggingTypes.AUTHENTICATOR,
                eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
                eks.ClusterLoggingTypes.SCHEDULER,
            ],
            endpoint_access=eks.EndpointAccess.PUBLIC_AND_PRIVATE
        )

        kubectl_role = iam.Role(
            self, "ConsoleReadOnlyRole", assumed_by=iam.AccountRootPrincipal()
        )

        kubectl_role.add_to_policy(
            iam.PolicyStatement(
                actions=["eks:AccessKubernetesApi", "eks:Describe*", "eks:List*"],
                resources=[cluster.cluster_arn],
            )
        )

        # Add this role to system:masters RBAC group
        cluster.aws_auth.add_masters_role(kubectl_role)

        node_group = cluster.add_nodegroup_capacity(
            "nitro-enclave-node-group",
            launch_template_spec=nitro_enclave_launch_template_spec,
            desired_size=2,
            instance_types=[
                ec2.InstanceType(
                    target_architecture_config[target_architecture]["instance_type"]
                )
            ],
            ami_type=target_architecture_config[target_architecture]["ami_type"],
            labels={"aws-nitro-enclaves-k8s-dp": "enabled"},
        )
        node_group.role.add_managed_policy(
            iam.ManagedPolicy.from_managed_policy_arn(
                self,
                "nitro-enclaves-node-group-ssm-permissions",
                managed_policy_arn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
            )
        )

        node_group.role.add_managed_policy(
            iam.ManagedPolicy.from_managed_policy_arn(
                self,
                "nitro-enclaves-node-group-cw-permissions",
                managed_policy_arn="arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
            )
        )

        with open("./lib/policy_templates/alb_policy.json") as policy:
            policy_doc = policy.read()

        eks.AlbController(
            self,
            "nitro-eks-alb-controller",
            cluster=cluster,
            version=eks.AlbControllerVersion.V2_4_1,
            policy=json.loads(policy_doc),
        )

        eks_cloudwatch_service_namespace_name = "aws-for-fluent-bit"
        eks_cloudwatch_service_account_name = "eks-cloud-watch"

        eks_cloudwatch_service_namespace = self._create_k8s_namespace(
            name=eks_cloudwatch_service_namespace_name, cluster=cluster, override=True
        )

        eks_cloudwatch_service_account = cluster.add_service_account(
            "eks-cloudwatch-service-account",
            name=eks_cloudwatch_service_account_name,
            namespace=eks_cloudwatch_service_namespace_name,
        )
        eks_cloudwatch_service_account.node.add_dependency(
            eks_cloudwatch_service_namespace
        )
        eks_cloudwatch_service_account.role.add_managed_policy(
            eks_cloudwatch_logs_iam_policy
        )

        container_insights_helm_chart = eks.HelmChart(
            self,
            "nitro-eks-container-insights",
            cluster=cluster,
            chart="aws-for-fluent-bit",
            version="0.1.32",
            repository="https://aws.github.io/eks-charts",
            namespace=eks_cloudwatch_service_namespace_name,
            create_namespace=True,
            values={
                "serviceAccount": {
                    "name": eks_cloudwatch_service_account_name,
                    "create": False,
                },
                "cloudWatch": {
                    "enabled": False,
                },
                "cloudWatchLogs": {
                    "enabled": True,
                    "region": self.region,
                    "logGroupName": "/aws/eks/nitro/workloads",
                    "logGroupTemplate": "/aws/eks/nitro/workloads/$kubernetes['namespace_name']",
                    "logStreamTemplate": "$kubernetes['container_name'].$kubernetes['pod_name']",
                    "logKey": "log",
                    "logRetentionDays": 5,
                },
            },
        )
        container_insights_helm_chart.node.add_dependency(
            eks_cloudwatch_service_namespace
        )
        container_insights_helm_chart.node.add_dependency(
            eks_cloudwatch_service_account
        )

        eks.HelmChart(
            self,
            "nitro-eks-metrics-server",
            cluster=cluster,
            chart="metrics-server",
            version="3.11.0",
            repository="https://kubernetes-sigs.github.io/metrics-server/",
            namespace="metrics-server",
            create_namespace=True,
        )

        external_dns_name = "external-dns"
        external_dns_name_namespace = self._create_k8s_namespace(
            name=external_dns_name, cluster=cluster, override=True
        )
        external_dns_service_account = cluster.add_service_account(
            "eks-external-dns-service-account",
            name=external_dns_name,
            namespace=external_dns_name,
        )
        external_dns_service_account.node.add_dependency(external_dns_name_namespace)

        external_dns_service_account.role.add_managed_policy(
            zone_external_dns_updates_iam_policy
        )

        external_dns_helm_chart = eks.HelmChart(
            self,
            "nitro-eks-externalDNS",
            cluster=cluster,
            chart="external-dns",
            version="6.28.6",
            namespace=external_dns_name,
            create_namespace=True,
            repository="https://charts.bitnami.com/bitnami",
            values={
                "provider": "aws",
                "aws": {"region": self.region, "zoneType": "private"},
                "txtOwnerId": zone.hosted_zone_id,
                "domainFilters": [zone.zone_name],
                "policy": "sync",
                "serviceAccount": {"name": external_dns_name, "create": False},
            },
        )
        external_dns_helm_chart.node.add_dependency(external_dns_name_namespace)
        external_dns_helm_chart.node.add_dependency(external_dns_service_account)

        # custom function to apply customized manifests to the EKS clusterd
        self._apply_k8s_nitro_operator(
            folder="applications/ethereum-signer/third_party",
            cluster=cluster,
            platform=target_architecture_config[target_architecture]["platform"],
        )

        ssm.StringParameter(
            self,
            "NitroEKSClusterDomainNameSSMParameter",
            parameter_name=f"/{prefix}eks/nitro/ethereum/domain",
            string_value=zone.zone_name,
        )

        ssm.StringParameter(
            self,
            "NitroEKSClusterHostedZoneIDSSMParameter",
            parameter_name=f"/{prefix}eks/nitro/ethereum/zoneid",
            string_value=zone.hosted_zone_id,
        )

        ssm.StringParameter(
            self,
            "NitroEKSClusterNameSSMParameter",
            parameter_name=f"/{prefix}eks/nitro/ethereum/cluster_name",
            string_value=cluster.cluster_name,
        )

        ssm.StringParameter(
            self,
            "NitroEKSClusterOIDCProviderARNSSMParameter",
            parameter_name=f"/{prefix}eks/nitro/ethereum/oidc_provider_arn",
            string_value=cluster.open_id_connect_provider.open_id_connect_provider_arn,
        )

        ssm.StringParameter(
            self,
            "NitroEKSClusterKubectlRoleARNSSMParameter",
            parameter_name=f"/{prefix}eks/nitro/ethereum/kubectl_role_arn",
            string_value=kubectl_role.role_arn,
        )

        ssm.StringParameter(
            self,
            "NitroEKSClusterVPCIDSSMParameter",
            parameter_name=f"/{prefix}eks/nitro/ethereum/vpc_id",
            string_value=vpc.vpc_id,
        )

        CfnOutput(self, "NitroEKSClusterKubectlRole", value=kubectl_role.role_arn)

        CfnOutput(self, "NitroEKSClusterName", value=cluster.cluster_name)

        NagSuppressions.add_resource_suppressions(
            construct=self,
            suppressions=[
                NagPackSuppression(
                    id="AwsSolutions-VPC7",
                    reason="No VPC Flow Log required for PoC-grade deployment",
                ),
                NagPackSuppression(
                    id="AwsSolutions-IAM5",
                    reason="Permission to read CF stack is restrictive enough",
                ),
                NagPackSuppression(
                    id="AwsSolutions-IAM4",
                    reason="AmazonEKS* are restrictive roles",
                ),
                NagPackSuppression(
                    id="AwsSolutions-EKS1",
                    reason="EKS cluster Kubernetes API server endpoint is secured by RBAC",
                ),
                NagPackSuppression(
                    id="AwsSolutions-DDB3",
                    reason="Point in time recovery not required for PoC-grade deployment",
                ),
                NagPackSuppression(
                    id="AwsSolutions-L1",
                    reason="Non-container Lambda function managed by predefined EKS templates for CDK",
                ),
            ],
            apply_to_children=True,
        )

    def _create_private_link(self, vpc, services):
        for service in services:
            if service in ["DYNAMODB", "S3"]:
                service_gateway = getattr(ec2.GatewayVpcEndpointAwsService, service)
                vpc.add_gateway_endpoint(
                    "{}GatewayEndpoint".format(service), service=service_gateway
                )
            else:
                service_endpoint = getattr(ec2.InterfaceVpcEndpointAwsService, service)
                ec2.InterfaceVpcEndpoint(
                    self,
                    "{}InterfaceEndpoint".format(service),
                    vpc=vpc,
                    subnets=ec2.SubnetSelection(
                        subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                    ),
                    service=service_endpoint,
                    private_dns_enabled=True,
                )

    def _apply_k8s_nitro_operator(
            self, folder: str, cluster: eks.ICluster, platform: ecr_assets.Platform
    ) -> None:
        repo_folder = f"{folder}/aws-nitro-enclaves-k8s-device-plugin"
        # clone repo if folder does not yet exist
        if not os.path.isdir(repo_folder):
            try:
                # has to be pinned to specific tag when available - v0.1.0 outdated
                Repo.clone_from(
                    "https://github.com/aws/aws-nitro-enclaves-k8s-device-plugin.git",
                    repo_folder,
                    branch="main",
                )
            except Exception as e:
                print(
                    f"AWS Nitro Enclave operator for EKS repo could not be cloned - stopping operation: {e}"
                )
                exit(1)
        else:
            print("skipping git clone due to existing repository")

        # build docker image asset for enclave operator till 4 enclave support is available via public ecr
        # https://gallery.ecr.aws/aws-nitro-enclaves/aws-nitro-enclaves-k8s-device-plugin
        enclave_operator_image = ecr_assets.DockerImageAsset(
            self,
            "NitroEnclaveOperator",
            directory=repo_folder,
            file="container/Dockerfile",
            platform=platform,
            asset_name="nitro-enclave-device-plugin-ds",
        )

        with open(
                f"{repo_folder}/aws-nitro-enclaves-k8s-ds.yaml", "r", encoding="UTF-8"
        ) as file:
            manifests_raw = file.read()

        # returns generator
        manifests_generator = yaml.safe_load_all(manifests_raw)

        # build list of manifests and manipulate custom daemon set uri
        manifests = []
        for manifest_raw in manifests_generator:
            manifest = manifest_raw

            if manifest["kind"] in "DaemonSet":
                manifest["spec"]["template"]["spec"]["containers"][0][
                    "image"
                ] = enclave_operator_image.image_uri
            manifests.append(manifest)

        eks.KubernetesManifest(
            self,
            "nitro_enclave_ds",
            cluster=cluster,
            manifest=manifests,
            overwrite=True,
        )

    def _create_k8s_namespace(
            self, name: str, cluster: eks.ICluster, override: bool = True
    ) -> eks.KubernetesManifest:

        return eks.KubernetesManifest(
            self,
            f"{name}NamespaceManifest",
            cluster=cluster,
            overwrite=override,
            manifest=[
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {
                        "name": name,
                    },
                }
            ],
        )
