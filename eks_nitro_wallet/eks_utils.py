import requests
import yaml
from aws_cdk import aws_ec2 as ec2, aws_eks as eks


def create_private_link(self, vpc, services):
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


def apply_remote_manifest(
    self, cluster: eks.ICluster, manifest_url: str, manifest_name: str
) -> None:
    # Fetch the manifest from remote URL
    try:
        response = requests.get(manifest_url)
        response.raise_for_status()
        manifest_content = response.text

        # Parse all YAML documents in the manifest
        manifests = list(yaml.safe_load_all(manifest_content))

        # Apply the manifest to the cluster
        eks.KubernetesManifest(
            self, f"{manifest_name}Manifest", cluster=cluster, manifest=manifests
        )
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch manifest from {manifest_url}: {e}")
        raise
    except yaml.YAMLError as e:
        print(f"Failed to parse manifest YAML: {e}")
        raise


def create_k8s_namespace(
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
