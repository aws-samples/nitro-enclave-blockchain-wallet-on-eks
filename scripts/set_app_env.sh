eks_output=${1}

eks_stack_name=$(jq -r '. |= keys | .[0]' "${eks_output}")

cluster_name=$(jq -r ".${eks_stack_name}.NitroEKSClusterName" "${eks_output}")
cluster_oidc_provider_arn=$(jq -r ".${eks_stack_name}.NitroEKSClusterOIDCProviderARN" "${eks_output}")
cluster_kubectl_role_arn=$(jq -r ".${eks_stack_name}.NitroEKSClusterKubectlRoleARN" "${eks_output}")
cluster_vpc=$(jq -r ".${eks_stack_name}.NitroEKSClusterVPCID" "${eks_output}")
cluster_zone_name=$(jq -r ".${eks_stack_name}.NitroEKSClusterDomainName" "${eks_output}")

export CLUSTER_NAME=${cluster_name}
export CLUSTER_OIDC_PROVIDER_ARN=${cluster_oidc_provider_arn}
export CLUSTER_KUBECTL_ROLE_ARN=${cluster_kubectl_role_arn}
export CLUSTER_VPC=${cluster_vpc}
export CLUSTER_ZONE_NAME=${cluster_zone_name}
