#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e

eks_output=${1}
stack_name=$(jq -r '. |= keys | .[0]' "${eks_output}")
# required in pre cdk v2.80.0 environments
# https://github.com/aws/aws-cdk/blob/main/CHANGELOG.v2.md#2800-2023-05-19
#cluster_config=$(jq -r ".${stack_name} | with_entries(select(.key|match(\"nitroeksclusterConfigCommand\";\"i\")))[]" "${eks_output}")

cluster_name=$(jq -r ".${stack_name}.NitroEKSClusterName" "${eks_output}")
kubectl_role_arn=$(jq -r ".${stack_name}.NitroEKSClusterKubectlRole" "${eks_output}")
cluster_config="aws eks update-kubeconfig --region ${CDK_DEPLOY_REGION} --name ${cluster_name} --role-arn ${kubectl_role_arn}"

eval "${cluster_config}"
