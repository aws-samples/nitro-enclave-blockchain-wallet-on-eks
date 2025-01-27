#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

set +x
set -e

#source tests/e2e/.env

source .venv/bin/activate || true
./scripts/delete_deployment.sh ethereum-key-generator || true
./scripts/delete_deployment.sh ethereum-signer || true
cdk destroy "${CDK_PREFIX}EthKeyManagementApp" --force --output "${CDK_PREFIX}cdk.out"
cdk destroy "${CDK_PREFIX}EksNitroCluster" --force --output "${CDK_PREFIX}cdk.out"

# previous (prefixed) base images need to be deleted to ensure that all required test dependencies are baked into the images between different runs
# todo third party repo / binaries, containers are not prefixed
#docker rmi -f ethereum-signer_enclave kmstool-enclave-cli ethereum-key-generator_enclave go_eks_base go_lambda_base nitro_eks_pod_base_image nitro_eks_build_base_image || true

# delete all temporary code, config and build artifacts
#rm -rf applications/ethereum-signer/third_party/*

rm -rf cdk.context.json "${CDK_PREFIX}cdk.out" "${CDK_PREFIX}EksClusterOutput.json" "${CDK_PREFIX}vsock_base_port_assignments.tmp"
docker rmi $(docker images | grep -e cdkasset -e ${CDK_DEPLOY_REGION}) 2>/dev/null || true
