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

# delete all temporary code, config and build artifacts
#  rm -rf applications/ethereum-signer/third_party/*

rm -rf cdk.context.json "${CDK_PREFIX}cdk.out" "${CDK_PREFIX}EksClusterOutput.json" "${CDK_PREFIX}vsock_base_port_assignments.tmp"

# remove ephemeral build images
docker rmi $(docker images | grep -e cdkasset -e ${CDK_DEPLOY_REGION}) 2>/dev/null || true

# prune can also be extended to all images except foundational images via image filter
# docker rmi $(docker images --filter "label=eks_nitro_wallet_base!=true") 2>/dev/null || true
