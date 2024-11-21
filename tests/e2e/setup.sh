#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

set +x
set -e

# https://github.com/aws/aws-cdk/issues/30258
export BUILDX_NO_DEFAULT_ATTESTATIONS=1

#source tests/e2e/.env

# files need to be present to allow EKS stack to synthesize
source .venv/bin/activate
mkdir -p applications/ethereum-signer/third_party/eif
touch "applications/ethereum-signer/third_party/eif/${CDK_PREFIX}ethereum-signer_enclave.eif"
touch "applications/ethereum-signer/third_party/eif/${CDK_PREFIX}ethereum-key-generator_enclave.eif"

# ensure that environment variable have been set and venv has been sourced - no pid capture available right now to stop background build processes
# https://stackoverflow.com/a/39375902/2054009
# todo move enclave build tasks to background, ensure that context such
#  as PREFIX and vsock base ports dont get mixed up
./scripts/build_enclave_image.sh ethereum-key-generator
./scripts/build_enclave_image.sh ethereum-signer

# eks overly permissive trust policy issue (cdk version) causes issue / cdk acknowledge 25674
# https://github.com/aws/aws-cdk/issues/30258
cdk deploy "${CDK_PREFIX}EksNitroCluster" --verbose -O "${CDK_PREFIX}EksClusterOutput.json" --output "${CDK_PREFIX}cdk.out" --require-approval=never
# todo check wait / wait -n for bg processes to have finished
#wait

# parse kubectl config command from json file
./scripts/configure_environment.sh "${CDK_PREFIX}EksClusterOutput.json"

rm -rf cdk.context.json
cdk deploy ${CDK_PREFIX}EthKeyManagementApp --verbose --output "${CDK_PREFIX}cdk.out" --require-approval=never
./scripts/apply_deployment_spec.sh

kms_key_id=$(aws ssm get-parameter --name "/${CDK_PREFIX}app/ethereum/key_id" --region "${CDK_DEPLOY_REGION}" | jq -r ".Parameter.Value")

./scripts/generate_key_policy.sh ethereum-signer >key_policy.json
aws kms put-key-policy --region "${CDK_DEPLOY_REGION}" --policy-name default --key-id "${kms_key_id}" --policy file://key_policy.json
