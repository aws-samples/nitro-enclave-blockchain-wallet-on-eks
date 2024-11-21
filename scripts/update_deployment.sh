#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e

application=${1:-none}
# parameter to update enclave (rebuild and upload), takes significant more time
valid_values="ethereum-key-generator ethereum-signer all none"
SCRIPTS_FOLDER="scripts"

# trigger cleanup function in trap
trap cleanup EXIT ERR

cleanup() {
  # state bloat in asset folder because application folder including images is copied over
  rm -rf ${CDK_PREFIX}cdk.out/asset.*
  docker rmi $(docker images | grep -e cdkasset -e ${CDK_DEPLOY_REGION}) 2>/dev/null || true
}


if [[ ! "${valid_values}" =~ (" "|^)${application}(" "|$) ]]; then
  echo "just empty or one of the following values is supported as argument: ${valid_values}"
  exit 1
fi

# delete file with every new deployment
rm -f .vsock_base_port_assignments.tmp

if [[ "${application}" == "ethereum-key-generator" ]]; then
  ./${SCRIPTS_FOLDER}/build_enclave_image.sh "${application}"
elif [[ "${application}" == "ethereum-signer" ]]; then
  ./${SCRIPTS_FOLDER}/build_enclave_image.sh "${application}"
elif [[ "${application}" == "all" ]]; then
#  todo run both in background and wait till finished
  ./${SCRIPTS_FOLDER}/build_enclave_image.sh ethereum-key-generator
  ./${SCRIPTS_FOLDER}/build_enclave_image.sh ethereum-signer
#  wait
fi

BUILDX_NO_DEFAULT_ATTESTATIONS=1 cdk deploy ${CDK_PREFIX}EthKeyManagementApp --verbose --output "${CDK_PREFIX}cdk.out" --require-approval=never
./${SCRIPTS_FOLDER}/apply_deployment_spec.sh

