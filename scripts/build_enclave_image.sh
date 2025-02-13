#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e
# ethereum-signer or ethereum-key-generator
application=${1}
[ -z "${application}" ] && echo "application parameter needs to be specified: ethereum-signer, ethereum-key-generator" && exit 1

target_architecture=${CDK_TARGET_ARCHITECTURE:-linux/amd64}
architecture=$(echo "${target_architecture}" | cut -d "/" -f 2)

# parameters statically provided to the enclaves environment via docker build args
REGION="${CDK_DEPLOY_REGION:-${AWS_DEFAULT_REGION}}"

LOG_LEVEL=${CDK_APP_LOG_LEVEL:-INFO}

# base port for enclave and vsock-proxy(ies) and metrics server
# requires Homebrew coreutils on MacOS
vsock_base_port=$(shuf -i 2000-65000 -n 1)
# append ports for each not enclave build / cdk deploy step to keep port history
echo "${application}:${vsock_base_port}" >>"${CDK_PREFIX}vsock_base_port_assignments.tmp"

# lib/docker/Dockerfile_nitro-cli_build
#NITRO_EKS_BASE_BUILD_IMAGE="nitro-cli_build_image"

NITRO_EKS_BASE_BUILD_IMAGE="nitro_eks_build_base_image"
ENCLAVE_DOCKER_PATH="./applications/ethereum-signer"
THIRD_PARTY_PATH="${ENCLAVE_DOCKER_PATH}/third_party"
KMS_PATH="${THIRD_PARTY_PATH}/kms"
PROXY_PATH="${THIRD_PARTY_PATH}/proxy"
EIF_PATH="${THIRD_PARTY_PATH}/eif"
ETHEREUM_SIGNER_ENCLAVE="${EIF_PATH}/${CDK_PREFIX}ethereum-signer_enclave.eif"
ETHEREUM_KEY_GENERATOR_ENCLAVE="${EIF_PATH}/${CDK_PREFIX}ethereum-key-generator_enclave.eif"

[ -z "${REGION}" ] && echo "CDK_DEPLOY_REGION or AWS_DEFAULT_REGION cannot be empty" && exit 1

if [[ ! -d ${EIF_PATH} ]]; then
  mkdir -p "${EIF_PATH}"
fi

# required to be able to synthesize both stacks all the time
if [[ ! -f ${ETHEREUM_SIGNER_ENCLAVE} ]]; then
  touch "${ETHEREUM_SIGNER_ENCLAVE}"
fi

if [[ ! -f ${ETHEREUM_KEY_GENERATOR_ENCLAVE} ]]; then
  touch "${ETHEREUM_KEY_GENERATOR_ENCLAVE}"
fi

base_image_id=$(docker images -q ${NITRO_EKS_BASE_BUILD_IMAGE} 2>/dev/null)
# validate that required base images exists and that they correspond with the target architecture
if [[ ${base_image_id} == "" ]] || [[ $(docker image inspect "${base_image_id}" | jq -r '.[0].Architecture') != "${architecture}" ]]; then
  ./scripts/build_docker_base.sh
fi

if [[ ${application} == "ethereum-signer" ]]; then

  DOCKER_FILE_PATH="./images/signing_enclave/Dockerfile"
  ENCLAVE_NAME="ethereum-signer_enclave"

elif [[ ${application} == "ethereum-key-generator" ]]; then

  #  rebuild proxy with specified target architecture
  ./scripts/build_vsock_proxy.sh

  DOCKER_FILE_PATH="./images/key-generator_enclave/Dockerfile"
  ENCLAVE_NAME="ethereum-key-generator_enclave"
fi

cd "${ENCLAVE_DOCKER_PATH}"

docker build --platform "${target_architecture}" --build-arg REGION_ARG="${REGION}" --build-arg LOG_LEVEL_ARG="${LOG_LEVEL}" --build-arg VSOCK_BASE_PORT_ARG="${vsock_base_port}" --build-arg SKIP_TEST_ARG="${CDK_SKIP_TESTS}" -t "${ENCLAVE_NAME}" -f "${DOCKER_FILE_PATH}" .
docker run -ti --rm -v "$(pwd)":/app -v /var/run/docker.sock:/var/run/docker.sock "${NITRO_EKS_BASE_BUILD_IMAGE}" \
  sh -c "cd /app && \
    nitro-cli build-enclave --docker-uri ${ENCLAVE_NAME}:latest --output-file /app/third_party/eif/${CDK_PREFIX}${ENCLAVE_NAME}.eif"
