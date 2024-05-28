#!/usr/bin/env bash

set -e
set -x
NITRO_CLI_REPO="https://github.com/aws/aws-nitro-enclaves-cli.git"
NITRO_CLI_VERSION="v1.3.0"

BASE_DOCKER_PATH="$(pwd)/lib/docker"
DOCKER_FILE_PATH="${BASE_DOCKER_PATH}/Dockerfile_nitro-cli_build"
REPO_TMP_PATH="/tmp/aws-nitro-enclaves-cli"

rm -rf "${REPO_TMP_PATH}"
git clone -b "${NITRO_CLI_VERSION}" "${NITRO_CLI_REPO}" /tmp/aws-nitro-enclaves-cli
cd ${REPO_TMP_PATH}
repo=$(pwd)
docker run -it -v /var/run/docker.sock:/var/run/docker.sock -v ${REPO_TMP_PATH}:${REPO_TMP_PATH} -e repo=${REPO_TMP_PATH} amazonlinux:2023 bash -c "dnf install docker gcc make git clang -y && \
  cd ${repo} && \
  make nitro-cli && make vsock-proxy"

docker build --target nitro-cli_build_image -t nitro-cli_build_image -f "${DOCKER_FILE_PATH}" .
rm -rf ${REPO_TMP_PATH}
