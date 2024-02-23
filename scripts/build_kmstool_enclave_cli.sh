#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e

application=${1}
target_architecture=${CDK_TARGET_ARCHITECTURE:-linux/amd64}
architecture=$(echo "${target_architecture}" | cut -d "/" -f 2)

NITRO_ENCLAVE_CLI_VERSION="v0.4.1"

KMS_TARGET_FOLDER="./applications/${application}/third_party/kms_${architecture}"
KMSTOOL_FOLDER="./aws-nitro-enclaves-sdk-c/bin/kmstool-enclave-cli"

if [[ ! -d "${KMS_TARGET_FOLDER}" ]]; then
  mkdir -p "${KMS_TARGET_FOLDER}"
fi

# delete repo if already there or if folder exists
rm -rf "${KMS_TARGET_FOLDER}/aws-nitro-enclaves-sdk-c"

cd "${KMS_TARGET_FOLDER}"
git clone --depth 1 --branch "${NITRO_ENCLAVE_CLI_VERSION}" https://github.com/aws/aws-nitro-enclaves-sdk-c.git

cd ./aws-nitro-enclaves-sdk-c/containers
awk 'NR==1{print; print "ARG GOPROXY=direct"} NR!=1' Dockerfile.al2 > Dockerfile.al2_new
mv Dockerfile.al2_new Dockerfile.al2
cd ../../

cd "${KMSTOOL_FOLDER}"

sed "s|-f ../../containers/Dockerfile.al2 ../..|-f ../../containers/Dockerfile.al2 ../.. --platform=${target_architecture}|g" build.sh >build.sh_new
mv build.sh_new build.sh
chmod +x build.sh
./build.sh

cp ./kmstool_enclave_cli ../../../kmstool_enclave_cli
cp ./libnsm.so ../../../libnsm.so

cd -

rm -rf ./aws-nitro-enclaves-sdk-c

echo "kmstool_enclave_cli build successful"