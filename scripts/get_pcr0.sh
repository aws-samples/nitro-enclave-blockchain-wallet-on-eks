#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e

eif_file=${1}
NITRO_EKS_BUILD_BASE_IMAGE="nitro_eks_build_base_image"

docker run -ti --log-driver=none -a stdout -a stderr --rm -v $(PWD)/"${eif_file}":/tmp/enclave.eif ${NITRO_EKS_BUILD_BASE_IMAGE} \
  sh -c "nitro-cli describe-eif --eif-path /tmp/enclave.eif | jq -r '.Measurements.PCR0'" | tail -n 1
