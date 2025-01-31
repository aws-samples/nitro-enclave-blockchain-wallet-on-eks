#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e

target_architecture=${CDK_TARGET_ARCHITECTURE:-linux/amd64}

BASE_DOCKER_PATH="./lib/docker"
NITRO_EKS_POD_BASE_IMAGE_FILE="Dockerfile_pod"
NITRO_EKS_POD_BASE_IMAGE="nitro_eks_pod_base_image"
NITRO_EKS_BUILD_BASE_IMAGE="nitro_eks_build_base_image"

GO_BASE_PATH="./applications/ethereum-signer"
GO_BASE_IMAGE_FILE="../../lib/docker/Dockerfile_go_base"
GO_EKS_BASE_IMAGE="go_eks_base"
GO_LAMBDA_BASE_IMAGE="go_lambda_base"

cd "${BASE_DOCKER_PATH}"
# attaching "eks_nitro_wallet_base=true" label to each of the base images to avoid pruning these later on
docker build --target pod_image --platform "${target_architecture}" -t "${NITRO_EKS_POD_BASE_IMAGE}" -f "${NITRO_EKS_POD_BASE_IMAGE_FILE}" --label "eks_nitro_wallet_base=true" .
docker build --target build_image --platform "${target_architecture}" -t "${NITRO_EKS_BUILD_BASE_IMAGE}" -f "${NITRO_EKS_POD_BASE_IMAGE_FILE}" --label "eks_nitro_wallet_base=true" .
cd -

cd "${GO_BASE_PATH}"
docker build --target "${GO_EKS_BASE_IMAGE}" --platform "${target_architecture}" --build-arg SKIP_TEST_ARG="${CDK_SKIP_TESTS}" -t "${GO_EKS_BASE_IMAGE}" -f "${GO_BASE_IMAGE_FILE}" --label "eks_nitro_wallet_base=true" .
docker build --target "${GO_LAMBDA_BASE_IMAGE}" --platform linux/amd64 --build-arg SKIP_TEST_ARG="${CDK_SKIP_TESTS}" -t "${GO_LAMBDA_BASE_IMAGE}" -f "${GO_BASE_IMAGE_FILE}" --label "eks_nitro_wallet_base=true" .
