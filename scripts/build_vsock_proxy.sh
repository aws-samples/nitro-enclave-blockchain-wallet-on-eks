#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e

target_architecture=${CDK_TARGET_ARCHITECTURE:-linux/amd64}
PROXY_TARGET_DIRECTORY="./applications/ethereum-signer/third_party/proxy"

if [[ ! -d ${PROXY_TARGET_DIRECTORY} ]]; then
  mkdir -p ${PROXY_TARGET_DIRECTORY}
fi

cd "${PROXY_TARGET_DIRECTORY}"

# if viproxy has already been cloned continue
if [[ ! -d "./viproxy" ]]; then
  git clone --depth 1 --branch v0.1.2 https://github.com/brave/viproxy.git
fi

cd ./viproxy

architecture=$(echo "${target_architecture}" | cut -d "/" -f 2)
GOOS=linux GOARCH="${architecture}" CGO_ENABLED=0 go build ./example/main.go
cp main ../proxy
cd ..
rm -rf ./viproxy
