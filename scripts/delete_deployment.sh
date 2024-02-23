#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e
# ethereum-signer or ethereum-key-generator
application=${1}

kubectl delete deployment "${application}-deployment"
kubectl delete service "${application}-service-loadbalancer"
