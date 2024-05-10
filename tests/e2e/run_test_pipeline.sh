#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

set +x
set -e

#source tests/e2e/.env

./tests/e2e/setup.sh

# trigger tests after k8s deployments have been finished - Route53 propagation / Lambda lookup takes about 5min for the first deployment
kubectl get pods
echo "sleeping for 360 seconds till Route53 entries have been fully propagated for Lambda lookup"
sleep 360
# run 20 instances with 100 requests (userOp, ethereumTx) each, total of 4000 signing request, 20 key generation requests
./tests/e2e/signing_load_test.sh load 20 100

./tests/e2e/cleanup.sh
