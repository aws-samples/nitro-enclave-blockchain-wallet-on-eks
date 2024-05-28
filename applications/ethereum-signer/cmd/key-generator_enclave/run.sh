#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

set -e
set -x

ip addr add 127.0.0.1/32 dev lo:0
ip addr add 127.0.0.2/32 dev lo:0
ip link set dev lo:0 up

echo "127.0.0.1   kms.${REGION}.amazonaws.com" >>/etc/hosts
echo "127.0.0.2   dynamodb.${REGION}.amazonaws.com" >>/etc/hosts

# start outbound proxy for kms
# todo fail if binary cannot be found
IN_ADDRS=127.0.0.1:443 OUT_ADDRS=3:"$(($PORT))" /app/proxy &

# start outbound proxy for dynamodb
IN_ADDRS=127.0.0.2:443 OUT_ADDRS=3:"$(($PORT + 1))" /app/proxy &

/app/key-generator_enclave
