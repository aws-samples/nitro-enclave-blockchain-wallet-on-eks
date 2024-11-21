#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

set -e
set -x

# tcp and kernel tuning would go here
#sysctl -w net.core.rmem_max=16777216 # 4MB
#sysctl -w net.core.wmem_max=16777216 # 4MB
#sysctl -w net.ipv4.tcp_max_syn_backlog=65536
#sysctl -w net.core.somaxconn=65535
#sysctl -w net.core.netdev_max_backlog=65536

/app/signing_enclave
