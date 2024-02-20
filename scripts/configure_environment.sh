#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e

eks_output=${1}
stack_name=$(jq -r '. |= keys | .[0]' "${eks_output}")
cluster_config=$(jq -r ".${stack_name} | with_entries(select(.key|match(\"nitroeksclusterConfigCommand\";\"i\")))[]" "${eks_output}")
eval "${cluster_config}"
