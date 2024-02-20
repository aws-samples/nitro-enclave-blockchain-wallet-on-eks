#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e

REGION="${CDK_DEPLOY_REGION:-${AWS_DEFAULT_REGION}}"
nodes=$(kubectl get nodes -o custom-columns=NAME:.metadata.name --no-headers)

domain=$(aws ssm get-parameter --name "/${CDK_PREFIX}eks/nitro/ethereum/domain" --region "${CDK_DEPLOY_REGION}" | jq -r ".Parameter.Value")
hosted_zone_id=$(aws ssm get-parameter --name "/${CDK_PREFIX}eks/nitro/ethereum/zoneid" --region "${CDK_DEPLOY_REGION}" | jq -r ".Parameter.Value")


# install k8s metrics service e.g. for kubectl top or k9s
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# install the k8s enclave device plugin
kubectl apply -f https://raw.githubusercontent.com/aws/aws-nitro-enclaves-k8s-device-plugin/main/aws-nitro-enclaves-k8s-ds.yaml


# label all available EKS nodes as enclave enabled
for node in ${nodes}; do
  kubectl label node "${node}" aws-nitro-enclaves-k8s-dp=enabled --overwrite
  sleep 2
done

# export variables to make them accessible for envsubst during external dns deployment
export REGION
export hosted_zone_id
export domain

# install external dns
envsubst <./lib/k8s_templates/external_dns.yaml | kubectl create -f -
