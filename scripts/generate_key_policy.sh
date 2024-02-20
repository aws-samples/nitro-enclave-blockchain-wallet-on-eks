#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set -e
set +x

application=${1}
debug_flag=${2}

eif_file="./applications/ethereum-signer/third_party/eif/${CDK_PREFIX}${application}_enclave.eif"

if [[ "${debug_flag}" == "debug" ]]; then
  pcr_0="000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
else
  measurement=$(./scripts/get_pcr0.sh "${eif_file}")
  #  required to remove carriage return
  pcr_0=$(echo "${measurement//\r/}" | sed 's/\r//g')
fi

lambda_arn=$(aws ssm get-parameter --name "/${CDK_PREFIX}app/ethereum/invoke_lambda" --region "${CDK_DEPLOY_REGION}" | jq -r ".Parameter.Value")
lambda_execution_role_arn=$(aws lambda --region "${CDK_DEPLOY_REGION}" get-function --function-name "${lambda_arn}" | jq -r '.Configuration.Role')

pod_service_account_role_arn=$(aws ssm get-parameter --name "/${CDK_PREFIX}app/ethereum/signer_pod/service_account_role_arn" --region "${CDK_DEPLOY_REGION}" | jq -r ".Parameter.Value")

# account
account_id=$(aws sts get-caller-identity | jq -r '.Account')

jq '.Statement[0].Condition.StringEqualsIgnoreCase."kms:RecipientAttestation:ImageSha384"="'${pcr_0}'" | .Statement[0].Principal.AWS="'${pod_service_account_role_arn}'" | .Statement[1].Principal.AWS="'${lambda_execution_role_arn}'" | .Statement[2].Principal.AWS="arn:aws:iam::'${account_id}':root"' ./lib/policy_templates/enclave_key_policy.json | jq '.'
