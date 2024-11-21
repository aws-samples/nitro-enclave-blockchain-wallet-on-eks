#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set -e
set +x

LOG_LEVEL=${CDK_APP_LOG_LEVEL:-INFO}

application=${1}
external_key_generation_flag=${2:-false}

eif_file="./applications/ethereum-signer/third_party/eif/${CDK_PREFIX}${application}_enclave.eif"

# compare to upper case debug flag
log_level_upper=$(echo "${LOG_LEVEL}" | tr '[:lower:]' '[:upper:]')
if [[ "${log_level_upper}" == "DEBUG" ]]; then
  pcr_0="000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
else
  measurement=$(./scripts/get_pcr0.sh "${eif_file}")
  #  required to remove carriage return
  pcr_0=$(echo "${measurement//\r/}" | sed 's/\r//g')
fi

pod_service_account_role_arn=$(aws ssm get-parameter --name "/${CDK_PREFIX}app/ethereum/signer_pod/service_account_role_arn" --region "${CDK_DEPLOY_REGION}" | jq -r ".Parameter.Value")

# account
account_id=$(aws sts get-caller-identity | jq -r '.Account')

if [[ "${external_key_generation_flag}" == "true" ]]; then
  #  add permission for lambda function to run encrypt on KMS key to encrypt externally generated private keys
  lambda_arn=$(aws ssm get-parameter --name "/${CDK_PREFIX}app/ethereum/invoke_lambda" --region "${CDK_DEPLOY_REGION}" | jq -r ".Parameter.Value")
  lambda_execution_role_arn=$(aws lambda --region "${CDK_DEPLOY_REGION}" get-function --function-name "${lambda_arn}" | jq -r '.Configuration.Role')
  jq '.Statement[0].Condition.StringEqualsIgnoreCase."kms:RecipientAttestation:ImageSha384"="'${pcr_0}'" | .Statement[0].Principal.AWS="'${pod_service_account_role_arn}'" | .Statement[1].Principal.AWS="'${lambda_execution_role_arn}'" | .Statement[2].Principal.AWS="arn:aws:iam::'${account_id}':root"' ./lib/policy_templates/enclave_key_policy_lambda.json | jq '.'
else
  jq '.Statement[0].Condition.StringEqualsIgnoreCase."kms:RecipientAttestation:ImageSha384"="'${pcr_0}'" | .Statement[0].Principal.AWS="'${pod_service_account_role_arn}'" | .Statement[1].Principal.AWS="arn:aws:iam::'${account_id}':root"' ./lib/policy_templates/enclave_key_policy.json | jq '.'
fi
