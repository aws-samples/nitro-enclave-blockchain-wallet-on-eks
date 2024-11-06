#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

set -x
set -e

task=${1}
runners=${2:-17}
iterations=${3:-200}

# start concurrent aws cli requests towards lambda
# https://learning.postman.com/docs/collections/testing-api-performance/
# start newman collections in parallel -> keep track of 200, 500 and timeouts

POSTMAN_COLLECTION="./tests/e2e/postman/eks_nitro_wallet.postman_collection.json"

# get role arn
api_role_arn=$(aws ssm get-parameter --name "/${CDK_PREFIX}app/ethereum/rest_url_role_arn" --region "${CDK_DEPLOY_REGION}" | jq -r ".Parameter.Value")

# get url
api_endpoint=$(aws ssm get-parameter --name "/${CDK_PREFIX}app/ethereum/rest_url" --region "${CDK_DEPLOY_REGION}" | jq -r ".Parameter.Value")

# assume rest api role
AWS_SESSION_TOKEN_RESPONSE=$(aws sts assume-role --role-arn "${api_role_arn}" --region "${CDK_DEPLOY_REGION}" --role-session-name TestUserSession)

aws_session_token=$(jq -r '.Credentials.SessionToken' <(echo "${AWS_SESSION_TOKEN_RESPONSE}"))
aws_secret=$(jq -r '.Credentials.SecretAccessKey' <(echo "${AWS_SESSION_TOKEN_RESPONSE}"))
aws_key=$(jq -r '.Credentials.AccessKeyId' <(echo "${AWS_SESSION_TOKEN_RESPONSE}"))
aws_region="${CDK_DEPLOY_REGION}"

tmp_ethereum_key=$(openssl ecparam -name secp256k1 -genkey -noout | openssl ec -text -noout | grep priv -A 3 | tail -n +2 | tr -d '\n[:space:]:' | sed 's/^00//')
secret="Welcome12345678!"
secret_hash=$(sha256sum <<<$secret | awk '{ print $1 }')

user_op_hash="0xf3df4bcb3b24437160ba86a88f41d522662ed994dddd11ac477cfc16e9a71869"
key_id="ea9d742b-a330-4fd4-a437-b6de8dba5b53"

# inject the credentials into the newman file
if [[ "${task}" == "integration" ]]; then
  echo "------- running standard e2e tests -------"
  newman run "${POSTMAN_COLLECTION}" --folder  integration \
    --env-var "base_url=${api_endpoint}" \
    --env-var "aws_key=${aws_key}" \
    --env-var "aws_secret=${aws_secret}" \
    --env-var "aws_session_token=${aws_session_token}" \
    --env-var "aws_region=${aws_region}" \
    --env-var "secret=${secret_hash}" \
    --env-var "user_op_hash=${user_op_hash}" \
    --env-var "eth_key=${tmp_ethereum_key}" \
    --env-var "key_id=${key_id}" \
    --verbose
fi

if [[ "${task}" == "load" ]]; then
  echo "------- running load e2e tests -------"

  newman run "${POSTMAN_COLLECTION}" --folder load_testing_key_generation \
      --env-var "base_url=${api_endpoint}" \
      --env-var "aws_key=${aws_key}" \
      --env-var "aws_secret=${aws_secret}" \
      --env-var "aws_session_token=${aws_session_token}" \
      --env-var "aws_region=${aws_region}" \
      --env-var "secret=${secret_hash}" \
      --env-var "user_op_hash=${user_op_hash}" \
      --env-var "eth_key=${tmp_ethereum_key}" \
      --env-var "key_id=${key_id}" \
      --env-var "iterations=${runners}" \
      --bail
#      --verbose \

  # give enclave a few seconds to propagate keys to DynamoDB
  sleep 5

  #  create n new key_ids in database and just get key_ids via
  secrets_table_arn=$(aws ssm get-parameter --name "/${CDK_PREFIX}app/ethereum/secrets_table" --region "${CDK_DEPLOY_REGION}" | jq -r ".Parameter.Value")
  secrets_table_name=$(echo "${secrets_table_arn}" | cut -d "/" -f 2)
  key_ids=$(aws dynamodb scan --table-name "${secrets_table_name}" --region "${CDK_DEPLOY_REGION}" --max-items ${runners} --attributes-to-get "key_id" | jq -r '.Items[].key_id.S')

  while IFS= read -r key_id; do

    newman run ./tests/e2e/postman/eks_nitro_wallet.postman_collection.json --folder load_testing_signing \
      --env-var "base_url=${api_endpoint}" \
      --env-var "aws_key=${aws_key}" \
      --env-var "aws_secret=${aws_secret}" \
      --env-var "aws_session_token=${aws_session_token}" \
      --env-var "aws_region=${aws_region}" \
      --env-var "secret=${secret_hash}" \
      --env-var "user_op_hash=${user_op_hash}" \
      --env-var "eth_key=${tmp_ethereum_key}" \
      --env-var "key_id=${key_id}" \
      --env-var "iterations=${iterations}" \
      --bail &
#      --verbose \
#      --env-var "runner_id=${i}" \
  done <<< "${key_ids}"
  wait
fi
