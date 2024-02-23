#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

set +x
set -e

app_output=${1}

app_stack_name=$(jq -r '. |= keys | .[0]' "${app_output}")
lambda_function_name=$(jq -r ".${app_stack_name}.InvokeLambdaName" "${app_output}")

CREATE_KEY_REQUEST='{
  "operation": "ethereum-key-generator_generate_key",
  "payload": {
    "secret": ""
  }
}'

SET_KEY_REQUEST='{
  "operation": "ethereum-signer_set_key",
  "payload": {
    "eth_key": "",
    "secret": ""
    }
}'

SIGN_TX_REQUEST='{
  "operation": "ethereum-signer_sign_transaction",
  "payload": {
    "transaction_payload": {
      "value": 0.01,
      "to": "0xa5D3241A1591061F2a4bB69CA0215F66520E67cf",
      "nonce": 0,
      "type": 2,
      "chainId": 5,
      "gas": 100000,
      "maxFeePerGas": 100000000000,
      "maxPriorityFeePerGas": 3000000000
    },
    "key_id": "",
    "secret": ""
    }
}'

SIGN_USEROP_REQUEST='{
  "operation": "ethereum-signer_sign_transaction",
  "payload": {
    "transaction_payload": {
      "userOpHash": ""
    },
    "key_id": "",
    "secret": ""
    }
}'


tmp_ethereum_key=$(openssl ecparam -name secp256k1 -genkey -noout | openssl ec -text -noout | grep priv -A 3 | tail -n +2 | tr -d '\n[:space:]:' | sed 's/^00//')
secret=Welcome12345678!
secret_hash=$(sha256sum <<< $secret | awk '{ print $1 }')

# store new key via lambda
printf "\n**** lambda set key request ****\n"
echo "${SET_KEY_REQUEST}" | jq '.payload.eth_key="'${tmp_ethereum_key}'" | .payload.secret="'${secret_hash}'"' >.tmp.payload
 $( echo ${payload} | jq -R -s '.')
aws lambda invoke --region ${CDK_DEPLOY_REGION} --cli-binary-format raw-in-base64-out --function-name "${lambda_function_name}" --payload file://.tmp.payload .tmp.out
key_id=$(jq -r '.key_id' <.tmp.out)
cat .tmp.out

# create new key via enclave / 64 character hash
printf "\n**** generate key request (64) ****\n"
date +"%T"

echo "${CREATE_KEY_REQUEST}" | jq '.payload.secret="'${secret_hash}'"' >.tmp.payload
# $( echo ${payload} | jq -R -s '.')

aws lambda invoke --region ${CDK_DEPLOY_REGION} --cli-binary-format raw-in-base64-out --function-name "${lambda_function_name}" --payload file://.tmp.payload .tmp.out
key_id=$(jq -r '.enclave_result.key_id' <.tmp.out)
#
cat .tmp.out


# create new key via enclave / 36 character uuid
printf "\n**** generate key request (36) ****\n"
echo "${CREATE_KEY_REQUEST}" | jq '.payload.secret="DE7C53C4-F4D2-4D38-AAF4-A5B2E77D41B3"' >.tmp.payload
# $( echo ${payload} | jq -R -s '.')

aws lambda invoke --region ${CDK_DEPLOY_REGION} --cli-binary-format raw-in-base64-out --function-name "${lambda_function_name}" --payload file://.tmp.payload .tmp.out
key_id=$(jq -r '.enclave_result.key_id' <.tmp.out)
#
cat .tmp.out


# manual override
#key_id="3bb4a6d5-eab4-43f1-a0c0-30d91ea521a0"

# sign payload
# 200
printf "\n**** signing request ****\n"
echo "${SIGN_TX_REQUEST}" | jq '.payload.key_id="'${key_id}'" | .payload.secret="'${secret_hash}'"' >.tmp.payload
aws lambda invoke --region ${CDK_DEPLOY_REGION} --cli-binary-format raw-in-base64-out --function-name "${lambda_function_name}" --payload file://.tmp.payload .tmp.out

cat .tmp.out

# 500
printf "\n**** signing request - too short secret ****\n"
echo "${SIGN_TX_REQUEST}" | jq '.payload.key_id="'${key_id}'" | .payload.secret="LengthBelow64"' >.tmp.payload
aws lambda invoke --region ${CDK_DEPLOY_REGION} --cli-binary-format raw-in-base64-out --function-name "${lambda_function_name}" --payload file://.tmp.payload .tmp.out

cat .tmp.out

# 404
wrong_secret=Welcome12345178!
wrong_secret_hash=$(sha256sum <<< $wrong_secret | awk '{ print $1 }')
printf "\n**** signing request - wrong key ****\n"
echo "${SIGN_TX_REQUEST}" | jq '.payload.key_id="12345" | .payload.secret="'${wrong_secret_hash}'"' >.tmp.payload
aws lambda invoke --region ${CDK_DEPLOY_REGION} --cli-binary-format raw-in-base64-out --function-name "${lambda_function_name}" --payload file://.tmp.payload .tmp.out

cat .tmp.out


# sign user op
# 200
printf "\n**** signing user op request ****\n"
#echo "${SIGN_USEROP_REQUEST}" | jq '.payload.key_id="'${key_id}'" | .payload.secret="'${secret_hash}'" | .payload.transaction_payload.userOpHash="'0x${secret_hash}'"' >.tmp.payload
echo "${SIGN_USEROP_REQUEST}" | jq '.payload.key_id="7e99e372-0eba-4001-8002-35e6a1478070" | .payload.secret="94ad88b873ef6779bdd76962c6394e77a2e39a025986aca6cfb75bac8583dbcf" | .payload.transaction_payload.userOpHash="0xf3df4bcb3b24437160ba86a88f41d522662ed994dddd11ac477cfc16e9a71869"' >.tmp.payload
cat .tmp.payload
aws lambda invoke --region ${CDK_DEPLOY_REGION} --cli-binary-format raw-in-base64-out --function-name "${lambda_function_name}" --payload file://.tmp.payload .tmp.out

cat .tmp.out

# signature validation issue
printf "\n**** signing user op request - too short signature ****\n"
echo "${SIGN_USEROP_REQUEST}" | jq '.payload.key_id="'${key_id}'" | .payload.secret="'${secret_hash}'" | .payload.transaction_payload.userOpHash="5033589a303c005b7e7818f4bf00e7361335f51f648be16c028951f90a1585d"' >.tmp.payload
aws lambda invoke --region ${CDK_DEPLOY_REGION} --cli-binary-format raw-in-base64-out --function-name "${lambda_function_name}" --payload file://.tmp.payload .tmp.out

cat .tmp.out

rm -rf .tmp.out .tmp.payload
