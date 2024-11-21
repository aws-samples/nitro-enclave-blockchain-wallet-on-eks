#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e

K8S_TEMPLATES="./lib/k8s_templates"
DEPLOYMENT_TEMPLATE="${K8S_TEMPLATES}/deployment_spec_template.yaml"
LOAD_BALANCER_TEMPLATE="${K8S_TEMPLATES}/load_balancer_service_template.yaml"

METADATA_NAME_PATH=".metadata.name"
SERVICE_ACCOUNT_PATH=".spec.template.spec.serviceAccountName"
IMAGE_PATH=".spec.template.spec.containers[0].image"
SECRETS_TABLE_PATH=".spec.template.spec.containers[0].env[0].value"
FQDN_PATH=".spec.template.spec.containers[0].env[1].value"
KEY_ARN_PATH=".spec.template.spec.containers[0].env[2].value"
ENCLAVE_IMAGE_URI_SSM_PATH=".spec.template.spec.containers[0].env[3].value"
VSOCK_BASE_PORT_PATH=".spec.template.spec.containers[0].env[4].value"
LOG_LEVEL_PATH=".spec.template.spec.containers[0].env[5].value"

TEMPLATE_APP_PATH=".spec.template.metadata.labels.app"
SELECTOR_APP_PATH=".spec.selector.matchLabels.app"

CONTAINER_NAME_PATH=".spec.template.spec.containers[0].name"

LOAD_BALANCER_APP_PATH=".spec.selector.app"
LOAD_BALANCER_NAME_PATH=".metadata.name"
LOAD_BALANCER_ANNOTATIONS_PATH=".metadata.annotations"

if [ ! -f "${CDK_PREFIX}vsock_base_port_assignments.tmp" ]; then
  echo "${CDK_PREFIX}vsock_base_port_assignments.tmp file is missing, stopping deployment"
  exit 1
fi

deployment_params=$(
  aws ssm get-parameters --region "${CDK_DEPLOY_REGION}" --names \
    "/${CDK_PREFIX}eks/nitro/ethereum/domain" \
    "/${CDK_PREFIX}app/ethereum/secrets_table" \
    "/${CDK_PREFIX}app/ethereum/key_id" \
    "/${CDK_PREFIX}app/ethereum/generator_pod/image_uri" \
    "/${CDK_PREFIX}app/ethereum/generator_enclave/eif_uri" \
    "/${CDK_PREFIX}app/ethereum/generator_pod/service_account_name" \
    "/${CDK_PREFIX}app/ethereum/signer_pod/image_uri" \
    "/${CDK_PREFIX}app/ethereum/signer_enclave/eif_uri" \
    "/${CDK_PREFIX}app/ethereum/signer_pod/service_account_name" \
    "/${CDK_PREFIX}app/ethereum/log_level" \
    --query "Parameters[*].{Name:Name,Value:Value}" | jq 'INDEX(.Name)'
)

domain=$(echo "${deployment_params}" | jq -r '."/'${CDK_PREFIX}'eks/nitro/ethereum/domain".Value' | tr '[:upper:]' '[:lower:]')
key_arn=$(echo "${deployment_params}" | jq -r '."/'${CDK_PREFIX}'app/ethereum/key_id".Value')

generator_app_name="ethereum-key-generator"
secrets_table_name=$(echo "${deployment_params}" | jq -r '."/'${CDK_PREFIX}'app/ethereum/secrets_table".Value')
generator_pod_image_uri=$(echo "${deployment_params}" | jq -r '."/'${CDK_PREFIX}'app/ethereum/generator_pod/image_uri".Value')

generator_enclave_image_uri_ssm="/${CDK_PREFIX}app/ethereum/generator_enclave/eif_uri"
generator_pod_service_account=$(echo "${deployment_params}" | jq -r '."/'${CDK_PREFIX}'app/ethereum/generator_pod/service_account_name".Value')
generator_fqdn="${generator_app_name}.${domain}"
generator_vsock_base_port=$(grep "ethereum-key-generator" < "${CDK_PREFIX}vsock_base_port_assignments.tmp" | cut -d ":" -f 2 | tail -n 1)

signer_app_name="ethereum-signer"
signer_pod_image_uri=$(echo "${deployment_params}" | jq -r '."/'${CDK_PREFIX}'app/ethereum/signer_pod/image_uri".Value')
signer_enclave_image_uri_ssm="/${CDK_PREFIX}app/ethereum/signer_enclave/eif_uri"
signer_pod_service_account=$(echo "${deployment_params}" | jq -r '."/'${CDK_PREFIX}'app/ethereum/signer_pod/service_account_name".Value')
signer_fqdn="${signer_app_name}.${domain}"
signer_vsock_base_port=$(grep "ethereum-signer" < "${CDK_PREFIX}vsock_base_port_assignments.tmp" | cut -d ":" -f 2 | tail -n 1)

log_level=$(echo "${deployment_params}" | jq -r '."/'${CDK_PREFIX}'app/ethereum/log_level".Value')
# create deployment spec and service using path parameters defined above
# generator deployment

# todo how to ensure that there are no 'empty' or 'nonetype' values / env keys are always available
yq eval "(${METADATA_NAME_PATH} = \"${generator_app_name}-deployment\") |(${SERVICE_ACCOUNT_PATH} = \"${generator_pod_service_account}\") | (${IMAGE_PATH} = \"${generator_pod_image_uri}\") | (${TEMPLATE_APP_PATH} = \"${generator_app_name}\") | (${SELECTOR_APP_PATH} = \"${generator_app_name}\") | (${SECRETS_TABLE_PATH} = \"${secrets_table_name}\") | (${CONTAINER_NAME_PATH} = \"${generator_app_name}-container\") | (${FQDN_PATH} = \"${generator_fqdn}}\") | (${KEY_ARN_PATH} = \"${key_arn}\") | (${VSOCK_BASE_PORT_PATH} = \"${generator_vsock_base_port}\") | (${LOG_LEVEL_PATH} = \"${log_level}\") | (${ENCLAVE_IMAGE_URI_SSM_PATH} = \"${generator_enclave_image_uri_ssm}\")" ${DEPLOYMENT_TEMPLATE} | kubectl apply -f -
yq eval "(${LOAD_BALANCER_APP_PATH} = \"${generator_app_name}\") | (${LOAD_BALANCER_NAME_PATH} = \"${generator_app_name}-service-loadbalancer\") | (${LOAD_BALANCER_ANNOTATIONS_PATH} += {\"external-dns.alpha.kubernetes.io/hostname\":\"${generator_fqdn}\"})" "${LOAD_BALANCER_TEMPLATE}" | kubectl apply -f -

# signer deployment
yq eval "(${METADATA_NAME_PATH} = \"${signer_app_name}-deployment\") |(${SERVICE_ACCOUNT_PATH} = \"${signer_pod_service_account}\") | (${IMAGE_PATH} = \"${signer_pod_image_uri}\") | (${TEMPLATE_APP_PATH} = \"${signer_app_name}\") | (${SELECTOR_APP_PATH} = \"${signer_app_name}\") | (${SECRETS_TABLE_PATH} = \"${secrets_table_name}\") | (${CONTAINER_NAME_PATH} = \"${signer_app_name}-container\") | (${FQDN_PATH} = \"${signer_fqdn}}\") | (${KEY_ARN_PATH} = \"${key_arn}\") | (${VSOCK_BASE_PORT_PATH} = \"${signer_vsock_base_port}\") | (${LOG_LEVEL_PATH} = \"${log_level}\") | (${ENCLAVE_IMAGE_URI_SSM_PATH} = \"${signer_enclave_image_uri_ssm}\")" ${DEPLOYMENT_TEMPLATE} | kubectl apply -f -
yq eval "(${LOAD_BALANCER_APP_PATH} = \"${signer_app_name}\") | (${LOAD_BALANCER_NAME_PATH} = \"${signer_app_name}-service-loadbalancer\") | (${LOAD_BALANCER_ANNOTATIONS_PATH} += {\"external-dns.alpha.kubernetes.io/hostname\":\"${signer_fqdn}\"})" "${LOAD_BALANCER_TEMPLATE}" | kubectl apply -f -
