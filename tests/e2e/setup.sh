#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

set +x
set -e

# https://github.com/aws/aws-cdk/issues/30258
export BUILDX_NO_DEFAULT_ATTESTATIONS=1

usage() {
    echo "Usage: $0 [--cluster] [--app] [--build-enclave] [--all]"
    echo "  --cluster        Deploy EKS cluster only"
    echo "  --app            Deploy application stack only (requires --build-enclave)"
    echo "  --build-enclave  Build enclave images"
    echo "  --all            Deploy everything (default)"
    exit 1
}

DEPLOY_CLUSTER=false
DEPLOY_APP=false
BUILD_ENCLAVE=false

# Parse arguments
if [[ $# -eq 0 ]]; then
    DEPLOY_CLUSTER=true
    BUILD_ENCLAVE=true
	DEPLOY_APP=true
else
    while [[ $# -gt 0 ]]; do
        case $1 in
            --cluster)
                DEPLOY_CLUSTER=true
                shift
                ;;
            --app)
                DEPLOY_APP=true
                shift
                ;;
            --build-enclave)
                BUILD_ENCLAVE=true
                shift
                ;;
            --all)
                DEPLOY_CLUSTER=true
                DEPLOY_APP=true
                BUILD_ENCLAVE=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                echo "Unknown option: $1"
                usage
                ;;
        esac
    done
fi

source .venv/bin/activate

# Check if enclave docker images exist
check_enclave_images() {
    local missing=false
    if ! docker image inspect "ethereum-signer_enclave" &>/dev/null; then
        echo "Error: Docker image 'ethereum-signer_enclave' not found"
        missing=true
    fi
    if ! docker image inspect "ethereum-key-generator_enclave" &>/dev/null; then
        echo "Error: Docker image 'ethereum-key-generator_enclave' not found"
        missing=true
    fi
    if [[ "$missing" == "true" ]]; then
        echo "Run with '--build-enclave' first to build the required images"
        exit 1
    fi
}

# Validate: --app requires enclave images (either via --build-enclave or pre-existing)
if [[ "$DEPLOY_APP" == "true" && "$BUILD_ENCLAVE" == "false" ]]; then
    check_enclave_images
fi

# files need to be present to allow EKS stack to synthesize
mkdir -p applications/ethereum-signer/third_party/eif
touch "applications/ethereum-signer/third_party/eif/${CDK_PREFIX}ethereum-signer_enclave.eif"
touch "applications/ethereum-signer/third_party/eif/${CDK_PREFIX}ethereum-key-generator_enclave.eif"

if [[ "$DEPLOY_CLUSTER" == "true" ]]; then
    echo "=== Deploying EKS cluster ==="
    cdk deploy "${CDK_PREFIX}EksNitroCluster" --verbose -O "${CDK_PREFIX}EksClusterOutput.json" --output "${CDK_PREFIX}cdk.out" --require-approval=never

    # parse kubectl config command from json file
    ./scripts/configure_environment.sh "${CDK_PREFIX}EksClusterOutput.json"
    
    # Run cluster health check
    echo "=== Running cluster health check ==="
    ./tests/e2e/healthcheck.sh
fi

if [[ "$BUILD_ENCLAVE" == "true" ]]; then
    echo "=== Building enclave images ==="
    ./scripts/build_enclave_image.sh ethereum-key-generator
    ./scripts/build_enclave_image.sh ethereum-signer
fi

if [[ "$DEPLOY_APP" == "true" ]]; then
    echo "=== Deploying application stack ==="
    rm -rf cdk.context.json
    cdk deploy "${CDK_PREFIX}EthKeyManagementApp" --verbose --output "${CDK_PREFIX}cdk.out" --require-approval=never
    ./scripts/apply_deployment_spec.sh

    echo "=== Configuring KMS key policy ==="
    kms_key_id=$(aws ssm get-parameter --name "/${CDK_PREFIX}app/ethereum/key_id" --region "${CDK_DEPLOY_REGION}" | jq -r ".Parameter.Value")
    ./scripts/generate_key_policy.sh ethereum-signer >key_policy.json
    aws kms put-key-policy --region "${CDK_DEPLOY_REGION}" --policy-name default --key-id "${kms_key_id}" --policy file://key_policy.json

    # Run health check including app deployments
    echo "=== Running health check with app deployments ==="
    CHECK_APP_DEPLOYMENTS=true ./tests/e2e/healthcheck.sh
fi

echo "=== Setup complete ==="
