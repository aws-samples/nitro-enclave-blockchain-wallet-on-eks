#!/usr/bin/env bash
# Enclave Performance - Pod startup script
# Starts the enclave and runs performance measurements

set +e
set -x

EIF_PATH="/app/enclave.eif"

# Debug mode for enclave if LOG_LEVEL is DEBUG
if [[ "${LOG_LEVEL}" == "DEBUG" ]]; then
    debug="--debug-mode"
else
    debug=""
fi

# Function to start the enclave
start_enclave() {
    local eif_path=$1
    
    echo "Starting Nitro Enclave..."
    echo "  CPU Count: ${ENCLAVE_CPU_COUNT}"
    echo "  Memory Size: ${ENCLAVE_MEMORY_SIZE} MB"
    echo "  EIF Path: ${eif_path}"
    
    nitro-cli run-enclave \
        --cpu-count "${ENCLAVE_CPU_COUNT}" \
        --memory "${ENCLAVE_MEMORY_SIZE}" \
        --eif-path "${eif_path}" \
        ${debug}
    
    # Wait for enclave to initialize
    sleep 3
}

# Function to get enclave CID
get_enclave_cid() {
    nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID'
}

# Check if enclave is already running
enclave=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveName')

if [[ "${enclave}" == "null" ]]; then
    # Download EIF from S3 if ENCLAVE_IMAGE_URI_SSM is set
    if [[ -n "${ENCLAVE_IMAGE_URI_SSM}" ]] && [[ -n "${AWS_REGION}" ]]; then
        echo "Fetching enclave image URI from SSM parameter: ${ENCLAVE_IMAGE_URI_SSM}"
        enclave_image_uri=$(aws ssm get-parameter --region "${AWS_REGION}" --name "${ENCLAVE_IMAGE_URI_SSM}" | jq -r '.Parameter.Value')
        echo "Downloading enclave image from: ${enclave_image_uri}"
        aws s3 cp "${enclave_image_uri}" "${EIF_PATH}"
    elif [[ -n "${ENCLAVE_IMAGE_S3_URI}" ]]; then
        echo "Downloading enclave image from: ${ENCLAVE_IMAGE_S3_URI}"
        aws s3 cp "${ENCLAVE_IMAGE_S3_URI}" "${EIF_PATH}"
    fi
    
    # Start the enclave if EIF exists
    if [[ -f "${EIF_PATH}" ]]; then
        start_enclave "${EIF_PATH}"
    else
        echo "ERROR: No enclave image found at ${EIF_PATH}"
        echo "Set ENCLAVE_IMAGE_URI_SSM or ENCLAVE_IMAGE_S3_URI environment variable"
        exit 1
    fi
fi

# Get the enclave CID
enclave_cid=$(get_enclave_cid)

if [[ "${enclave_cid}" == "null" ]] || [[ -z "${enclave_cid}" ]]; then
    echo "ERROR: Failed to get enclave CID. Enclave may not be running."
    nitro-cli describe-enclaves
    exit 1
fi

echo "Enclave started successfully with CID: ${enclave_cid}"
export ENCLAVE_CID=${enclave_cid}

# Run the performance measurement tool
# Default: roundtrip mode with 100 iterations
MODE=${MEASUREMENT_MODE:-roundtrip}
ITERATIONS=${MEASUREMENT_ITERATIONS:-100}
PORT=${VSOCK_BASE_PORT:-5000}

echo "Running performance measurements..."
echo "  Mode: ${MODE}"
echo "  Iterations: ${ITERATIONS}"
echo "  CID: ${enclave_cid}"
echo "  Port: ${PORT}"

exec /app/pod \
    --cid "${enclave_cid}" \
    --port "${PORT}" \
    --mode "${MODE}" \
    --iterations "${ITERATIONS}"
