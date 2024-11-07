#!/usr/bin/env bash

set +e
set -x

EIF_PATH="/usr/src/app/enclave.eif"
ENCLAVE_CPU_COUNT=2
# based on eif file size
ENCLAVE_MEMORY_SIZE=1500

if [[ "${LOG_LEVEL}" == "DEBUG" ]]; then
  debug="--debug-mode"
else
  debug=
fi

# todo old arithmetic
vsock_port_1=$((VSOCK_BASE_PORT))

generate_tls_artifact() {
  local fqdn=${1}

  openssl11 ecparam -name prime256v1 -genkey -noout -out private-key.pem

  # generate associated public key
  openssl11 ec -in private-key.pem -pubout -out public-key.pem

  # generate self-signed x509 certificate for EC2 instance
  host=$(echo "${fqdn}" | tr "." "\n" | head -n 1)

  # requires openssl > 1.1.1 / is 1.0.2k
  openssl11 req -new -x509 -key private-key.pem -out cert.pem -days 360 -subj "/C=US/O=AWS/OU=Blockchain Compute/CN=${host}" --addext "subjectAltName=DNS:${fqdn}"
}

enclave_image_uri=$(aws ssm get-parameter --region "${AWS_REGION}" --name "${ENCLAVE_IMAGE_URI_SSM}" | jq -r '.Parameter.Value')
enclave=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveName')

if [[ ${enclave} == "null" ]]; then
  aws s3 cp "${enclave_image_uri}" "${EIF_PATH}"
  nitro-cli run-enclave --cpu-count "${ENCLAVE_CPU_COUNT}" --memory "${ENCLAVE_MEMORY_SIZE}" --eif-path "${EIF_PATH}" ${debug}
  sleep 5
fi

# second call for pod logs to see if enclave is still up and running
enclave_cid=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID')

# ensure that proper cid has been assigned
[ "${enclave_cid}" == "null" ] && exit 1

export ENCLAVE_CID=${enclave_cid}

# start outbound vsock proxy in background
vsock-proxy "${vsock_port_1}" kms."${AWS_REGION}".amazonaws.com 443 -w 20 &

# todo tls inject private key and cert -> secrets manager download
# todo save in ssm config store and point lambda to x509 cert for validation
generate_tls_artifact "${FQDN}"

./signing_pod
