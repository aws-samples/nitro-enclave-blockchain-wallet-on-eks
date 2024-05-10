#!/usr/bin/env bash

set +e
set -x

EIF_PATH="/usr/src/app/enclave.eif"
ENCLAVE_CPU_COUNT=2
# based on eif file size
ENCLAVE_MEMORY_SIZE=1500

# increment base port for every single application on pod (vsock_1, vsock_n, metrics)
vsock_port_1=$((VSOCK_BASE_PORT))
vsock_port_2=$((vsock_port_1 + 1))

#|| [[ "${LOG_LEVEL}" == "INFO" ]]
if [[ "${LOG_LEVEL}" == "DEBUG" ]]; then
  debug="--debug-mode"
else
  debug=
fi

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

# have pod panic so that enclave status and pod status are synced and k8s can restart if required
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

VSOCK_PROXY_YAML=./vsock-proxy.yaml
cat <<'EOF' | envsubst >$VSOCK_PROXY_YAML
allowlist:
- {address: kms.${AWS_REGION}.amazonaws.com, port: 443}
- {address: dynamodb.${AWS_REGION}.amazonaws.com, port: 443}
EOF

# start KMS and DynamoDB outbound proxies in background
# https://github.com/aws/aws-nitro-enclaves-cli/blob/main/vsock_proxy/README.md
vsock-proxy  "${vsock_port_1}" kms."${AWS_REGION}".amazonaws.com 443 --config ./vsock-proxy.yaml -w 20 &
vsock-proxy "${vsock_port_2}" dynamodb."${AWS_REGION}".amazonaws.com 443 --config ./vsock-proxy.yaml -w 20 &

generate_tls_artifact "${FQDN}"
./key-generator_pod
