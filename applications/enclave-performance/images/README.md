# Enclave Performance Docker Images

This directory contains Dockerfiles for building the enclave performance measurement tool.

## Images

### Enclave Image (`enclave/`)

Runs inside the Nitro Enclave. Listens on vsock for measurement requests.

**Build:**
```bash
# From the enclave-performance directory
docker build -f images/enclave/Dockerfile -t enclave-perf-enclave .
```

**Build EIF (Enclave Image File):**
```bash
nitro-cli build-enclave --docker-uri enclave-perf-enclave:latest --output-file enclave.eif
```

**Environment Variables:**
- `VSOCK_PORT` - Port to listen on (default: 5000)
- `LOG_LEVEL` - Logging level (default: INFO)

### Pod Image (`pod/`)

Runs in the Kubernetes pod. Starts the enclave and executes performance tests.

**Build:**
```bash
# From the enclave-performance directory
docker build -f images/pod/Dockerfile -t enclave-perf-pod .
```

**Environment Variables:**
- `VSOCK_BASE_PORT` - Base vsock port (default: 5000)
- `LOG_LEVEL` - Logging level (default: INFO)
- `ENCLAVE_CPU_COUNT` - CPUs allocated to enclave (default: 2)
- `ENCLAVE_MEMORY_SIZE` - Memory in MB for enclave (default: 512)
- `ENCLAVE_IMAGE_URI_SSM` - SSM parameter containing S3 URI for EIF
- `ENCLAVE_IMAGE_S3_URI` - Direct S3 URI for EIF
- `MEASUREMENT_MODE` - Test mode: roundtrip, json, or sign (default: roundtrip)
- `MEASUREMENT_ITERATIONS` - Number of iterations (default: 100)

## Usage

### Local Development

1. Build the enclave image and create EIF:
```bash
docker build -f images/enclave/Dockerfile -t enclave-perf-enclave .
nitro-cli build-enclave --docker-uri enclave-perf-enclave:latest --output-file enclave.eif
```

2. Upload EIF to S3:
```bash
aws s3 cp enclave.eif s3://your-bucket/enclave-perf/enclave.eif
```

3. Build and run the pod image:
```bash
docker build -f images/pod/Dockerfile -t enclave-perf-pod .
# Run on a Nitro-enabled EC2 instance
docker run -e ENCLAVE_IMAGE_S3_URI=s3://your-bucket/enclave-perf/enclave.eif enclave-perf-pod
```

### Kubernetes Deployment

Deploy the pod image to an EKS cluster with Nitro Enclave support. The pod will:
1. Download the EIF from S3
2. Start the Nitro Enclave
3. Run performance measurements
4. Report results to stdout
