# Enclave Performance - Pod Binary Dockerfile
# Runs in the Kubernetes pod, starts the enclave and executes performance tests

## Build stage - compile Rust binary
FROM rust:1.92-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

WORKDIR /app

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./

# Create dummy source to build dependencies
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/bin/enclave.rs && \
    echo "fn main() {}" > src/bin/pod.rs && \
    echo "pub mod protocol; pub mod stats; pub mod json;" > src/lib.rs && \
    echo "" > src/protocol.rs && \
    echo "" > src/stats.rs && \
    echo "" > src/json.rs

# Build dependencies only (cached layer)
RUN cargo build --release --bin pod 2>/dev/null || true

# Copy actual source code
COPY src ./src

# Fix mtimes so Cargo detects change
RUN find src -type f -name '*.rs' -exec touch {} +


# Build the actual binary
RUN cargo build --release --bin pod

## Production stage - includes nitro-cli for enclave management
FROM amazonlinux:2023 AS prod

# Install required packages for Nitro Enclave management
RUN dnf update -y && \
    dnf install -y \
        aws-nitro-enclaves-cli \
        aws-nitro-enclaves-cli-devel \
        jq \
        aws-cli && \
    dnf clean all && \
    rm -rf /var/cache/dnf

# Environment variables
ARG VSOCK_BASE_PORT_ARG=5000
ENV VSOCK_BASE_PORT=$VSOCK_BASE_PORT_ARG

ARG LOG_LEVEL_ARG=INFO
ENV LOG_LEVEL=$LOG_LEVEL_ARG

ARG ENCLAVE_CPU_COUNT_ARG=2
ENV ENCLAVE_CPU_COUNT=$ENCLAVE_CPU_COUNT_ARG

ARG ENCLAVE_MEMORY_SIZE_ARG=512
ENV ENCLAVE_MEMORY_SIZE=$ENCLAVE_MEMORY_SIZE_ARG

WORKDIR /app

# Copy the run script and binary
COPY images/pod/run.sh /app/run.sh
COPY --from=builder /app/target/release/pod /app/pod

# Make scripts executable
RUN chmod +x /app/run.sh /app/pod

CMD ["/app/run.sh"]
