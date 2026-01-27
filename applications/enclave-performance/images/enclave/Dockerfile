# Enclave Performance - Enclave Binary Dockerfile
# Runs inside the Nitro Enclave, listens on vsock for measurement requests

## Build stage - compile Rust binary
FROM rust:1.75-alpine AS builder

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
RUN cargo build --release --bin enclave 2>/dev/null || true

# Copy actual source code
COPY src ./src

# Build the actual binary
RUN cargo build --release --bin enclave

## Production stage - minimal runtime image
FROM alpine:3.19 AS prod

# Install runtime dependencies
RUN apk update && \
    apk add --no-cache ca-certificates iproute2 && \
    rm -rf /var/cache/apk/*

# Environment variables for enclave configuration
ARG VSOCK_PORT_ARG=5000
ENV VSOCK_PORT=$VSOCK_PORT_ARG

ARG LOG_LEVEL_ARG=INFO
ENV LOG_LEVEL=$LOG_LEVEL_ARG

WORKDIR /app

# Copy the run script and binary
COPY images/enclave/run.sh /app/run.sh
COPY --from=builder /app/target/release/enclave /app/enclave

# Make scripts executable
RUN chmod +x /app/run.sh /app/enclave

CMD ["sh", "/app/run.sh"]
