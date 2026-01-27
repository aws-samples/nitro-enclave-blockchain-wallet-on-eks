#!/usr/bin/env bash
# Enclave Performance - Enclave startup script
# Runs inside the Nitro Enclave

set -e

# Setup loopback interface (required for enclave networking)
ip addr add 127.0.0.1/32 dev lo 2>/dev/null || true
ip link set dev lo up 2>/dev/null || true

echo "Starting enclave performance server..."
echo "  VSOCK_PORT: ${VSOCK_PORT:-5000}"
echo "  LOG_LEVEL: ${LOG_LEVEL:-INFO}"

# Start the enclave binary
# The binary listens on VMADDR_CID_ANY (accepts connections from any CID)
# and the configured port (default 5000)
exec /app/enclave
