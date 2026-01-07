#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

set +x
set -e

TIMEOUT=${HEALTHCHECK_TIMEOUT:-300}
INTERVAL=10

echo "=== Cluster Health Check ==="

# Helm chart namespaces and expected deployments/daemonsets
declare -A HELM_CHECKS=(
    ["kube-system"]="aws-nitro-enclaves-k8s-ds"
    ["external-dns"]="external-dns"
    ["aws-for-fluent-bit"]="aws-for-fluent-bit"
    ["metrics-server"]="metrics-server"
)

# App deployments in default namespace
APP_DEPLOYMENTS=(
    "ethereum-signer-deployment"
    "ethereum-key-generator-deployment"
)

check_pods_in_namespace() {
    local namespace=$1
    local component=$2
    
    echo "Checking ${component} in namespace ${namespace}..."
    
    # Get pod count and ready count
    local total=$(kubectl get pods -n "${namespace}" -l "app.kubernetes.io/name=${component}" --no-headers 2>/dev/null | wc -l || echo 0)
    local ready=$(kubectl get pods -n "${namespace}" -l "app.kubernetes.io/name=${component}" --no-headers 2>/dev/null | grep -c "Running" || echo 0)
    
    # Fallback: check by partial name match if label selector returns nothing
    if [[ "$total" -eq 0 ]]; then
        total=$(kubectl get pods -n "${namespace}" --no-headers 2>/dev/null | grep -c "${component}" || echo 0)
        ready=$(kubectl get pods -n "${namespace}" --no-headers 2>/dev/null | grep "${component}" | grep -c "Running" || echo 0)
    fi
    
    if [[ "$total" -eq 0 ]]; then
        echo "  ⚠ No pods found for ${component}"
        return 1
    elif [[ "$ready" -lt "$total" ]]; then
        echo "  ⚠ ${component}: ${ready}/${total} pods ready"
        return 1
    else
        echo "  ✓ ${component}: ${ready}/${total} pods running"
        return 0
    fi
}

check_deployment_ready() {
    local deployment=$1
    local namespace=${2:-default}
    
    echo "Checking deployment ${deployment} in namespace ${namespace}..."
    
    if ! kubectl get deployment "${deployment}" -n "${namespace}" &>/dev/null; then
        echo "  ⚠ Deployment ${deployment} not found"
        return 1
    fi
    
    local ready=$(kubectl get deployment "${deployment}" -n "${namespace}" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 0)
    local desired=$(kubectl get deployment "${deployment}" -n "${namespace}" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo 0)
    
    if [[ -z "$ready" ]]; then
        ready=0
    fi
    
    if [[ "$ready" -ge "$desired" && "$desired" -gt 0 ]]; then
        echo "  ✓ ${deployment}: ${ready}/${desired} replicas ready"
        return 0
    else
        echo "  ⚠ ${deployment}: ${ready}/${desired} replicas ready"
        return 1
    fi
}

check_for_error_states() {
    echo "Checking for pods in error states..."
    
    local errors=$(kubectl get pods -A --no-headers 2>/dev/null | grep -E "ImagePull|CrashLoop|Error|Pending|Init:" || true)
    
    if [[ -n "$errors" ]]; then
        echo "  ⚠ Pods in error state detected:"
        echo "$errors" | while read -r line; do
            echo "    $line"
        done
        return 1
    else
        echo "  ✓ No pods in error state"
        return 0
    fi
}

wait_for_all_healthy() {
    local start_time=$(date +%s)
    local all_healthy=false
    
    while [[ "$all_healthy" == "false" ]]; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        if [[ "$elapsed" -ge "$TIMEOUT" ]]; then
            echo "❌ Health check timed out after ${TIMEOUT}s"
            echo ""
            echo "=== Debug Information ==="
            kubectl get pods -A
            echo ""
            kubectl get events -A --sort-by='.lastTimestamp' | tail -20
            exit 1
        fi
        
        echo ""
        echo "--- Health check (${elapsed}s / ${TIMEOUT}s) ---"
        
        local failed=false
        
        # Check helm chart components
        for namespace in "${!HELM_CHECKS[@]}"; do
            component="${HELM_CHECKS[$namespace]}"
            if ! check_pods_in_namespace "$namespace" "$component"; then
                failed=true
            fi
        done
        
        # Check app deployments
        for deployment in "${APP_DEPLOYMENTS[@]}"; do
            if ! check_deployment_ready "$deployment" "default"; then
                failed=true
            fi
        done
        
        # Check for error states
        if ! check_for_error_states; then
            failed=true
        fi
        
        if [[ "$failed" == "false" ]]; then
            all_healthy=true
        else
            echo ""
            echo "Waiting ${INTERVAL}s before next check..."
            sleep "$INTERVAL"
        fi
    done
    
    echo ""
    echo "✅ All components healthy!"
}

# Run health check
wait_for_all_healthy

echo ""
echo "=== Final Cluster Status ==="
kubectl get pods -A
