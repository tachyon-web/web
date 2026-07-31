#!/usr/bin/env bash
set -euo pipefail

CONNECTIONS=400
DURATION=15s

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

OHA="$WORKSPACE_ROOT/local_bin/usr/bin/oha"

cleanup() {
    echo "Cleaning up ports..."
    fuser -k 8080/tcp 8080/udp 8084/tcp 8084/udp >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

echo "=== BUILDING OPTIMISTIC H3 BENCHMARK SERVERS (release profile) ==="
cargo build --release -p optimistic-bench --bin tachyon-h3 --bin salvo-h3

run_bench() {
    local name=$1
    local port=$2
    local bin="$WORKSPACE_ROOT/target/release/${name}"
    
    echo ""
    echo "=================================================="
    echo "=== STAGE: ${name^^} BENCHMARK"
    echo "=================================================="
    "$bin" >/dev/null 2>&1 &
    local pid=$!
    sleep 2
    
    echo "→ [1/2] Plaintext GET /"
    "$OHA" --http-version 3 --insecure --no-tui -c ${CONNECTIONS} -z ${DURATION} https://127.0.0.1:${port}/
    echo ""
    
    kill -9 "$pid" 2>/dev/null || true
    cleanup
    sleep 1

    "$bin" >/dev/null 2>&1 &
    local pid=$!
    sleep 2
    
    echo "→ [2/2] JSON GET /json"
    "$OHA" --http-version 3 --insecure --no-tui -c ${CONNECTIONS} -z ${DURATION} https://127.0.0.1:${port}/json
    
    kill -9 "$pid" 2>/dev/null || true
    cleanup
    sleep 1
}

run_bench "tachyon-h3" 8080
run_bench "salvo-h3" 8084

echo ""
echo "=== OPTIMISTIC H3 BENCHMARK DONE ==="
