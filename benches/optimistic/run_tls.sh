#!/usr/bin/env bash
set -euo pipefail

THREADS=12
CONNECTIONS=400
DURATION=3s
BASE=https://127.0.0.1

# Ensure local_bin shared library path is included
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
export LD_LIBRARY_PATH="$WORKSPACE_ROOT/local_bin/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"

H2LOAD="$WORKSPACE_ROOT/local_bin/usr/bin/h2load"

cleanup() {
    echo "Cleaning up ports..."
    fuser -k 8080/tcp 8081/tcp 8082/tcp 8083/tcp 8084/tcp >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

echo "=== BUILDING OPTIMISTIC TLS BENCHMARK SERVERS (release profile) ==="
cargo build --release -p optimistic-bench --bins

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
    "$H2LOAD" -t${THREADS} -c${CONNECTIONS} -n100000000 -D${DURATION} --alpn-list=h2 ${BASE}:${port}/ | awk '/^finished in/ {print_stats = 1} print_stats'
    echo ""
    
    echo "→ [2/2] JSON GET /json"
    "$H2LOAD" -t${THREADS} -c${CONNECTIONS} -n100000000 -D${DURATION} --alpn-list=h2 ${BASE}:${port}/json | awk '/^finished in/ {print_stats = 1} print_stats'
    
    kill -9 "$pid" 2>/dev/null || true
    cleanup
    sleep 1
}

run_bench "tachyon-tls" 8080
run_bench "axum-tls" 8081
run_bench "actix-tls" 8082
run_bench "salvo-tls" 8084

echo ""
echo "=== OPTIMISTIC TLS BENCHMARK DONE ==="
