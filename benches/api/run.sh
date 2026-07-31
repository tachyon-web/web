#!/usr/bin/env bash
set -euo pipefail

THREADS=12
CONNECTIONS=400
DURATION=20s
BASE=http://127.0.0.1

cleanup() {
    echo "Cleaning up ports..."
    fuser -k 8080/tcp 8081/tcp 8082/tcp 8083/tcp 8084/tcp >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

# Resolve paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LUA_SCRIPT="$SCRIPT_DIR/scripts/api_mixed.lua"

echo "=== BUILDING API BENCHMARK SERVERS (release profile) ==="
cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml"

run_bench() {
    local name=$1
    local port=$2
    local bin="$WORKSPACE_ROOT/target/release/${name}"
    
    echo ""
    echo "=================================================="
    echo "=== STAGE: ${name^^} API BENCHMARK"
    echo "=================================================="
    "$bin" >/dev/null 2>&1 &
    local pid=$!
    sleep 2
    
    echo "→ [1/4] Mixed realistic API traffic (weighted distribution)"
    wrk -t${THREADS} -c${CONNECTIONS} -d${DURATION} \
        -s "$LUA_SCRIPT" \
        ${BASE}:${port} -- 0
    echo ""
    
    echo "→ [2/4] Focused: GET /api/v1/users/:id (path param + JSON response)"
    wrk -t${THREADS} -c${CONNECTIONS} -d15s \
        "${BASE}:${port}/api/v1/users/42"
    echo ""
    
    echo "→ [3/4] Focused: GET /api/v1/search?q=rust&page=1 (query params)"
    wrk -t${THREADS} -c${CONNECTIONS} -d15s \
        "${BASE}:${port}/api/v1/search?q=rust&page=1&per_page=20"
    echo ""
    
    echo "→ [4/4] Focused: GET /api/v1/metrics (large JSON ~60 data points)"
    wrk -t${THREADS} -c${CONNECTIONS} -d15s \
        "${BASE}:${port}/api/v1/metrics"
    
    kill -9 "$pid" 2>/dev/null || true
    cleanup
    sleep 1
}

run_bench "tachyon" 8080
run_bench "axum" 8081
run_bench "actix" 8082
run_bench "rocket" 8083
run_bench "salvo" 8084

echo ""
echo "=== API BENCHMARK DONE ==="
