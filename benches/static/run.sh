#!/usr/bin/env bash
set -euo pipefail

THREADS=12
CONNECTIONS=400
DURATION=30s
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
LUA_SCRIPT="$SCRIPT_DIR/scripts/static_mixed.lua"

echo "=== BUILDING STATIC BENCHMARK SERVERS (release profile) ==="
cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml"

run_bench() {
    local name=$1
    local port=$2
    local bin="$WORKSPACE_ROOT/target/release/${name}"
    
    echo ""
    echo "=================================================="
    echo "=== STAGE: ${name^^} STATIC BENCHMARK"
    echo "=================================================="
    "$bin" >/dev/null 2>&1 &
    local pid=$!
    sleep 2
    
    echo "→ [1/3] Mixed traffic (HTML 40% / JS 25% / CSS 20% / PNG 15%)"
    wrk -t${THREADS} -c${CONNECTIONS} -d${DURATION} \
        -s "$LUA_SCRIPT" \
        ${BASE}:${port} -- 0
    echo ""
    
    echo "→ [2/3] Focused: HTML page (5KB)"
    wrk -t${THREADS} -c${CONNECTIONS} -d15s \
        "${BASE}:${port}/index.html"
    echo ""
    
    echo "→ [3/3] Focused: Binary image (80KB PNG)"
    wrk -t${THREADS} -c${CONNECTIONS} -d15s \
        "${BASE}:${port}/logo.png"
    
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
echo "=== STATIC BENCHMARK DONE ==="
