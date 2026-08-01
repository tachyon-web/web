#!/usr/bin/env bash
set -euo pipefail

THREADS=12
CONNECTIONS=400
DURATION=15s
BASE=http://127.0.0.1

cleanup() {
    echo "cleaning up ports"
    fuser -k 8080/tcp 8081/tcp 8082/tcp 8083/tcp 8084/tcp >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "building optimistic benchmark servers (release)"
cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml"

run_bench() {
    local name=$1
    local port=$2
    local bin="$WORKSPACE_ROOT/target/release/${name}"

    echo ""
    echo "-- ${name} --"
    "$bin" >/dev/null 2>&1 &
    local pid=$!
    sleep 2

    echo "GET /"
    wrk -t${THREADS} -c${CONNECTIONS} -d${DURATION} ${BASE}:${port}/
    echo ""

    echo "GET /json"
    wrk -t${THREADS} -c${CONNECTIONS} -d${DURATION} ${BASE}:${port}/json

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
echo "optimistic benchmark done"
