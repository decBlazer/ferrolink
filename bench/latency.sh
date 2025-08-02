#!/usr/bin/env bash
# -------------------------------------------------------------
# FerroLink latency benchmark script
# Usage:  ./bench/latency.sh [HOST] [PORT] [SAMPLES]
# Example: ./bench/latency.sh 192.168.1.42 8080 100
# -------------------------------------------------------------
set -euo pipefail

HOST=${1:-127.0.0.1}
PORT=${2:-8080}
SAMPLES=${3:-50}
CLIENT_BIN="$(dirname "$0")/../target/release/client"
CERT_PATH="$(dirname "$0")/../ca-cert.pem"

if [[ ! -x "$CLIENT_BIN" ]]; then
  echo "Client binary not found at $CLIENT_BIN; build it first (cargo build -p client --release)" >&2
  exit 1
fi
if [[ ! -f "$CERT_PATH" ]]; then
  echo "CA certificate not found at $CERT_PATH" >&2
  exit 1
fi

echo "# FerroLink latency benchmark"
echo "# host=$HOST port=$PORT samples=$SAMPLES"
echo "# started=$(date -Is)"

declare -a durations=()
for i in $(seq 1 "$SAMPLES"); do
  START=$(date +%s%3N)
  "$CLIENT_BIN" --host "$HOST" --port "$PORT" --cert-path "$CERT_PATH" ping >/dev/null
  END=$(date +%s%3N)
  durations+=("$((END-START))")
  echo "${durations[-1]}"
done | awk '
{sum+=$1; arr[NR]=$1} END {
  n=NR; asort(arr); p50=arr[int(0.5*n)]; p90=arr[int(0.9*n)];
  printf("\nResults (ms): avg=%.1f  p50=%d  p90=%d  max=%d  samples=%d\n", sum/n, p50, p90, arr[n], n);
}' 