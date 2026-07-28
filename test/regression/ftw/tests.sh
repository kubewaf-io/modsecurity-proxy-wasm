#!/bin/sh
set -eu

cd /workspace

if ! command -v curl >/dev/null 2>&1; then
  if command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl >/dev/null
  else
    echo "[Fail] curl is required in the go-ftw container"
    exit 1
  fi
fi

step=1
total_steps=1
max_retries=120
host="${1:-envoy}"
health_url="http://${host}:8080"

echo "[$step/$total_steps] Testing application reachability"
status_code="000"
while [ "$status_code" = "000" ]; do
  status_code=$(curl --write-out "%{http_code}" --silent --output /dev/null "$health_url" || true)
  sleep 1
  printf "[Wait] Waiting for response from %s. Timeout: %ss   \r" "$health_url" "$max_retries"
  max_retries=$((max_retries - 1))
  if [ "$max_retries" -eq 0 ]; then
    echo ""
    echo "[Fail] Timeout waiting for response from $health_url"
    if [ -f /home/envoy/logs/envoy.log ]; then
      echo "Envoy logs:" && tail -n 80 /home/envoy/logs/envoy.log
    fi
    exit 1
  fi
done

if [ "$status_code" != "200" ]; then
  echo ""
  echo "[Fail] Unexpected status code $status_code, expected 200."
  exit 1
fi
echo ""
echo "[Ok] Got status code $status_code. Ready to run go-ftw."

# Brief settle so the first marker is not raced (was 5s; tee makes logs immediate).
sleep "${FTW_MARKER_SETTLE:-1}"

FTW_CLOUDMODE="${FTW_CLOUDMODE:-false}"
FTW_INCLUDE_ARG=""
if [ -n "${FTW_INCLUDE:-}" ]; then
  FTW_INCLUDE_ARG="-i ${FTW_INCLUDE}"
fi

# Marker sync. With line-buffered tee (see docker-compose), markers appear in ~ms
# so a short budget is enough. Old --log-path needed 300ms×40 (~12s) for ~8s flush lag.
FTW_RATE_LIMIT="${FTW_RATE_LIMIT:-50ms}"
FTW_MAX_MARKER_RETRIES="${FTW_MAX_MARKER_RETRIES:-40}"
FTW_READ_TIMEOUT="${FTW_READ_TIMEOUT:-5s}"

echo "[go-ftw] rate-limit=$FTW_RATE_LIMIT max-marker-retries=$FTW_MAX_MARKER_RETRIES include=${FTW_INCLUDE:-*}"

# shellcheck disable=SC2086
/ftw run -d coreruleset/tests/regression/tests \
  --config ftw.yml \
  --read-timeout="$FTW_READ_TIMEOUT" \
  --rate-limit="$FTW_RATE_LIMIT" \
  --max-marker-retries="$FTW_MAX_MARKER_RETRIES" \
  --cloud="$FTW_CLOUDMODE" \
  $FTW_INCLUDE_ARG