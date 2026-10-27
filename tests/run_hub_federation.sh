#!/usr/bin/env bash
# Real NATS broker, isolated network and storage; no shared AIC or hub deployment.
set -euo pipefail
run="hub-federation-test-$(date -u +%Y%m%d%H%M%S)-$$"
docker network create "$run" >/dev/null
cleanup() {
  docker rm -f "$run-broker" >/dev/null 2>&1 || true
  docker network rm "$run" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker run -d --name "$run-broker" --network "$run" --network-alias broker \
  --user "$(id -u):$(id -g)" --read-only --tmpfs /tmp:size=64m \
  nats@sha256:777787bbb4c7c4083ec2213b0b8b14151617610a3e0d85776bd995cd46599c73 \
  -js -sd /tmp/nats >/dev/null
docker run --rm --network "$run" -e HUB_NATS_TEST_MODE=1 "${HUB_VERIFY_IMAGE:-hub-public-verification}" \
  python tests/integration_hub_federation.py
