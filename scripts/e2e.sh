#!/usr/bin/env bash
# End-to-end test against a real cluster. Intended for a throwaway kind or
# minikube cluster: it deploys the deliberately insecure demo.
#
#   kind create cluster --name kpaudit-e2e
#   scripts/e2e.sh
#   kind delete cluster --name kpaudit-e2e
set -euo pipefail
cd "$(dirname "$0")/.."

report="$(mktemp -t kpaudit-live.XXXXXX.json)"
trap 'rm -f "$report"' EXIT

echo "==> Deploying demo workloads to context: $(kubectl config current-context)"
kubectl apply -f demo/insecure/ -f demo/hardened/

echo "==> Waiting for the hardened demo to become ready (proves the secure config runs)"
kubectl -n shop rollout status deployment/api --timeout=240s
kubectl -n shop rollout status statefulset/cache --timeout=240s

echo "==> Live scan"
kpaudit scan --format json --fail-on never --output "$report"
python3 scripts/verify_live.py "$report"

echo "==> Exit codes"
kpaudit scan --namespace shop --fail-on low > /dev/null
echo "ok: hardened namespace passes with --fail-on low"

status=0
kpaudit scan --namespace shop-insecure > /dev/null || status=$?
if [ "$status" -ne 2 ]; then
  echo "FAIL: expected exit code 2 for shop-insecure, got $status" >&2
  exit 1
fi
echo "ok: insecure namespace fails the gate (exit 2)"

echo "==> End-to-end test passed"
