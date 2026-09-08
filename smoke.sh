#!/usr/bin/env bash
# Smoke test for the deployed auth Worker (auth#41): the health check and the
# OIDC discovery documents must all answer 200 over TLS.
#
#   ./smoke.sh https://auth.factory0.ventures
set -euo pipefail

BASE="${1:?usage: smoke.sh <base-url>}"
BASE="${BASE%/}"

paths=(
  /__health
  /.well-known/openid-configuration
  /.well-known/jwks.json
)

for path in "${paths[@]}"; do
  code="$(curl -fsS -o /dev/null -w '%{http_code}' "${BASE}${path}" || true)"
  if [ "$code" != "200" ]; then
    echo "FAIL ${path} -> ${code}"
    exit 1
  fi
  echo "ok   ${path}"
done

echo "smoke passed against ${BASE}"
