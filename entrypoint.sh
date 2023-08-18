#! /usr/bin/env bash
set -euo pipefail

exec gunicorn \
    --workers 4 \
    --bind 0.0.0.0:5000 \
    --env BREWBLOX_AUTH_JWT_SECRET="$(openssl rand --base64 12)" \
    "$@" \
    brewblox_auth:app
