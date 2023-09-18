#! /usr/bin/env bash
set -euo pipefail

DATA_DIR=./data
PASSWD_FILE=$DATA_DIR/users.passwd
JWT_SECRET="$(openssl rand --base64 12)"

export BREWBLOX_AUTH_JWT_SECRET="${JWT_SECRET}"
export BREWBLOX_AUTH_PASSWD_FILE="${PASSWD_FILE}"

mkdir -p $DATA_DIR
touch $PASSWD_FILE

exec uvicorn \
    --host 0.0.0.0 \
    --port 5000 \
    --reload \
    --reload-dir $DATA_DIR \
    --reload-include "*.passwd" \
    "$@" \
    brewblox_auth:app
