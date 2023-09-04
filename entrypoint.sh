#! /usr/bin/env bash
set -euo pipefail

DATA_DIR=./data
PASSWD_FILE=$DATA_DIR/users.passwd

mkdir -p $DATA_DIR
touch $PASSWD_FILE

exec gunicorn \
    --workers 4 \
    --bind 0.0.0.0:5000 \
    --env BREWBLOX_AUTH_JWT_SECRET="$(openssl rand --base64 12)" \
    --env BREWBLOX_AUTH_PASSWD_FILE=$PASSWD_FILE \
    --reload \
    --reload-extra-file $PASSWD_FILE \
    "$@" \
    brewblox_auth:app
