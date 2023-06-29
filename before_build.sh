#!/usr/bin/env bash
set -euo pipefail
pushd "$(git rev-parse --show-toplevel)" >/dev/null

rm -rf dist

poetry build --format sdist
poetry export --without-hashes -f requirements.txt -o dist/requirements.txt
