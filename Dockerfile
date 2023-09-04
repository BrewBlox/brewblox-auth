# syntax=docker/dockerfile:1.4

FROM python:3.9-bookworm as base

COPY ./dist /app/dist

ENV PIP_EXTRA_INDEX_URL=https://www.piwheels.org/simple
ENV PIP_FIND_LINKS=/wheeley

RUN <<EOF
    set -ex

    mkdir /wheeley
    pip3 install --upgrade pip wheel setuptools
    pip3 wheel --wheel-dir=/wheeley -r /app/dist/requirements.txt
    pip3 wheel --wheel-dir=/wheeley /app/dist/*.tar.gz
EOF

FROM python:3.9-slim-bookworm
EXPOSE 5000
WORKDIR /app

ARG service_info=UNKNOWN
ENV SERVICE_INFO=${service_info}

COPY --from=base /wheeley /wheeley
COPY ./entrypoint.sh /app/entrypoint.sh

RUN <<EOF
    set -ex

    pip3 install --no-index --find-links=/wheeley brewblox_auth
    rm -rf /wheeley
    pip3 freeze
EOF

ENTRYPOINT ["/app/entrypoint.sh"]
