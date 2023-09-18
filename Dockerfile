FROM python:3.11-bookworm as base

COPY ./dist /app/dist

ENV PIP_EXTRA_INDEX_URL=https://www.piwheels.org/simple
ENV PIP_FIND_LINKS=/wheeley
ENV VENV=/app/.venv
ENV PATH="$VENV/bin:$PATH"

RUN <<EOF
    set -ex

    mkdir /wheeley
    python3 -m venv $VENV
    pip3 install --upgrade pip wheel setuptools
    pip3 wheel --wheel-dir=/wheeley -r /app/dist/requirements.txt
    pip3 wheel --wheel-dir=/wheeley /app/dist/*.tar.gz
EOF

FROM python:3.11-slim-bookworm
EXPOSE 5000
WORKDIR /app

ENV PIP_FIND_LINKS=/wheeley
ENV VENV=/app/.venv
ENV PATH="$VENV/bin:$PATH"

COPY --from=base /wheeley /wheeley
COPY ./entrypoint.sh /app/entrypoint.sh

RUN <<EOF
    set -ex

    python3 -m venv $VENV
    pip3 install --no-index brewblox_auth
    rm -rf /wheeley
    pip3 freeze
EOF

ENTRYPOINT ["/app/entrypoint.sh"]
