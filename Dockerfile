FROM python:3.9-bookworm as base

COPY ./dist /app/dist

ENV PIP_EXTRA_INDEX_URL=https://www.piwheels.org/simple
ENV PIP_FIND_LINKS=/wheeley

RUN set -ex \
    && mkdir /wheeley \
    && pip3 install --upgrade pip wheel setuptools \
    && pip3 wheel --wheel-dir=/wheeley -r /app/dist/requirements.txt \
    && pip3 wheel --wheel-dir=/wheeley /app/dist/*.tar.gz

FROM python:3.9-slim-bookworm
EXPOSE 5000
WORKDIR /app

ARG service_info=UNKNOWN
ENV SERVICE_INFO=${service_info}

COPY --from=base /wheeley /wheeley

RUN set -ex \
    && pip3 install --no-index --find-links=/wheeley brewblox_auth \
    && rm -rf /wheeley \
    && pip3 freeze

ENTRYPOINT ["gunicorn", "-w=4", "-b=0.0.0.0:5000", "brewblox_auth:app"]
