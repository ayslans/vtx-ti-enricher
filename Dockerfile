# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /build

COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip install --upgrade pip \
    && pip install --prefix=/opt/vtx .


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/vtx/bin:$PATH" \
    PYTHONPATH="/opt/vtx/lib/python3.12/site-packages:/opt/vtx/local/lib/python3.12/site-packages" \
    VTX_CACHE_DB="/var/lib/vtx-ti-enricher/cache.sqlite3"

RUN groupadd --gid 10001 vtxapp \
    && useradd --uid 10001 --gid 10001 --home-dir /app --shell /usr/sbin/nologin vtxapp \
    && mkdir -p /app /var/lib/vtx-ti-enricher \
    && chown -R vtxapp:vtxapp /app /var/lib/vtx-ti-enricher

COPY --from=builder --chown=root:root /opt/vtx /opt/vtx

WORKDIR /app
USER 10001:10001

ENTRYPOINT ["vtx-ti-enricher"]
CMD ["--help"]
