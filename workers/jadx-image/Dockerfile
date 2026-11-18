FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /opt/mobius

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

ARG JADX_VERSION=1.5.6
ARG JADX_SHA256=545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974
RUN set -eux; \
    curl -fsSL --retry 3 "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -o /tmp/jadx.zip; \
    echo "${JADX_SHA256}  /tmp/jadx.zip" | sha256sum --check -; \
    mkdir -p /opt/jadx; \
    unzip -q /tmp/jadx.zip -d /opt/jadx; \
    rm /tmp/jadx.zip; \
    test -x /opt/jadx/bin/jadx; \
    test "$(/opt/jadx/bin/jadx --version)" = "${JADX_VERSION}"

COPY pyproject.toml README.md ./
COPY src ./src
COPY scripts/smoke_jadx_image.py ./scripts/smoke_jadx_image.py
COPY tests/fixtures/dex/AnalysisTest.dex ./tests/fixtures/dex/AnalysisTest.dex

RUN pip install --no-cache-dir . \
    && useradd --system --uid 65532 --no-create-home mobius \
    && mkdir -p /work \
    && chown 65532:65532 /work

USER 65532:65532
ENV PATH="/opt/jadx/bin:${PATH}"
