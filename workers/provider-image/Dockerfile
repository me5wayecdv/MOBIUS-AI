FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /opt/mobius
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .
# The provider binary is NOT a pyproject script on purpose: adding one would
# put pyproject.toml into this package's change set and fire the DEX image's
# push trigger on merge. The wrapper invokes the reviewed module directly.
RUN printf '#!/bin/sh\nexec python -m mobius.worker.provider_analysis "$@"\n' \
      > /usr/local/bin/mobius-provider-analysis \
    && chmod 0755 /usr/local/bin/mobius-provider-analysis
RUN useradd --system --uid 65532 --no-create-home mobius
USER 65532:65532
