# MOBIUS local-delivery image: War Room UI + API + inline static pipeline.
# Worker images (DEX/RECON/JADX) build separately from workers/*/Dockerfile;
# this image runs the documented inline development path (docs/OCI_WORKER_BACKEND.md).

# Stage 1: build the War Room graph UI into the package static directory.
FROM node:22-alpine AS ui
WORKDIR /build
COPY frontend ./frontend
RUN cd frontend && npm install --no-audit --no-fund && npm run build

# Stage 2: runtime.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml alembic.ini ./
COPY src ./src
COPY migrations ./migrations
COPY corpus ./corpus
COPY --from=ui /build/src/mobius/api/static ./src/mobius/api/static
RUN pip install --no-cache-dir ".[worker]" \
    && useradd --create-home --uid 10001 mobius
USER mobius
EXPOSE 8000
# Migrations are idempotent; apply them before serving so a fresh compose stack
# comes up ready without a separate step.
CMD ["sh", "-c", "alembic upgrade head && python -m uvicorn mobius.api.app:create_app --factory --host 0.0.0.0 --port 8000"]
