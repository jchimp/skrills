# ---- Stage 1: gitleaks binary ----
FROM zricethezav/gitleaks:latest AS gitleaks

# ---- Stage 2: trivy binary ----
FROM aquasec/trivy:latest AS trivy

# ---- Stage 3: app ----
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Install system deps: git for clone, ca-certs for HTTPS
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv for fast installs
RUN pip install --no-cache-dir uv

WORKDIR /app

# Copy scanner binaries from upstream images
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

# Install Python deps first for layer caching
COPY pyproject.toml ./
RUN uv pip install --system -r pyproject.toml

# Copy source
COPY src/ ./src/

# Data + scratch dirs
RUN mkdir -p /app/data /app/scratch
VOLUME ["/app/data"]

ENV SKRILLS_DB=/app/data/skrills.db \
    SKRILLS_SCRATCH=/app/scratch \
    SKRILLS_HOST=0.0.0.0 \
    SKRILLS_PORT=8000

# Run as an unprivileged user
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["uvicorn", "skrills.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "src"]
