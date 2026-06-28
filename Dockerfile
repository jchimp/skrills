# ---- Stage 1: gitleaks binary ----
FROM zricethezav/gitleaks:latest AS gitleaks

# ---- Stage 2: app ----
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# uv for fast installs
RUN pip install --no-cache-dir uv

WORKDIR /app

# Copy gitleaks binary from scanner image
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks

# Install deps first for layer caching
COPY pyproject.toml ./
RUN uv pip install --system -r pyproject.toml

# Copy source
COPY src/ ./src/

# SQLite data dir (used in internal mode; unused when SKRILLS_PUBLIC=true)
RUN mkdir -p /app/data
VOLUME ["/app/data"]

ENV SKRILLS_DB=/app/data/skrills.db \
    SKRILLS_HOST=0.0.0.0 \
    SKRILLS_PORT=8000

# Run as an unprivileged user
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["uvicorn", "skrills.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "src"]
