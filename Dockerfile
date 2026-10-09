FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Minimal system dependency for liveness checks and diagnostics.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

# Application code (read-only to the runtime user).
COPY core/ core/
COPY api/ api/
COPY modules/ modules/
COPY config/ config/
COPY policies/ policies/

# Writable runtime directories are owned by the non-root application user.
RUN mkdir -p data logs && chown -R appuser:appuser /app/data /app/logs
USER appuser

EXPOSE 8400

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8400"]
