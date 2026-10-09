FROM python:3.12.15-alpine3.24

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Create the non-root runtime identity without adding an unused network client.
RUN adduser -D -u 10001 -s /sbin/nologin appuser

# Python deps
COPY requirements.lock .
RUN pip install --no-cache-dir --disable-pip-version-check --require-hashes -r requirements.lock

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
