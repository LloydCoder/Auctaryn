FROM python:3.11-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY core/ core/
COPY api/ api/
COPY modules/ modules/
COPY config/ config/
COPY policies/ policies/

# Create data directories
RUN mkdir -p data logs

EXPOSE 8400

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8400"]
