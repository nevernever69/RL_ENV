FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends git curl && \
    rm -rf /var/lib/apt/lists/*

# Copy project files
COPY openenv.yaml /app/openenv.yaml
COPY pyproject.toml /app/pyproject.toml
COPY uv.lock /app/uv.lock
COPY inference.py /app/inference.py
COPY redveil /app/redveil
COPY server /app/server

# Install Python dependencies
RUN pip install --no-cache-dir \
    "openenv-core[core]>=0.2.2" \
    uvicorn \
    fastapi \
    pydantic \
    flask \
    requests

# Set PYTHONPATH so "redveil" is importable as a package
ENV PYTHONPATH="/app:$PYTHONPATH"

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:7860/health || exit 1

EXPOSE 7860

CMD ["uvicorn", "redveil.server.app:app", "--host", "0.0.0.0", "--port", "7860"]
