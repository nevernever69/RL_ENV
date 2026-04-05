FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends git curl && \
    rm -rf /var/lib/apt/lists/*

# Copy project files as a proper Python package
COPY . /app/cyber_gym

# Install Python dependencies
RUN pip install --no-cache-dir \
    "openenv-core[core]>=0.2.2" \
    uvicorn \
    fastapi \
    pydantic \
    flask \
    requests

# Set PYTHONPATH so "cyber_gym" is importable as a package
ENV PYTHONPATH="/app:$PYTHONPATH"

# Health check (checks OpenEnv server)
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

# The vulnerable Flask app is started automatically by the environment
# when CyberGymEnvironment.__init__() is called, running on port 5000
# internally. Only port 8000 (OpenEnv API) is exposed externally.
CMD ["uvicorn", "cyber_gym.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
