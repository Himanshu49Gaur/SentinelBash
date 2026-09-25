FROM python:3.12-slim-bookworm

LABEL maintainer="SentinelBash Core Team"
LABEL description="SentinelBash SOC Automation & Incident Response Appliance"

# Install system utilities, iptables, sqlite3, and process management
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    iptables \
    sqlite3 \
    curl \
    jq \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/sentinelbash

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY bin/ ./bin/
COPY config/ ./config/
COPY server/ ./server/
COPY static/ ./static/
COPY deploy/ ./deploy/

# Fix permissions
RUN chmod +x bin/*.sh deploy/*.sh

# Create runtime directories
RUN mkdir -p data/logs data/incidents data/run

EXPOSE 8000

# Docker entrypoint script
RUN cat <<'EOF' > /opt/sentinelbash/entrypoint.sh
#!/usr/bin/env bash
set -e

# Initialize DB if schema not present
if [ ! -f /opt/sentinelbash/data/sentinel.db ]; then
    echo "[CONTAINER] Initializing SentinelBash SQLite database..."
    python3 /opt/sentinelbash/server/db/init_db.py
fi

# Start Bash Core Engine in background
echo "[CONTAINER] Starting SentinelBash core engine daemon..."
/opt/sentinelbash/bin/sentinel.sh start

# Handle graceful shutdown
trap '/opt/sentinelbash/bin/sentinel.sh stop; exit 0' SIGTERM SIGINT

# Start FastAPI server in foreground
echo "[CONTAINER] Launching Tactical SOC Management API on port 8000..."
exec uvicorn server.main:app --host 0.0.0.0 --port 8000 --workers 2
EOF

RUN chmod +x /opt/sentinelbash/entrypoint.sh

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

ENTRYPOINT ["/opt/sentinelbash/entrypoint.sh"]
