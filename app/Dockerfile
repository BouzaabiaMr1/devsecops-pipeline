# VulnFlask — Dockerfile
# Intentionally uses an older base image so Trivy can find CVEs (demo purposes)
FROM python:3.11-slim

LABEL maintainer="devsecops-student"
LABEL description="Intentionally vulnerable Flask app — scan target only"

WORKDIR /app

# Copy requirements first (layer caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .

# VULNERABILITY: Running as root (should use non-root user)
# VULNERABILITY: No HEALTHCHECK directive

EXPOSE 5000

CMD ["python", "app.py"]
