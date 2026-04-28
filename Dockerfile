# ============================================================
# Dockerfile — Python Anomaly Detector Container
#
# Builds a minimal Python image containing your daemon.
# Multi-stage is overkill here — single stage is clean and fast.
# ============================================================

# Base image
# python:3.11-slim = Python 3.11 on Debian Slim (~50MB vs ~900MB for full).
# We use slim because we only need Python + pip + our packages.
# "3.11" is pinned (not "latest") so builds are reproducible.
FROM python:3.11-slim

# Metadata
LABEL maintainer="HNG DevSecOps"
LABEL description="Anomaly Detection Daemon for HNG cloud.ng"

# System dependencies
# Install OS packages needed by the detector.
# We install them in a single RUN command to keep the image layer small.
# --no-install-recommends: skip optional packages to reduce image size.
# After installing, clean apt cache (rm -rf /var/lib/apt/lists/*) to
# further reduce image size.
RUN apt-get update && apt-get install -y --no-install-recommends \
    # iptables: the binary your blocker.py calls via subprocess
    iptables \
    # curl: used by the Docker healthcheck to hit /health endpoint
    curl \
    # procps: provides ps, free, etc. (used by psutil for process stats)
    procps \
    # iputils-ping: basic networking debug tool
    iputils-ping \
    # Clean up apt cache — reduces final image size significantly
    && rm -rf /var/lib/apt/lists/*

# Working directory
# All subsequent commands run relative to /app.
# This is where your Python source files will live inside the container.
WORKDIR /app

# Python dependencies
# Copy requirements.txt FIRST (before source code).
# Docker caches each layer. If requirements.txt hasn't changed,
# Docker skips the pip install step on rebuild — much faster iteration.
COPY requirements.txt .

# Install Python packages.
# --no-cache-dir: don't cache pip downloads inside the image (saves space).
# --upgrade pip: ensure pip itself is up to date before installing.
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Source code
# Copy your Python source files into the container.
# We copy after pip install so code changes don't invalidate the
# dependency cache layer (only changed source triggers a fast rebuild).
COPY *.py ./

# Log directory
# Create the audit log directory inside the container.
# This is also bind-mounted from the host, but creating it here
# ensures the directory exists even if the mount fails.
RUN mkdir -p /var/log/detector /var/log/nginx

# Non-root user?
# Normally we'd run as a non-root user for security.
# HOWEVER: iptables requires root (or NET_ADMIN capability + root).
# So we keep root here and use cap_add in docker-compose instead.
# Comment below documents this intentional decision.
# USER detector  ← NOT used because iptables needs root

# Entrypoint
# CMD is the command run when the container starts.
# Using python -u for unbuffered output (logs appear immediately).
# main.py reads config from /app/config.yaml (mounted in docker-compose).
CMD ["python", "-u", "main.py", "/app/config.yaml"]