FROM python:3.11-slim

# Metadata
LABEL maintainer="HNG DevSecOps"
LABEL description="Anomaly Detection Daemon for HNG cloud.ng"

# System dependencies
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
WORKDIR /app

# Copy Python dependencies
COPY requirements.txt .

# Install Python packages.
# --no-cache-dir: don't cache pip downloads inside the image (saves space).
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy the source files into the container.
COPY *.py ./

# Create the audit log directory inside the container.
RUN mkdir -p /var/log/detector /var/log/nginx

# Entrypoint: run the main.py script with the config file as an argument.
CMD ["python", "-u", "main.py", "/app/config.yaml"]