FROM python:3.11-slim

WORKDIR /app

# ── System tools for dynamic analysis ──
RUN apt-get update && apt-get install -y \
    strace \
    curl \
    wget \
    git \
    nodejs \
    npm \
    procps \
    iproute2 \
    net-tools \
    tcpdump \
    tshark \
    binutils \
    build-essential \
    libssl-dev \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# ── Pull OpenSSF analysis image so it is cached and ready ──
# This avoids pulling during analysis which adds latency
RUN docker pull gcr.io/ossf-malware-analysis/analysis 2>/dev/null || \
    echo "OpenSSF image will be pulled at runtime"

# ── Copy project ──
COPY . .

# ── Install project Python dependencies ──
RUN pip install --no-cache-dir -r requirements.txt

# ── Ensure scripts module works ──
ENV PYTHONPATH=/app

# ── Default command ──
CMD ["python", "sandbox/runner.py"]
