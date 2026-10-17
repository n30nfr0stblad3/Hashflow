FROM python:3.11-slim

LABEL maintainer="Hashflow Team"
LABEL description="Hashflow - Ethical Monero Mining Wrapper"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libuv1-dev \
    libssl-dev \
    libhwloc-dev \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Build xmrig
WORKDIR /tmp
RUN git clone https://github.com/xmrig/xmrig.git && \
    mkdir xmrig/build && cd xmrig/build && \
    cmake .. -DWITH_OPENCL=OFF -DWITH_CUDA=OFF && \
    make -j$(nproc) && \
    make install && \
    cp xmrig /usr/local/bin/xmrig && \
    cd / && rm -rf /tmp/xmrig

WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt pyproject.toml ./
COPY hashflow ./hashflow
COPY README.md LICENSE ./

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -e .

# Copy rest
COPY . .

# Create data dir
RUN mkdir -p /root/.hashflow /app/data

# Expose dashboard port
EXPOSE 8080

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/api/health || exit 1

# Default command - dashboard only (mining requires wallet)
CMD ["hashflow", "dashboard", "--host", "0.0.0.0", "--port", "8080"]
