# syntax=docker/dockerfile:1

# ---- Stage 1: build dependencies ----
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build-time system deps (needed by some pip packages)
RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ && \
    rm -rf /var/lib/apt/lists/*

# Copy only dependency manifests first to maximise layer caching
COPY requirements.txt pyproject.toml ./

# Install Python deps into a virtual-env so we can copy it cleanly
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-compile -r requirements.txt && \
    pip install --no-compile dyana

# ---- Stage 2: runtime image ----
FROM python:3.12-slim

LABEL maintainer="evilsocket"
LABEL description="SENT — Supply-chain Event Network Triage"

# Runtime system deps: subversion for WordPress SVN diffs
RUN apt-get update && \
    apt-get install -y --no-install-recommends subversion && \
    rm -rf /var/lib/apt/lists/*

# Docker CLI for dyana dynamic analysis (container sandboxing)
COPY --from=docker:cli /usr/local/bin/docker /usr/local/bin/docker

# Bring the pre-built virtual-env from the builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app
COPY . .

# Persistent volumes for database and download cache
VOLUME ["/app/data"]
ENV SENT_DB=/app/data/sent.db
ENV SENT_CACHE=/app/data/cache

ENTRYPOINT ["python3", "cli.py"]
CMD ["--help"]
