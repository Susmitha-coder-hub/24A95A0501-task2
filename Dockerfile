############################
# Stage 1: Builder
############################
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /app

# Copy dependency file (if you use requirements.txt)
COPY requirements.txt .

# Install dependencies
RUN pip install --user -r requirements.txt


############################
# Stage 2: Runtime
############################
FROM python:3.11-slim

# Set timezone to UTC
ENV TZ=UTC

# Install cron + timezone tools
RUN apt-get update && apt-get install -y \
    cron \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY . /app

# Create required volumes
VOLUME ["/data", "/cron"]

# Copy cron job (cleanup.cron must exist in project)
COPY cleanup.cron /cron/cleanup.cron

# Register cron job
RUN crontab /cron/cleanup.cron

# Expose API port
EXPOSE 8080

# Start cron + API server
CMD service cron start && uvicorn app:app --host 0.0.0.0 --port 8080
