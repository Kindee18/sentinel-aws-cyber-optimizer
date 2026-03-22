# =============================================================================
# Sentinel-AWS Cyber-Optimizer — Multi-Stage Docker Build
# Hardened container image for the log transformer workload
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Builder — Install dependencies
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install only production dependencies
COPY lambda/requirements.txt .
RUN pip install --no-cache-dir --target=/build/deps -r requirements.txt 2>/dev/null || true

# Copy application code
COPY lambda/log_transformer.py .

# ---------------------------------------------------------------------------
# Stage 2: Production — Minimal runtime image
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS production

# Security: Add metadata labels
LABEL maintainer="sentinel-security-team" \
      project="sentinel-aws-cyber-optimizer" \
      description="Log transformer for FinOps optimization pipeline" \
      org.opencontainers.image.source="https://github.com/sentinel/cyber-optimizer" \
      org.opencontainers.image.vendor="Sentinel Security"

# Security: Install security updates and clean up
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Security: Create non-root user
RUN groupadd -r appuser && \
    useradd -r -g appuser -d /app -s /sbin/nologin appuser

WORKDIR /app

# Copy dependencies from builder stage
COPY --from=builder /build/deps/ /usr/local/lib/python3.12/site-packages/ 2>/dev/null || true
COPY --from=builder /build/log_transformer.py .

# Security: Set file ownership
RUN chown -R appuser:appuser /app

# Security: Switch to non-root user
USER appuser

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port (for sidecar/health check purposes)
EXPOSE 8080

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOG_LEVEL=INFO \
    ENVIRONMENT=dev

# Entry point
CMD ["python", "log_transformer.py"]
