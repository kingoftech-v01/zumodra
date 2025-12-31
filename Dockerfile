# =============================================================================
# ZUMODRA MULTI-TENANT ATS/HR SAAS PLATFORM
# =============================================================================
# Production-ready Dockerfile with multi-stage build
# Includes: migrations, static collection, health checks
# =============================================================================

# syntax=docker/dockerfile:1

# -----------------------------------------------------------------------------
# Build Arguments
# -----------------------------------------------------------------------------
ARG PYTHON_VERSION=3.11

# =============================================================================
# STAGE 1: Builder - Install dependencies
# =============================================================================
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

# Environment variables for build
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install build dependencies (needed for psycopg2, GDAL, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libgdal-dev \
    libgeos-dev \
    libproj-dev \
    gdal-bin \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt

# =============================================================================
# STAGE 2: Production - Runtime image
# =============================================================================
FROM python:${PYTHON_VERSION}-slim-bookworm AS production

# Labels
LABEL maintainer="Rhematek Solutions <support@rhematek-solutions.com>" \
      version="1.0.0" \
      description="Zumodra Multi-Tenant ATS/HR SaaS Platform"

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    APP_HOME=/app \
    APP_USER=zumodra

# Install runtime dependencies only (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libgdal32 \
    libgeos-c1v5 \
    libproj25 \
    gdal-bin \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd --gid 1000 ${APP_USER} && \
    useradd --uid 1000 --gid ${APP_USER} --shell /bin/bash --create-home ${APP_USER}

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR ${APP_HOME}

# Create necessary directories with proper permissions
RUN mkdir -p ${APP_HOME}/staticfiles \
             ${APP_HOME}/media \
             ${APP_HOME}/logs && \
    chown -R ${APP_USER}:${APP_USER} ${APP_HOME}

# Copy application code
COPY --chown=${APP_USER}:${APP_USER} . ${APP_HOME}

# Switch to non-root user
USER ${APP_USER}

# Expose port
EXPOSE 8000

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health/ || exit 1

# =============================================================================
# ENTRYPOINT: Run migrations, collect static files, then start Gunicorn
# =============================================================================
CMD sh -c "python manage.py migrate --noinput && \
           python manage.py collectstatic --noinput && \
           gunicorn 'zumodra.wsgi:application' \
               --bind=0.0.0.0:8000 \
               --workers=4 \
               --threads=2 \
               --timeout=120 \
               --access-logfile=- \
               --error-logfile=-"
