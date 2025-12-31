# Zumodra Deployment Guide

**Version:** 1.0.0
**Last Updated:** December 2025

This guide covers deploying Zumodra in development, staging, and production environments.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Development Deployment](#development-deployment)
4. [Staging Deployment](#staging-deployment)
5. [Production Deployment](#production-deployment)
6. [Database Setup](#database-setup)
7. [SSL/TLS Configuration](#ssltls-configuration)
8. [Monitoring & Logging](#monitoring--logging)
9. [Backup & Recovery](#backup--recovery)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Storage | 20 GB SSD | 50+ GB SSD |
| OS | Ubuntu 22.04 / Debian 12 | Ubuntu 22.04 LTS |

### Required Software

- **Docker:** 24.0+
- **Docker Compose:** 2.20+
- **Python:** 3.11+ (for local development)
- **PostgreSQL:** 16+ with PostGIS 3.4
- **Redis:** 7+
- **RabbitMQ:** 3.12+

### Required Services

- **Stripe Account:** For payment processing
- **SMTP Provider:** For email (e.g., Mailgun, SendGrid, SES)
- **Object Storage:** For media files (optional: S3, MinIO)

---

## Environment Setup

### 1. Clone Repository

```bash
git clone https://github.com/your-org/zumodra.git
cd zumodra
```

### 2. Create Environment File

Copy the example and configure:

```bash
cp .env.example .env
```

### 3. Required Environment Variables

```bash
# Core Settings
DEBUG=False
SECRET_KEY=<generate-secure-key>
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# Database
DB_ENGINE=django.contrib.gis.db.backends.postgis
DB_DEFAULT_NAME=zumodra
DB_USER=zumodra_user
DB_PASSWORD=<strong-password>
DB_HOST=db
DB_DEFAULT_PORT=5432

# Redis
REDIS_URL=redis://redis:6379/0

# Celery
CELERY_BROKER_URL=amqp://zumodra:<password>@rabbitmq:5672/zumodra
CELERY_RESULT_BACKEND=redis://redis:6379/1

# Stripe
STRIPE_PUBLIC_KEY=pk_live_...
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...

# Email
EMAIL_HOST=smtp.mailgun.org
EMAIL_PORT=587
EMAIL_HOST_USER=postmaster@mg.yourdomain.com
EMAIL_HOST_PASSWORD=<api-key>
EMAIL_USE_TLS=True
DEFAULT_FROM_EMAIL=noreply@yourdomain.com

# Security
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
```

### Generate Secret Key

```python
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

---

## Development Deployment

### Quick Start

```bash
# Start all services
docker compose up -d

# Run migrations
docker compose exec web python manage.py migrate

# Create superuser
docker compose exec web python manage.py createsuperuser

# Load demo data (optional)
docker compose exec web python manage.py setup_demo_data
```

### Access Points

| Service | URL |
|---------|-----|
| Web App | http://localhost:8000 |
| WebSocket | ws://localhost:8001 |
| Admin | http://localhost:8000/admin/ |
| API Docs | http://localhost:8000/api/docs/ |
| RabbitMQ | http://localhost:15672 |
| MailHog | http://localhost:8025 |

### Development with Hot Reload

The development docker-compose mounts the source code as a volume, enabling hot reload:

```bash
# View logs
docker compose logs -f web

# Restart specific service
docker compose restart web
```

---

## Staging Deployment

### Docker Compose Override

Create `docker-compose.staging.yml`:

```yaml
services:
  web:
    environment:
      DEBUG: "False"
      ALLOWED_HOSTS: staging.zumodra.com
      SECURE_SSL_REDIRECT: "True"

  nginx:
    volumes:
      - ./docker/nginx-staging.conf:/etc/nginx/nginx.conf:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
```

### Deploy to Staging

```bash
# Deploy with staging overrides
docker compose -f docker-compose.yml -f docker-compose.staging.yml up -d

# Run migrations
docker compose exec web python manage.py migrate --noinput

# Collect static files
docker compose exec web python manage.py collectstatic --noinput
```

---

## Production Deployment

### Pre-Deployment Checklist

- [ ] Environment variables configured (no defaults)
- [ ] SSL certificates obtained (Let's Encrypt or commercial)
- [ ] Firewall configured (only 80, 443, 22 open)
- [ ] Database backups configured
- [ ] Monitoring set up (Prometheus/Grafana or Datadog)
- [ ] Log aggregation configured
- [ ] DNS records pointing to server

### Production Architecture

```
                    ┌─────────────┐
                    │   Nginx     │
                    │  (SSL/LB)   │
                    └──────┬──────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
   ┌─────▼─────┐    ┌─────▼─────┐    ┌─────▼─────┐
   │  Django   │    │  Django   │    │  Daphne   │
   │   Web 1   │    │   Web 2   │    │ (WebSocket)│
   └─────┬─────┘    └─────┬─────┘    └─────┬─────┘
         │                 │                 │
         └────────────┬────┴─────────────────┘
                      │
    ┌─────────────────┼─────────────────┐
    │                 │                 │
┌───▼───┐       ┌────▼────┐       ┌────▼────┐
│PostGIS│       │  Redis  │       │RabbitMQ │
└───────┘       └─────────┘       └─────────┘
```

### Production Docker Compose

```bash
# Create production config
docker compose -f docker-compose.yml \
  -f docker-compose.prod.yml \
  up -d --scale web=2

# Health check
curl https://yourdomain.com/health/ready/
```

### Scaling Web Workers

```bash
# Scale to 4 web instances
docker compose up -d --scale web=4

# Verify
docker compose ps
```

---

## Database Setup

### Initial Setup

```sql
-- Create database and user
CREATE USER zumodra_user WITH PASSWORD 'your-password';
CREATE DATABASE zumodra OWNER zumodra_user;

-- Enable PostGIS
\c zumodra
CREATE EXTENSION IF NOT EXISTS postgis;
CREATE EXTENSION IF NOT EXISTS postgis_topology;
```

### Migrations

```bash
# Generate migrations after model changes
docker compose exec web python manage.py makemigrations

# Apply migrations
docker compose exec web python manage.py migrate

# Show migration status
docker compose exec web python manage.py showmigrations
```

### Multi-Tenant Setup

```bash
# Create public schema tables
docker compose exec web python manage.py migrate_schemas --shared

# Create tenant
docker compose exec web python manage.py shell
>>> from tenants.models import Tenant, Domain, Plan
>>> plan = Plan.objects.get(slug='professional')
>>> tenant = Tenant.objects.create(
...     name='Acme Corp',
...     slug='acme',
...     schema_name='acme',
...     owner_email='admin@acme.com',
...     plan=plan
... )
>>> Domain.objects.create(
...     domain='acme.localhost',
...     tenant=tenant,
...     is_primary=True
... )
```

---

## SSL/TLS Configuration

### Let's Encrypt with Certbot

```bash
# Install certbot
apt install certbot python3-certbot-nginx

# Obtain certificate
certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Auto-renewal
certbot renew --dry-run
```

### Nginx SSL Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # Modern TLS settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;

    location / {
        proxy_pass http://web:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws/ {
        proxy_pass http://channels:8001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

## Monitoring & Logging

### Enable Monitoring Stack

```bash
# Start with monitoring profile
docker compose --profile monitoring up -d

# Access points
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3000 (admin/admin)
```

### Health Checks

```bash
# Basic health
curl http://localhost:8000/health/

# Readiness (includes DB/Redis)
curl http://localhost:8000/health/ready/

# Liveness
curl http://localhost:8000/health/live/
```

### Log Aggregation

Configure centralized logging:

```python
# settings.py
LOGGING = {
    'version': 1,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'json',
        },
    },
    'formatters': {
        'json': {
            'class': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            'format': '%(asctime)s %(levelname)s %(name)s %(message)s',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
}
```

### Celery Monitoring

```bash
# Monitor Celery workers
docker compose exec celery_worker celery -A zumodra inspect active

# Check queue lengths
docker compose exec celery_worker celery -A zumodra inspect stats
```

---

## Backup & Recovery

### Database Backup

```bash
# Manual backup
docker compose exec db pg_dump -U postgres zumodra > backup_$(date +%Y%m%d).sql

# Automated backup script
#!/bin/bash
BACKUP_DIR=/backups
docker compose exec -T db pg_dump -U postgres zumodra | gzip > $BACKUP_DIR/zumodra_$(date +%Y%m%d_%H%M%S).sql.gz

# Keep 30 days of backups
find $BACKUP_DIR -name "zumodra_*.sql.gz" -mtime +30 -delete
```

### Restore Database

```bash
# Restore from backup
docker compose exec -T db psql -U postgres zumodra < backup_20251231.sql

# Or with gzip
gunzip -c backup_20251231.sql.gz | docker compose exec -T db psql -U postgres zumodra
```

### Media Files Backup

```bash
# Backup media volume
docker run --rm -v zumodra_media_volume:/data -v $(pwd):/backup alpine \
  tar czf /backup/media_backup.tar.gz -C /data .

# Restore
docker run --rm -v zumodra_media_volume:/data -v $(pwd):/backup alpine \
  tar xzf /backup/media_backup.tar.gz -C /data
```

---

## Troubleshooting

### Common Issues

#### Database Connection Refused

```bash
# Check database is running
docker compose ps db

# View logs
docker compose logs db

# Test connection
docker compose exec web python manage.py dbshell
```

#### Celery Tasks Not Processing

```bash
# Check worker status
docker compose exec celery_worker celery -A zumodra inspect ping

# Restart worker
docker compose restart celery_worker

# Check RabbitMQ
docker compose logs rabbitmq
```

#### WebSocket Connection Failed

```bash
# Check Daphne is running
docker compose logs channels

# Verify Redis channel layer
docker compose exec web python -c "
import channels.layers
import asyncio
layer = channels.layers.get_channel_layer()
asyncio.run(layer.send('test', {'type': 'hello'}))
print('Channel layer OK')
"
```

#### Migration Errors

```bash
# Check migration status
docker compose exec web python manage.py showmigrations

# Fake problematic migration
docker compose exec web python manage.py migrate app_name 0001 --fake

# Run single migration
docker compose exec web python manage.py migrate app_name 0002
```

### Performance Issues

```bash
# Check container resource usage
docker stats

# Database slow queries (enable in PostgreSQL)
docker compose exec db psql -U postgres zumodra -c "
SELECT pid, now() - pg_stat_activity.query_start AS duration, query
FROM pg_stat_activity
WHERE state = 'active' AND now() - pg_stat_activity.query_start > interval '5 seconds';
"
```

### Reset Everything

```bash
# Stop all containers
docker compose down

# Remove volumes (WARNING: deletes all data)
docker compose down -v

# Rebuild images
docker compose build --no-cache

# Start fresh
docker compose up -d
```

---

## Deployment Checklist

### Before Deploy

- [ ] Code reviewed and merged
- [ ] Tests passing (`pytest`)
- [ ] Migrations tested locally
- [ ] Environment variables updated
- [ ] Backup taken

### Deploy

- [ ] Pull latest code
- [ ] Build new images
- [ ] Run migrations
- [ ] Restart services
- [ ] Collect static files

### After Deploy

- [ ] Health checks passing
- [ ] Smoke tests passing
- [ ] Logs checked for errors
- [ ] Monitoring dashboards verified

---

**Document maintained by:** DevOps Team
**Review frequency:** Quarterly or after infrastructure changes
