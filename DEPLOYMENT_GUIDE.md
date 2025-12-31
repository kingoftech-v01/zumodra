# Zumodra Deployment Guide

## Production Deployment (1M Users, 500K Concurrent)

### Prerequisites

- Docker 24.0+ and Docker Compose 2.20+
- PostgreSQL 16+ with PostGIS
- Redis 7.4+
- Domain with SSL certificate
- Minimum 32GB RAM, 16 CPU cores for production

### Quick Start

```bash
# Clone repository
git clone https://github.com/rhematek/zumodra.git
cd zumodra

# Copy environment file
cp .env.example .env

# Edit .env with production values
vim .env

# Generate SSL certificates (first time)
cd docker/ssl && bash generate-certs.sh && cd ../..

# Deploy production stack
docker compose -f docker-compose.prod.yml up -d

# Verify deployment
curl -f https://zumodra.rhematek-solutions.com/health
```

### Production Stack Components

| Service | Replicas | Memory | Purpose |
|---------|----------|--------|---------|
| web | 10 | 2GB | Django/Gunicorn ASGI |
| celery-worker | 20 | 1GB | Background tasks |
| celery-beat | 1 | 512MB | Task scheduler |
| postgres-primary | 1 | 8GB | Primary database |
| postgres-replica | 1 | 4GB | Read replica |
| redis-master | 1 | 2GB | Queue/sessions |
| redis-cache | 1 | 4GB | Caching |
| nginx | 1 | 512MB | Reverse proxy |
| prometheus | 1 | 1GB | Metrics |
| grafana | 1 | 512MB | Dashboards |

### Scaling Commands

```bash
# Scale web workers
docker compose -f docker-compose.prod.yml up -d --scale web=20

# Scale Celery workers
docker compose -f docker-compose.prod.yml up -d --scale celery-worker=50

# Full scale for 500K concurrent
docker compose -f docker-compose.prod.yml up -d \
  --scale web=100 \
  --scale celery-worker=200
```

### Health Checks

```bash
# API health
curl https://zumodra.rhematek-solutions.com/api/v1/health/

# Database connection
docker exec zumodra-web-1 python manage.py dbshell -c "SELECT 1;"

# Redis connectivity
docker exec zumodra-redis-master-1 redis-cli ping

# Celery status
docker exec zumodra-celery-worker-1 celery -A zumodra inspect active
```

### Monitoring

- **Grafana**: https://zumodra.rhematek-solutions.com:3000
- **Prometheus**: http://localhost:9090 (internal)
- **Alerts**: alerts@rhematek-solutions.com

### Backup & Recovery

```bash
# Manual backup
docker exec zumodra-postgres-primary-1 pg_dump -U postgres zumodra > backup.sql

# Restore
docker exec -i zumodra-postgres-primary-1 psql -U postgres zumodra < backup.sql
```

### SSL Certificate Renewal

Certificates auto-renew via Certbot. Manual renewal:

```bash
docker exec zumodra-nginx-1 certbot renew --dry-run
```

### Troubleshooting

```bash
# View logs
docker compose -f docker-compose.prod.yml logs -f web

# Check container health
docker ps --format "table {{.Names}}\t{{.Status}}"

# Enter container shell
docker exec -it zumodra-web-1 bash
```

## Security Checklist

- [ ] SECRET_KEY changed from default
- [ ] DEBUG=False in production
- [ ] HTTPS enforced
- [ ] Database password strong
- [ ] Redis password set
- [ ] Rate limiting enabled
- [ ] CORS origins restricted
- [ ] CSP headers active

## Support

- **Email**: support@rhematek-solutions.com
- **CEO Escalation**: stephane@rhematek-solutions.com
- **Status Page**: https://status.rhematek-solutions.com
