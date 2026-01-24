# Nginx Setup Documentation - Day 2

**Date:** January 16, 2026
**Status:** Production Ready
**Author:** DevOps Setup

## Overview

This document describes the complete Nginx setup for Zumodra's multi-tenant platform deployed at `zumodra.rhematek-solutions.com`. The architecture uses a two-tier Nginx approach:

1. **System Nginx** (Host Level) - Port 80/443
2. **Docker Nginx** (Container Level) - Port 8084

## Architecture

```
Internet (HTTPS)
    ↓
Cloudflare CDN/SSL
    ↓
System Nginx (Port 80/443) ← SSL Termination
    ↓
Docker Containers:
    ├── Web (Django/Gunicorn) - Port 8002
    ├── Channels (Daphne/WebSocket) - Port 8003
    └── Nginx (Optional Layer) - Port 8084
```

## System Nginx Configuration

### Location
- Config File: `/etc/nginx/sites-available/zumodra`
- Enabled Link: `/etc/nginx/sites-enabled/zumodra`
- SSL Certificates: `/etc/letsencrypt/live/zumodra.rhematek-solutions.com-0001/`

### Key Features

1. **Multi-Tenant Wildcard Support**
   ```nginx
   server_name zumodra.rhematek-solutions.com *.zumodra.rhematek-solutions.com;
   ```
   This allows any subdomain (e.g., `demo-company.zumodra.rhematek-solutions.com`) to be routed correctly.

2. **SSL/TLS Configuration**
   - Automatic HTTP to HTTPS redirect on port 80
   - Let's Encrypt wildcard certificate for `*.zumodra.rhematek-solutions.com`
   - Modern SSL configuration with HSTS enabled
   - TLS 1.2+ with secure cipher suites

3. **Proxy Configuration**
   - Web traffic proxied to: `http://localhost:8002` (Django/Gunicorn)
   - WebSocket traffic proxied to: `http://localhost:8003` (Daphne)
   - Preserves `Host` header for multi-tenant routing (CRITICAL)

### Full Configuration

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name zumodra.rhematek-solutions.com *.zumodra.rhematek-solutions.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name zumodra.rhematek-solutions.com *.zumodra.rhematek-solutions.com;

    client_max_body_size 64M;

    # Wildcard SSL certificate
    ssl_certificate /etc/letsencrypt/live/zumodra.rhematek-solutions.com-0001/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/zumodra.rhematek-solutions.com-0001/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;

    # WebSocket connections
    location /ws/ {
        proxy_pass http://localhost:8003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400s;
    }

    # All requests go through Django
    location / {
        proxy_pass http://localhost:8002;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 30s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Static file caching
        location ~* \.(css|js|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot|webp)$ {
            proxy_pass http://localhost:8002;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
}
```

## Docker Nginx Configuration

### Location
- Config File: `/root/zumodra/docker/nginx.conf` (main config)
- Site Config: `/root/zumodra/docker/nginx-sites/zumodra.rhematek.conf`
- Docker Mount: Mounted at `/etc/nginx/conf.d/default.conf` in container

### Purpose
The Docker Nginx container (port 8084) serves as an optional additional proxy layer and can be used for:
- Development/testing without system Nginx
- Additional rate limiting at the container level
- Advanced routing rules specific to the application

### Configuration Highlights

The Docker Nginx configuration includes:
- Rate limiting zones for API, login, WebSocket, and general traffic
- Separate upstream definitions for Django and Channels
- Static file serving from Docker volumes
- Connection limiting and buffering configuration

### Key Configuration Files

1. **Main Nginx Config** (`docker/nginx.conf`):
   - Worker process configuration
   - Rate limiting zones
   - Upstream backend definitions
   - Gzip compression
   - Security headers

2. **Site Config** (`docker/nginx-sites/zumodra.rhematek.conf`):
   - Wildcard subdomain support
   - Multi-tenant Host header preservation
   - Location blocks for health, static, media, API, WebSocket
   - Security rules

## Multi-Tenant Routing

### How It Works

1. **DNS Resolution**
   - Cloudflare DNS resolves `*.zumodra.rhematek-solutions.com` to server IP
   - Wildcard DNS entry: `*.zumodra.rhematek-solutions.com` → `147.93.47.35`

2. **System Nginx (Port 443)**
   - Receives HTTPS request with Host header (e.g., `demo-company.zumodra.rhematek-solutions.com`)
   - Preserves the Host header when proxying to Django

3. **Django Tenant Middleware**
   - Reads the Host header
   - Extracts subdomain: `demo-company`
   - Loads tenant from database using subdomain
   - Sets database schema to tenant-specific schema
   - Serves tenant-specific content

### Critical Configuration Points

For multi-tenancy to work, these headers MUST be preserved:

```nginx
proxy_set_header Host $host;                    # Original hostname
proxy_set_header X-Forwarded-Host $host;        # For multi-proxy setups
proxy_set_header X-Real-IP $remote_addr;        # Client IP
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;     # http or https
```

**Never** use hardcoded hostnames in proxy_set_header directives.

## Testing & Verification

### Health Check

```bash
# System Nginx health
curl -I https://zumodra.rhematek-solutions.com/health/

# Expected: HTTP 200 OK with JSON response
```

### Tenant Routing

```bash
# Test main domain
curl -I https://zumodra.rhematek-solutions.com/

# Test tenant subdomain
curl -I https://demo-company.zumodra.rhematek-solutions.com/

# Both should return HTTP 302/200 and serve different content
```

### WebSocket Testing

```bash
# Check WebSocket upgrade
curl -I -H "Upgrade: websocket" \
     -H "Connection: Upgrade" \
     https://demo-company.zumodra.rhematek-solutions.com/ws/chat/room123/
```

### Container Status

```bash
# Check Nginx container
ssh zumodra "docker ps | grep nginx"

# Check Nginx logs
ssh zumodra "docker logs zumodra_nginx --tail 50"

# Check system Nginx
ssh zumodra "systemctl status nginx"
```

## Troubleshooting

### 404 Errors

**Symptom:** Getting 404 errors when accessing tenant subdomains

**Solution:**
1. Verify system Nginx has wildcard server_name:
   ```bash
   grep server_name /etc/nginx/sites-available/zumodra
   ```
   Should show: `*.zumodra.rhematek-solutions.com`

2. Check Host header is being preserved:
   ```bash
   ssh zumodra "docker logs zumodra_web | grep -i 'host:'"
   ```

3. Verify Django ALLOWED_HOSTS includes wildcard:
   ```bash
   ssh zumodra "grep ALLOWED_HOSTS /root/zumodra/.env"
   ```
   Should include: `.zumodra.rhematek-solutions.com`

### SSL Certificate Issues

**Symptom:** SSL certificate errors or warnings

**Solution:**
1. Check certificate expiry:
   ```bash
   ssh zumodra "certbot certificates"
   ```

2. Renew certificate if needed:
   ```bash
   ssh zumodra "certbot renew"
   ```

3. Reload Nginx:
   ```bash
   ssh zumodra "systemctl reload nginx"
   ```

### Container Not Starting

**Symptom:** Nginx container fails to start

**Solution:**
1. Check configuration syntax:
   ```bash
   ssh zumodra "cd /root/zumodra && docker compose config"
   ```

2. Check Nginx config syntax:
   ```bash
   ssh zumodra "docker run --rm -v /root/zumodra/docker/nginx.conf:/etc/nginx/nginx.conf:ro nginx:alpine nginx -t"
   ```

3. Check logs:
   ```bash
   ssh zumodra "docker logs zumodra_nginx"
   ```

## Maintenance

### Reloading Configuration

**System Nginx:**
```bash
ssh zumodra "nginx -t && systemctl reload nginx"
```

**Docker Nginx:**
```bash
ssh zumodra "cd /root/zumodra && docker compose restart nginx"
```

### Updating Configuration

1. Edit configuration file locally
2. Copy to server:
   ```bash
   scp docker/nginx-sites/zumodra.rhematek.conf zumodra:/root/zumodra/docker/nginx-sites/
   ```
3. Restart container:
   ```bash
   ssh zumodra "cd /root/zumodra && docker compose restart nginx"
   ```

### Monitoring

**Check access logs:**
```bash
ssh zumodra "tail -f /var/log/nginx/access.log"
```

**Check error logs:**
```bash
ssh zumodra "tail -f /var/log/nginx/error.log"
```

**Check container logs:**
```bash
ssh zumodra "docker logs -f zumodra_nginx"
```

## Security Considerations

### Rate Limiting

The Docker Nginx configuration includes rate limiting:
- API endpoints: 10 req/s with burst of 20
- Login endpoints: 5 req/min with burst of 5
- WebSocket: 5 req/s with burst of 10
- General: 20 req/s with burst of 50

### Security Headers

Both system and Docker Nginx add security headers:
- `Strict-Transport-Security`: HSTS with preload
- `X-Content-Type-Options`: nosniff
- `X-Frame-Options`: SAMEORIGIN
- `Referrer-Policy`: same-origin
- `Cross-Origin-Opener-Policy`: same-origin

### File Upload Limits

- System Nginx: `client_max_body_size 64M`
- Docker Nginx: `client_max_body_size 100M`

## Performance Optimization

### Caching

System Nginx caches static assets:
```nginx
location ~* \.(css|js|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot|webp)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
}
```

### Compression

Gzip compression enabled for:
- text/plain
- text/css
- text/xml
- application/json
- application/javascript
- application/xml
- image/svg+xml

### Connection Keepalive

Upstream keepalive connections:
```nginx
upstream django {
    server web:8000;
    keepalive 32;
}
```

## Environment Variables

Key environment variables in `.env`:

```bash
# Domain Configuration
PRIMARY_DOMAIN=zumodra.rhematek-solutions.com
TENANT_BASE_DOMAIN=zumodra.rhematek-solutions.com
ALLOWED_HOSTS=zumodra.rhematek-solutions.com,.zumodra.rhematek-solutions.com,localhost

# Port Configuration
WEB_PORT=8002
CHANNELS_PORT=8003
NGINX_PORT=8084
```

## Production Checklist

- [x] System Nginx configured with wildcard SSL
- [x] Host header preservation enabled
- [x] Docker Nginx container running and healthy
- [x] Multi-tenant routing tested and working
- [x] WebSocket connections configured
- [x] SSL/TLS certificates installed and auto-renewing
- [x] Security headers configured
- [x] Rate limiting enabled
- [x] Static file caching configured
- [x] Health check endpoints working

## References

- System Nginx Config: `/etc/nginx/sites-available/zumodra`
- Docker Nginx Config: `/root/zumodra/docker/nginx-sites/zumodra.rhematek.conf`
- Docker Compose: `/root/zumodra/docker-compose.yml`
- Environment Config: `/root/zumodra/.env`
- SSL Certificates: `/etc/letsencrypt/live/zumodra.rhematek-solutions.com-0001/`

## Changelog

### 2026-01-16 - Initial Production Setup
- Configured system Nginx with wildcard SSL for `*.zumodra.rhematek-solutions.com`
- Set up Docker Nginx container with production configuration
- Verified multi-tenant routing with demo-company subdomain
- Tested health endpoints and WebSocket connections
- Documented complete architecture and troubleshooting steps
