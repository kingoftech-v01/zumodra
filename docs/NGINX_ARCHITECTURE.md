# Nginx Architecture Diagram

## Complete Request Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            Internet Users                                │
│                                                                          │
│  https://zumodra.rhematek-solutions.com                                 │
│  https://demo-company.zumodra.rhematek-solutions.com                    │
│  https://any-tenant.zumodra.rhematek-solutions.com                      │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          Cloudflare CDN                                  │
│  - DNS Resolution (*.zumodra.rhematek-solutions.com → 147.93.47.35)    │
│  - DDoS Protection                                                       │
│  - CDN Caching                                                          │
│  - HTTP → HTTPS Redirect (handled by Cloudflare)                        │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │ HTTPS
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Server: 147.93.47.35 (Port 443)                      │
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │              System Nginx (Host Level)                             │ │
│  │  - SSL Termination (Let's Encrypt Wildcard Cert)                  │ │
│  │  - Port 80 → 443 Redirect                                         │ │
│  │  - Port 443 (HTTPS) → Proxy to Docker Containers                  │ │
│  │                                                                     │ │
│  │  Config: /etc/nginx/sites-available/zumodra                       │ │
│  │                                                                     │ │
│  │  server_name: *.zumodra.rhematek-solutions.com                    │ │
│  │                                                                     │ │
│  │  Critical Headers:                                                 │ │
│  │    proxy_set_header Host $host;  ← PRESERVES SUBDOMAIN           │ │
│  │    proxy_set_header X-Real-IP $remote_addr;                       │ │
│  │    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  │ │
│  │    proxy_set_header X-Forwarded-Proto https;                      │ │
│  └────────────────┬─────────────────────────┬────────────────────────┘ │
│                   │                         │                           │
│                   │ HTTP Requests           │ WebSocket Requests        │
│                   │ Port 8002               │ Port 8003                 │
│                   ▼                         ▼                           │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │              Docker Network: zumodra_network                      │  │
│  │                                                                    │  │
│  │  ┌─────────────────────┐     ┌──────────────────────┐           │  │
│  │  │  zumodra_web        │     │  zumodra_channels    │           │  │
│  │  │  (Django/Gunicorn)  │     │  (Daphne/WebSocket)  │           │  │
│  │  │                     │     │                      │           │  │
│  │  │  Container Port:    │     │  Container Port:     │           │  │
│  │  │  8000               │     │  8001                │           │  │
│  │  │  ↓ Exposed:         │     │  ↓ Exposed:          │           │  │
│  │  │  0.0.0.0:8002       │     │  0.0.0.0:8003        │           │  │
│  │  │                     │     │                      │           │  │
│  │  │  Receives Host      │     │  Receives Host       │           │  │
│  │  │  header with        │     │  header for          │           │  │
│  │  │  subdomain intact   │     │  WebSocket tenant    │           │  │
│  │  │                     │     │  routing             │           │  │
│  │  └──────────┬──────────┘     └────────┬─────────────┘           │  │
│  │             │                         │                          │  │
│  │             ▼                         ▼                          │  │
│  │  ┌────────────────────────────────────────────────────────────┐ │  │
│  │  │         Django Tenant Middleware                           │ │  │
│  │  │  1. Reads Host header                                      │ │  │
│  │  │  2. Extracts subdomain (e.g., "demo-company")             │ │  │
│  │  │  3. Queries database for tenant                           │ │  │
│  │  │  4. Sets database schema to tenant schema                 │ │  │
│  │  │  5. All queries now scoped to tenant                      │ │  │
│  │  └────────────────────────────────────────────────────────────┘ │  │
│  │             │                                                    │  │
│  │             ▼                                                    │  │
│  │  ┌────────────────────────────────────────────────────────────┐ │  │
│  │  │         PostgreSQL Database                                 │ │  │
│  │  │  - Schema: public (shared data)                            │ │  │
│  │  │  - Schema: demo_company (tenant data)                      │ │  │
│  │  │  - Schema: demo_freelancer (tenant data)                   │ │  │
│  │  │  - Schema: [other-tenant] (tenant data)                    │ │  │
│  │  │                                                             │ │  │
│  │  │  Container: zumodra_db                                      │ │  │
│  │  │  Port: 5432 → Exposed: 5434                                │ │  │
│  │  └────────────────────────────────────────────────────────────┘ │  │
│  │                                                                    │  │
│  │  ┌─────────────────────┐     ┌──────────────────────┐           │  │
│  │  │  zumodra_redis      │     │  zumodra_rabbitmq    │           │  │
│  │  │  (Cache/Sessions)   │     │  (Message Broker)    │           │  │
│  │  │  Port: 6379→6380    │     │  Port: 5672→5673     │           │  │
│  │  └─────────────────────┘     └──────────────────────┘           │  │
│  │                                                                    │  │
│  │  ┌─────────────────────────────────────────────────────────────┐ │  │
│  │  │  zumodra_nginx (Optional)                                   │ │  │
│  │  │  - Additional proxy layer                                   │ │  │
│  │  │  - Port: 80 → Exposed: 8084                                │ │  │
│  │  │  - Rate limiting, caching                                   │ │  │
│  │  │  - Config: /root/zumodra/docker/nginx-sites/               │ │  │
│  │  │            zumodra.rhematek.conf                            │ │  │
│  │  └─────────────────────────────────────────────────────────────┘ │  │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

## Port Summary

| Service | Container Port | Host Port | Access |
|---------|---------------|-----------|---------|
| System Nginx | N/A | 80, 443 | Public (HTTPS) |
| Docker Nginx | 80 | 8084 | Internal/Optional |
| Django Web | 8000 | 8002 | Via Nginx |
| Channels WebSocket | 8001 | 8003 | Via Nginx |
| PostgreSQL | 5432 | 5434 | Internal |
| Redis | 6379 | 6380 | Internal |
| RabbitMQ | 5672 | 5673 | Internal |
| RabbitMQ Management | 15672 | 15673 | Internal |
| Mailhog SMTP | 1025 | 1026 | Internal |
| Mailhog UI | 8025 | 8026 | Internal |

## Multi-Tenant Request Example

### Request Flow for `https://demo-company.zumodra.rhematek-solutions.com/ats/jobs/`

```
1. Client Request
   GET /ats/jobs/ HTTP/2
   Host: demo-company.zumodra.rhematek-solutions.com

2. Cloudflare
   - Resolves DNS: demo-company.zumodra.rhematek-solutions.com → 147.93.47.35
   - Forwards with HTTPS

3. System Nginx (Port 443)
   server_name *.zumodra.rhematek-solutions.com matches ✓

   Proxies to localhost:8002 with headers:
   - Host: demo-company.zumodra.rhematek-solutions.com
   - X-Real-IP: 203.0.113.42
   - X-Forwarded-Proto: https

4. Docker Network
   Request arrives at zumodra_web:8000

5. Django Tenant Middleware
   - Reads Host header: "demo-company.zumodra.rhematek-solutions.com"
   - Extracts subdomain: "demo-company"
   - Queries public.tenants_tenant WHERE domain = "demo-company..."
   - Sets schema: "demo_company"

6. Django View
   - All database queries now use schema "demo_company"
   - Job.objects.all() → SELECT * FROM demo_company.ats_job
   - Returns tenant-specific jobs

7. Response
   HTTP 200 OK
   Content-Type: text/html

   <Jobs page for Demo Company tenant>
```

## Key Configuration Files

### 1. System Nginx
**Location:** `/etc/nginx/sites-available/zumodra`

**Purpose:**
- Primary entry point for all HTTPS traffic
- SSL/TLS termination
- Wildcard subdomain routing
- Proxy to Docker containers

**Key Settings:**
- Wildcard server_name: `*.zumodra.rhematek-solutions.com`
- SSL certificates with Let's Encrypt
- Host header preservation (critical for multi-tenancy)

### 2. Docker Nginx
**Location:** `/root/zumodra/docker/nginx-sites/zumodra.rhematek.conf`

**Purpose:**
- Optional secondary proxy layer
- Rate limiting
- Advanced routing rules
- Static file serving

**Key Settings:**
- Rate limiting zones
- Connection limits
- Buffer configuration
- Static/media file serving

### 3. Docker Compose
**Location:** `/root/zumodra/docker-compose.yml`

**Purpose:**
- Service orchestration
- Port mappings
- Volume mounts
- Health checks

**Key Settings:**
- Nginx service mounts configuration files
- Port 8084 exposed for nginx container
- Health check endpoint: `/health/`

### 4. Django Settings
**Location:** `/root/zumodra/zumodra/settings_tenants.py`

**Purpose:**
- Multi-tenant configuration
- Tenant middleware setup
- Database routing

**Key Settings:**
- TENANT_BASE_DOMAIN
- ALLOWED_HOSTS with wildcard
- Tenant middleware in MIDDLEWARE

## Troubleshooting Flow

```
Issue: Cannot access tenant subdomain (404 or wrong tenant)
  ↓
Step 1: Check DNS resolution
  $ nslookup demo-company.zumodra.rhematek-solutions.com
  Should resolve to: 147.93.47.35
  ↓
Step 2: Check System Nginx config
  $ ssh zumodra "grep server_name /etc/nginx/sites-available/zumodra"
  Should include: *.zumodra.rhematek-solutions.com
  ↓
Step 3: Check Host header preservation
  $ ssh zumodra "grep 'proxy_set_header Host' /etc/nginx/sites-available/zumodra"
  Should have: proxy_set_header Host $host;
  ↓
Step 4: Check Django receives correct Host
  $ ssh zumodra "docker logs zumodra_web | grep 'Host:'"
  Should show: Host: demo-company.zumodra.rhematek-solutions.com
  ↓
Step 5: Check tenant exists in database
  $ ssh zumodra "docker exec zumodra_web python manage.py shell -c \\"from tenants.models import Tenant; print(Tenant.objects.filter(schema_name='demo_company').first())\\""
  Should return tenant object
  ↓
Step 6: Check ALLOWED_HOSTS in Django
  $ ssh zumodra "grep ALLOWED_HOSTS /root/zumodra/.env"
  Should include: .zumodra.rhematek-solutions.com
```

## Security Layers

```
┌──────────────────────────────────────────┐
│  Layer 1: Cloudflare                     │
│  - DDoS protection                       │
│  - Web Application Firewall (WAF)       │
│  - Bot management                        │
└──────────────────┬───────────────────────┘
                   ▼
┌──────────────────────────────────────────┐
│  Layer 2: System Nginx                   │
│  - SSL/TLS termination                   │
│  - Request validation                    │
│  - Security headers                      │
│  - Client IP filtering (optional)        │
└──────────────────┬───────────────────────┘
                   ▼
┌──────────────────────────────────────────┐
│  Layer 3: Docker Nginx (Optional)        │
│  - Rate limiting                         │
│  - Connection limiting                   │
│  - Request size limits                   │
└──────────────────┬───────────────────────┘
                   ▼
┌──────────────────────────────────────────┐
│  Layer 4: Django Middleware              │
│  - Authentication                        │
│  - Tenant isolation                      │
│  - Permission checks                     │
│  - CSRF protection                       │
│  - XSS protection                        │
└──────────────────┬───────────────────────┘
                   ▼
┌──────────────────────────────────────────┐
│  Layer 5: Database                       │
│  - Schema-based isolation                │
│  - Row-level security (future)           │
│  - Encrypted connections                 │
└──────────────────────────────────────────┘
```

## Performance Optimizations

### 1. Cloudflare CDN
- Static asset caching at edge locations
- Automatic image optimization
- HTTP/2 and HTTP/3 support

### 2. System Nginx
- Keepalive connections to upstream
- Static file caching (1 year for immutable assets)
- Gzip compression

### 3. Docker Nginx
- Connection pooling with keepalive
- Proxy buffering for efficiency
- Rate limiting to prevent abuse

### 4. Django/Gunicorn
- Multiple worker processes
- Async workers with Uvicorn
- Database connection pooling

### 5. PostgreSQL
- Shared buffer cache
- Query result caching
- Index optimization

### 6. Redis
- Session caching
- View caching
- Query result caching

## Monitoring Points

```
External Monitoring:
├── UptimeRobot / Pingdom
│   ├── https://zumodra.rhematek-solutions.com/health/
│   └── https://demo-company.zumodra.rhematek-solutions.com/

Server Monitoring:
├── System Nginx
│   ├── /var/log/nginx/access.log
│   ├── /var/log/nginx/error.log
│   └── systemctl status nginx
│
├── Docker Containers
│   ├── docker logs zumodra_nginx
│   ├── docker logs zumodra_web
│   ├── docker logs zumodra_channels
│   └── docker stats
│
└── Application
    ├── Django logs: /root/zumodra/logs/
    ├── Database logs: docker logs zumodra_db
    └── Redis logs: docker logs zumodra_redis
```

## Backup & Recovery

### Configuration Backup
```bash
# Backup system nginx config
ssh zumodra "tar -czf /root/backups/nginx-$(date +%Y%m%d).tar.gz /etc/nginx/sites-available/zumodra"

# Backup docker nginx config
ssh zumodra "tar -czf /root/backups/docker-nginx-$(date +%Y%m%d).tar.gz /root/zumodra/docker/nginx*"
```

### SSL Certificate Backup
```bash
# Backup Let's Encrypt certificates
ssh zumodra "tar -czf /root/backups/letsencrypt-$(date +%Y%m%d).tar.gz /etc/letsencrypt/"
```

### Recovery
```bash
# Restore system nginx config
ssh zumodra "tar -xzf /root/backups/nginx-YYYYMMDD.tar.gz -C /"

# Reload nginx
ssh zumodra "systemctl reload nginx"
```

## References

- System Nginx: `/etc/nginx/sites-available/zumodra`
- Docker Nginx: `/root/zumodra/docker/nginx-sites/zumodra.rhematek.conf`
- Documentation: `/root/zumodra/docs/NGINX_SETUP_DAY2.md`
- Docker Compose: `/root/zumodra/docker-compose.yml`
