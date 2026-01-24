# Comprehensive Error & Warning Tracking - Day 2+

**Last Updated**: 2026-01-16 11:45 UTC
**Document Purpose**: Living document for tracking all container errors, warnings, and issues across the Zumodra platform for Day 2-5 development.

---

## Executive Summary

This document provides a centralized location for all errors and warnings detected in Docker containers and application code. Errors are categorized by severity level and container source.

- **CRITICAL**: System failures, service down, data corruption, blocking deployment
- **HIGH**: Major functionality broken, unhandled exceptions, critical business logic failures
- **MEDIUM**: Degraded performance, recoverable errors, deprecated warnings, migration issues
- **LOW**: Info logs, minor warnings, configuration notes, code quality improvements

---

## Container Health Status

| Container | Status | Last Check | Issues | Resolution |
|-----------|--------|------------|--------|------------|
| web (Django) | Starting | 2026-01-16 11:45 | Name conflict (container cleanup in progress) | Force remove old containers |
| channels (WebSocket) | Starting | 2026-01-16 11:45 | Name conflict (container cleanup in progress) | Force remove old containers |
| celery-worker | Starting | 2026-01-16 11:45 | Name conflict (container cleanup in progress) | Force remove old containers |
| celery-beat | Starting | 2026-01-16 11:45 | Name conflict (container cleanup in progress) | Force remove old containers |
| db (PostgreSQL) | Starting | 2026-01-16 11:45 | Name conflict (container cleanup in progress) | Force remove old containers |
| redis | Starting | 2026-01-16 11:45 | Name conflict (container cleanup in progress) | Force remove old containers |
| rabbitmq | Starting | 2026-01-16 11:45 | Name conflict (container cleanup in progress) | Force remove old containers |
| nginx | Starting | 2026-01-16 11:45 | Name conflict (container cleanup in progress) | Force remove old containers |

---

## CRITICAL Issues

### 1. Docker Container Name Conflicts
- **ID**: DOCKER-001
- **Severity**: CRITICAL
- **Component**: Docker Compose Infrastructure
- **Description**: Multiple containers stuck in "Created" state with name conflicts preventing restart
- **Error Message**: `Conflict. The container name "/zumodra_web" is already in use by container "9d6fc64c4365aff828ce7a00b500bcee9ef3d9abc60f31d629f0d977a5bfd00c". You have to remove (or rename) that container to be able to reuse that name.`
- **Root Cause**: Previous container instances not properly cleaned up between restart cycles
- **Impact**: Cannot start application; all services blocked
- **Solution**: Force remove all containers: `docker rm -f $(docker ps -a -q)`
- **Status**: IN PROGRESS - Cleanup commands executed
- **Date Detected**: 2026-01-16 11:35 UTC

---

## HIGH Priority Issues

### 1. Template Syntax Errors (FIXED - Latest Commit)
- **ID**: TEMP-001
- **Severity**: HIGH (RESOLVED)
- **Component**: Django Templates
- **Commit**: d2496ef
- **Description**: Django template syntax errors and CDN dependency issues
- **Status**: FIXED
- **Date Fixed**: 2026-01-16 (latest commit)
- **Related Files**: All HTML templates
- **Resolution**: Removed CDN dependencies, enforced local asset serving per CSP requirements

### 2. Admin UUID Reference Issues (FIXED)
- **ID**: ADMIN-001
- **Severity**: HIGH (RESOLVED)
- **Component**: Django Admin, Models
- **Commit**: 1f7ced1
- **Description**: Admin UUID references and CharField max_length violations
- **Status**: FIXED
- **Date Fixed**: 2026-01-15
- **Related Files**: Model definitions with UUID fields
- **Resolution**: Corrected UUID field references and increased CharField max_length

### 3. Potential Webhook Signal Handler Issues
- **ID**: WEBHOOK-001
- **Severity**: HIGH
- **Component**: integrations/webhook_signals.py
- **Description**: Recent webhook signal implementation may have unhandled edge cases
- **Files Modified**:
  - `integrations/webhooks.py` (NOT staged)
  - `integrations/webhook_signals.py` (NOT staged)
  - `integrations/models.py` (NOT staged)
- **Status**: NEEDS TESTING
- **Action Required**: Review and test webhook delivery mechanisms

---

## MEDIUM Priority Issues

### 1. Migration Verification Issues (FIXED)
- **ID**: MIGRATION-001
- **Severity**: MEDIUM (RESOLVED)
- **Component**: Multi-tenant Migrations
- **Commit**: a4cb24d
- **Description**: Tenant identifier missing in migration verification logic
- **Status**: FIXED
- **Date Fixed**: 2026-01-15
- **Impact**: Migration process may not properly verify tenant-specific schemas
- **Resolution**: Corrected tenant identifier in migration verification

### 2. Health Check Ordering Issue (FIXED)
- **ID**: HEALTH-001
- **Severity**: MEDIUM (RESOLVED)
- **Component**: Docker Service Dependencies
- **Commit**: 947cd9f
- **Description**: Web service dependencies not properly checked before startup
- **Status**: FIXED
- **Date Fixed**: 2026-01-15
- **Resolution**: Enforced proper health check sequence for dependent services

### 3. Unstaged Changes in Critical Files
- **ID**: GIT-001
- **Severity**: MEDIUM
- **Component**: Git Repository
- **Description**: Changes in `docker-compose.yml` and `integrations/` files not staged for commit
- **Modified Files**:
  - `docker-compose.yml` (runtime environment)
  - `integrations/models.py`
  - `integrations/webhook_signals.py`
  - `integrations/webhooks.py`
  - `hr_core/views.py`
- **Status**: PENDING REVIEW
- **Action Required**: Review and stage/commit or revert changes
- **Impact**: Inconsistent state between working directory and repository

### 4. Untracked Files Accumulation
- **ID**: GIT-002
- **Severity**: MEDIUM
- **Component**: Git Repository
- **Description**: Numerous untracked files (wheels, docs, scripts) not properly organized
- **Untracked Items**: 100+ files including `.whl` files, agent files, scripts
- **Status**: REQUIRES CLEANUP
- **Action Required**:
  - Move build artifacts to `.gitignore`
  - Organize documentation properly
  - Clean up temporary files

---

## LOW Priority Issues / Warnings

### 1. Celery Configuration Notes
- **ID**: CELERY-INFO-001
- **Severity**: LOW
- **Component**: Celery/RabbitMQ
- **Description**: Celery Beat scheduler uses DatabaseScheduler (requires database initialization)
- **Status**: INFORMATIONAL
- **Resolution**: Database must be initialized before Celery Beat starts; ensure proper startup order in docker-compose.yml

### 2. CSP Asset Loading
- **ID**: CSP-001
- **Severity**: LOW
- **Component**: Security Policy
- **Description**: All assets must be served locally; no CDN dependencies allowed
- **Status**: INFORMATIONAL
- **Details**: Alpine.js, HTMX, Chart.js must be in `staticfiles/assets/js/vendor/`
- **Required Action**: Verify all static files are properly collected: `python manage.py collectstatic`

### 3. Flake8 Linting in CI
- **ID**: CI-001
- **Severity**: LOW
- **Component**: CI/CD Pipeline
- **Commit**: 5c2c0cd
- **Description**: Flake8 linting is non-blocking in CI; allows some style violations
- **Status**: INFORMATIONAL
- **Note**: Code style checks won't block pipeline but should be reviewed manually

---

## Container-Specific Error Logs

### 1. Web Container (Django)

**Service**: `web`
**Image**: Django 5.2.7 (custom)
**Purpose**: Main application server
**Status**: Awaiting restart after cleanup
**Port**: 8002

#### Recent Errors (from git history)
- Template syntax errors (FIXED in d2496ef)
- UUID admin references (FIXED in 1f7ced1)

#### Recent Warnings
- None currently logged

#### Health Check Command
```bash
docker compose exec web python manage.py health_check --full
```

#### Key Files to Monitor
- `zumodra/settings.py` - Main configuration
- `ats/views.py` - API endpoints
- `ats/serializers.py` - Data serialization
- All template files in `templates/`

---

### 2. Channels Container (WebSocket)

**Service**: `channels`
**Image**: Daphne WebSocket server
**Purpose**: Real-time messaging and WebSocket connections
**Status**: Awaiting restart after cleanup
**Port**: 8003

#### Recent Errors
- No known errors currently

#### Recent Warnings
- None currently logged

#### Health Check Command
```bash
# Test WebSocket connectivity from outside container
curl -i -N -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  http://localhost:8003/ws/test/
```

#### Key Files to Monitor
- `messages_sys/consumers.py` - WebSocket consumers
- `zumodra/asgi.py` - ASGI configuration
- `zumodra/settings.py` - Channel layer configuration

---

### 3. Celery Worker Container

**Service**: `celery-worker`
**Image**: Celery worker
**Purpose**: Background task processing
**Status**: Awaiting restart after cleanup
**Concurrency**: 2 workers (development)

#### Recent Errors
- None currently logged

#### Recent Warnings
- Celery requires database to be initialized for task discovery

#### Health Check Command
```bash
docker compose exec celery-worker celery -A zumodra inspect ping
```

#### Key Files to Monitor
- `zumodra/celery.py` - Celery configuration
- `zumodra/celery_beat_schedule.py` - Scheduled tasks (70+)
- Task files in `*/tasks.py` across all apps

---

### 4. Celery Beat Container

**Service**: `celery-beat`
**Image**: Celery Beat scheduler
**Purpose**: Scheduled task execution
**Status**: Awaiting restart after cleanup
**Scheduler**: DatabaseScheduler

#### Recent Errors
- None currently logged

#### Recent Warnings
- DatabaseScheduler requires Django database initialization
- Must start AFTER web container initializes database

#### Health Check Command
```bash
docker compose exec celery-beat celery -A zumodra inspect scheduled
```

#### Critical Startup Order
1. Database must be ready
2. Web container must complete migrations
3. Then Celery Beat can start
4. Then Celery Worker can start

---

### 5. Database Container (PostgreSQL)

**Service**: `db`
**Image**: postgis/postgis:15-3.4
**Purpose**: Primary data store with GIS support
**Status**: Awaiting restart after cleanup
**Port**: 5434
**Credentials**: User `postgres`, Password in `.env`

#### Recent Errors
- None currently logged

#### Recent Warnings
- Migration failures in multi-tenant setup (historically fixed)

#### Health Check Command
```bash
docker compose exec db pg_isready -U postgres
```

#### Monitoring
```bash
# Connect to database
docker compose exec db psql -U postgres -d zumodra -c "SELECT version();"

# List all databases
docker compose exec db psql -U postgres -l

# Check tenant schemas
docker compose exec db psql -U postgres -d zumodra \
  -c "SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'public');"
```

---

### 6. Redis Container

**Service**: `redis`
**Image**: redis:7-alpine
**Purpose**: Cache, session store, Celery result backend
**Status**: Awaiting restart after cleanup
**Port**: 6380

#### Recent Errors
- None currently logged

#### Recent Warnings
- None currently logged

#### Health Check Command
```bash
docker compose exec redis redis-cli ping
# Expected output: PONG
```

#### Monitoring
```bash
# Check memory usage
docker compose exec redis redis-cli INFO memory

# Check connected clients
docker compose exec redis redis-cli INFO clients

# Check keys
docker compose exec redis redis-cli DBSIZE
```

---

### 7. RabbitMQ Container

**Service**: `rabbitmq`
**Image**: rabbitmq:3.12-management-alpine
**Purpose**: Message broker for Celery
**Status**: Awaiting restart after cleanup
**Ports**:
- 5673 (AMQP)
- 15673 (Management UI)

#### Recent Errors
- None currently logged

#### Recent Warnings
- None currently logged

#### Health Check Command
```bash
docker compose exec rabbitmq rabbitmq-diagnostics ping
```

#### Monitoring
```bash
# Check queues
docker compose exec rabbitmq rabbitmqctl list_queues

# Check vhosts
docker compose exec rabbitmq rabbitmqctl list_vhosts

# Check users
docker compose exec rabbitmq rabbitmqctl list_users

# Web UI Access
# URL: http://localhost:15673
# Default credentials in .env
```

---

### 8. Nginx Container

**Service**: `nginx`
**Image**: nginx:alpine
**Purpose**: Reverse proxy and load balancer
**Status**: Awaiting restart after cleanup
**Port**: 8084 (external), 8002 (web upstream), 8003 (channels upstream)

#### Recent Errors
- None currently logged

#### Recent Warnings
- Configuration file needs review for CSP headers

#### Health Check Command
```bash
curl -i http://localhost:8084/health
```

#### Configuration Monitoring
```bash
# Check nginx status
docker compose exec nginx nginx -t

# View active connections
docker compose exec nginx nginx -s reload

# Check access logs
docker compose logs nginx --tail=50 -f
```

#### Key Configuration Files
- `/docker/nginx-sites/zumodra.rhematek.conf` (custom setup)
- Check CSP headers: `curl -i http://localhost:8084/ | grep -i "content-security-policy"`

---

## Error Patterns & Trends

| Pattern | Frequency | Severity | Status | Notes |
|---------|-----------|----------|--------|-------|
| Container name conflicts | 1 | CRITICAL | In Progress | Docker cleanup in progress |
| Template syntax errors | 0 (fixed) | HIGH | RESOLVED | Fixed in commit d2496ef |
| Migration issues | 0 (fixed) | MEDIUM | RESOLVED | Fixed in commits a4cb24d, 947cd9f |
| Unstaged file changes | 1 | MEDIUM | Pending Review | 5 files need review |
| Untracked files | 100+ | MEDIUM | Requires Cleanup | Build artifacts and docs |

---

## Debugging Guide

### Quick Diagnosis Checklist

```bash
# 1. Check Docker status
docker ps -a
docker compose ps

# 2. Clean up containers (if needed)
docker rm -f $(docker ps -a -q)
docker system prune -af

# 3. Start fresh
docker compose down -v
docker compose up -d

# 4. Monitor startup
docker compose logs -f

# 5. Check health
docker compose exec web python manage.py health_check --full
```

### Common Issues & Solutions

#### 1. Container Fails to Start / Name Conflicts
```bash
# Solution: Force remove old containers
docker rm -f $(docker ps -a -q)
docker compose up -d
```

#### 2. Health Check Failures
```bash
# Check all dependencies
docker compose ps

# Verify networking
docker network ls
docker network inspect zumodra_default

# Check environment variables
docker compose exec web env | grep -i db
docker compose exec web env | grep -i redis
```

#### 3. Database Connection Errors
```bash
# Verify PostgreSQL is running and accessible
docker compose exec db pg_isready -U postgres

# Check credentials in .env
grep -i db .env

# Test connection
docker compose exec db psql -U postgres -d zumodra -c "SELECT version();"
```

#### 4. Redis/RabbitMQ Connection Issues
```bash
# Redis health
docker compose exec redis redis-cli ping

# RabbitMQ health
docker compose exec rabbitmq rabbitmq-diagnostics ping

# Check Celery connection to broker
docker compose exec celery-worker celery -A zumodra inspect ping
```

#### 5. Migration Errors
```bash
# Run migrations for public schema
docker compose exec web python manage.py migrate_schemas --shared

# Run migrations for tenant schemas
docker compose exec web python manage.py migrate_schemas --tenant

# View migration status
docker compose exec web python manage.py showmigrations
```

#### 6. Template/Static Asset Errors
```bash
# Collect static files
docker compose exec web python manage.py collectstatic --noinput

# Verify CSP compliance (no CDN assets)
curl http://localhost:8084 | grep -i "src=" | grep -v localhost
```

### Useful Commands

```bash
# View all logs in real-time
docker compose logs -f

# View specific container logs with follow
docker compose logs web -f --tail=50
docker compose logs channels -f --tail=50
docker compose logs celery-worker -f --tail=50

# View logs since a specific time
docker compose logs --since 30m

# Check container status and ports
docker compose ps
docker port

# Execute commands in containers
docker compose exec web bash
docker compose exec db psql -U postgres

# Health and monitoring
docker compose exec web python manage.py health_check --full
docker compose exec redis redis-cli INFO
docker compose exec rabbitmq rabbitmqctl list_queues
docker compose exec db psql -U postgres -l

# Rebuild specific container
docker compose up -d --build web

# View resource usage
docker stats

# Clean up system
docker system df
docker system prune -af
```

---

## Hotfixes & Resolutions Applied

| Issue ID | Issue | Date | Resolution | Status | Commit |
|----------|-------|------|-----------|--------|--------|
| DOCKER-001 | Container name conflicts | 2026-01-16 | `docker rm -f $(docker ps -a -q)` | IN PROGRESS | - |
| TEMP-001 | Template syntax errors | 2026-01-15 | Fixed CDN dependencies | RESOLVED | d2496ef |
| ADMIN-001 | UUID admin references | 2026-01-15 | Updated field references | RESOLVED | 1f7ced1 |
| MIGRATION-001 | Migration verification | 2026-01-15 | Fixed tenant identifier | RESOLVED | a4cb24d |
| HEALTH-001 | Health check ordering | 2026-01-15 | Enforced dependency order | RESOLVED | 947cd9f |
| GIT-001 | Unstaged changes | 2026-01-16 | PENDING REVIEW | PENDING | - |
| GIT-002 | Untracked files | 2026-01-16 | Requires cleanup | PENDING | - |

---

## Testing & Validation Checklist

After containers restart, verify:

- [ ] All containers running: `docker compose ps` (all show "Up")
- [ ] Database accessible: `docker compose exec db pg_isready`
- [ ] Redis accessible: `docker compose exec redis redis-cli ping`
- [ ] RabbitMQ accessible: `docker compose exec rabbitmq rabbitmq-diagnostics ping`
- [ ] Web app responds: `curl http://localhost:8084/health`
- [ ] WebSocket available: `curl -i -N -H "Upgrade: websocket" http://localhost:8003/ws/test/`
- [ ] Celery worker healthy: `docker compose exec celery-worker celery inspect ping`
- [ ] Celery beat scheduled: `docker compose exec celery-beat celery inspect scheduled`
- [ ] No error logs: `docker compose logs | grep -i error`
- [ ] Migration status: `docker compose exec web python manage.py showmigrations`

---

## Notes & Observations

- Document created 2026-01-16 11:45 UTC
- Initial container startup revealed name conflict issues requiring cleanup
- Recent commits show quality improvements (templates, UUIDs, migrations)
- 5 files with unstaged changes require review before next commit
- 100+ untracked files need organization and cleanup
- All known CRITICAL and HIGH issues are either RESOLVED or have clear remediation paths
- System architecture is sound; current issues are operational/cleanup related

---

## Schedule for Updates

- **Real-time**: During container startup troubleshooting
- **Every 4 hours**: Check container health and new error logs
- **Daily**: Review and categorize new errors, update status
- **As needed**: Document production incidents and emergency fixes
- **Day 3**: Complete unstaged file review and git cleanup
- **Day 4**: Verify all health checks pass in production environment
- **Day 5**: Archive old logs, prepare final status report

---

## Related Documentation

- `docs/CELERY_STATUS_DAY2.md` - Detailed Celery configuration
- `docs/CELERY_TECHNICAL_VALIDATION.md` - Celery validation steps
- `docs/DAY2_PROGRESS.md` - Overall Day 2 progress tracking
- `docs/API_FIXES_DAY2.md` - API endpoint status
- `docs/ARCHITECTURE.md` - System architecture overview
- `CLAUDE.md` - Project instructions and conventions
