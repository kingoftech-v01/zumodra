# Error Tracking Quick Reference

**Last Updated**: 2026-01-16 11:52 UTC
**Main Document**: `docs/ERROR_LOG_DAY2.md` (635 lines, 19 KB)

---

## Current Status at a Glance

| Category | Count | Status |
|----------|-------|--------|
| **CRITICAL** | 1 | IN PROGRESS |
| **HIGH** | 3 | 2 Fixed, 1 Testing |
| **MEDIUM** | 4 | 2 Fixed, 2 Pending |
| **LOW** | 3 | Informational |
| **Total Issues** | 11 | Tracked |

---

## Critical Issues to Fix NOW

### DOCKER-001: Container Name Conflicts
```bash
# Immediate fix (execute now)
docker rm -f $(docker ps -a -q)
docker compose up -d

# Verify
docker compose ps
```

---

## High Priority Review Items

### WEBHOOK-001: Webhook Signal Handlers
Files to review:
- `integrations/webhooks.py`
- `integrations/webhook_signals.py`
- `integrations/models.py`

Action: Run webhook delivery tests after container restart

---

## Medium Priority Cleanup

### GIT-001: Unstaged Changes (5 files)
```bash
# Review changes
git diff docker-compose.yml
git diff integrations/models.py
git diff integrations/webhook_signals.py
git diff integrations/webhooks.py
git diff hr_core/views.py

# Then either stage or revert
git add [file]      # or
git restore [file]
```

### GIT-002: Untracked Files (100+ items)
```bash
# View all untracked
git status

# Organize/cleanup
rm GDAL-*.whl gdal_core.whl  # Remove build artifacts
```

---

## Most Important Health Checks

```bash
# All-in-one health check
docker compose exec web python manage.py health_check --full

# Per-service checks (run these in order)
docker compose exec db pg_isready -U postgres
docker compose exec redis redis-cli ping
docker compose exec rabbitmq rabbitmq-diagnostics ping
docker compose exec celery-worker celery -A zumodra inspect ping
curl http://localhost:8084/health
```

---

## Container Restart Procedure

```bash
# 1. Stop everything
docker compose down

# 2. Clean up old containers
docker rm -f $(docker ps -a -q)

# 3. Start fresh
docker compose up -d

# 4. Monitor logs
docker compose logs -f

# 5. Verify after ~30 seconds
docker compose exec web python manage.py health_check --full
```

---

## Daily Checklist (Morning)

- [ ] `docker compose ps` - All containers "Up"
- [ ] `docker compose exec db pg_isready` - Database ready
- [ ] `docker compose exec redis redis-cli ping` - Redis PONG
- [ ] `docker compose exec rabbitmq rabbitmq-diagnostics ping` - RabbitMQ OK
- [ ] `curl http://localhost:8084/health` - Web app responding
- [ ] `docker compose logs | grep -i error` - No new errors
- [ ] Review `docs/ERROR_LOG_DAY2.md` - Update as needed

---

## Common Solutions

| Problem | Solution | Command |
|---------|----------|---------|
| Containers won't start | Remove conflicts | `docker rm -f $(docker ps -a -q)` |
| DB won't connect | Check is running | `docker compose exec db pg_isready` |
| Redis not responding | Restart redis | `docker compose restart redis` |
| RabbitMQ issues | Check diagnostics | `docker compose exec rabbitmq rabbitmqctl list_queues` |
| Migrations failed | Rerun migrations | `docker compose exec web python manage.py migrate_schemas` |
| Static files missing | Collect statics | `docker compose exec web python manage.py collectstatic` |

---

## 30-Second Diagnostic

```bash
# Copy and paste this entire block to check everything:
echo "=== CONTAINER STATUS ===" && \
docker compose ps && \
echo -e "\n=== DATABASE ===" && \
docker compose exec db pg_isready -U postgres 2>/dev/null || echo "Not ready" && \
echo -e "\n=== REDIS ===" && \
docker compose exec redis redis-cli ping 2>/dev/null || echo "Not responding" && \
echo -e "\n=== RABBITMQ ===" && \
docker compose exec rabbitmq rabbitmq-diagnostics ping 2>/dev/null || echo "Not responding" && \
echo -e "\n=== WEB APP ===" && \
curl -s http://localhost:8084/health | head -10 || echo "Not responding" && \
echo -e "\n=== RECENT ERRORS ===" && \
docker compose logs --since 5m | grep -i error | tail -5 || echo "No recent errors"
```

---

## File Locations

- **Main Error Log**: `/c/Users/techn/OneDrive/Documents/zumodra/docs/ERROR_LOG_DAY2.md`
- **Related Docs**:
  - `docs/CELERY_STATUS_DAY2.md` - Celery configuration
  - `docs/DAY2_PROGRESS.md` - Overall progress
  - `docs/API_FIXES_DAY2.md` - API status (200+ endpoints)
  - `docs/ARCHITECTURE.md` - System design

---

## When to Update ERROR_LOG_DAY2.md

- Every 4 hours during active development
- After each container restart
- When new errors appear in logs
- When hot fixes are applied
- Daily: Review and categorize

---

## Quick Reference Links

For detailed information, see:
- **Container Setup**: Error Log sections 1-5
- **Debugging Steps**: Error Log section "Debugging Guide"
- **Validation**: Error Log section "Testing & Validation Checklist"
- **All Commands**: Error Log section "Useful Commands"

---

**Last checked**: 2026-01-16 11:52 UTC
**Next check**: Within 4 hours
**Document maintainer**: Claude Code Agent
