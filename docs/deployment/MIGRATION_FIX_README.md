# Migration Fix Guide - Integrations Error

## Problem

Your production server shows this error:
```
ERROR Failed to dispatch tenant webhook: relation "integrations_outboundwebhook" does not exist
```

## Root Cause

The `integrations` app was added to `INSTALLED_APPS` but **NOT** to `SHARED_APPS` in `settings_tenants.py`. This means:

1. The webhook models (`OutboundWebhook`, etc.) are trying to be created in tenant schemas
2. But webhooks are dispatched from the PUBLIC schema during tenant creation
3. So the table doesn't exist where the code expects it

## Why Simply Restarting Doesn't Fix It

**CRITICAL**: Your running Docker containers have the OLD `settings_tenants.py` baked into the image. The containers must be **REBUILT** (not just restarted) to load the new configuration.

## Solution - Complete Fix (3 Steps)

### Step 1: Generate Missing Migration (Local)

The `ai_matching` app has models but no migrations. Generate them:

```bash
# If Docker Desktop is running locally:
docker compose run --rm web python manage.py makemigrations ai_matching

# This will create: ai_matching/migrations/0001_initial.py
```

Then commit and push:
```bash
git add ai_matching/migrations/0001_initial.py
git commit -m "feat: add initial migration for ai_matching app"
git push origin main
```

### Step 2: Deploy to Server

SSH into your production server and run:

```bash
cd /path/to/zumodra
bash deploy_migration_fix.sh
```

This script will:
1. Pull latest code from `main`
2. **Rebuild Docker images** (loads new `settings_tenants.py`)
3. Start services (entrypoint runs migrations automatically)
4. Monitor logs for errors

### Step 3: Verify the Fix

Check that the integrations tables exist in the public schema:

```bash
docker compose exec web python manage.py dbshell
```

Then in the PostgreSQL prompt:
```sql
-- Switch to public schema
SET search_path TO public;

-- List integrations tables
\dt integrations_*

-- You should see:
-- integrations_integration
-- integrations_integrationcredential
-- integrations_integrationevent
-- integrations_integrationsynclog
-- integrations_outboundwebhook  <-- This is the missing one!
-- integrations_outboundwebhookdelivery
-- integrations_webhookdelivery
-- integrations_webhookendpoint

\q
```

Check logs for success:
```bash
docker compose logs web | grep -i integrations_outboundwebhook
```

You should see NO more "relation does not exist" errors.

## What Was Changed

### Files Modified:
1. **zumodra/settings_tenants.py** - Added to `SHARED_APPS`:
   - `integrations` (CRITICAL FIX)
   - `core`
   - `security`
   - `ai_matching`
   - `marketing`
   - `drf_spectacular`
   - `user_agents`
   - `analytical`
   - `django_celery_beat`
   - `newsletter`

2. **docker/entrypoint.sh** - Updated migration permissions list to include new shared apps

3. **ai_matching/migrations/** - Created directory (app has extensive models but no migrations)

## Technical Details

### Shared vs Tenant Apps

- **SHARED_APPS**: Tables created in the `public` schema, accessible to all tenants
- **TENANT_APPS**: Tables created in each tenant's schema, isolated per tenant

The `integrations` app MUST be in `SHARED_APPS` because:
- Webhooks are dispatched globally when tenants are created/modified
- The webhook dispatch code runs in the public schema context
- OutboundWebhook table must exist in the public schema

### Migration Order

The entrypoint runs migrations in this order:
1. `migrate_schemas --shared` → Creates public schema tables (including integrations)
2. `migrate_schemas --tenant` → Creates/updates existing tenant schemas
3. `bootstrap_demo_tenants` → Creates demo tenants (triggers webhooks)
4. `migrate_schemas --tenant` again → Migrates newly created tenant schemas

### Why Rebuild is Required

Python modules are loaded when the Docker image is built. The running container has:
- Old `settings_tenants.py` cached in memory
- Old `INSTALLED_APPS` configuration
- Old `SHARED_APPS` list

Restarting the container doesn't reload the Python modules - you must rebuild the image.

## Troubleshooting

### If error persists after rebuild:

1. **Check the running configuration**:
   ```bash
   docker compose exec web python manage.py shell
   ```
   ```python
   from django.conf import settings
   print('integrations' in settings.SHARED_APPS)  # Should be True
   print('integrations' in settings.INSTALLED_APPS)  # Should be True
   ```

2. **Force clean rebuild**:
   ```bash
   docker compose down -v  # WARNING: This deletes volumes!
   docker compose build --no-cache --pull
   docker compose up -d
   ```

3. **Check migration status**:
   ```bash
   docker compose exec web python manage.py showmigrations integrations
   ```
   All integrations migrations should show `[X]` (applied).

4. **Check which apps are in SHARED_APPS**:
   ```bash
   docker compose exec web python -c "from django.conf import settings; print('\\n'.join(settings.SHARED_APPS))"
   ```
   You should see `integrations` in the list.

### If demo tenant creation still fails:

The webhook dispatch might be failing for a different reason. Check:
```bash
docker compose exec web python manage.py shell
```
```python
from tenants.models import Tenant
from integrations.models import OutboundWebhook

# This should work without errors if fix is applied
tenants = Tenant.objects.all()
webhooks = OutboundWebhook.objects.all()
print(f"Tenants: {tenants.count()}, Webhooks: {webhooks.count()}")
```

## Questions?

If you're still seeing the error after following all steps:
1. Provide output of: `docker compose exec web python -c "from django.conf import settings; print(settings.SHARED_APPS)"`
2. Provide output of: `docker compose exec web python manage.py showmigrations integrations`
3. Provide recent logs: `docker compose logs --tail=200 web`
