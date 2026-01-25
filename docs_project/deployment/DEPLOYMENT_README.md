# Deployment Guide - Public User Schema Fixes

**Date**: 2026-01-17
**Version**: 1.2.0
**Status**: ✅ Code Ready | ⚠️ Server Restart Required

---

## What Was Fixed

### 1. Critical Schema Errors (FIXED)
Fixed database schema errors that caused crashes for public users (users without tenant workspace).

**Problem**: Public users encountered "An error occurred" messages when accessing:
- Dashboard
- Finance pages
- Notifications
- Any page that queries tenant-specific database tables

**Root Cause**: Django-tenants creates tables only in tenant schemas, not in the public schema. When public users accessed pages querying these tables, they got `ProgrammingError: relation does not exist`.

**Solution Applied**:
- Added schema-aware checks to all affected views
- Views now detect public schema and return empty/default data
- Proper error handling with fallbacks

---

## Changes Made

### Files Modified

#### 1. `notifications/template_views.py` (Commit: 93b1d55)
**9 views fixed** - All notification views now handle public users gracefully

**Changes**:
- Added import: `from django.db import connection`
- Added import: `from django.db.utils import ProgrammingError`
- Added schema checks: `if connection.schema_name == 'public':`
- Added try-except blocks around all database queries

**Views Fixed**:
1. `NotificationListView` - Returns empty notification list
2. `NotificationFullListView` - Returns empty queryset
3. `MarkNotificationReadView` - Returns error for public users
4. `MarkAllNotificationsReadView` - Returns success with 0 updates
5. `DismissNotificationView` - Returns error for public users
6. `DeleteNotificationView` - Returns error for public users
7. `NotificationCountView` - Returns 0 count
8. `NotificationPreferencesView` - Returns empty preferences
9. `UpdateNotificationPreferencesView` - Returns error for public users

**Impact**: Dashboard no longer crashes for public users

---

#### 2. `finance/template_views.py` (Commit: ad122ab)
**8+ views fixed** - All finance views now handle public users gracefully

**Changes**:
- Added import: `from django.db import connection`
- Added import: `from django.db.utils import ProgrammingError`
- Added schema checks before all database queries
- Return empty stats/lists for public users

**Views Fixed**:
1. `FinanceDashboardView` - Returns empty financial stats
2. `FinanceQuickStatsView` - Returns zero stats
3. `RecentPaymentsView` - Returns empty payment list
4. `PendingInvoicesView` - Returns empty invoice list
5. `EscrowSummaryView` - Returns zero escrow stats
6. `PaymentHistoryTemplateView` - Returns empty payment history
7. `SubscriptionTemplateView` - Returns empty subscription data
8. `InvoiceListTemplateView` - Returns empty invoice list

**Impact**: Finance pages no longer crash for public users

---

#### 3. Signup Links (Commit: 61cad1c)
**9+ templates fixed** - All signup buttons now use multi-tier signup flow

**Templates Modified**:
1. `templates/base/public_base.html` - 2 signup links updated
2. `templates/components/freelanhub_header.html` - 1 signup link updated
3. `templates/components/public_header.html` - 2 signup links updated
4. `templates_auth/account/signup_type_selection.html` - Branding updated
5. `templates/careers/public_landing.html` - 2 signup links updated
6. `templates/contact.html` - 1 signup link updated
7. `templates/become-seller.html` - 2 signup links updated
8. `templates/become-buyer.html` - 2 signup links updated

**Changes**:
- OLD: `{% url 'account_signup' %}`
- NEW: `{% url 'custom_account_u:signup_type_selection' %}`
- Branding: "FreelanHub" → "Zumodra"

**Impact**: All signup flows now show account type selection (Public/Company/Freelancer)

---

## No New Dependencies Added

**Important**: No new Python packages or system dependencies were added. All changes use existing Django and Python standard library imports.

**Imports Added** (already available):
- `from django.db import connection` - Django core
- `from django.db.utils import ProgrammingError` - Django core

**No `pip install` required** ✅

---

## Deployment Steps

### Prerequisites
- SSH access to server: `ssh zumodra` (or your configured alias)
- Git configured on server
- Virtual environment activated
- Proper permissions for systemd services

---

### Step 1: SSH into Server

```bash
ssh zumodra
# Or use your server alias/IP
# ssh user@zumodra.rhematek-solutions.com
```

---

### Step 2: Navigate to Project Directory

```bash
# Common locations (adjust if different):
cd /var/www/zumodra
# OR
cd /home/youruser/zumodra.rhematek-solutions.com
# OR
cd /opt/zumodra

# Verify you're in the right directory
ls manage.py  # Should exist
```

---

### Step 3: Pull Latest Code from GitHub

```bash
# Check current branch
git branch

# Pull latest changes
git pull origin main

# Verify commits are present
git log --oneline -5

# Expected output should include:
# ad122ab fix: prevent finance pages crashes for public users without tenants
# 93b1d55 fix: prevent dashboard crashes for public users without tenants
# 61cad1c fix: standardize all signup links to use multi-tier signup flow
```

---

### Step 4: Activate Virtual Environment (if not already active)

```bash
# Activate virtual environment
source venv/bin/activate
# OR
source env/bin/activate
# OR whatever your venv is named

# Verify activation
which python  # Should point to venv
python --version  # Should be 3.10+
```

---

### Step 5: Check for Migration Issues (Optional but Recommended)

```bash
# Run Django checks
python manage.py check

# Check for unapplied migrations
python manage.py showmigrations | grep '\[ \]'

# If any migrations are unapplied, run:
python manage.py migrate_schemas --shared
python manage.py migrate_schemas --tenant
```

---

### Step 6: Collect Static Files (if needed)

```bash
# Only needed if templates changed
python manage.py collectstatic --noinput
```

---

### Step 7: Restart Services

#### Option A: Docker Deployment

If using Docker:

```bash
# Stop containers
docker-compose down

# Start containers
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f web
```

#### Option B: Systemd Services

If using systemd:

```bash
# Restart Django web server
sudo systemctl restart zumodra-web

# Restart Django Channels (WebSocket)
sudo systemctl restart zumodra-channels

# Restart Celery (background tasks)
sudo systemctl restart zumodra-celery

# Restart Nginx (web server)
sudo systemctl restart nginx

# Wait 5 seconds for services to start
sleep 5

# Check service status
sudo systemctl status zumodra-web
sudo systemctl status zumodra-channels
sudo systemctl status nginx
```

---

### Step 8: Verify Services Are Running

```bash
# Check if all services are active
sudo systemctl is-active zumodra-web
sudo systemctl is-active zumodra-channels
sudo systemctl is-active nginx

# Check listening ports
sudo netstat -tlnp | grep :8000  # Django should be here
sudo netstat -tlnp | grep :80    # Nginx should be here
sudo netstat -tlnp | grep :443   # Nginx SSL should be here

# Check recent logs for errors
sudo journalctl -u zumodra-web -n 20 --no-pager
sudo tail -20 /var/log/zumodra/web.log
sudo tail -20 /var/log/nginx/error.log
```

---

### Step 9: Test Health Endpoint

```bash
# Test from server itself (should return 200)
curl -v http://localhost:8000/health/

# Test through nginx (should return 200)
curl -v http://localhost/health/

# If both return 200, the server is healthy! ✅
```

---

### Step 10: Test External Access

From your local machine:

```bash
# Test public URL
curl -v https://zumodra.rhematek-solutions.com/health/

# Expected: HTTP 200 with JSON health data
```

---

## Troubleshooting

### Issue 1: Services Won't Start

**Symptom**: `systemctl restart zumodra-web` fails

**Solution**:
```bash
# Check error logs
sudo journalctl -u zumodra-web -n 50

# Common causes:
# - Python syntax error in code
# - Missing environment variables
# - Database connection issue
# - Port already in use

# Check if port is in use
sudo lsof -i :8000

# Kill process if needed
sudo kill -9 <PID>

# Restart
sudo systemctl restart zumodra-web
```

### Issue 2: Still Getting 502 Bad Gateway

**Symptom**: Nginx returns 502 even after restart

**Solution**:
```bash
# Check if Django is running
ps aux | grep gunicorn

# Check if port 8000 is listening
sudo netstat -tlnp | grep 8000

# If not listening, Django didn't start
# Check the logs:
sudo journalctl -u zumodra-web -n 100

# Manually test Django
python manage.py runserver 0.0.0.0:8000
# Then access http://server-ip:8000/health/
```

### Issue 3: Database Errors

**Symptom**: Logs show database connection errors

**Solution**:
```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Restart PostgreSQL
sudo systemctl restart postgresql

# Test database connection
psql -h localhost -U zumodra_user -d zumodra_db

# Check DATABASE_URL in .env
cat .env | grep DATABASE_URL
```

### Issue 4: Permission Errors

**Symptom**: Cannot read logs or restart services

**Solution**:
```bash
# Add user to required groups
sudo usermod -aG www-data $USER

# Fix log file permissions
sudo chmod 644 /var/log/zumodra/*.log
sudo chown www-data:www-data /var/log/zumodra/*.log

# Restart services
sudo systemctl restart zumodra-web
```

---

## Quick Diagnostic Script

We've created an automated diagnostic and restart script:

```bash
# Download the script (if not already on server)
# ... or create it manually from check_and_restart_server.sh

# Make executable
chmod +x check_and_restart_server.sh

# Run it
./check_and_restart_server.sh

# Follow the prompts
```

The script will:
1. Check Docker containers (if using Docker)
2. Check systemd services status
3. Check listening ports
4. Check nginx configuration
5. Check application logs
6. Offer to restart all services
7. Perform final health check
8. Provide summary

---

## Expected Behavior After Deployment

### ✅ Public Users Can Now:
- Register and login successfully
- Access dashboard without "An error occurred" message
- View notification dropdown (shows 0 notifications)
- Access finance pages (shows empty state or upgrade message)
- Browse public pages without crashes
- Choose account type during signup (Public/Company/Freelancer)

### ✅ No More Errors:
- No `ProgrammingError: relation "notifications_notification" does not exist`
- No `ProgrammingError: relation "finance_paymenttransaction" does not exist`
- No crashes when accessing dashboard or finance pages
- No schema-related exceptions in logs

### ✅ Tenant Users (Companies/Freelancers):
- All existing functionality works as before
- No breaking changes
- Same features and permissions

---

## Rollback Plan (If Needed)

If deployment causes issues:

```bash
# Find previous working commit
git log --oneline -10

# Rollback to before these changes (commit before 61cad1c)
git reset --hard 0c67aa2

# Restart services
sudo systemctl restart zumodra-web zumodra-channels

# Test
curl http://localhost:8000/health/
```

---

## Testing Checklist

After deployment, verify:

- [ ] Server health endpoint returns 200: `/health/`
- [ ] Homepage loads without errors
- [ ] Signup type selection page loads: `/user/signup/choose/`
- [ ] Can create public user account
- [ ] Can login as public user
- [ ] Dashboard loads without "An error occurred"
- [ ] Notification dropdown opens (shows 0 notifications)
- [ ] Finance pages load without crashes
- [ ] Public API endpoints work: `/api/v1/careers/jobs/`
- [ ] Authenticated API requires auth: `/api/v1/jobs/jobs/` returns 401
- [ ] No ProgrammingError in logs: `sudo grep -i "programmingError" /var/log/zumodra/web.log`

---

## Summary

**What Changed**: Fixed schema errors in notifications and finance views, updated signup flow
**Dependencies**: None added (uses existing Django imports)
**Migrations**: None required
**Restart Required**: ✅ YES - All Django services must be restarted
**Downtime**: ~30 seconds during restart
**Risk Level**: Low (only adds safety checks, no breaking changes)

---

## Support

If you encounter issues:

1. Check logs: `sudo journalctl -u zumodra-web -n 50`
2. Run diagnostic script: `./check_and_restart_server.sh`
3. Review troubleshooting section above
4. Check GitHub commits for details

---

**Deployed By**: Claude Code
**Deployment Date**: 2026-01-17
**Commits Included**: 61cad1c, 93b1d55, ad122ab
