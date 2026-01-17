# Server Troubleshooting Guide - 502 Bad Gateway

## Current Status
**Issue**: Server returning 502 Bad Gateway on all endpoints
**Date**: 2026-01-17
**URL**: https://zumodra.rhematek-solutions.com

## Quick Fix Steps

### Step 1: SSH into Server
```bash
ssh zumodra
# Or use your configured SSH alias
```

### Step 2: Check Service Status
```bash
# Check if web service is running
sudo systemctl status zumodra-web

# Check if channels service is running
sudo systemctl status zumodra-channels

# Check if nginx is running
sudo systemctl status nginx
```

### Step 3: Check Recent Logs
```bash
# Check web logs for errors
sudo tail -50 /var/log/zumodra/web.log

# Check nginx error logs
sudo tail -50 /var/log/nginx/error.log

# Check for Python errors
sudo journalctl -u zumodra-web -n 50
```

### Step 4: Restart Services
```bash
# Navigate to project directory
cd /path/to/zumodra.rhematek-solutions.com  # Adjust path

# Pull latest code (if needed)
git pull origin main

# Activate virtual environment
source venv/bin/activate  # Adjust if using different venv name

# Collect static files
python manage.py collectstatic --noinput

# Run migrations (if needed)
python manage.py migrate_schemas --shared
python manage.py migrate_schemas --tenant

# Restart services
sudo systemctl restart zumodra-web
sudo systemctl restart zumodra-channels
sudo systemctl restart nginx

# Wait 5 seconds
sleep 5

# Check status
sudo systemctl status zumodra-web
sudo systemctl status zumodra-channels
```

### Step 5: Verify Server is Responding
```bash
# Test from server itself
curl http://localhost:8000/health/

# Test through nginx
curl http://localhost/health/

# Check if port is listening
sudo netstat -tlnp | grep :8000
```

## Common Issues and Solutions

### Issue 1: Service Failed to Start
**Symptom**: `systemctl status zumodra-web` shows "failed" or "inactive"

**Solution**:
```bash
# Check the error
sudo journalctl -u zumodra-web -n 100

# Common causes:
# 1. Python syntax error - check logs
# 2. Missing dependency - pip install -r requirements.txt
# 3. Database connection issue - check DATABASE_URL in .env
# 4. Port already in use - sudo lsof -i :8000
```

### Issue 2: Database Connection Error
**Symptom**: Logs show "could not connect to database"

**Solution**:
```bash
# Check if PostgreSQL is running
sudo systemctl status postgresql

# Restart PostgreSQL if needed
sudo systemctl restart postgresql

# Test database connection
psql -h localhost -U zumodra_user -d zumodra_db

# Check DATABASE_URL in .env
cat .env | grep DATABASE_URL
```

### Issue 3: Import Errors
**Symptom**: Logs show "ModuleNotFoundError" or "ImportError"

**Solution**:
```bash
# Reinstall requirements
pip install -r requirements.txt

# Check for recent code changes
git log --oneline -5

# If recent commit broke things, revert:
git revert HEAD
sudo systemctl restart zumodra-web
```

### Issue 4: Static Files 404
**Symptom**: Pages load but CSS/JS missing

**Solution**:
```bash
# Recollect static files
python manage.py collectstatic --noinput --clear

# Check STATIC_ROOT permissions
ls -la /path/to/staticfiles/

# Restart nginx
sudo systemctl restart nginx
```

### Issue 5: Nginx Configuration Error
**Symptom**: Nginx fails to start or restart

**Solution**:
```bash
# Test nginx configuration
sudo nginx -t

# If config is invalid, check nginx conf
sudo nano /etc/nginx/sites-available/zumodra

# Reload nginx config
sudo nginx -s reload
```

## Deployment Checklist

After fixing the server, verify deployment is correct:

```bash
# 1. Check current git commit
cd /path/to/zumodra.rhematek-solutions.com
git log --oneline -1

# Should show:
# ad122ab fix: prevent finance pages crashes for public users without tenants
# OR a more recent commit

# 2. Verify environment
source venv/bin/activate
python --version  # Should be Python 3.10+
which python  # Should point to venv

# 3. Check dependencies
pip list | grep Django  # Should show Django 5.2.7
pip list | grep django-tenants

# 4. Test manage.py
python manage.py check

# 5. Test database connection
python manage.py shell -c "from django.db import connection; connection.cursor()"

# 6. Check migrations
python manage.py showmigrations | grep '\[ \]'  # Should show no unapplied migrations

# 7. Restart all services
sudo systemctl restart zumodra-web
sudo systemctl restart zumodra-channels
sudo systemctl restart zumodra-celery
sudo systemctl restart nginx

# 8. Monitor logs in real-time
sudo tail -f /var/log/zumodra/web.log
```

## Testing After Restart

```bash
# From server:
curl http://localhost:8000/health/  # Should return 200

# From outside:
curl https://zumodra.rhematek-solutions.com/health/  # Should return 200
```

## Emergency Rollback

If the latest code is broken, rollback to previous working version:

```bash
# Find last working commit
git log --oneline -10

# Rollback (example: rollback to commit 61cad1c)
git reset --hard 61cad1c

# Restart services
sudo systemctl restart zumodra-web
sudo systemctl restart zumodra-channels

# Test
curl http://localhost:8000/health/
```

## Contact Points

**Issue**: 502 Bad Gateway
**Cause**: Application server (Gunicorn/uWSGI) not running or crashed
**Fix**: Restart services as shown above

**If all else fails**:
1. Check server resources: `htop`, `df -h`, `free -m`
2. Check for OOM killer: `dmesg | grep -i kill`
3. Reboot server: `sudo reboot` (last resort)

## Notes for User

The server is currently down (502 Bad Gateway). You'll need to:

1. SSH into the server
2. Check what service crashed
3. Restart the services using the commands above
4. Monitor logs for any errors

Once the server is back up, we can continue with the comprehensive testing plan.

**Common Cause**: If this happened right after deployment, it might be:
- A Python syntax error in the recent commits
- A missing dependency
- A database migration issue
- Nginx configuration problem

Check the logs first to identify the exact issue!
