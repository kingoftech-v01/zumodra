# 502 Error Investigation Guide

**Pages Affected:**
- `/our-services/`
- `/become-seller/`
- `/become-buyer/`
- `/careers/`

## Step-by-Step Investigation

### 1. Check Server Logs

```bash
# SSH into the server
ssh user@demo-company.zumodra.rhematek-solutions.com

# Check nginx error logs
sudo tail -f /var/log/nginx/error.log

# Check Django/application logs
docker compose logs -f web

# Or if using systemd
sudo journalctl -u zumodra-web -f
```

### 2. Check URL Configuration

Based on `zumodra/urls.py`, these views should be defined:

```python
# From zumodra/urls.py lines 20-44
from .views import (
    services_view,        # /our-services/
    become_seller_view,   # /become-seller/
    become_buyer_view,    # /become-buyer/
)

# Careers is in separate app
from careers.urls      # /careers/
```

**Check if these views exist:**

```bash
# Look for the views file
cd /path/to/zumodra
cat zumodra/views.py | grep -E "(services_view|become_seller_view|become_buyer_view)"
```

### 3. Verify View Functions

The views should be defined in `zumodra/views.py`. Check if:

1. Functions are properly defined
2. No unhandled exceptions
3. Templates exist
4. Database queries are valid

```bash
# Check if view file exists
ls -la zumodra/views.py

# Check for syntax errors
python manage.py check
```

### 4. Check Templates

These views likely render templates. Verify templates exist:

```bash
# Expected template locations
ls -la templates/our-services.html
ls -la templates/become-seller.html
ls -la templates/become-buyer.html
ls -la careers/templates/
```

### 5. Test in Django Shell

```bash
python manage.py shell

# Try importing the views
from zumodra.views import services_view, become_seller_view, become_buyer_view

# Check if they're callable
print(callable(services_view))
print(callable(become_seller_view))
print(callable(become_buyer_view))
```

### 6. Check Database Connectivity

502 errors can be caused by database issues:

```bash
# Test database connection
python manage.py dbshell

# Or
python manage.py check --database default
```

### 7. Check for Wagtail CMS Conflicts

From `zumodra/urls.py`, Wagtail has a catch-all pattern. This could be intercepting these URLs:

```python
# Line 363-367: Wagtail catch-all MUST BE LAST
urlpatterns += i18n_patterns(
    path('', include(wagtail_urls)),  # This catches everything not matched above
)
```

**Verify URL order:** These views must be defined BEFORE the Wagtail catch-all.

Check lines 240-256 in `zumodra/urls.py`:

```python
i18n_patterns(
    # These should come BEFORE wagtail_urls
    path('our-services/', services_view, name='services'),
    path('become-seller/', become_seller_view, name='become_seller'),
    path('become-buyer/', become_buyer_view, name='become_buyer'),
    ...
)
```

### 8. Reproduce Error Locally

```bash
# Start local development server
docker compose up -d

# Or
python manage.py runserver 0.0.0.0:8002

# Test the URLs
curl http://localhost:8002/our-services/
curl http://localhost:8002/become-seller/
curl http://localhost:8002/become-buyer/
curl http://localhost:8002/careers/
```

### 9. Check Nginx Configuration

```bash
# View nginx config
sudo cat /etc/nginx/sites-enabled/zumodra

# Test nginx config
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx
```

### 10. Check Upstream Service

502 means the gateway (nginx) cannot reach the upstream (Django/Daphne):

```bash
# Check if Django is running
docker compose ps
# or
sudo systemctl status zumodra-web

# Check if port is listening
netstat -tulpn | grep 8002
```

## Common Causes

1. **Missing View Functions** - Views imported but not defined
2. **Template Not Found** - View tries to render non-existent template
3. **Database Error** - View queries fail (wrong schema, missing table)
4. **Import Error** - Circular import or missing dependency
5. **Wagtail Conflict** - URL pattern order incorrect
6. **Upstream Down** - Django/Gunicorn crashed or not running
7. **Timeout** - View takes too long, nginx times out
8. **Permission Error** - File permissions on templates/static files

## Quick Fix Checklist

- [ ] Verify views exist in `zumodra/views.py`
- [ ] Verify templates exist in `templates/`
- [ ] Check `python manage.py check` for errors
- [ ] Review server logs for stack traces
- [ ] Verify database connection works
- [ ] Confirm URL patterns are before Wagtail catch-all
- [ ] Restart web service: `docker compose restart web`
- [ ] Clear cache: `python manage.py clear_cache`
- [ ] Test locally before deploying to production

## Expected Files to Check

1. `c:\Users\techn\OneDrive\Documents\zumodra\zumodra\views.py`
2. `c:\Users\techn\OneDrive\Documents\zumodra\templates\our-services.html`
3. `c:\Users\techn\OneDrive\Documents\zumodra\templates\become-seller.html`
4. `c:\Users\techn\OneDrive\Documents\zumodra\templates\become-buyer.html`
5. `c:\Users\techn\OneDrive\Documents\zumodra\careers\urls.py`
6. `c:\Users\techn\OneDrive\Documents\zumodra\careers\views.py`

## Contact Points

If you need help:
- Check Django error logs first
- Review nginx error logs second
- Test views in Django shell
- Verify URL routing order
