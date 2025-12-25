# 🐛 Bugs and Fixes - Zumodra Project

**Last Updated:** December 25, 2025
**Status:** Identified bugs awaiting fixes

---

## 🔴 CRITICAL BUGS (Fix Immediately)

### BUG #1: Blog App - Model/View Mismatch
**Severity:** CRITICAL
**Location:** `blog/views.py`
**Status:** ❌ Broken

**Description:**
The blog app uses Wagtail CMS Page models (`BlogPostPage`, `CategoryPage`) but the views reference traditional Django models (`BlogPost`, `Category`, `Tag`) that don't exist.

**Error:**
```python
# blog/views.py attempts:
BlogPost.objects.all()  # ❌ Model doesn't exist
Category.objects.all()  # ❌ Model doesn't exist
Tag.objects.all()       # ❌ Model doesn't exist
```

**Actual Models:**
```python
# blog/models.py has:
class BlogPostPage(Page):  # ✅ Wagtail Page model
class CategoryPage(Page):  # ✅ Wagtail Page model
```

**Impact:**
- Blog views will raise `LookupError: No installed app with label 'BlogPost'`
- All blog URLs will return 500 errors
- Admin can create blog posts via Wagtail but frontend doesn't work

**Fix Option 1 - Use Wagtail (Recommended):**
```python
# blog/views.py - Rewrite to use Wagtail Page API
from wagtail.models import Page
from .models import BlogPostPage, CategoryPage

def blog_list(request):
    posts = BlogPostPage.objects.live().public().order_by('-first_published_at')
    return render(request, 'blog/list.html', {'posts': posts})

def blog_detail(request, slug):
    # Wagtail Pages handle their own routing via serve() method
    # May need to rely on Wagtail's built-in URL routing instead
    pass
```

**Fix Option 2 - Remove Wagtail:**
```python
# blog/models.py - Create traditional Django models
class Category(models.Model):
    name = models.CharField(max_length=200)
    slug = models.SlugField(unique=True)

class BlogPost(models.Model):
    title = models.CharField(max_length=200)
    slug = models.SlugField(unique=True)
    content = models.TextField()
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
```

**Recommended Action:**
Keep Wagtail for CMS benefits, rewrite views or use Wagtail's built-in routing.

**Files to Modify:**
- `blog/views.py` - Rewrite all views
- `blog/urls.py` - Update URL patterns for Wagtail routing
- `templates/blog/*.html` - Update template context variables

---

### BUG #2: Hardcoded Secrets in Settings
**Severity:** CRITICAL (Security)
**Location:** `zumodra/settings.py`
**Status:** ❌ Security Risk

**Description:**
Sensitive credentials are hardcoded in settings.py instead of environment variables.

**Exposed Secrets:**
```python
SECRET_KEY = "1_v5itzez)b(o-9eb@c4%)%hkgof^%-&7i*h2ne(7d7f-5p(z9"  # ❌
EMAIL_HOST_PASSWORD = "yOoiODNuXIYb"  # ❌
'PASSWORD': 'mysecretpassword',  # ❌
STRIPE_SECRET_KEY = ""  # Empty but hardcoded
```

**Impact:**
- Secret key exposed in version control
- Email password compromised
- Database password visible
- Cannot deploy to multiple environments safely

**Fix:**
```python
# zumodra/settings.py
import os
from environ import Env

env = Env()
env.read_env(str(BASE_DIR / '.env'))

SECRET_KEY = env('SECRET_KEY')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')

DATABASES = {
    'default': {
        'ENGINE': 'django.contrib.gis.db.backends.postgis',
        'NAME': env('DB_NAME'),
        'USER': env('DB_USER'),
        'PASSWORD': env('DB_PASSWORD'),
        'HOST': env('DB_HOST'),
        'PORT': env('DB_PORT', default='5432'),
    }
}
```

**Files to Create:**
```bash
# .env (DO NOT COMMIT)
SECRET_KEY=your-secret-key-here
DB_NAME=zumodra
DB_USER=postgres
DB_PASSWORD=mysecretpassword
DB_HOST=localhost
DB_PORT=5433
EMAIL_HOST_PASSWORD=actual-password

# .env.example (COMMIT THIS)
SECRET_KEY=your-secret-key-here
DB_NAME=zumodra
DB_USER=postgres
DB_PASSWORD=
DB_HOST=localhost
DB_PORT=5432
EMAIL_HOST_PASSWORD=
```

**Files to Modify:**
- `zumodra/settings.py` - Replace all hardcoded secrets
- `.gitignore` - Ensure `.env` is ignored
- `.env.example` - Create template

---

### BUG #3: SSL Settings Break Development
**Severity:** HIGH
**Location:** `zumodra/settings.py` (lines 624-627)
**Status:** ❌ Breaks local development

**Description:**
Production SSL settings are enabled globally, breaking local development.

**Current Code:**
```python
# Lines 624-627
SECURE_SSL_REDIRECT = True      # ❌ Forces HTTPS redirect
SESSION_COOKIE_SECURE = True    # ❌ Cookies only over HTTPS
CSRF_COOKIE_SECURE = True       # ❌ CSRF only over HTTPS
```

**Impact:**
- Local development at `http://localhost:8000` redirects to HTTPS (fails)
- Cannot test without SSL certificate
- Session/CSRF cookies don't work on localhost

**Fix:**
```python
# zumodra/settings.py
DEBUG = env.bool('DEBUG', default=False)

# Security settings - only enable in production
if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
else:
    # Development settings
    SECURE_SSL_REDIRECT = False
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
```

**Files to Modify:**
- `zumodra/settings.py` - Make SSL settings conditional

---

## 🟡 HIGH PRIORITY BUGS

### BUG #4: Services App - Missing Views
**Severity:** HIGH
**Location:** `services/views.py`
**Status:** ❌ 99% Incomplete

**Description:**
Services app has comprehensive models (marketplace functionality) but only 1 view implemented.

**Implemented:**
- `browse_service()` - Basic service listing

**Missing:**
- Service detail view
- Service creation/editing forms
- Provider profile CRUD
- Client request submission
- Proposal creation/management
- Contract acceptance/management
- Search and filtering
- Rating/review submission
- Messaging interface
- All API endpoints

**Impact:**
- Core marketplace functionality non-operational
- Cannot create/manage services
- No way to submit proposals
- No contract workflow

**Fix:**
Create comprehensive views and API endpoints (see PROJECT_PLAN.md Phase 2, Week 4-5).

**Estimated Work:** 40-60 hours

---

### BUG #5: Dashboard - Template-Only Views
**Severity:** HIGH
**Location:** `dashboard/views.py`
**Status:** ❌ No Real Logic

**Description:**
Dashboard has 50+ views that only render templates without any QuerySets or data processing.

**Example:**
```python
def dashboard_view(request):
    return render(request, 'dashboard/index.html')  # ❌ No data
```

**Impact:**
- Dashboard shows empty or static data
- No real metrics or analytics
- Just placeholder UI

**Fix:**
```python
from django.db.models import Count, Sum, Avg
from services.models import DService, DServiceContract
from finance.models import PaymentTransaction

def dashboard_view(request):
    # Get user-specific metrics
    user_services = DService.objects.filter(provider__user=request.user)

    context = {
        'total_services': user_services.count(),
        'active_contracts': DServiceContract.objects.filter(
            service__provider__user=request.user,
            status='active'
        ).count(),
        'total_revenue': PaymentTransaction.objects.filter(
            user=request.user,
            status='completed'
        ).aggregate(Sum('amount'))['amount__sum'] or 0,
        'avg_rating': user_services.aggregate(
            Avg('comments__rating')
        )['comments__rating__avg'] or 0,
    }
    return render(request, 'dashboard/index.html', context)
```

**Files to Modify:**
- `dashboard/views.py` - Add QuerySets to all 50+ views
- `dashboard/models.py` - Create analytics models if needed

**Estimated Work:** 20-30 hours

---

### BUG #6: Database Configuration - Hardcoded Credentials
**Severity:** HIGH (Security)
**Location:** `zumodra/settings.py` (lines 240-247)
**Status:** ❌ Credentials in Code

**Description:**
Database credentials hardcoded with weak password.

**Current:**
```python
'default': {
    'ENGINE': 'django.contrib.gis.db.backends.postgis',
    'NAME': 'zumodra',
    'USER': 'postgres',
    'PASSWORD': 'mysecretpassword',  # ❌
    'HOST': 'localhost',
    'PORT': '5433',
}
```

**Fix:**
Use environment variables (see BUG #2 fix).

---

## 🟠 MEDIUM PRIORITY BUGS

### BUG #7: Duplicate Newsletter Models
**Severity:** MEDIUM
**Location:** Multiple apps
**Status:** ⚠️ Code Duplication

**Description:**
Newsletter functionality duplicated across 3 apps.

**Locations:**
1. `newsletter/` - Full newsletter app ✅ (django-newsletter)
2. `leads/models.py` - Has Newsletter model
3. `marketing/models.py` - Has NewsletterCampaign, NewsletterSubscriber

**Impact:**
- Code confusion
- Potential data inconsistency
- Difficult to maintain

**Fix:**
1. Use `newsletter` app as canonical source
2. Remove Newsletter from `leads`
3. Remove Newsletter models from `marketing`
4. Migrate any data to `newsletter` app
5. Update all references

**Files to Modify:**
- `leads/models.py` - Remove Newsletter
- `marketing/models.py` - Remove Newsletter models
- Update any views/forms referencing removed models

---

### BUG #8: Simple History Middleware Not Installed
**Severity:** MEDIUM
**Location:** `zumodra/settings.py` (line 186)
**Status:** ⚠️ Middleware Exists but Package Commented

**Description:**
`simple_history.middleware.HistoryRequestMiddleware` is in MIDDLEWARE but `simple_history` is commented out in INSTALLED_APPS.

**Current:**
```python
INSTALLED_APPS = [
    # 'simple_history',  # ❌ Commented
]

MIDDLEWARE = [
    'simple_history.middleware.HistoryRequestMiddleware',  # ⚠️ Active
]
```

**Impact:**
- Middleware will fail to import
- Django may not start or throw warnings

**Fix Option 1 - Enable:**
```python
INSTALLED_APPS = [
    'simple_history',  # ✅
]
```

**Fix Option 2 - Remove:**
```python
MIDDLEWARE = [
    # 'simple_history.middleware.HistoryRequestMiddleware',  # Not using
]
```

**Recommended:** Remove if not using, or enable and add history to models.

---

### BUG #9: Celery Not Initialized
**Severity:** MEDIUM
**Location:** Missing `zumodra/celery.py`
**Status:** ❌ Configuration Incomplete

**Description:**
Celery broker configured in settings but no `celery.py` app initialization.

**Current State:**
```python
# zumodra/settings.py
CELERY_BROKER_URL = 'redis://localhost:6379/0'  # ✅ Configured
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'

# But no zumodra/celery.py exists ❌
```

**Impact:**
- Celery worker won't start
- Background tasks won't run
- Email sending may fail if async

**Fix:**
Create `zumodra/celery.py`:
```python
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')

app = Celery('zumodra')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
```

Update `zumodra/__init__.py`:
```python
from .celery import app as celery_app

__all__ = ('celery_app',)
```

**Files to Create:**
- `zumodra/celery.py`

**Files to Modify:**
- `zumodra/__init__.py`

---

### BUG #10: Missing Nginx Configuration
**Severity:** MEDIUM
**Location:** Missing `nginx.conf`
**Status:** ❌ Production Deployment Blocked

**Description:**
Project ready for Docker deployment but no Nginx configuration.

**Impact:**
- Cannot deploy to production without reverse proxy
- Static files won't be served efficiently
- No SSL termination

**Fix:**
Create `docker/nginx/nginx.conf`:
```nginx
upstream django {
    server web:8000;
}

server {
    listen 80;
    server_name _;

    location /static/ {
        alias /app/static/;
    }

    location /media/ {
        alias /app/media/;
    }

    location / {
        proxy_pass http://django;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Files to Create:**
- `docker/nginx/nginx.conf`
- `docker/nginx/Dockerfile`

**Files to Modify:**
- `compose.yaml` - Add nginx service

---

### BUG #11: Django-Q vs django-q2 Confusion
**Severity:** MEDIUM
**Location:** `requirements.txt` (line 67-68)
**Status:** ⚠️ Conflicting Packages

**Description:**
Requirements file has `django-q==1.3.9` commented out but `django-q2==1.8.0` installed.

**Current:**
```
# django-q==1.3.9
django-q2==1.8.0
```

**Settings:**
```python
INSTALLED_APPS = [
    'django_q',  # Works with both
]
```

**Impact:**
- Unclear which package is being used
- Different feature sets
- Potential compatibility issues

**Fix:**
Remove commented line, stick with django-q2:
```
django-q2==1.8.0  # ✅ Using this one
```

**Files to Modify:**
- `requirements.txt` - Remove commented django-q

---

## 🟢 LOW PRIORITY ISSUES

### ISSUE #1: Empty drip App
**Severity:** LOW
**Location:** `drip/`
**Status:** ⚠️ Unused

**Description:**
`drip` directory exists but app may not be used.

**Check:**
- Is `drip` in INSTALLED_APPS? (appears commented: `# 'drip',`)
- Any code referencing it?

**Fix:**
If not used, remove directory and ensure not in INSTALLED_APPS.

---

### ISSUE #2: Commented Dependencies in Settings
**Severity:** LOW
**Location:** `zumodra/settings.py`
**Status:** ⚠️ Dead Code

**Description:**
Many apps commented out in INSTALLED_APPS:
```python
# 'campaign',
# 'drip',
# 'leads',
# 'clickify',
# 'simple_history',
# 'geoip2',
# 'django_celery',
# 'services',
```

**Impact:**
- Confusing to determine what's actually used
- Dead code in repository

**Fix:**
Either:
1. Enable these apps if needed
2. Remove comments if not using
3. Document why they're commented

---

### ISSUE #3: Wagtail Admin URL Unclear
**Severity:** LOW
**Location:** `zumodra/urls.py`
**Status:** ⚠️ Potentially Missing

**Description:**
Wagtail installed but admin URLs might not be included.

**Check:**
```python
# zumodra/urls.py - is this present?
from wagtail.admin import urls as wagtailadmin_urls
from wagtail import urls as wagtail_urls

urlpatterns += [
    path('cms/', include(wagtailadmin_urls)),
    path('', include(wagtail_urls)),  # Should be last
]
```

**Fix:**
Verify Wagtail admin is accessible at `/cms/` or add URLs if missing.

---

## 📋 Bug Fix Checklist

### Immediate Actions (Do Today)
- [ ] Fix hardcoded secrets (BUG #2)
- [ ] Fix SSL settings for development (BUG #3)
- [ ] Decide on blog architecture (BUG #1)

### This Week
- [ ] Create Celery initialization (BUG #9)
- [ ] Create Nginx configuration (BUG #10)
- [ ] Enable or remove simple_history (BUG #8)
- [ ] Clean up django-q confusion (BUG #11)

### Next Two Weeks
- [ ] Implement services app views (BUG #4)
- [ ] Add dashboard logic (BUG #5)
- [ ] Consolidate newsletter apps (BUG #7)

### Before Production
- [ ] Security audit (all critical bugs fixed)
- [ ] Performance testing
- [ ] Load testing
- [ ] Backup/recovery testing

---

## 🔍 How to Test Fixes

### After Each Fix:
```bash
# 1. Check for Python errors
python manage.py check

# 2. Check for deployment issues
python manage.py check --deploy

# 3. Run migrations
python manage.py makemigrations
python manage.py migrate

# 4. Test server starts
python manage.py runserver

# 5. Run tests (if available)
python manage.py test

# 6. Check static files
python manage.py collectstatic --noinput
```

---

**Priority:** Fix critical bugs before adding new features.
**Status:** Document updated, fixes pending implementation.
