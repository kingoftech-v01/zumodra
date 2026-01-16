# Zumodra Project – Backend Lead Developer
## Comprehensive Onboarding Document

**Project:** Zumodra HR/Management SaaS  
**Deadline:** January 21, 2026  
**Role:** Backend Lead Developer  
**Team Lead:** Supervisor/Project Lead  

---

## 1. Executive Summary

You are the **Backend Lead Developer** for Zumodra. Your role is to establish a solid, functional Django foundation that all other developers depend on. The backend is currently broken with startup errors, missing imports, unhandled exceptions, and inconsistent module structure. Within the first 48 hours, you must get the application running cleanly—this unblocks the entire team.

### Primary Objectives
- **Day 1 (4 hours):** Fix all startup errors, resolve broken imports, get app running
- **Day 1 (4 hours):** Establish standardized Django app structure and patterns
- **Day 2:** Document architecture and create patterns for other developers to follow
- **Days 3–5:** Support and code review from other backend developers

### Success Criteria
- [ ] App starts cleanly with `python manage.py runserver` or `docker-compose up`
- [ ] Zero unhandled exceptions in startup logs
- [ ] All migrations run cleanly from scratch
- [ ] Django shell works (`python manage.py shell`)
- [ ] URL routing matches frontend expectations
- [ ] Architecture document completed and shared with team

---

## 2. Your First 2 Hours: Triage

### 2.1 Get the App Running Locally

**Steps:**
1. Clone the repository: `git clone https://github.com/kingoftech-v01/zumodra.git`
2. Create Python virtual environment: `python -m venv venv`
3. Activate it: `source venv/bin/activate` (or `venv\Scripts\activate` on Windows)
4. Install dependencies: `pip install -r requirements.txt`
5. Copy environment file: `cp .env.example .env` (or ask Supervisor for actual .env)
6. Run migrations: `python manage.py migrate`
7. Start server: `python manage.py runserver`

**Expected Errors (Write them down):**
- `ModuleNotFoundError: No module named 'X'` → Missing dependency in requirements.txt
- `django.core.exceptions.ImproperlyConfigured: ...` → Settings issue
- `ProgrammingError` on migrate → Schema mismatch or DB connection issue
- `TemplateDoesNotExist` → Not relevant at this stage, ignore for now

### 2.2 Categorize Errors

Create a document titled `BACKEND_TRIAGE.md`:

```markdown
## Backend Startup Errors & Fixes

### Error 1: Import Error in app_name/views.py
**Error Message:** `ImportError: cannot import name 'ModelName' from 'app_name.models'`
**Root Cause:** Model doesn't exist or is named differently
**Fix:** [describe fix]
**Status:** ☐ Fixed | ☐ In Progress | ☐ Blocked

### Error 2: Missing INSTALLED_APPS
**Error Message:** `ModuleNotFoundError: No module named 'app_name'`
**Root Cause:** App not added to INSTALLED_APPS in settings.py
**Fix:** Add 'app_name' to INSTALLED_APPS
**Status:** ☐ Fixed | ☐ In Progress | ☐ Blocked

[... more errors ...]
```

### 2.3 Settings.py Audit

Review `project_name/settings.py`:

**Required:**
- [ ] `DEBUG = False` for production safety (can be True locally via .env)
- [ ] `SECRET_KEY` not hardcoded (use environment variable)
- [ ] `ALLOWED_HOSTS` includes 'localhost' for dev and actual domain for prod
- [ ] `INSTALLED_APPS` includes all Django apps in the project
- [ ] `DATABASES` correctly points to PostgreSQL with env vars
- [ ] `TEMPLATES` includes template directory
- [ ] `STATIC_URL` and `MEDIA_URL` configured
- [ ] `MIDDLEWARE` includes CSRF, Auth, Sessions

---

## 3. Days 1–2: Establish Backend Foundation

### 3.1 App Structure & Organization

**Expected Django Project Layout:**

```
zumodra/
├── manage.py
├── requirements.txt
├── .env
├── .gitignore
├── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── API.md
│   └── DEPLOYMENT.md
├── zumodra/  (project folder)
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   ├── wsgi.py
│   └── asgi.py
├── apps/
│   ├── users/
│   │   ├── models.py
│   │   ├── views.py
│   │   ├── urls.py
│   │   ├── admin.py
│   │   ├── tests.py
│   │   ├── serializers.py (if REST API)
│   │   └── templates/users/
│   ├── hr/  (or payroll, projects, etc.)
│   │   ├── models.py
│   │   ├── views.py
│   │   ├── urls.py
│   │   ├── templates/hr/
│   │   └── ...
│   └── core/ (shared utilities, authentication)
├── templates/
│   ├── base.html
│   ├── components/
│   │   ├── navbar.html
│   │   ├── sidebar.html
│   │   └── ...
│   └── ...
├── static/
│   ├── css/
│   ├── js/
│   └── images/
└── docker-compose.yml
```

**Enforce This Structure:**
- One app per business domain (users, hr, projects, etc.)
- Shared logic in a `core` app
- All apps in an `apps/` folder (easier to manage)
- Templates organized by app: `templates/app_name/`
- Utilities in separate modules: `utils.py`, `helpers.py`

### 3.2 Models & Database Schema

**Tasks:**
1. Review all models in each app
2. Check for:
   - Correct relationships (ForeignKey, ManyToMany, OneToOne)
   - Appropriate null/blank settings
   - `__str__` methods defined (for admin)
   - Timestamps (created_at, updated_at)
   - Soft deletes if needed

3. Run migrations test:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

4. Start from scratch:
   ```bash
   python manage.py migrate --fake-initial  # or reset DB if safe
   ```

**Red Flags:**
- Circular imports between models
- Missing `on_delete` in ForeignKey
- Field names that conflict with Django internals (`id`, `pk`)
- No indexes on frequently queried fields

### 3.3 Views & URLconf

**Standardize Views:**

**Class-Based Views (Recommended):**
```python
from django.views import View
from django.views.generic import ListView, DetailView, CreateView

class UserListView(ListView):
    model = User
    template_name = 'users/user_list.html'
    context_object_name = 'users'
    paginate_by = 20
```

**Function-Based Views (for API/simple logic):**
```python
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

@require_http_methods(["GET", "POST"])
def api_user_list(request):
    if request.method == 'GET':
        users = User.objects.all()
        return JsonResponse({'users': [...]})
    elif request.method == 'POST':
        # Create user
        pass
```

**URL Configuration Pattern:**

**Root URLs (`zumodra/urls.py`):**
```python
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/users/', include('apps.users.urls', namespace='users')),
    path('api/hr/', include('apps.hr.urls', namespace='hr')),
    # Frontend pages
    path('', include('apps.core.urls', namespace='core')),
]
```

**App URLs (`apps/users/urls.py`):**
```python
from django.urls import path
from . import views

app_name = 'users'

urlpatterns = [
    path('list/', views.UserListView.as_view(), name='list'),
    path('<int:pk>/', views.UserDetailView.as_view(), name='detail'),
    path('create/', views.UserCreateView.as_view(), name='create'),
    path('<int:pk>/edit/', views.UserUpdateView.as_view(), name='edit'),
    path('<int:pk>/delete/', views.UserDeleteView.as_view(), name='delete'),
]
```

**Ensure:**
- [ ] All app URLs are included in root `urls.py` with namespace
- [ ] URL names follow pattern: `app:action` (e.g., `users:detail`, `hr:create`)
- [ ] No hardcoded paths (use `{% url %}` in templates)
- [ ] 404 page is implemented (`templates/404.html`)
- [ ] 500 error handler is implemented (`templates/500.html`)

### 3.4 Settings.py Best Practices

**Environment-Based Configuration:**

Use `python-decouple` or `python-dotenv` to load from .env:

```python
import os
from decouple import config

# Core
DEBUG = config('DEBUG', default=False, cast=bool)
SECRET_KEY = config('SECRET_KEY')
ALLOWED_HOSTS = config('ALLOWED_HOSTS', cast=lambda v: [s.strip() for s in v.split(',')])

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD': config('DB_PASSWORD'),
        'HOST': config('DB_HOST', default='localhost'),
        'PORT': config('DB_PORT', default='5432'),
    }
}

# Security
SECURE_SSL_REDIRECT = config('SECURE_SSL_REDIRECT', default=False, cast=bool)
SESSION_COOKIE_SECURE = config('SESSION_COOKIE_SECURE', default=False, cast=bool)
CSRF_COOKIE_SECURE = config('CSRF_COOKIE_SECURE', default=False, cast=bool)

# Email
EMAIL_BACKEND = config('EMAIL_BACKEND', default='django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = config('EMAIL_HOST', default='')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
```

**Example .env:**
```
DEBUG=True
SECRET_KEY=your-secret-key-here-change-in-production
ALLOWED_HOSTS=localhost,127.0.0.1,zumodra.rhematek-solutions.com
DB_NAME=zumodra
DB_USER=postgres
DB_PASSWORD=secure_password
DB_HOST=localhost
DB_PORT=5432
```

---

## 4. Backend Standards & Patterns

### 4.1 Code Style

**Python/Django Standards:**
- Follow PEP 8 (use `black` or `flake8`)
- Docstrings for all functions and classes
- Type hints (Python 3.6+)
- No commented-out code
- Meaningful variable names (not `x`, `y`, `tmp`)

**Example:**
```python
def get_active_users(limit: int = 100) -> list:
    """
    Fetch active users limited by count.
    
    Args:
        limit: Maximum number of users to return (default: 100)
    
    Returns:
        List of active User objects
    """
    return User.objects.filter(is_active=True)[:limit]
```

### 4.2 Models Best Practices

```python
from django.db import models
from django.utils import timezone

class BaseModel(models.Model):
    """Abstract base model with timestamps."""
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        abstract = True

class User(BaseModel):
    """User model with core fields."""
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['is_active']),
        ]
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})"
```

### 4.3 Views & Permissions

**Always Check Permissions:**

```python
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404

class UserDetailView(LoginRequiredMixin, DetailView):
    model = User
    template_name = 'users/user_detail.html'
    
    def get_queryset(self):
        # Only allow users to view their own profile or admin to view all
        if self.request.user.is_staff:
            return User.objects.all()
        return User.objects.filter(pk=self.request.user.pk)
```

### 4.4 Testing

**Minimum Test Coverage:**
- Models: Test creation, validation, methods
- Views: Test GET/POST, permissions, redirects
- APIs: Test all endpoints, authentication, data validation

**Example:**
```python
from django.test import TestCase, Client
from django.urls import reverse
from apps.users.models import User

class UserListViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(email='test@test.com', password='pass123')
    
    def test_anonymous_user_redirected(self):
        response = self.client.get(reverse('users:list'))
        self.assertEqual(response.status_code, 302)  # Redirect
    
    def test_authenticated_user_can_view(self):
        self.client.login(email='test@test.com', password='pass123')
        response = self.client.get(reverse('users:list'))
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.user, response.context['users'])
```

---

## 5. Communication & Handoff

### 5.1 Daily Updates to Supervisor

**Morning (10 AM):**
- "Started, running triage, found X errors"

**Afternoon (4 PM):**
- "Fixed Y errors, app now runs, working on URL routing"

**Evening (if major issues):**
- Slack message: "Blocked on [issue], need [help/decision] from [person]"

### 5.2 Unblocking Other Developers

**Once you complete Day 1 triage:**
1. Share `BACKEND_TRIAGE.md` with team
2. Post message: "Backend runs cleanly. Other devs can now clone and develop."
3. Host optional 15-min Q&A session for developers with questions

**Once you complete Day 2 architecture:**
1. Share `ARCHITECTURE.md`
2. Post in Slack: "Architecture doc ready. Follow patterns in `apps/users/` for new apps."
3. Review first PR from other backend devs to ensure they follow patterns

---

## 6. Deliverables

By **End of Day 2**, provide:

- [ ] `BACKEND_TRIAGE.md` – All startup errors categorized and resolved
- [ ] Clean app startup (zero exceptions)
- [ ] `ARCHITECTURE.md` – Project structure, app organization, patterns
- [ ] `SETTINGS.md` – Settings configuration explanation and .env template
- [ ] `TESTING.md` – Testing strategy and sample tests
- [ ] Updated `requirements.txt` with all dependencies and pinned versions
- [ ] Code review checklist in README

### ARCHITECTURE.md Template

```markdown
# Zumodra Backend Architecture

## Project Structure
- **apps/** – Django applications (users, hr, projects, etc.)
- **zumodra/** – Project settings and root URL configuration
- **templates/** – Django HTML templates
- **static/** – CSS, JavaScript, images

## App Organization
Each app contains:
- `models.py` – Database models
- `views.py` – Request handlers (class-based views preferred)
- `urls.py` – URL routing with namespace
- `admin.py` – Django admin configuration
- `tests.py` – Unit and integration tests
- `templates/app_name/` – HTML templates for this app

## Key Patterns

### URL Naming
Pattern: `app:action`
Examples:
- `users:list` – List all users
- `users:detail` – User detail view
- `users:create` – Create new user

### View Architecture
- Use class-based views (ListView, DetailView, CreateView) for standard CRUD
- Use function-based views for APIs
- Always include login checks via `LoginRequiredMixin`

### Database
- PostgreSQL only
- Migrations tracked in Git
- Always provide `__str__` methods on models
- Use soft deletes (is_active flag) instead of hard deletes if needed

## Dependencies
Key packages:
- Django 4.2+
- psycopg2-binary – PostgreSQL driver
- djangorestframework – REST API (if used)
- celery – Background tasks (if used)
- python-decouple – Environment variables
```

---

## 7. Success Metrics

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| App startup time | <5 seconds | ? | |
| Unhandled exceptions on startup | 0 | ? | |
| Migration run time | <10 seconds | ? | |
| Code coverage | 70%+ | ? | |
| All URLs resolvable | 100% | ? | |

---

## 8. Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: No module named 'X'` | Add to INSTALLED_APPS in settings.py, or `pip install X` |
| `ProgrammingError` on migrate | Check DB connection string, reset migrations if schema out of sync |
| `TemplateDoesNotExist` | Not critical now, Frontend Lead will fix; note which template is missing |
| `ImportError: circular import` | Restructure imports, move shared code to `utils.py`, use late imports |
| `static files not loading` | Ensure `STATIC_URL` is set, run `python manage.py collectstatic` |

---

## Final Notes

You are the **foundation setter**. Everything depends on you in the first 48 hours. Focus on:
1. **Getting it running** – Unblock the team
2. **Making it clear** – Document patterns so others follow
3. **Moving fast** – Don't over-engineer, solve the immediate problem

After Day 2, shift to **code review** and **support** for other backend devs. You're no longer coding; you're enabling 4 other developers to ship quality work.

**Let's go.**

---

**Document Version:** 1.0  
**Created:** January 16, 2026  
**Owner:** Backend Lead Developer