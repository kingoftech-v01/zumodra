# Zumodra Project – Backend Developer – Database & Authentication
## Comprehensive Onboarding Document

**Project:** Zumodra HR/Management SaaS  
**Deadline:** January 21, 2026  
**Role:** Backend Developer (Database & Authentication)

---

## 1. Executive Summary

You are responsible for stabilizing the database layer and authentication system. The database may have migration issues, and authentication may be incomplete or broken. Your goal is to ensure clean migrations, proper user authentication workflows, and secure permission management.

### Primary Objectives
- **Day 1:** Audit models and migrations, run clean migrations from scratch
- **Day 2:** Implement/repair authentication (login, signup, password reset, email verification)
- **Day 3:** Setup permission system and test access control
- **Day 4:** Optimize database and document schema
- **Day 5:** Final validation

### Success Criteria
- [ ] All migrations run cleanly on fresh database
- [ ] Authentication workflows (login, logout, signup, password reset) work end-to-end
- [ ] User permissions properly enforced
- [ ] PostgreSQL properly configured
- [ ] Database schema documented

---

## 2. Database Audit & Cleanup

### 2.1 Model Review

```python
# Check all models for common issues
# 1. Missing __str__ methods
# 2. Incorrect null/blank settings
# 3. Circular imports
# 4. Missing on_delete in ForeignKey
# 5. Soft deletes (is_active vs hard delete)

# Example good model:
from django.db import models

class BaseModel(models.Model):
    """Abstract base with timestamps."""
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        abstract = True

class Department(BaseModel):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    manager = models.ForeignKey('User', on_delete=models.SET_NULL, null=True)
    
    class Meta:
        ordering = ['name']
        indexes = [models.Index(fields=['is_active'])]
    
    def __str__(self):
        return self.name
```

### 2.2 Migration Cleanup

```bash
# List all migrations
python manage.py showmigrations

# If migrations are corrupted:
# 1. Backup current database
# 2. Delete migration files (except __init__.py)
# 3. Run: python manage.py makemigrations
# 4. Create initial migration: python manage.py migrate --fake-initial

# Test on fresh database
python manage.py migrate --fake
python manage.py migrate --fake-initial apps.users 0001_initial
python manage.py migrate
```

### 2.3 PostgreSQL Configuration

Create `.env` with:
```
DB_ENGINE=django.db.backends.postgresql
DB_NAME=zumodra
DB_USER=zumodra_user
DB_PASSWORD=secure_password_here
DB_HOST=localhost
DB_PORT=5432
```

settings.py:
```python
from decouple import config

DATABASES = {
    'default': {
        'ENGINE': config('DB_ENGINE', default='django.db.backends.postgresql'),
        'NAME': config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD': config('DB_PASSWORD'),
        'HOST': config('DB_HOST', default='localhost'),
        'PORT': config('DB_PORT', default='5432'),
        'CONN_MAX_AGE': 600,
        'ATOMIC_REQUESTS': True,  # Wrap each request in transaction
    }
}

# Connection pooling (optional, for high-traffic apps)
DATABASES['default']['OPTIONS'] = {
    'connect_timeout': 10,
}
```

---

## 3. Authentication System

### 3.1 Django's Built-in User Model (Recommended)

```python
# Use Django's User model or extend it
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    """Custom user model for future extensibility."""
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20, blank=True)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    
    USERNAME_FIELD = 'email'  # Use email as username
    REQUIRED_FIELDS = ['username']  # Required for createsuperuser
    
    class Meta:
        ordering = ['-date_joined']
    
    def __str__(self):
        return self.email

# In settings.py:
AUTH_USER_MODEL = 'users.User'
```

### 3.2 Authentication Views

**Login (Class-Based):**
```python
from django.contrib.auth.views import LoginView as DjangoLoginView
from django.contrib.auth.forms import AuthenticationForm

class LoginView(DjangoLoginView):
    template_name = 'auth/login.html'
    form_class = AuthenticationForm
    redirect_authenticated_user = True
    
    def get_success_url(self):
        return reverse('core:dashboard')
```

**Logout:**
```python
from django.contrib.auth.views import LogoutView as DjangoLogoutView

class LogoutView(DjangoLogoutView):
    next_page = 'core:login'
```

**Signup:**
```python
from django import forms
from django.contrib.auth import get_user_model

User = get_user_model()

class SignupForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    password_confirm = forms.CharField(widget=forms.PasswordInput)
    
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name']
    
    def clean(self):
        if self.cleaned_data['password'] != self.cleaned_data['password_confirm']:
            raise forms.ValidationError("Passwords don't match")
        return self.cleaned_data
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password'])
        if commit:
            user.save()
        return user

from django.views.generic import CreateView

class SignupView(CreateView):
    form_class = SignupForm
    template_name = 'auth/signup.html'
    success_url = reverse_lazy('core:login')
    
    def form_valid(self, form):
        user = form.save()
        # Send verification email
        send_verification_email(user)
        return super().form_valid(form)
```

**Password Reset:**
```python
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView

class CustomPasswordResetView(PasswordResetView):
    template_name = 'auth/password_reset.html'
    email_template_name = 'auth/password_reset_email.html'
    success_url = reverse_lazy('core:password_reset_done')

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'auth/password_reset_confirm.html'
    success_url = reverse_lazy('core:password_reset_complete')
```

**Email Verification:**
```python
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode

def send_verification_email(user):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    verification_link = f"http://yourdomain.com/auth/verify/{uid}/{token}/"
    
    send_mail(
        'Verify your email',
        f'Click this link to verify: {verification_link}',
        'noreply@zumodra.com',
        [user.email],
    )
```

---

## 4. Permissions & Access Control

### 4.1 Django Permissions

```python
# Add to User model:
class User(AbstractUser):
    # ... other fields ...
    
    def has_perm_to_edit_payroll(self):
        """Check if user can edit payroll."""
        return self.groups.filter(name='HR_Manager').exists()

# Usage in views:
from django.contrib.auth.decorators import login_required, permission_required

@login_required
@permission_required('users.view_user', raise_exception=True)
def user_detail(request, pk):
    user = User.objects.get(pk=pk)
    return render(request, 'users/detail.html', {'user': user})

# Or with class-based views:
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin

class UserDetailView(LoginRequiredMixin, PermissionRequiredMixin, DetailView):
    model = User
    permission_required = 'users.view_user'
```

### 4.2 Row-Level Access (Multi-tenancy)

```python
class Document(models.Model):
    title = models.CharField(max_length=255)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True)
    
    @classmethod
    def for_user(cls, user):
        """Get documents user can access."""
        if user.is_staff:
            return cls.objects.all()
        
        # Users can see their own docs or their department's docs
        return cls.objects.filter(
            models.Q(owner=user) |
            models.Q(department=user.department)
        )

# In view:
def document_list(request):
    docs = Document.for_user(request.user)
    return render(request, 'documents/list.html', {'documents': docs})
```

---

## 5. Authentication URLs & Templates

**URLs (`apps/auth/urls.py`):**
```python
from django.urls import path
from . import views

app_name = 'auth'

urlpatterns = [
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('signup/', views.SignupView.as_view(), name='signup'),
    path('password-reset/', views.CustomPasswordResetView.as_view(), name='password_reset'),
    path('verify/<uid>/<token>/', views.VerifyEmailView.as_view(), name='verify_email'),
]
```

**Template (`templates/auth/login.html`):**
```html
{% extends "base.html" %}

{% block content %}
<div class="container">
    <h2>Login</h2>
    <form method="post">
        {% csrf_token %}
        {{ form.as_p }}
        <button type="submit">Login</button>
    </form>
</div>
{% endblock %}
```

---

## 6. Testing Authentication

```python
from django.test import TestCase, Client
from django.contrib.auth import get_user_model

User = get_user_model()

class AuthenticationTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email='test@test.com',
            password='pass123'
        )
    
    def test_login(self):
        """Test login functionality."""
        response = self.client.post('/auth/login/', {
            'username': 'test@test.com',
            'password': 'pass123'
        })
        self.assertEqual(response.status_code, 302)  # Redirect on success
        self.assertTrue(response.wsgi_request.user.is_authenticated)
    
    def test_logout(self):
        """Test logout functionality."""
        self.client.login(username='test@test.com', password='pass123')
        response = self.client.get('/auth/logout/')
        self.assertFalse(response.wsgi_request.user.is_authenticated)
    
    def test_signup(self):
        """Test user registration."""
        response = self.client.post('/auth/signup/', {
            'email': 'newuser@test.com',
            'password': 'newpass123',
            'password_confirm': 'newpass123'
        })
        self.assertEqual(User.objects.filter(email='newuser@test.com').count(), 1)
```

---

## 7. Deliverables

By **End of Day 4**, provide:

- [ ] Clean migrations running on fresh database
- [ ] Custom User model (if extending Django's)
- [ ] Login/logout functionality working
- [ ] Signup and email verification implemented
- [ ] Password reset working
- [ ] Permission groups created and assigned
- [ ] Tests for all auth flows
- [ ] Database schema documented
- [ ] Security checklist completed

---

## 8. Security Checklist

- [ ] Passwords hashed (using Django's `set_password()`)
- [ ] CSRF protection enabled on all forms
- [ ] SQL injection prevented (using ORM)
- [ ] XSS protection enabled in templates
- [ ] Session timeout configured
- [ ] Password requirements enforced
- [ ] Account lockout after failed attempts (optional)
- [ ] Two-factor authentication (optional, future)

---

**Document Version:** 1.0  
**Created:** January 16, 2026  
**Owner:** Backend Developer – Database & Auth