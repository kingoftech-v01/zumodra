# Zumodra – Code Standards & Best Practices
## Unified Development Guidelines

**Project:** Zumodra HR/Management SaaS  
**Created:** January 16, 2026  
**Applies To:** All developers

---

## 1. Python/Django Code Standards

### 1.1 File Structure

```
apps/
├── users/
│   ├── __init__.py
│   ├── models.py          # Database models
│   ├── views.py           # Views and viewsets
│   ├── serializers.py     # API serializers
│   ├── urls.py            # URL routing
│   ├── forms.py           # Django forms
│   ├── managers.py        # Custom managers
│   ├── tasks.py           # Celery tasks
│   ├── signals.py         # Django signals
│   ├── permissions.py     # Custom permissions
│   ├── filters.py         # Custom filters
│   ├── migrations/        # Database migrations
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── test_models.py
│   │   ├── test_views.py
│   │   ├── test_api.py
│   │   └── factories.py   # Test factories
│   └── templates/
│       └── users/
│           ├── list.html
│           ├── detail.html
│           └── form.html
```

### 1.2 Naming Conventions

**Classes:**
```python
# ✅ CORRECT - PascalCase
class UserSerializer(serializers.ModelSerializer):
    pass

class CreateUserView(APIView):
    pass

# ❌ WRONG
class user_serializer(serializers.ModelSerializer):
    pass
```

**Functions/Methods:**
```python
# ✅ CORRECT - snake_case
def get_user_by_email(email):
    return User.objects.get(email=email)

def is_user_active(user):
    return user.is_active

# ❌ WRONG
def getUserByEmail(email):
    pass
```

**Constants:**
```python
# ✅ CORRECT - UPPER_CASE
MAX_LOGIN_ATTEMPTS = 5
TIMEOUT_SECONDS = 300
USER_ROLES = ['admin', 'user', 'guest']

# ❌ WRONG
max_login_attempts = 5
```

### 1.3 Django Models

```python
from django.db import models
from django.utils import timezone

class User(models.Model):
    """User model for authentication and profile."""
    
    # Fields
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Metadata
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['is_active', 'created_at']),
        ]
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})"
    
    def get_full_name(self):
        """Return user's full name."""
        return f"{self.first_name} {self.last_name}".strip()
```

**Best Practices:**
- ✅ Always add `created_at` and `updated_at` timestamps
- ✅ Use `auto_now` and `auto_now_add` for timestamps
- ✅ Add database indexes on frequently queried fields
- ✅ Use `default=timezone.now` for date fields (not `auto_now`)
- ✅ Document models with docstrings
- ✅ Use `choices` for limited values
- ✅ Add `Meta.ordering` for list view defaults

### 1.4 Django Views

**Class-Based Views (CBV):**

```python
from django.views.generic import ListView, DetailView, CreateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q

class UserListView(LoginRequiredMixin, ListView):
    """List all users with search and filtering."""
    
    model = User
    paginate_by = 50
    context_object_name = 'users'
    
    def get_queryset(self):
        """Filter users by search query."""
        queryset = User.objects.filter(is_active=True)
        
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                Q(email__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search)
            )
        
        return queryset.order_by('-created_at')
    
    def get_context_data(self, **kwargs):
        """Add extra context."""
        context = super().get_context_data(**kwargs)
        context['search_query'] = self.request.GET.get('search', '')
        return context
```

**Function-Based Views (FBV) for APIs:**

```python
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def user_list(request):
    """List users or create new user."""
    
    if request.method == 'GET':
        users = User.objects.filter(is_active=True)
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
```

### 1.5 Error Handling

```python
# ✅ CORRECT
try:
    user = User.objects.get(email=email)
except User.DoesNotExist:
    return Response({'error': 'User not found'}, status=404)
except Exception as e:
    logger.error(f"Error fetching user: {e}")
    return Response({'error': 'Server error'}, status=500)

# ❌ WRONG
try:
    user = User.objects.get(email=email)
except:  # Catches ALL exceptions
    pass
```

---

## 2. HTML/Template Standards

### 2.1 Template Structure

```html
{% extends "base.html" %}

{% block title %}Page Title - Zumodra{% endblock %}

{% block extra_css %}
    <link rel="stylesheet" href="{% static 'css/custom.css' %}">
{% endblock %}

{% block content %}
<div class="container mt-4">
    <h1>Page Heading</h1>
    
    <!-- Main content here -->
</div>
{% endblock %}

{% block extra_js %}
    <script src="{% static 'js/custom.js' %}"></script>
{% endblock %}
```

### 2.2 Template Best Practices

**HTMX Usage:**
```html
<!-- ✅ CORRECT -->
<button hx-post="{% url 'api:user-create' %}"
        hx-target="#user-list"
        hx-swap="beforeend"
        class="btn btn-primary">
    Add User
</button>

<!-- ❌ WRONG - Hardcoded URL -->
<button hx-post="/api/users/"
        hx-target="#user-list">
    Add User
</button>
```

**Form Rendering:**
```html
<!-- ✅ CORRECT -->
<form method="post" action="{% url 'users:create' %}">
    {% csrf_token %}
    
    {% for field in form %}
        <div class="form-group mb-3">
            <label for="{{ field.id_for_label }}">{{ field.label }}</label>
            {{ field }}
            {% if field.errors %}
                <div class="invalid-feedback d-block">
                    {{ field.errors.0 }}
                </div>
            {% endif %}
        </div>
    {% endfor %}
    
    <button type="submit" class="btn btn-primary">Submit</button>
</form>

<!-- ❌ WRONG - Manual form fields -->
<form>
    <input type="text" name="email">
    <input type="text" name="first_name">
    <!-- Missing CSRF token! -->
</form>
```

---

## 3. CSS/Frontend Standards

### 3.1 CSS Organization

```css
/* Utility classes */
.text-center { text-align: center; }
.mt-4 { margin-top: 1.5rem; }
.d-none { display: none; }

/* Component styles */
.btn {
    padding: 0.5rem 1rem;
    border-radius: 0.25rem;
    cursor: pointer;
    transition: all 0.15s ease-in-out;
}

.btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0,0,0,0.2);
}

.btn.btn-primary {
    background: #007bff;
    color: white;
}

/* Responsive breakpoints */
@media (max-width: 768px) {
    .btn { padding: 0.375rem 0.75rem; }
    .container { padding: 0 1rem; }
}
```

### 3.2 Responsive Design

```html
<!-- Mobile-first approach -->
<div class="container">
    <div class="row">
        <!-- Full width on mobile, half on tablet, 1/3 on desktop -->
        <div class="col-12 col-md-6 col-lg-4">
            <div class="card">
                <h3>Card Title</h3>
                <p>Card content</p>
            </div>
        </div>
    </div>
</div>

<!-- Media query for specific layouts -->
<style>
    @media (max-width: 600px) {
        .sidebar { display: none; }
        .main { width: 100%; }
    }
</style>
```

---

## 4. Testing Standards

### 4.1 Unit Tests

```python
from django.test import TestCase
from apps.users.models import User

class UserModelTestCase(TestCase):
    """Test User model methods."""
    
    def setUp(self):
        """Create test data."""
        self.user = User.objects.create(
            email='test@example.com',
            first_name='John',
            last_name='Doe'
        )
    
    def test_get_full_name(self):
        """Test get_full_name method."""
        self.assertEqual(self.user.get_full_name(), 'John Doe')
    
    def test_user_string_representation(self):
        """Test __str__ method."""
        self.assertEqual(str(self.user), 'John Doe (test@example.com)')
```

### 4.2 Integration Tests

```python
from django.test import Client
from rest_framework.test import APITestCase

class UserAPITestCase(APITestCase):
    """Test User API endpoints."""
    
    def setUp(self):
        """Create test user and authenticate."""
        self.user = User.objects.create_user(
            email='admin@example.com',
            password='testpass123'
        )
        self.client = Client()
        self.client.login(email='admin@example.com', password='testpass123')
    
    def test_list_users(self):
        """Test GET /users/"""
        response = self.client.get('/api/users/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('email', response.data[0])
    
    def test_create_user(self):
        """Test POST /users/"""
        data = {
            'email': 'newuser@example.com',
            'first_name': 'Jane',
            'last_name': 'Smith',
            'password': 'pass123'
        }
        response = self.client.post('/api/users/', data)
        self.assertEqual(response.status_code, 201)
        self.assertTrue(User.objects.filter(email='newuser@example.com').exists())
```

---

## 5. Documentation Standards

### 5.1 Code Comments

```python
# ✅ GOOD - Explains WHY, not WHAT
def calculate_user_score(user):
    """
    Calculate user's activity score.
    
    Higher scores indicate more engagement.
    Used to rank users in admin interface.
    """
    # Double-weight recent activities (last 30 days)
    recent_multiplier = 2 if user.last_activity_date > timezone.now() - timedelta(days=30) else 1
    
    score = (user.login_count * 1) + (user.action_count * recent_multiplier)
    return score

# ❌ BAD - States obvious
def calculate_user_score(user):
    # Multiply login count by 1
    score = user.login_count * 1
    # Add action count
    score += user.action_count
    return score
```

### 5.2 Docstrings

```python
def create_user(email: str, password: str) -> User:
    """
    Create a new user with email and password.
    
    Args:
        email (str): User's email address. Must be unique.
        password (str): User's password. Minimum 8 characters.
    
    Returns:
        User: Created user instance.
    
    Raises:
        ValueError: If email already exists or password too weak.
    
    Example:
        >>> user = create_user('john@example.com', 'password123')
        >>> user.email
        'john@example.com'
    """
    if User.objects.filter(email=email).exists():
        raise ValueError(f"User with email {email} already exists")
    
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    
    user = User.objects.create_user(email=email, password=password)
    return user
```

---

## 6. Security Best Practices

| Issue | Fix |
|-------|-----|
| Hardcoded secrets | Use environment variables: `os.getenv('API_KEY')` |
| SQL injection | Use Django ORM: `User.objects.filter(email=email)` |
| XSS attack | Escape output: `{{ variable\|escape }}` or `{{ variable }}` (auto-escaped) |
| CSRF attack | Include `{% csrf_token %}` in all forms |
| Weak passwords | Enforce minimum 8 chars + complexity in Django settings |
| Unencrypted data | Use HTTPS in production: `SECURE_SSL_REDIRECT = True` |
| Exposed secrets | Never commit `.env` files or config with secrets |

---

## 7. Code Review Checklist

Before submitting a pull request:

- [ ] Code follows naming conventions (PascalCase, snake_case)
- [ ] Functions have docstrings explaining purpose, args, returns
- [ ] Error handling with try/except on external calls
- [ ] Security reviewed (no hardcoded secrets, SQL injection, XSS)
- [ ] Tests pass: `python manage.py test`
- [ ] Code coverage ≥ 70%: `coverage run -m django test && coverage report`
- [ ] No debug print statements or `console.log()`
- [ ] Database queries optimized (uses `select_related` / `prefetch_related`)
- [ ] No N+1 queries (test with Django Debug Toolbar)
- [ ] Frontend code responsive (tested at 320px, 768px, 1200px)
- [ ] Accessibility verified (alt text, labels, color contrast)

---

## 8. Deployment Checklist

Before deploying to production:

- [ ] All tests passing
- [ ] Code review approved
- [ ] Database migrations tested locally
- [ ] Static files collected: `python manage.py collectstatic`
- [ ] Environment variables configured correctly
- [ ] Secrets not in code
- [ ] HTTPS enabled
- [ ] DEBUG = False
- [ ] ALLOWED_HOSTS configured
- [ ] Backups created
- [ ] Rollback plan documented

---

**Document Version:** 1.0  
**Created:** January 16, 2026  
**Applies To:** All Zumodra developers