# Zumodra Project – Frontend Lead Developer (HTMX)
## Comprehensive Onboarding Document

**Project:** Zumodra HR/Management SaaS  
**Deadline:** January 21, 2026  
**Role:** Frontend Lead Developer (HTMX)

---

## 1. Executive Summary

You are the Frontend Lead. Your role is to establish the frontend architecture using HTML templates enhanced with HTMX for dynamic interactions. The frontend currently has no templates or design alignment. Within 48 hours, you must create a solid base template and define HTMX patterns that other frontend developers follow.

### Primary Objectives
- **Day 1:** Create base template with layout, navigation, and HTMX integration
- **Day 1–2:** Define and document HTMX patterns and best practices
- **Days 3–4:** Support other frontend developers
- **Day 5:** Final Polish and testing

### Success Criteria
- [ ] Base template renders correctly on all pages
- [ ] Navigation works (no 404s)
- [ ] HTMX script integrated and working
- [ ] CSRF protection in place for HTMX requests
- [ ] Frontend architecture documented
- [ ] Example components created

---

## 2. Frontend Architecture

### 2.1 Directory Structure

```
templates/
├── base.html                 # Master template
├── components/
│   ├── navbar.html
│   ├── sidebar.html
│   ├── form_errors.html
│   ├── pagination.html
│   └── modals.html
├── auth/
│   ├── login.html
│   ├── signup.html
│   └── password_reset.html
├── users/
│   ├── list.html
│   ├── detail.html
│   ├── form.html
│   └── partials/
│       ├── user_row.html
│       ├── user_card.html
│       └── user_form.html
├── errors/
│   ├── 404.html
│   ├── 500.html
│   └── base_error.html
└── ...other apps...
```

### 2.2 Base Template (`templates/base.html`)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Zumodra{% endblock %}</title>
    
    <!-- Bootstrap 5 or Tailwind CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- HTMX -->
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    
    <!-- Your custom CSS -->
    <link rel="stylesheet" href="{% static 'css/style.css' %}">
    
    {% block extra_css %}{% endblock %}
</head>
<body>
    {% include "components/navbar.html" %}
    
    <div class="container-fluid">
        <div class="row">
            {% if user.is_authenticated %}
                <nav class="col-md-2 d-md-block bg-light sidebar">
                    {% include "components/sidebar.html" %}
                </nav>
            {% endif %}
            
            <main class="col-md-{% if user.is_authenticated %}10{% else %}12{% endif %}">
                {% if messages %}
                    {% for message in messages %}
                        <div class="alert alert-{{ message.tags }}" role="alert">
                            {{ message }}
                        </div>
                    {% endfor %}
                {% endif %}
                
                {% block content %}{% endblock %}
            </main>
        </div>
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- HTMX Configuration -->
    <script>
        // Set CSRF token for HTMX requests
        htmx.config.inlineScriptNonce = "{{ csrf_token }}";
        
        document.body.addEventListener('htmx:configRequest', function(evt) {
            evt.detail.headers['X-CSRFToken'] = "{{ csrf_token }}";
        });
    </script>
    
    {% block extra_js %}{% endblock %}
</body>
</html>
```

### 2.3 HTMX Patterns

**Pattern 1: Load Content on Click**
```html
<!-- Button that loads partial -->
<button class="btn btn-primary" hx-get="{% url 'users:detail' user.id %}" 
        hx-target="#content" hx-swap="innerHTML">
    View Details
</button>

<!-- Container for loaded content -->
<div id="content"></div>
```

**Pattern 2: Form Submission**
```html
<!-- Form that submits via HTMX -->
<form hx-post="{% url 'users:create' %}" 
      hx-target="#user-list" 
      hx-swap="beforeend">
    {% csrf_token %}
    {% for field in form %}
        <div class="mb-3">
            {{ field.label_tag }}
            {{ field }}
            {% if field.errors %}
                <div class="invalid-feedback">{{ field.errors }}</div>
            {% endif %}
        </div>
    {% endfor %}
    <button type="submit" class="btn btn-success">Create</button>
</form>
```

**Pattern 3: Live Search/Filter**
```html
<!-- Search input with debounce -->
<input type="text" placeholder="Search users..." 
       hx-get="{% url 'users:search' %}" 
       hx-target="#results" 
       hx-trigger="keyup changed delay:500ms" 
       hx-swap="innerHTML">

<div id="results"></div>
```

**Pattern 4: Pagination**
```html
<div hx-target="this" hx-swap="outerHTML">
    <a class="page-link" hx-get="?page=1">First</a>
    <a class="page-link" hx-get="?page={{ page_obj.previous_page_number }}">Previous</a>
    <span class="page-current">Page {{ page_obj.number }}</span>
    <a class="page-link" hx-get="?page={{ page_obj.next_page_number }}">Next</a>
</div>
```

### 2.4 CSRF Token Handling

Django automatically includes CSRF tokens in `POST` requests. For HTMX:

```html
<!-- Method 1: Include token in form -->
<form hx-post="...">
    {% csrf_token %}
    ...
</form>

<!-- Method 2: Set in JavaScript (already done in base.html) -->
<script>
    document.body.addEventListener('htmx:configRequest', function(evt) {
        evt.detail.headers['X-CSRFToken'] = document.querySelector('[name=csrfmiddlewaretoken]').value;
    });
</script>
```

---

## 3. Creating Reusable Components

### 3.1 Form Component (`templates/components/form.html`)

```html
{% if form.non_field_errors %}
    <div class="alert alert-danger">
        {% for error in form.non_field_errors %}
            <p>{{ error }}</p>
        {% endfor %}
    </div>
{% endif %}

{% for field in form %}
    <div class="mb-3">
        {{ field.label_tag }}
        {% if field.field.widget.input_type == "checkbox" %}
            <div class="form-check">
                {{ field }}
                <label class="form-check-label">{{ field.label }}</label>
            </div>
        {% else %}
            {{ field }}
        {% endif %}
        {% if field.errors %}
            <div class="invalid-feedback d-block">
                {{ field.errors.0 }}
            </div>
        {% endif %}
        {% if field.help_text %}
            <small class="form-text text-muted">{{ field.help_text|safe }}</small>
        {% endif %}
    </div>
{% endfor %}
```

### 3.2 Pagination Component (`templates/components/pagination.html`)

```html
{% if is_paginated %}
    <nav aria-label="Page navigation">
        <ul class="pagination justify-content-center">
            {% if page_obj.has_previous %}
                <li class="page-item">
                    <a class="page-link" hx-get="?page=1">First</a>
                </li>
                <li class="page-item">
                    <a class="page-link" hx-get="?page={{ page_obj.previous_page_number }}">Previous</a>
                </li>
            {% endif %}
            
            <li class="page-item active"><span class="page-link">{{ page_obj.number }}</span></li>
            
            {% if page_obj.has_next %}
                <li class="page-item">
                    <a class="page-link" hx-get="?page={{ page_obj.next_page_number }}">Next</a>
                </li>
                <li class="page-item">
                    <a class="page-link" hx-get="?page={{ page_obj.paginator.num_pages }}">Last</a>
                </li>
            {% endif %}
        </ul>
    </nav>
{% endif %}
```

---

## 4. View Patterns

### 4.1 Template Tags for HTMX

```python
# apps/core/templatetags/htmx_tags.py
from django import template

register = template.Library()

@register.simple_tag
def hx_url(view_name, *args, **kwargs):
    """Generate URL for HTMX request."""
    from django.urls import reverse
    return reverse(view_name, args=args, kwargs=kwargs)
```

Usage: `{% hx_url 'users:detail' user.id %}`

### 4.2 Partial Response Views

```python
def user_detail_modal(request, pk):
    """Return just the modal body (partial)."""
    user = get_object_or_404(User, pk=pk)
    return render(request, 'users/partials/detail_modal.html', {'user': user})

def user_list_page(request):
    """Return paginated list (can be swapped into DOM)."""
    users = User.objects.all()
    paginator = Paginator(users, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'users/partials/list.html', {'page_obj': page_obj})
```

---

## 5. Testing Frontend

```python
from django.test import TestCase, Client

class FrontendTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(email='test@test.com', password='pass')
        self.client.login(username='test@test.com', password='pass')
    
    def test_base_template_renders(self):
        response = self.client.get('/dashboard/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<nav')  # Navigation present
        self.assertContains(response, 'href="{% url')  # Links work
    
    def test_htmx_request(self):
        response = self.client.get(
            '/api/users/1/',
            HTTP_HX_REQUEST='true'  # Simulate HTMX request
        )
        self.assertEqual(response.status_code, 200)
```

---

## 6. Deliverables

By **End of Day 2**, provide:

- [ ] Base template fully functional
- [ ] Navigation and sidebar working
- [ ] HTMX integrated and tested
- [ ] CSRF protection enabled for HTMX
- [ ] Frontend architecture documented (`docs/FRONTEND.md`)
- [ ] 5+ reusable components created
- [ ] Example HTMX patterns demonstrated
- [ ] Error pages (404, 500) styled

---

## 7. Quick Reference

**HTMX Attributes:**
- `hx-get` – GET request
- `hx-post` – POST request
- `hx-put` – PUT request
- `hx-delete` – DELETE request
- `hx-target` – Where to insert response
- `hx-swap` – How to swap (innerHTML, outerHTML, beforeend, etc.)
- `hx-trigger` – When to trigger (change, click, keyup, etc.)
- `hx-confirm` – Confirmation before request

**Common Patterns:**
```
Load on click: hx-get="..." hx-target="#result"
Form submit: hx-post="..." hx-target="#list" hx-swap="beforeend"
Live search: hx-get="..." hx-trigger="keyup changed delay:500ms"
Confirmation: hx-confirm="Are you sure?"
```

---

**Document Version:** 1.0  
**Created:** January 16, 2026  
**Owner:** Frontend Lead Developer