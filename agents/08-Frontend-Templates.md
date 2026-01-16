# Zumodra Project – Frontend Developer – Templates Implementation
## Comprehensive Onboarding Document

**Project:** Zumodra HR/Management SaaS  
**Deadline:** January 21, 2026  
**Role:** Frontend Developer (Templates)  
**Reports To:** Frontend Lead Developer

---

## 1. Executive Summary

You are responsible for building all HTML page templates. The frontend currently has no templates or design files. Your goal is to create every page the app needs using Django's template language, ensuring they load without errors and are responsive on all devices.

### Primary Objectives
- **Day 1–2:** Audit all required pages, create template structure
- **Day 3:** Build all core templates (list, detail, create, edit views)
- **Day 4:** Implement remaining pages and test for errors
- **Day 5:** Fix any TemplateDoesNotExist errors, optimize for speed

### Success Criteria
- [ ] All app pages have corresponding templates
- [ ] Zero TemplateDoesNotExist 404 errors
- [ ] All templates inherit from base.html
- [ ] Forms use Django's form rendering
- [ ] URLs use `{% url %}` tags (no hardcoded paths)
- [ ] All pages responsive (mobile/tablet/desktop)

---

## 2. Template Inventory & Structure

### 2.1 Required Pages Audit

Create a spreadsheet of all needed pages:

| App | Page Type | Template Path | View Class | Priority |
|-----|-----------|---------------|-----------|----------|
| auth | Login | `templates/auth/login.html` | LoginView | Critical |
| auth | Signup | `templates/auth/signup.html` | SignupView | Critical |
| auth | Password Reset | `templates/auth/password_reset.html` | PasswordResetView | High |
| users | List | `templates/users/list.html` | UserListView | Critical |
| users | Detail | `templates/users/detail.html` | UserDetailView | Critical |
| users | Create | `templates/users/form.html` | UserCreateView | Critical |
| users | Edit | `templates/users/form.html` | UserUpdateView | Critical |
| users | Delete | `templates/users/confirm_delete.html` | UserDeleteView | High |
| dashboard | Dashboard | `templates/core/dashboard.html` | DashboardView | Critical |
| [other apps] | [pages] | [paths] | [views] | [priority] |

### 2.2 Template Directory Structure

```
templates/
├── base.html                    # Master template (from Frontend Lead)
├── components/
│   ├── navbar.html             # Navigation bar
│   ├── sidebar.html            # Sidebar menu
│   ├── form_errors.html        # Form error display
│   ├── pagination.html         # Pagination component
│   └── alerts.html             # Alert/message component
├── auth/
│   ├── login.html              # Login form page
│   ├── signup.html             # Registration form
│   └── password_reset.html     # Password reset form
├── users/
│   ├── list.html               # Users list page
│   ├── detail.html             # Single user detail
│   ├── form.html               # Create/Edit form (reused)
│   ├── confirm_delete.html     # Delete confirmation
│   └── partials/
│       ├── user_row.html       # Table row for HTMX swap
│       ├── user_card.html      # Card view for HTMX swap
│       └── user_form.html      # Form partial
├── core/
│   ├── dashboard.html          # Main dashboard
│   └── index.html              # Landing page
├── errors/
│   ├── 404.html                # Page not found
│   └── 500.html                # Server error
└── [other_apps]/
    └── [pages].html
```

---

## 3. Template Best Practices

### 3.1 Base Template Inheritance

Every template should start with:

```html
{% extends "base.html" %}

{% block title %}Page Title - Zumodra{% endblock %}

{% block extra_css %}
    {# Optional extra CSS for this page #}
{% endblock %}

{% block content %}
    <div class="container">
        <h1>Page Heading</h1>
        
        {# Your content here #}
    </div>
{% endblock %}

{% block extra_js %}
    {# Optional extra JS for this page #}
{% endblock %}
```

### 3.2 Using Django Template Language

**Conditionals:**
```html
{% if user.is_authenticated %}
    <p>Welcome, {{ user.first_name }}!</p>
{% else %}
    <p><a href="{% url 'auth:login' %}">Login</a></p>
{% endif %}
```

**Loops:**
```html
<ul>
    {% for item in items %}
        <li>{{ item.name }} - {{ item.created_at|date:"SHORT_DATE_FORMAT" }}</li>
    {% empty %}
        <li>No items found.</li>
    {% endfor %}
</ul>
```

**Filters:**
```html
{{ object.created_at|date:"Y-m-d H:i" }}
{{ object.description|truncatewords:50 }}
{{ object.price|floatformat:2 }}
```

**URL Reversal (Never hardcode URLs):**
```html
<!-- ✅ CORRECT - Uses URL names -->
<a href="{% url 'users:list' %}">Users</a>
<a href="{% url 'users:detail' user.id %}">View User</a>
<a href="{% url 'users:edit' object.id %}">Edit</a>

<!-- ❌ WRONG - Hardcoded paths -->
<a href="/users/">Users</a>
<a href="/users/{{ user.id }}/">View User</a>
```

### 3.3 Forms with Django Form Rendering

```html
<form method="post" action="{% url 'users:create' %}">
    {% csrf_token %}
    
    {% if form.non_field_errors %}
        <div class="alert alert-danger">
            {{ form.non_field_errors }}
        </div>
    {% endif %}
    
    {% for field in form %}
        <div class="form-group mb-3">
            {{ field.label_tag }}
            {{ field }}
            
            {% if field.errors %}
                <div class="invalid-feedback d-block">
                    {{ field.errors.0 }}
                </div>
            {% endif %}
            
            {% if field.help_text %}
                <small class="form-text text-muted">
                    {{ field.help_text|safe }}
                </small>
            {% endif %}
        </div>
    {% endfor %}
    
    <button type="submit" class="btn btn-primary">Submit</button>
    <a href="{% url 'users:list' %}" class="btn btn-secondary">Cancel</a>
</form>
```

---

## 4. Common Page Templates

### 4.1 List Page Example

**Template: `templates/users/list.html`**

```html
{% extends "base.html" %}

{% block title %}Users - Zumodra{% endblock %}

{% block content %}
<div class="container mt-4">
    <div class="row mb-4">
        <div class="col-md-6">
            <h1>Users</h1>
        </div>
        <div class="col-md-6 text-end">
            <a href="{% url 'users:create' %}" class="btn btn-primary">
                + Add User
            </a>
        </div>
    </div>
    
    <!-- Search form with HTMX -->
    <form method="get" class="mb-4">
        <div class="input-group">
            <input type="text" name="search" class="form-control" 
                   placeholder="Search users..."
                   hx-get="{% url 'users:search' %}"
                   hx-target="#user-list"
                   hx-trigger="keyup changed delay:500ms">
            <button class="btn btn-outline-secondary" type="submit">Search</button>
        </div>
    </form>
    
    <!-- User list (will be replaced by HTMX) -->
    <div id="user-list">
        {% if page_obj %}
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>Name</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in page_obj %}
                        <tr>
                            <td>{{ user.email }}</td>
                            <td>{{ user.first_name }} {{ user.last_name }}</td>
                            <td>
                                {% if user.is_active %}
                                    <span class="badge bg-success">Active</span>
                                {% else %}
                                    <span class="badge bg-danger">Inactive</span>
                                {% endif %}
                            </td>
                            <td>
                                <a href="{% url 'users:detail' user.id %}" 
                                   class="btn btn-sm btn-info">View</a>
                                <a href="{% url 'users:edit' user.id %}" 
                                   class="btn btn-sm btn-warning">Edit</a>
                                <a href="{% url 'users:delete' user.id %}" 
                                   class="btn btn-sm btn-danger"
                                   hx-confirm="Delete this user?">Delete</a>
                            </td>
                        </tr>
                    {% endfor %}
                </tbody>
            </table>
            
            <!-- Pagination -->
            {% include "components/pagination.html" %}
        {% else %}
            <div class="alert alert-info">
                No users found. <a href="{% url 'users:create' %}">Create one</a>
            </div>
        {% endif %}
    </div>
</div>
{% endblock %}
```

### 4.2 Detail Page Example

**Template: `templates/users/detail.html`**

```html
{% extends "base.html" %}

{% block title %}{{ object.first_name }} {{ object.last_name }} - Zumodra{% endblock %}

{% block content %}
<div class="container mt-4">
    <div class="row mb-4">
        <div class="col-md-8">
            <h1>{{ object.first_name }} {{ object.last_name }}</h1>
        </div>
        <div class="col-md-4 text-end">
            <a href="{% url 'users:edit' object.id %}" class="btn btn-warning">Edit</a>
            <a href="{% url 'users:delete' object.id %}" class="btn btn-danger"
               hx-confirm="Delete this user?">Delete</a>
        </div>
    </div>
    
    <div class="card">
        <div class="card-body">
            <p><strong>Email:</strong> {{ object.email }}</p>
            <p><strong>Name:</strong> {{ object.first_name }} {{ object.last_name }}</p>
            <p><strong>Status:</strong>
                {% if object.is_active %}
                    <span class="badge bg-success">Active</span>
                {% else %}
                    <span class="badge bg-danger">Inactive</span>
                {% endif %}
            </p>
            <p><strong>Created:</strong> {{ object.created_at|date:"Y-m-d H:i" }}</p>
            <p><strong>Last Updated:</strong> {{ object.updated_at|date:"Y-m-d H:i" }}</p>
        </div>
    </div>
    
    <a href="{% url 'users:list' %}" class="btn btn-secondary mt-4">Back to List</a>
</div>
{% endblock %}
```

### 4.3 Form Page Example

**Template: `templates/users/form.html`**

```html
{% extends "base.html" %}

{% block title %}
    {% if form.instance.pk %}
        Edit User - Zumodra
    {% else %}
        Create User - Zumodra
    {% endif %}
{% endblock %}

{% block content %}
<div class="container mt-4">
    <div class="row">
        <div class="col-md-6 offset-md-3">
            <h1>
                {% if form.instance.pk %}
                    Edit User
                {% else %}
                    Create New User
                {% endif %}
            </h1>
            
            <form method="post" class="mt-4">
                {% csrf_token %}
                
                {% if form.non_field_errors %}
                    <div class="alert alert-danger">
                        {% for error in form.non_field_errors %}
                            <p>{{ error }}</p>
                        {% endfor %}
                    </div>
                {% endif %}
                
                {% for field in form %}
                    <div class="mb-3">
                        <label for="{{ field.id_for_label }}" class="form-label">
                            {{ field.label }}
                        </label>
                        
                        {% if field.field.widget.input_type == "checkbox" %}
                            <div class="form-check">
                                {{ field }}
                                <label class="form-check-label" for="{{ field.id_for_label }}">
                                    {{ field.label }}
                                </label>
                            </div>
                        {% elif field.field.widget.input_type == "textarea" %}
                            {{ field }}
                        {% else %}
                            {{ field }}
                        {% endif %}
                        
                        {% if field.errors %}
                            <div class="invalid-feedback d-block">
                                {% for error in field.errors %}
                                    <p>{{ error }}</p>
                                {% endfor %}
                            </div>
                        {% endif %}
                        
                        {% if field.help_text %}
                            <small class="form-text text-muted d-block mt-2">
                                {{ field.help_text|safe }}
                            </small>
                        {% endif %}
                    </div>
                {% endfor %}
                
                <div class="d-flex gap-2">
                    <button type="submit" class="btn btn-primary">
                        {% if form.instance.pk %}Save Changes{% else %}Create User{% endif %}
                    </button>
                    <a href="{% url 'users:list' %}" class="btn btn-secondary">Cancel</a>
                </div>
            </form>
        </div>
    </div>
</div>
{% endblock %}
```

---

## 5. Testing Templates

### 5.1 Manual Testing Checklist

For each template, verify:

```html
<!-- Template Test Checklist -->
☐ Page loads without TemplateDoesNotExist error
☐ All variables render correctly ({{ object.field }})
☐ All links use {% url %} tags (no /hardcoded/paths/)
☐ Forms have {% csrf_token %}
☐ Forms render without errors
☐ Pagination links work
☐ Responsive design on mobile (375px)
☐ Responsive design on tablet (768px)
☐ Responsive design on desktop (1200px)
☐ HTMX attributes work (hx-get, hx-post, etc.)
☐ No JavaScript console errors
☐ Accessibility: Can tab through form fields
☐ Accessibility: Form labels present for all inputs
```

### 5.2 Testing Command

```bash
# Start dev server
python manage.py runserver

# Test each page in browser
# Watch for TemplateDoesNotExist in console
# Check responsive design with DevTools (F12)
```

---

## 6. Deliverables

By **End of Day 4**, provide:

- [ ] All required templates created
- [ ] Zero TemplateDoesNotExist errors
- [ ] All templates inherit from base.html
- [ ] No hardcoded URLs (all use `{% url %}`)
- [ ] All forms include {% csrf_token %}
- [ ] Responsive design verified on all devices
- [ ] 404 and 500 error pages implemented
- [ ] Template inventory spreadsheet completed

---

## 7. Quick Reference

**Common Template Tags:**
```django
{% extends "base.html" %}           - Inherit from parent
{% block name %}...{% endblock %}   - Define content area
{% for item in items %}...{% endfor %} - Loop
{% if condition %}...{% endif %}    - Conditional
{{ object.field }}                  - Display variable
{{ object.field|date:"Y-m-d" }}     - Apply filter
{% url 'app:name' object.id %}      - Generate URL
{% csrf_token %}                    - CSRF protection
```

---

**Document Version:** 1.0  
**Created:** January 16, 2026  
**Owner:** Frontend Developer – Templates