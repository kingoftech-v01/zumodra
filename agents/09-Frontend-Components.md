# Zumodra Project – Frontend Developer – UI/UX Components & Design
## Comprehensive Onboarding Document

**Project:** Zumodra HR/Management SaaS  
**Deadline:** January 21, 2026  
**Role:** Frontend Developer (UI/UX Components)

---

## 1. Executive Summary

You are responsible for building reusable UI components and ensuring consistent, polished user experience. You work closely with the Templates developer to create forms, tables, modals, cards, and other components that look professional and are accessible.

### Primary Objectives
- **Day 1–2:** Build form components (inputs, validation, error display)
- **Day 3:** Create table, modal, and notification components
- **Day 4:** Design breadcrumbs, pagination, and other utilities
- **Day 5:** Refine all components for polish and accessibility

### Success Criteria
- [ ] Reusable form component with validation styling
- [ ] Table component with responsive design
- [ ] Modal dialogs for confirmations
- [ ] Alert/notification components (success, error, warning)
- [ ] Breadcrumb navigation component
- [ ] All components accessible (WCAG 2.1 AA)
- [ ] Component library documented

---

## 2. Form Components

### 2.1 Base Form Field Component

**File: `templates/components/form_field.html`**

```html
<div class="mb-3">
    <label for="{{ field.id_for_label }}" class="form-label">
        {{ field.label }}
        {% if field.field.required %}
            <span class="text-danger">*</span>
        {% endif %}
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
    {% elif field.field.widget.input_type == "select" %}
        {{ field }}
    {% else %}
        {{ field }}
    {% endif %}
    
    {% if field.errors %}
        <div class="invalid-feedback d-block mt-2">
            {% for error in field.errors %}
                <i class="bi bi-exclamation-circle"></i> {{ error }}
            {% endfor %}
        </div>
    {% endif %}
    
    {% if field.help_text %}
        <small class="form-text text-muted d-block mt-2">
            {{ field.help_text|safe }}
        </small>
    {% endif %}
</div>
```

### 2.2 Custom CSS for Form Fields

**File: `static/css/forms.css`**

```css
/* Form styling */
.form-control, .form-select {
    border-radius: 0.375rem;
    border: 1px solid #dee2e6;
    padding: 0.625rem 0.875rem;
    font-size: 0.9375rem;
    transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
}

.form-control:focus, .form-select:focus {
    border-color: #80bdff;
    box-shadow: 0 0 0 0.2rem rgba(0, 123, 255, 0.25);
}

.form-control.is-invalid, .form-select.is-invalid {
    border-color: #dc3545;
}

.form-control.is-invalid:focus, .form-select.is-invalid:focus {
    border-color: #dc3545;
    box-shadow: 0 0 0 0.2rem rgba(220, 53, 69, 0.25);
}

.invalid-feedback {
    color: #dc3545;
    font-size: 0.875rem;
}

.form-text {
    color: #6c757d;
}

/* Required field indicator */
.form-label .text-danger {
    margin-left: 0.25rem;
}

/* Checkbox and radio styling */
.form-check {
    margin-bottom: 1rem;
}

.form-check-input {
    margin-top: 0.3125rem;
}

.form-check-label {
    margin-left: 0.5rem;
}
```

---

## 3. Table Component

### 3.1 Responsive Table

**File: `templates/components/table.html`**

```html
<div class="table-responsive">
    <table class="table table-hover">
        <thead class="table-light">
            <tr>
                {% for column in columns %}
                    <th scope="col">
                        {% if sort_field == column.field %}
                            <a href="?sort={% if sort_order == 'asc' %}-{% endif %}{{ column.field }}">
                                {{ column.label }}
                                {% if sort_order == 'asc' %}
                                    <i class="bi bi-arrow-up"></i>
                                {% else %}
                                    <i class="bi bi-arrow-down"></i>
                                {% endif %}
                            </a>
                        {% else %}
                            <a href="?sort={{ column.field }}">{{ column.label }}</a>
                        {% endif %}
                    </th>
                {% endfor %}
                <th scope="col">Actions</th>
            </tr>
        </thead>
        <tbody>
            {% for object in objects %}
                <tr>
                    {% for column in columns %}
                        <td>{{ object|get_item:column.field }}</td>
                    {% endfor %}
                    <td>
                        <a href="{% url view_name object.id %}" class="btn btn-sm btn-info">
                            <i class="bi bi-eye"></i> View
                        </a>
                        <a href="{% url edit_name object.id %}" class="btn btn-sm btn-warning">
                            <i class="bi bi-pencil"></i> Edit
                        </a>
                        <a href="{% url delete_name object.id %}" class="btn btn-sm btn-danger"
                           hx-confirm="Are you sure?">
                            <i class="bi bi-trash"></i> Delete
                        </a>
                    </td>
                </tr>
            {% empty %}
                <tr>
                    <td colspan="{{ columns|length|add:1 }}" class="text-center text-muted">
                        No records found.
                    </td>
                </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
```

**Custom Template Filter:**

```python
# apps/core/templatetags/custom_filters.py
from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    """Get item from object using string key."""
    try:
        if '.' in key:  # Handle nested attributes
            parts = key.split('.')
            obj = dictionary
            for part in parts:
                obj = getattr(obj, part)
            return obj
        return getattr(dictionary, key)
    except (AttributeError, KeyError):
        return '-'
```

---

## 4. Modal Component

### 4.1 Reusable Modal

**File: `templates/components/modal.html`**

```html
<div class="modal fade" id="{{ modal_id }}" tabindex="-1" aria-labelledby="{{ modal_id }}Label" aria-hidden="true">
    <div class="modal-dialog {% if modal_size %}modal-{{ modal_size }}{% endif %}">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="{{ modal_id }}Label">{{ modal_title }}</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            
            <div class="modal-body">
                {{ modal_content|safe }}
            </div>
            
            {% if modal_footer %}
                <div class="modal-footer">
                    {{ modal_footer|safe }}
                </div>
            {% else %}
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <button type="button" class="btn btn-primary" id="{{ modal_id }}-submit">Save</button>
                </div>
            {% endif %}
        </div>
    </div>
</div>
```

**Usage:**

```html
{% include "components/modal.html" with 
    modal_id="deleteConfirmModal" 
    modal_title="Delete User" 
    modal_content="Are you sure you want to delete this user? This cannot be undone." 
    modal_footer="<button class='btn btn-danger' hx-delete='/api/users/1/' hx-target='#user-list'>Delete</button>"
%}
```

---

## 5. Alert & Notification Components

### 5.1 Alert Component

**File: `templates/components/alert.html`**

```html
<div class="alert alert-{{ alert_type }} alert-dismissible fade show" role="alert">
    {% if icon %}
        <i class="bi bi-{{ icon }}"></i>
    {% endif %}
    
    <strong>{{ alert_title }}</strong> {{ alert_message }}
    
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
</div>
```

**Usage:**

```html
{% include "components/alert.html" with
    alert_type="success"
    alert_title="Success!"
    alert_message="User created successfully."
    icon="check-circle"
%}

{% include "components/alert.html" with
    alert_type="danger"
    alert_title="Error!"
    alert_message="Something went wrong."
    icon="exclamation-circle"
%}
```

---

## 6. Breadcrumb Component

### 6.1 Breadcrumb Navigation

**File: `templates/components/breadcrumb.html`**

```html
<nav aria-label="breadcrumb">
    <ol class="breadcrumb">
        <li class="breadcrumb-item">
            <a href="{% url 'core:dashboard' %}">
                <i class="bi bi-house"></i> Home
            </a>
        </li>
        
        {% for item in breadcrumbs %}
            {% if forloop.last %}
                <li class="breadcrumb-item active" aria-current="page">
                    {{ item.label }}
                </li>
            {% else %}
                <li class="breadcrumb-item">
                    <a href="{{ item.url }}">{{ item.label }}</a>
                </li>
            {% endif %}
        {% endfor %}
    </ol>
</nav>
```

**Usage in View:**

```python
def user_detail(request, pk):
    user = User.objects.get(pk=pk)
    breadcrumbs = [
        {'label': 'Users', 'url': reverse('users:list')},
        {'label': user.email, 'url': '#'},
    ]
    return render(request, 'users/detail.html', {
        'object': user,
        'breadcrumbs': breadcrumbs,
    })
```

---

## 7. Accessibility Standards

### 7.1 Form Accessibility

- ✅ All inputs have associated `<label>` tags
- ✅ `for` attribute matches input `id`
- ✅ Required fields marked with `*` and aria-required
- ✅ Error messages linked with `aria-describedby`
- ✅ Placeholder text not used as label replacement

### 7.2 Table Accessibility

- ✅ `<thead>` and `<tbody>` properly structured
- ✅ `<th scope="col">` on header cells
- ✅ `<th scope="row">` on row headers if applicable
- ✅ Accessible names for sortable columns

### 7.3 Button & Link Accessibility

- ✅ Buttons have descriptive text
- ✅ Icon buttons have `aria-label`
- ✅ Color alone not used to convey meaning
- ✅ Focus indicators visible (not hidden)

---

## 8. Component Library & Style Guide

### 8.1 Documentation

Create `docs/COMPONENTS.md`:

```markdown
# Zumodra Component Library

## Forms
- Text input
- Textarea
- Select dropdown
- Checkbox group
- Radio group
- Date picker

## Tables
- Basic table
- Sortable table
- Table with actions
- Responsive table

## Modals
- Confirmation dialog
- Form modal
- Info modal

## Alerts
- Success alert
- Error alert
- Warning alert
- Info alert

## Navigation
- Breadcrumbs
- Pagination
- Tabs

## Buttons
- Primary button
- Secondary button
- Danger button
- Disabled state
- Loading state

## Cards
- Basic card
- Card with header/footer
- Card grid layout
```

---

## 9. Deliverables

By **End of Day 4**, provide:

- [ ] Form components (inputs, selects, checkboxes, textareas)
- [ ] Table component (responsive, sortable)
- [ ] Modal component (reusable, configurable)
- [ ] Alert/notification components
- [ ] Breadcrumb component
- [ ] Custom CSS for all components
- [ ] Component library documentation
- [ ] Accessibility audit completed
- [ ] Bootstrap 5 custom theme (if applicable)

---

**Document Version:** 1.0  
**Created:** January 16, 2026  
**Owner:** Frontend Developer – UI/UX Components