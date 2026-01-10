# UI Components Documentation

## Overview

This document describes all reusable UI components for the tenant type system and verification features.

All components are located in `templates/components/` and built with:
- **Tailwind CSS** for styling
- **HTMX** for dynamic interactions
- **Alpine.js** for client-side state (when needed)
- **Dark mode** support

## Component Catalog

### 1. Tenant Type Switcher
**File:** `templates/components/tenant_type_switcher.html`

Allows users to switch between Company and Freelancer tenant types.

**Usage:**
```django
{% include 'components/tenant_type_switcher.html' with tenant=request.tenant %}
```

**Features:**
- Displays current tenant type with badge
- "Switch to Freelancer" button (only if ≤1 member)
- "Switch to Company" button (always available for freelancers)
- Help text explaining limitations
- HTMX-powered switching

**Visual Design:**
- Company badge: Blue color scheme
- Freelancer badge: Green color scheme
- Disabled state when switch not allowed
- Tooltips for additional info

**Example:**
```html
<div class="tenant-type-switcher card">
  <h3>Organization Type</h3>
  <span class="badge badge-company">
    <i class="fas fa-building"></i> Company
  </span>
  <button hx-post="/api/tenants/switch_type/" ...>
    Switch to Freelancer
  </button>
</div>
```

---

### 2. Verification Badges
**File:** `templates/components/verification_badges.html`

Displays verification status badges for users and tenants.

**Usage:**
```django
{# User verification badges #}
{% include 'components/verification_badges.html' with user_obj=user %}

{# Tenant verification badges #}
{% include 'components/verification_badges.html' with tenant_obj=tenant %}
```

**Features:**
- **User badges**: CV Verified, KYC Verified
- **Tenant badges**: Business Verified (EIN)
- Color-coded status (green=verified, gray=pending)
- Tooltips showing verification date
- SVG icons for each type

**Visual Design:**
```
✓ CV Verified     (Green badge)
⏳ CV Pending     (Gray badge)
✓ KYC Verified    (Green badge)
⏳ Business Pending (Gray badge)
```

**Example:**
```html
<div class="verification-badges">
  <span class="badge badge-success" title="CV verified on 2026-01-09">
    <i class="fas fa-file-alt"></i> CV Verified
  </span>
  <span class="badge badge-secondary" title="KYC not verified">
    <i class="fas fa-id-card"></i> KYC Pending
  </span>
</div>
```

---

### 3. Hiring Context Selector
**File:** `templates/components/hiring_context_selector.html`

Radio button group for selecting hiring context (organizational vs personal).

**Usage:**
```django
{% include 'components/hiring_context_selector.html' with hiring_context='organizational' %}
```

**Features:**
- Two options: "For my organization" and "For myself"
- Visual icons (building vs user)
- Help text explaining each option
- Conditional display (hides "For organization" if user has no tenant)
- Pre-selected based on context

**Visual Design:**
- Radio buttons with custom styling
- Blue color for organizational
- Green color for personal
- Info box when user has no organization

**Example:**
```html
<div class="hiring-context-selector">
  <label>Who is hiring this service?</label>

  <label class="radio-label">
    <input type="radio" name="hiring_context" value="organizational">
    <div class="radio-content">
      <strong><i class="fas fa-building"></i> For my organization</strong>
      <p>Hire on behalf of Acme Corp</p>
    </div>
  </label>

  <label class="radio-label">
    <input type="radio" name="hiring_context" value="personal">
    <div class="radio-content">
      <strong><i class="fas fa-user"></i> For myself</strong>
      <p>Personal service request</p>
    </div>
  </label>
</div>
```

---

### 4. EIN Verification Form
**File:** `templates/components/ein_verification_form.html`

Form for submitting business EIN number for verification.

**Usage:**
```django
{% include 'components/ein_verification_form.html' with tenant=request.tenant %}
```

**Features:**
- Input field with pattern validation
- Format hint: XX-XXXXXXX
- Shows verified state with timestamp
- "Why verify?" section with benefits list
- HTMX-powered submission
- Real-time format validation

**Visual Design:**
- Card layout with header
- Success alert when verified
- Input with placeholder and help text
- Submit button with shield icon

**Example:**
```html
<div class="ein-verification-form card">
  <h3>Business Verification</h3>

  <!-- If verified -->
  <div class="alert alert-success">
    <i class="fas fa-check-circle"></i> Business verified - 2026-01-09
  </div>

  <!-- If not verified -->
  <form hx-post="/api/tenants/verify/ein/">
    <input type="text"
           name="ein_number"
           pattern="\d{2}-\d{7}"
           placeholder="12-3456789"
           required>
    <button type="submit">
      <i class="fas fa-shield-alt"></i> Verify Business
    </button>
  </form>
</div>
```

---

### 5. CV Verification
**File:** `templates/components/cv_verification.html`

CV file upload component with verification status.

**Usage:**
```django
{% include 'components/cv_verification.html' with user=request.user %}
```

**Features:**
- Drag-and-drop file upload interface
- Accepts PDF, DOC, DOCX (max 5MB)
- Shows current verification status
- File type and size validation
- Upload progress indicator (HTMX)
- "What happens after upload" section

**Visual Design:**
- Card with drop zone
- File type icons
- Success alert when verified
- Help text with supported formats

**Example:**
```html
<div class="cv-verification-component card">
  <h3>CV Verification</h3>

  <!-- If verified -->
  <div class="alert alert-success">
    <i class="fas fa-check-circle"></i> CV verified - 2026-01-09
  </div>

  <!-- If not verified -->
  <form hx-post="/api/accounts/verify/cv/" hx-encoding="multipart/form-data">
    <div class="file-upload-zone">
      <input type="file" accept=".pdf,.doc,.docx" required>
      <p>Drop CV here or click to browse</p>
      <small>PDF, DOC, DOCX (max 5MB)</small>
    </div>
    <button type="submit">
      <i class="fas fa-upload"></i> Upload for Verification
    </button>
  </form>
</div>
```

---

### 6. Company Profile Card
**File:** `templates/components/company_profile_card.html`

Summary card showing company tenant profile information.

**Usage:**
```django
{% include 'components/company_profile_card.html' with tenant=request.tenant services_count=10 jobs_count=5 %}
```

**Required Context:**
- `tenant`: Tenant object
- `services_count`: Number of services
- `jobs_count`: Number of active jobs

**Features:**
- Stats grid: members, services, jobs
- Industry and company size display
- Capabilities list (4 features)
- Gradient header with logo
- "Switch to Freelancer" button (if eligible)
- Verification badges

**Visual Design:**
- Blue gradient header
- Three-column stats layout
- Icon-based capabilities list
- Professional business look

**Example:**
```html
<div class="company-profile-card card">
  <div class="card-header gradient-blue">
    <h3>
      <i class="fas fa-building"></i> Acme Corp
      <span class="badge badge-company">Company</span>
    </h3>
    <!-- Verification badges -->
  </div>

  <div class="stats-grid">
    <div class="stat">
      <span class="stat-value">25</span>
      <span class="stat-label">Members</span>
    </div>
    <div class="stat">
      <span class="stat-value">10</span>
      <span class="stat-label">Services</span>
    </div>
    <div class="stat">
      <span class="stat-value">5</span>
      <span class="stat-label">Active Jobs</span>
    </div>
  </div>
</div>
```

---

### 7. Freelancer Profile Card
**File:** `templates/components/freelancer_profile_card.html`

Summary card showing freelancer tenant profile.

**Usage:**
```django
{% include 'components/freelancer_profile_card.html' with tenant=request.tenant services_count=8 %}
```

**Required Context:**
- `tenant`: Tenant object
- `services_count`: Number of services

**Features:**
- Stats: solo indicator, services count
- "What you can do" list (4 items)
- "Not available" limitations list (3 items)
- "Upgrade to Company" button
- Verification badges

**Visual Design:**
- Green color scheme (vs blue for companies)
- Solo/independent branding
- Clear limitation indicators
- Call-to-action for upgrading

**Example:**
```html
<div class="freelancer-profile-card card">
  <div class="card-header gradient-green">
    <h3>
      <i class="fas fa-user"></i> John Doe
      <span class="badge badge-freelancer">Freelancer</span>
    </h3>
  </div>

  <div class="stats-grid">
    <div class="stat">
      <span class="stat-value">1</span>
      <span class="stat-label">Solo</span>
    </div>
    <div class="stat">
      <span class="stat-value">8</span>
      <span class="stat-label">Services</span>
    </div>
  </div>

  <div class="info-box">
    As a freelancer, you provide services but cannot create jobs or hire employees.
  </div>

  <button hx-post="/api/tenants/switch_type/">
    <i class="fas fa-exchange-alt"></i> Switch to Company
  </button>
</div>
```

---

### 8. Hiring Context Badge
**File:** `templates/components/hiring_context_badge.html`

Small badge displaying hiring context (organizational vs personal).

**Usage:**
```django
{% include 'components/hiring_context_badge.html' with hiring_context='organizational' %}
```

**Features:**
- Color-coded badges (blue=org, green=personal)
- Icons for visual distinction
- Tooltips with explanation
- Compact size for inline use

**Visual Design:**
- Inline badge (small size)
- SVG icons
- Rounded corners
- Dark mode support

**Example:**
```html
<!-- Organizational -->
<span class="hiring-context-badge badge-primary" title="Hired on behalf of organization">
  <i class="fas fa-building"></i> Organizational
</span>

<!-- Personal -->
<span class="hiring-context-badge badge-success" title="Personal service request">
  <i class="fas fa-user"></i> Personal
</span>
```

---

## Integration Guide

### Adding Components to Pages

**Step 1: Include in Template**
```django
{% load static i18n %}

{# Include component #}
{% include 'components/tenant_type_switcher.html' with tenant=request.tenant %}
```

**Step 2: Pass Required Context**
```python
# views.py
def tenant_settings(request):
    context = {
        'tenant': request.tenant,
        'services_count': request.tenant.services.count(),
        'jobs_count': request.tenant.jobs.filter(status='published').count(),
    }
    return render(request, 'tenants/settings.html', context)
```

**Step 3: Handle HTMX Responses**
```python
# views.py
@api_view(['POST'])
def switch_tenant_type(request):
    # ... switch logic ...

    if request.headers.get('HX-Request'):
        # HTMX request - return partial
        return render(request, 'components/tenant_type_switcher.html', {
            'tenant': request.tenant
        })
    else:
        # Regular request - return JSON
        return Response({...})
```

### Styling Customization

All components use Tailwind CSS utility classes. To customize:

**1. Modify Tailwind Config:**
```javascript
// tailwind.config.js
module.exports = {
  theme: {
    extend: {
      colors: {
        'company': {
          50: '#eff6ff',
          500: '#3b82f6',
          900: '#1e3a8a',
        },
        'freelancer': {
          50: '#f0fdf4',
          500: '#22c55e',
          900: '#14532d',
        }
      }
    }
  }
}
```

**2. Override Component Styles:**
```html
<!-- Custom wrapper with modified classes -->
<div class="my-custom-wrapper">
  {% include 'components/verification_badges.html' %}
</div>

<style>
  .my-custom-wrapper .badge {
    /* Custom badge styles */
  }
</style>
```

### JavaScript Integration

Components support Alpine.js for client-side state:

```html
<div x-data="{ verified: {{ user.cv_verified|yesno:'true,false' }} }">
  {% include 'components/cv_verification.html' %}

  <template x-if="verified">
    <div>Your CV is verified!</div>
  </template>
</div>
```

### HTMX Event Handling

Listen to HTMX events for dynamic updates:

```html
<div hx-on::after-request="refreshBadges()">
  {% include 'components/verification_badges.html' %}
</div>

<script>
function refreshBadges() {
  // Reload badges after verification
  htmx.trigger('#badges-container', 'htmx:refresh');
}
</script>
```

## Best Practices

### 1. Always Pass Required Context
```django
{# ❌ Bad - missing required context #}
{% include 'components/company_profile_card.html' %}

{# ✅ Good - all required context provided #}
{% include 'components/company_profile_card.html'
   with tenant=request.tenant
        services_count=services.count
        jobs_count=jobs.count %}
```

### 2. Check Permissions Before Rendering
```django
{% if request.tenant.tenant_type == 'company' %}
  {% include 'components/company_profile_card.html' %}
{% else %}
  {% include 'components/freelancer_profile_card.html' %}
{% endif %}
```

### 3. Use Defensive Checks
```django
{% if tenant and tenant.tenant_type %}
  {% include 'components/tenant_type_switcher.html' %}
{% endif %}
```

### 4. Leverage HTMX for Dynamic Updates
```django
<div hx-get="/api/tenants/profile/"
     hx-trigger="load"
     hx-swap="innerHTML">
  {# Component loaded via HTMX #}
</div>
```

## Testing Components

### Visual Testing

1. **Light Mode**: Verify all components render correctly
2. **Dark Mode**: Toggle dark mode and verify colors
3. **Responsive**: Test on mobile, tablet, desktop
4. **Browser Testing**: Chrome, Firefox, Safari, Edge

### Functional Testing

```python
# tests/test_components.py
def test_tenant_type_switcher_renders(client, company_tenant):
    """Test tenant type switcher component renders."""
    response = client.get('/settings/')
    assert 'tenant-type-switcher' in response.content.decode()
    assert company_tenant.name in response.content.decode()

def test_verification_badges_show_status(client, verified_user):
    """Test verification badges display correctly."""
    response = client.get('/profile/')
    assert 'CV Verified' in response.content.decode()
    assert 'badge-success' in response.content.decode()
```

## Accessibility

All components follow WCAG 2.1 AA guidelines:

- ✅ Semantic HTML elements
- ✅ ARIA labels where needed
- ✅ Keyboard navigation support
- ✅ Screen reader friendly
- ✅ Sufficient color contrast (4.5:1)
- ✅ Focus indicators
- ✅ Alternative text for icons

**Example:**
```html
<button aria-label="Switch to freelancer tenant"
        title="Convert your company to a freelancer account">
  <i class="fas fa-exchange-alt" aria-hidden="true"></i>
  Switch to Freelancer
</button>
```

## Performance

### Optimization Tips

1. **Lazy Load Components:**
```html
<div hx-get="/components/profile/"
     hx-trigger="revealed">
  {# Loaded when scrolled into view #}
</div>
```

2. **Cache Context Data:**
```python
@cached_property
def services_count(self):
    return self.services.count()
```

3. **Use Template Fragments:**
```django
{% load cache %}
{% cache 600 "verification_badges" user.id %}
  {% include 'components/verification_badges.html' %}
{% endcache %}
```

## Troubleshooting

### Component Not Rendering

**Issue:** Component appears blank or broken

**Solutions:**
- Check required context variables are passed
- Verify template path is correct
- Check for JavaScript console errors
- Ensure Tailwind CSS is compiled

### HTMX Not Working

**Issue:** HTMX interactions not triggering

**Solutions:**
- Verify HTMX library is loaded
- Check `hx-*` attributes are correct
- Inspect network tab for AJAX requests
- Ensure CSRF token is present

### Styles Not Applied

**Issue:** Component looks unstyled

**Solutions:**
- Run `npm run build` to compile Tailwind
- Check `staticfiles/dist/styles.css` exists
- Verify `{% load static %}` at top of template
- Clear browser cache

## See Also

- [Tenant Type API](api/tenant_types.md) - Backend API reference
- [Verification System](verification.md) - Verification workflows
- [HTMX Documentation](https://htmx.org/) - HTMX reference
- [Tailwind CSS](https://tailwindcss.com/) - Tailwind utilities
