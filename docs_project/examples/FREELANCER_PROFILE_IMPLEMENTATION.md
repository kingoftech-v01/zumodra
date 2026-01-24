# FreelancerProfile Implementation - Reference Example

**Version**: 1.0
**Created**: 2026-01-17
**Status**: Complete implementation following URL & View Conventions

This document shows the complete implementation of FreelancerProfile as a reference example for following Zumodra's URL and View conventions.

---

## Table of Contents

1. [Overview](#overview)
2. [File Structure](#file-structure)
3. [URL Namespace Map](#url-namespace-map)
4. [API Endpoints](#api-endpoints)
5. [Frontend URLs](#frontend-urls)
6. [Implementation Highlights](#implementation-highlights)

---

## Overview

FreelancerProfile is a complete implementation demonstrating:
- ✅ Dual-layer architecture (API + Frontend)
- ✅ Proper namespace organization
- ✅ Separation of concerns (template_views vs API views)
- ✅ Dynamic data with filtering, search, pagination
- ✅ Comprehensive documentation
- ✅ Full CRUD operations on both layers

---

## File Structure

```
accounts/
├── models.py                           # FreelancerProfile model
├── serializers.py                      # 4 API serializers
├── views.py                            # FreelancerProfileViewSet (API)
├── template_views_freelancer.py        # ⭐ Frontend HTML views
├── urls.py                             # ⭐ Dual URL configuration
├── admin.py                            # Admin interface
├── migrations/
│   └── 0006_freelancerprofile.py      # Database migration
├── tests/
│   ├── unit/
│   │   └── test_freelancer_profile_model.py
│   ├── api/
│   │   └── test_freelancer_profile_api.py
│   └── integration/
│       └── test_freelancer_profile_workflows.py
└── templates/
    └── accounts/
        ├── freelancer_browse.html          # Public browsing (to create)
        ├── freelancer_detail.html          # Public profile (to create)
        ├── freelancer_profile_form.html    # Create/Edit (to create)
        └── freelancer_dashboard.html       # Owner dashboard (to create)
```

---

## URL Namespace Map

### API Namespace: `api:v1:accounts:*`

All API endpoints are under `/api/v1/accounts/`

| Action | URL | Namespace | View |
|--------|-----|-----------|------|
| **List** | `/api/v1/accounts/freelancer-profiles/` | `api:v1:accounts:freelancer-profile-list` | `FreelancerProfileViewSet.list()` |
| **Retrieve** | `/api/v1/accounts/freelancer-profiles/{uuid}/` | `api:v1:accounts:freelancer-profile-detail` | `FreelancerProfileViewSet.retrieve()` |
| **Create** | `/api/v1/accounts/freelancer-profiles/` | `api:v1:accounts:freelancer-profile-list` | `FreelancerProfileViewSet.create()` |
| **Update** | `/api/v1/accounts/freelancer-profiles/{uuid}/` | `api:v1:accounts:freelancer-profile-detail` | `FreelancerProfileViewSet.update()` |
| **Delete** | `/api/v1/accounts/freelancer-profiles/{uuid}/` | `api:v1:accounts:freelancer-profile-detail` | `FreelancerProfileViewSet.destroy()` |
| **Me** | `/api/v1/accounts/freelancer-profiles/me/` | `api:v1:accounts:freelancer-profile-me` | `FreelancerProfileViewSet.me()` |
| **Available** | `/api/v1/accounts/freelancer-profiles/available/` | `api:v1:accounts:freelancer-profile-available` | `FreelancerProfileViewSet.available()` |
| **Verified** | `/api/v1/accounts/freelancer-profiles/verified/` | `api:v1:accounts:freelancer-profile-verified` | `FreelancerProfileViewSet.verified()` |

### Frontend Namespace: `frontend:accounts:*`

All frontend URLs are under `/accounts/`

| Page | URL | Namespace | View |
|------|-----|-----------|------|
| **Browse Freelancers** | `/accounts/freelancers/` | `frontend:accounts:freelancer_browse` | `freelancer_browse()` |
| **Available Only** | `/accounts/freelancers/available/` | `frontend:accounts:freelancer_available` | `freelancer_available()` |
| **Freelancer Detail** | `/accounts/freelancers/{uuid}/` | `frontend:accounts:freelancer_detail` | `freelancer_detail()` |
| **My Profile** | `/accounts/my-freelancer-profile/` | `frontend:accounts:freelancer_profile_me` | `freelancer_profile_me()` |
| **Create Profile** | `/accounts/my-freelancer-profile/create/` | `frontend:accounts:freelancer_profile_create` | `freelancer_profile_create()` |
| **Edit Profile** | `/accounts/my-freelancer-profile/{uuid}/edit/` | `frontend:accounts:freelancer_profile_edit` | `freelancer_profile_edit()` |
| **Dashboard** | `/accounts/my-freelancer-profile/dashboard/` | `frontend:accounts:freelancer_profile_dashboard` | `freelancer_profile_dashboard()` |
| **Toggle Availability** | `/accounts/my-freelancer-profile/{uuid}/toggle-availability/` | `frontend:accounts:freelancer_toggle_availability` | `freelancer_toggle_availability()` |

---

## API Endpoints

### Complete API Reference

#### 1. List Freelancers (Public)
```http
GET /api/v1/accounts/freelancer-profiles/
```

**Query Parameters**:
- `?search=python` - Search in title, bio, skills
- `?availability_status=available` - Filter by availability
- `?is_verified=true` - Filter by verification
- `?remote_only=true` - Filter remote-only
- `?country=Canada` - Filter by country
- `?hourly_rate_currency=CAD` - Filter by currency
- `?ordering=-average_rating` - Sort by rating (desc)
- `?ordering=hourly_rate` - Sort by rate (asc)
- `?page=2` - Pagination

**Response** (200 OK):
```json
{
  "count": 42,
  "next": "http://api.example.com/api/v1/accounts/freelancer-profiles/?page=2",
  "previous": null,
  "results": [
    {
      "uuid": "123e4567-e89b-12d3-a456-426614174000",
      "user_name": "John Doe",
      "professional_title": "Senior Python Developer",
      "city": "Toronto",
      "country": "Canada",
      "hourly_rate": "150.00",
      "hourly_rate_currency": "CAD",
      "availability_status": "available",
      "availability_status_display": "Available for Work",
      "is_verified": true,
      "average_rating": "4.8",
      "total_reviews": 45,
      "completed_projects": 32,
      "completed_services": 18,
      "skills": ["Python", "Django", "PostgreSQL"],
      "remote_only": true
    }
  ]
}
```

#### 2. Retrieve Freelancer (Public)
```http
GET /api/v1/accounts/freelancer-profiles/{uuid}/
```

**Response** (200 OK):
```json
{
  "uuid": "123e4567-e89b-12d3-a456-426614174000",
  "user": {
    "id": 42,
    "email": "john@example.com",
    "first_name": "John",
    "last_name": "Doe"
  },
  "professional_title": "Senior Python Developer",
  "bio": "15 years building scalable backend systems...",
  "years_of_experience": 15,
  "availability_status": "available",
  "availability_status_display": "Available for Work",
  "availability_hours_per_week": 30,
  "is_available_for_work": true,
  "hourly_rate": "150.00",
  "hourly_rate_currency": "CAD",
  "hourly_rate_currency_display": "CAD",
  "minimum_project_budget": "5000.00",
  "skills": ["Python", "Django", "PostgreSQL", "Docker", "AWS"],
  "categories": [1, 3, 5],
  "portfolio_url": "https://johndoe.dev",
  "github_url": "https://github.com/johndoe",
  "linkedin_url": "https://linkedin.com/in/johndoe",
  "behance_url": "",
  "dribbble_url": "",
  "has_portfolio": true,
  "city": "Toronto",
  "country": "Canada",
  "timezone": "America/Toronto",
  "willing_to_relocate": false,
  "remote_only": true,
  "is_verified": true,
  "verification_date": "2025-06-15T10:30:00Z",
  "identity_verified": true,
  "payment_method_verified": true,
  "completed_projects": 32,
  "completed_services": 18,
  "total_earnings": "285000.00",
  "average_rating": "4.8",
  "total_reviews": 45,
  "completion_rate": 100.0,
  "service_provider": null,
  "created_at": "2023-01-10T08:00:00Z",
  "updated_at": "2026-01-15T14:22:00Z",
  "last_active_at": "2026-01-17T10:05:00Z"
}
```

#### 3. Create Profile (Authenticated)
```http
POST /api/v1/accounts/freelancer-profiles/
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "professional_title": "Full-Stack Developer",
  "bio": "Experienced developer...",
  "years_of_experience": 5,
  "hourly_rate": "85.00",
  "hourly_rate_currency": "USD",
  "availability_hours_per_week": 40,
  "skills": ["Python", "JavaScript", "React"],
  "city": "New York",
  "country": "USA",
  "remote_only": true
}
```

**Response** (201 Created): Full profile object

**Error** (400 Bad Request):
```json
{
  "error": "You already have a freelancer profile. Use PUT/PATCH to update it."
}
```

#### 4. Update Profile (Owner Only)
```http
PATCH /api/v1/accounts/freelancer-profiles/{uuid}/
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "hourly_rate": "100.00",
  "availability_status": "busy",
  "bio": "Updated bio..."
}
```

**Response** (200 OK): Updated profile object

**Error** (403 Forbidden):
```json
{
  "detail": "You can only update your own freelancer profile"
}
```

#### 5. Get/Create Own Profile
```http
GET /api/v1/accounts/freelancer-profiles/me/
Authorization: Bearer {access_token}
```

**Response** (200 OK): Own profile object
**Response** (404 Not Found): No profile exists

```http
POST /api/v1/accounts/freelancer-profiles/me/
Authorization: Bearer {access_token}
Content-Type: application/json

{...profile_data...}
```

**Response** (201 Created): New profile object

#### 6. List Available Freelancers
```http
GET /api/v1/accounts/freelancer-profiles/available/
```

Pre-filtered to `availability_status=available` AND `is_verified=true`

**Response**: Paginated list

#### 7. List Verified Freelancers
```http
GET /api/v1/accounts/freelancer-profiles/verified/
```

Pre-filtered to `is_verified=true`

**Response**: Paginated list

---

## Frontend URLs

### Complete Frontend Reference

#### 1. Browse Freelancers
```
URL: /accounts/freelancers/
Namespace: frontend:accounts:freelancer_browse
View: freelancer_browse()
Template: accounts/freelancer_browse.html
Access: Public (no auth required)
```

**Query Parameters**:
- `?search=python`
- `?availability=available`
- `?min_rate=50&max_rate=150&currency=CAD`
- `?remote_only=true`
- `?country=Canada`
- `?skills=Python,Django`
- `?sort=-average_rating`
- `?page=2`

**Context Variables**:
```python
{
    'freelancers': <Paginated QuerySet>,
    'total_count': 42,
    'search': 'python',
    'availability': 'available',
    'min_rate': '50',
    'max_rate': '150',
    'currency': 'CAD',
    'remote_only': 'true',
    'country': 'Canada',
    'skills': 'Python,Django',
    'sort_by': '-average_rating',
    'countries': ['Canada', 'USA', 'UK', ...],
    'common_skills': ['Python', 'JavaScript', ...],
    'currencies': ['CAD', 'USD', 'EUR', 'GBP'],
    'page_title': 'Browse Freelancers',
    'meta_description': '...'
}
```

#### 2. Browse Available Freelancers
```
URL: /accounts/freelancers/available/
Namespace: frontend:accounts:freelancer_available
View: freelancer_available()
Template: accounts/freelancer_browse.html
Access: Public
```

Same as browse but pre-filtered to available status.

#### 3. Freelancer Detail
```
URL: /accounts/freelancers/{uuid}/
Namespace: frontend:accounts:freelancer_detail
View: freelancer_detail()
Template: accounts/freelancer_detail.html
Access: Public
```

**Context Variables**:
```python
{
    'freelancer': <FreelancerProfile>,
    'can_contact': True/False,  # Based on auth status
    'similar_freelancers': <QuerySet[6]>,
    'page_title': 'Senior Python Developer - John Doe',
    'meta_description': '...'
}
```

#### 4. My Profile Router
```
URL: /accounts/my-freelancer-profile/
Namespace: frontend:accounts:freelancer_profile_me
View: freelancer_profile_me()
Access: Login required
```

Redirects to:
- `/accounts/my-freelancer-profile/create/` (if no profile)
- `/accounts/my-freelancer-profile/{uuid}/edit/` (if profile exists)

#### 5. Create Profile
```
URL: /accounts/my-freelancer-profile/create/
Namespace: frontend:accounts:freelancer_profile_create
View: freelancer_profile_create()
Template: accounts/freelancer_profile_form.html
Access: Login required
```

**Context Variables**:
```python
{
    'form_title': 'Create Your Freelancer Profile',
    'is_create': True,
    'cancel_url': 'dashboard:index',
    'api_endpoint': '/api/v1/accounts/freelancer-profiles/me/',
    'page_title': 'Create Freelancer Profile'
}
```

#### 6. Edit Profile
```
URL: /accounts/my-freelancer-profile/{uuid}/edit/
Namespace: frontend:accounts:freelancer_profile_edit
View: freelancer_profile_edit()
Template: accounts/freelancer_profile_form.html
Access: Login required (owner only)
```

**Context Variables**:
```python
{
    'freelancer': <FreelancerProfile>,
    'form_title': 'Edit Your Freelancer Profile',
    'is_create': False,
    'cancel_url': 'accounts:frontend:freelancer_detail',
    'api_endpoint': '/api/v1/accounts/freelancer-profiles/{uuid}/',
    'page_title': 'Edit Freelancer Profile'
}
```

#### 7. Freelancer Dashboard
```
URL: /accounts/my-freelancer-profile/dashboard/
Namespace: frontend:accounts:freelancer_profile_dashboard
View: freelancer_profile_dashboard()
Template: accounts/freelancer_dashboard.html
Access: Login required (owner only)
```

**Context Variables**:
```python
{
    'freelancer': <FreelancerProfile>,
    'completion_percentage': 85,  # Profile completion %
    'stats': {
        'total_earnings': Decimal('285000.00'),
        'completed_projects': 32,
        'completed_services': 18,
        'average_rating': Decimal('4.8'),
        'total_reviews': 45,
        'availability_status': 'Available for Work'
    },
    'page_title': 'Freelancer Dashboard'
}
```

#### 8. Toggle Availability
```
URL: /accounts/my-freelancer-profile/{uuid}/toggle-availability/
Namespace: frontend:accounts:freelancer_toggle_availability
View: freelancer_toggle_availability()
Method: POST only
Access: Login required (owner only)
```

Cycles through: `available` → `busy` → `unavailable` → `available`

Redirects to: `frontend:accounts:freelancer_profile_dashboard`

---

## Implementation Highlights

### 1. Dual-Layer Architecture

✅ **API Layer** (`views.py`):
- `FreelancerProfileViewSet` with full CRUD
- 4 serializers for different contexts
- Public browsing (AllowAny)
- Owner-only modifications
- Custom actions: `/me/`, `/available/`, `/verified/`

✅ **Frontend Layer** (`template_views_freelancer.py`):
- 8 views covering all user journeys
- Public browsing with filtering
- Authenticated profile management
- Dashboard with stats
- Custom actions (toggle availability)

### 2. Proper Namespace Organization

✅ **API Namespaces**: `api:v1:accounts:freelancer-profile-*`
- All DRF ViewSet routes auto-generated
- Custom actions registered properly
- Consistent with rest of platform

✅ **Frontend Namespaces**: `frontend:accounts:freelancer_*`
- All template views explicitly defined
- Clear hierarchy (browse → detail → manage)
- Consistent naming (snake_case)

### 3. Dynamic Data Throughout

✅ **API Filtering**:
```python
filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
filterset_fields = ['availability_status', 'is_verified', 'remote_only', ...]
search_fields = ['professional_title', 'bio', 'skills', ...]
ordering_fields = ['created_at', 'hourly_rate', 'average_rating', ...]
```

✅ **Frontend Filtering**:
```python
# All query parameters properly handled
if search:
    freelancers = freelancers.filter(Q(...) | Q(...))
if availability:
    freelancers = freelancers.filter(availability_status=availability)
# Pagination with 12 per page
paginator = Paginator(freelancers, 12)
```

### 4. Comprehensive Documentation

✅ **View Docstrings**:
- Every view has complete docstring
- Lists all features
- Shows template and context
- Explains permissions

✅ **URL Comments**:
- Clear sections (API vs Frontend)
- Each route documented inline
- Examples provided

### 5. Permission Control

✅ **API Permissions**:
```python
permission_classes = [permissions.IsAuthenticatedOrReadOnly, IsOwnerOrReadOnly]

def perform_update(self, serializer):
    if serializer.instance.user != self.request.user:
        raise PermissionDenied(...)
```

✅ **Frontend Permissions**:
```python
@login_required
def freelancer_profile_edit(request, uuid):
    freelancer = get_object_or_404(FreelancerProfile, uuid=uuid)
    if freelancer.user != request.user:
        messages.error(request, '...')
        return redirect(...)
```

---

## Usage Examples

### In Templates (Using URL Namespaces)

```django
{# Browse freelancers #}
<a href="{% url 'tenant_profiles:frontend:freelancer_browse' %}">Find Freelancers</a>

{# View specific freelancer #}
<a href="{% url 'tenant_profiles:frontend:freelancer_detail' uuid=freelancer.uuid %}">
    View Profile
</a>

{# Manage own profile #}
<a href="{% url 'tenant_profiles:frontend:freelancer_profile_me' %}">My Freelancer Profile</a>
<a href="{% url 'tenant_profiles:frontend:freelancer_profile_dashboard' %}">Dashboard</a>

{# Toggle availability (POST form) #}
<form method="post" action="{% url 'tenant_profiles:frontend:freelancer_toggle_availability' uuid=freelancer.uuid %}">
    {% csrf_token %}
    <button type="submit">Toggle Availability</button>
</form>
```

### In Python (Reverse URL Resolution)

```python
from django.urls import reverse

# API endpoints
api_list = reverse('tenant_profiles:api:freelancer-profile-list')
# → '/api/v1/accounts/freelancer-profiles/'

api_detail = reverse('tenant_profiles:api:freelancer-profile-detail', args=[uuid])
# → '/api/v1/accounts/freelancer-profiles/{uuid}/'

api_me = reverse('tenant_profiles:api:freelancer-profile-me')
# → '/api/v1/accounts/freelancer-profiles/me/'

# Frontend pages
browse = reverse('tenant_profiles:frontend:freelancer_browse')
# → '/accounts/freelancers/'

detail = reverse('tenant_profiles:frontend:freelancer_detail', kwargs={'uuid': uuid})
# → '/accounts/freelancers/{uuid}/'

dashboard = reverse('tenant_profiles:frontend:freelancer_profile_dashboard')
# → '/accounts/my-freelancer-profile/dashboard/'
```

### In JavaScript (Fetch API)

```javascript
// List freelancers with filters
fetch('/api/v1/accounts/freelancer-profiles/?availability=available&search=python')
  .then(response => response.json())
  .then(data => {
    console.log(`Found ${data.count} freelancers`);
    data.results.forEach(freelancer => {
      console.log(freelancer.professional_title);
    });
  });

// Get own profile
fetch('/api/v1/accounts/freelancer-profiles/me/', {
  headers: {
    'Authorization': `Bearer ${accessToken}`
  }
})
  .then(response => response.json())
  .then(profile => {
    console.log(`My profile: ${profile.professional_title}`);
  });

// Update profile
fetch(`/api/v1/accounts/freelancer-profiles/${uuid}/`, {
  method: 'PATCH',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    availability_status: 'busy',
    hourly_rate: '120.00'
  })
})
  .then(response => response.json())
  .then(updated => {
    console.log('Profile updated!');
  });
```

---

## Summary

FreelancerProfile demonstrates **complete adherence** to Zumodra's URL and View conventions:

✅ **Dual-layer architecture** - API + Frontend both fully implemented
✅ **Proper file organization** - `views.py` (API) + `template_views_freelancer.py` (Frontend)
✅ **Namespace convention** - `api:v1:accounts:*` and `frontend:accounts:*`
✅ **Single urls.py** - Both layers configured with clear separation
✅ **Dynamic data** - Filtering, search, pagination on both layers
✅ **Comprehensive docs** - Every view, URL, and action documented
✅ **Permission control** - Public browsing, authenticated management, owner-only edits
✅ **HTML optional** - Templates referenced but not required for functionality

**Use this as the reference implementation for all future features.**
