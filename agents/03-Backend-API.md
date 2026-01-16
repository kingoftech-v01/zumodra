# Zumodra Project – Backend Developer – API Endpoints
## Comprehensive Onboarding Document

**Project:** Zumodra HR/Management SaaS  
**Deadline:** January 21, 2026  
**Role:** Backend Developer (API Focus)  
**Team Lead:** Backend Lead Developer → Supervisor

---

## 1. Executive Summary

You are responsible for making all REST API endpoints work correctly and reliably. The current APIs are broken with incomplete implementations, missing validation, and inconsistent response formats. Your goal is to inventory all endpoints, fix broken ones, and ensure they're production-ready by Day 4.

### Primary Objectives
- **Day 1–2:** Inventory all API endpoints, identify broken ones, document spec
- **Day 3:** Fix all endpoints with proper validation and error handling
- **Day 4:** Add documentation and test collection (Postman/curl)
- **Day 5:** Final testing and optimization

### Success Criteria
- [ ] All API endpoints documented (request/response format)
- [ ] Endpoints validate input and return consistent JSON
- [ ] Proper HTTP status codes (200, 201, 400, 403, 404, 500)
- [ ] Authentication required on protected endpoints
- [ ] Postman collection or curl examples provided
- [ ] Basic tests for key endpoints passing

---

## 2. API Endpoint Inventory

### 2.1 Discovery Process

**Step 1: List All Endpoints**

Run this command:
```bash
python manage.py show_urls
```

Or check `urls.py` in each app. List every endpoint with:
- HTTP method (GET, POST, PUT, PATCH, DELETE)
- URL path
- View function/class
- Purpose/description

**Example Output:**
```
GET     /api/users/              → UserListView           (List all users)
POST    /api/users/              → UserListView           (Create user)
GET     /api/users/<id>/         → UserDetailView         (Get user)
PUT     /api/users/<id>/         → UserDetailView         (Update user)
DELETE  /api/users/<id>/         → UserDetailView         (Delete user)
GET     /api/users/<id>/profile/ → UserProfileView        (Get user profile)
POST    /api/users/login/        → LoginView              (Authenticate)
```

**Step 2: Test Each Endpoint**

For each endpoint, test with `curl` or Postman:

```bash
# GET example
curl http://localhost:8000/api/users/

# POST example
curl -X POST http://localhost:8000/api/users/ \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","name":"John"}'

# With authentication
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8000/api/users/1/
```

**Record Results:**
- Does it work? (200 OK, 500 Error, etc.)
- What does response look like?
- Is response consistent with other endpoints?
- What are required/optional fields?

### 2.2 API Specification Template

Create `docs/API.md`:

```markdown
# Zumodra API Documentation

## Authentication
- Method: Token-based (e.g., Bearer tokens)
- Header: `Authorization: Bearer <token>`
- How to get token: POST /api/auth/login/ with credentials

## Response Format
All responses are JSON:

**Success Response (2xx):**
```json
{
  "status": "success",
  "data": { /* actual data */ },
  "message": "Optional success message"
}
```

**Error Response (4xx, 5xx):**
```json
{
  "status": "error",
  "error": "error_code",
  "message": "Human-readable error message",
  "details": { /* optional detailed info */ }
}
```

## Endpoints

### Users API

#### List Users
- **Endpoint:** `GET /api/users/`
- **Auth Required:** Yes
- **Description:** Get paginated list of users
- **Query Parameters:**
  - `page` (int): Page number (default: 1)
  - `limit` (int): Items per page (default: 20)
  - `active` (bool): Filter by is_active (optional)
- **Response:** 
```json
{
  "status": "success",
  "data": {
    "count": 100,
    "next": "/api/users/?page=2",
    "previous": null,
    "results": [
      {
        "id": 1,
        "email": "john@test.com",
        "first_name": "John",
        "last_name": "Doe",
        "is_active": true,
        "created_at": "2026-01-16T10:00:00Z"
      }
    ]
  }
}
```
- **Errors:**
  - 401 Unauthorized (missing auth)
  - 403 Forbidden (user not staff)

#### Get User Details
- **Endpoint:** `GET /api/users/<id>/`
- **Auth Required:** Yes (own profile or staff)
- **Description:** Get details for specific user
- **Response:** Single user object (same as above)
- **Errors:**
  - 404 Not Found
  - 403 Forbidden (can't view other user's profile)

#### Create User
- **Endpoint:** `POST /api/users/`
- **Auth Required:** Yes (staff only)
- **Description:** Create new user
- **Request Body:**
```json
{
  "email": "newuser@test.com",
  "first_name": "Jane",
  "last_name": "Smith",
  "password": "secure_password_123"
}
```
- **Response:** 201 Created with new user object
- **Errors:**
  - 400 Bad Request (missing required fields, invalid email)
  - 403 Forbidden (user not staff)

[... more endpoints ...]
```

---

## 3. Fixing Broken APIs

### 3.1 Common API Issues

| Issue | Fix |
|-------|-----|
| Hardcoded data instead of querying DB | Query models correctly using ORM |
| Missing input validation | Add `.is_valid()` on serializers, check required fields |
| Inconsistent response format | Use standardized response wrapper |
| No error handling | Catch exceptions, return proper HTTP status |
| Missing pagination | Use `paginate_queryset()` for list endpoints |
| No authentication | Add `@login_required` or `permission_classes` |
| Wrong HTTP status codes | 201 for create, 204 for delete, 400 for bad request, etc. |

### 3.2 Standard API View Structure

**Using Django REST Framework (DRF) – Recommended:**

```python
from rest_framework import viewsets, serializers
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from apps.users.models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'is_active', 'created_at']
        read_only_fields = ['id', 'created_at']

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Users can only see their own profile unless staff
        if self.request.user.is_staff:
            return User.objects.all()
        return User.objects.filter(pk=self.request.user.pk)
    
    def perform_create(self, serializer):
        # Log creation or add additional logic
        return serializer.save()
    
    @action(detail=True, methods=['post'])
    def set_password(self, request, pk=None):
        # Custom action: POST /api/users/<id>/set_password/
        user = self.get_object()
        serializer = SetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            return Response({'status': 'password set'})
        return Response(serializer.errors, status=400)
```

**URL Configuration:**
```python
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'users', views.UserViewSet)

urlpatterns = router.urls
```

**Alternative: Function-Based Views (for simple APIs):**

```python
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def user_list(request):
    if request.method == 'GET':
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response({'status': 'success', 'data': serializer.data})
    
    elif request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response({'status': 'error', 'errors': serializer.errors}, status=400)
```

### 3.3 Error Handling

**Consistent Error Responses:**

```python
from rest_framework.response import Response
from rest_framework import status

def handle_api_errors(view_func):
    """Decorator to standardize error responses."""
    def wrapper(request, *args, **kwargs):
        try:
            return view_func(request, *args, **kwargs)
        except User.DoesNotExist:
            return Response(
                {'status': 'error', 'error': 'not_found', 'message': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except ValueError as e:
            return Response(
                {'status': 'error', 'error': 'invalid_input', 'message': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.exception("Unexpected error in API")
            return Response(
                {'status': 'error', 'error': 'internal_error', 'message': 'Internal server error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    return wrapper
```

### 3.4 Pagination & Filtering

```python
from rest_framework.pagination import PageNumberPagination

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

class UserViewSet(viewsets.ModelViewSet):
    pagination_class = StandardResultsSetPagination
    filter_backends = ['rest_framework.filters.SearchFilter', 'rest_framework.filters.OrderingFilter']
    search_fields = ['email', 'first_name', 'last_name']
    ordering_fields = ['created_at', 'email']
    ordering = ['-created_at']
```

**Usage:**
```
GET /api/users/?page=1&page_size=50
GET /api/users/?search=john
GET /api/users/?ordering=-created_at
```

---

## 4. Testing APIs

### 4.1 Postman Collection

Create a `postman_collection.json` file:

```json
{
  "info": {
    "name": "Zumodra API",
    "description": "API endpoints for Zumodra application"
  },
  "item": [
    {
      "name": "Users",
      "item": [
        {
          "name": "List Users",
          "request": {
            "method": "GET",
            "header": [
              {
                "key": "Authorization",
                "value": "Bearer {{token}}"
              }
            ],
            "url": {
              "raw": "{{base_url}}/api/users/?page=1&page_size=20",
              "host": ["{{base_url}}"],
              "path": ["api", "users"],
              "query": [
                {"key": "page", "value": "1"},
                {"key": "page_size", "value": "20"}
              ]
            }
          }
        },
        {
          "name": "Create User",
          "request": {
            "method": "POST",
            "header": [
              {
                "key": "Authorization",
                "value": "Bearer {{token}}"
              },
              {
                "key": "Content-Type",
                "value": "application/json"
              }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\"email\":\"newuser@test.com\",\"first_name\":\"John\",\"last_name\":\"Doe\",\"password\":\"password123\"}"
            },
            "url": {
              "raw": "{{base_url}}/api/users/",
              "host": ["{{base_url}}"],
              "path": ["api", "users"]
            }
          }
        }
      ]
    }
  ],
  "variable": [
    {
      "key": "base_url",
      "value": "http://localhost:8000"
    },
    {
      "key": "token",
      "value": "your_token_here"
    }
  ]
}
```

### 4.2 Automated Tests

```python
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from django.contrib.auth.models import User

class UserAPITestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(email='test@test.com', password='pass123')
        self.client.force_authenticate(user=self.user)
    
    def test_list_users(self):
        response = self.client.get('/api/users/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('data', response.data)
    
    def test_create_user_requires_auth(self):
        self.client.force_authenticate(user=None)
        response = self.client.post('/api/users/', {'email': 'new@test.com'})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_create_user(self):
        data = {
            'email': 'newuser@test.com',
            'first_name': 'Jane',
            'last_name': 'Smith',
            'password': 'newpass123'
        }
        response = self.client.post('/api/users/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['email'], data['email'])
```

---

## 5. Deliverables

By **End of Day 4**, provide:

- [ ] Complete API documentation (`docs/API.md`)
- [ ] All endpoints working and tested
- [ ] Postman collection or curl examples
- [ ] Automated tests with 70%+ coverage
- [ ] Error responses standardized and logged
- [ ] Pagination/filtering working on list endpoints
- [ ] Authentication enforced on protected endpoints

---

## 6. Quick Reference

**Common HTTP Status Codes:**
- `200 OK` – Success (GET, PUT, PATCH)
- `201 Created` – Resource created (POST)
- `204 No Content` – Success with no response body (DELETE)
- `400 Bad Request` – Invalid input
- `401 Unauthorized` – Missing or invalid authentication
- `403 Forbidden` – Authenticated but not authorized
- `404 Not Found` – Resource doesn't exist
- `500 Internal Server Error` – Server error

**Testing Commands:**
```bash
# Run API tests
python manage.py test apps.api

# Test a single endpoint
curl -H "Authorization: Bearer TOKEN" http://localhost:8000/api/users/

# POST request
curl -X POST http://localhost:8000/api/users/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"email":"test@test.com","first_name":"John"}'
```

---

## 7. Success Metrics

| Metric | Target |
|--------|--------|
| All endpoints documented | 100% |
| Tests passing | 100% |
| API response time | <500ms |
| Error handling coverage | 100% |
| Code coverage | 70%+ |

---

**Document Version:** 1.0  
**Created:** January 16, 2026  
**Owner:** Backend Developer – API