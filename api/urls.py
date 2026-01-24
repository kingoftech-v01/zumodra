"""
API URLs - REST API routing with Django REST Framework Router
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)
from .viewsets import *

# Create router and register viewsets
router = DefaultRouter()

# Service endpoints
router.register(r'categories', ServiceCategoryViewSet, basename='category')
router.register(r'providers', ServiceProviderViewSet, basename='provider')
router.register(r'services', ServiceViewSet, basename='service')
router.register(r'requests', ClientRequestViewSet, basename='request')
router.register(r'proposals', ServiceProposalViewSet, basename='proposal')
router.register(r'contracts', ServiceContractViewSet, basename='contract')
router.register(r'comments', ServiceReviewViewSet, basename='comment')

# Interview scheduling endpoints
router.register(r'appointments', AppointmentViewSet, basename='interviews')

# Company endpoints
router.register(r'companies', CompanyViewSet, basename='company')

app_name = 'api'

urlpatterns = [
    # JWT Authentication endpoints
    path('auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/token/verify/', TokenVerifyView.as_view(), name='token_verify'),

    # Router URLs
    path('', include(router.urls)),
]

"""
API Endpoints Available:

Authentication:
- POST /api/auth/token/ - Get JWT access & refresh tokens
- POST /api/auth/token/refresh/ - Refresh access token
- POST /api/auth/token/verify/ - Verify token validity

Categories:
- GET /api/categories/ - List all categories
- GET /api/categories/{id}/ - Get category detail

Providers:
- GET /api/providers/ - List all providers (with filters)
- POST /api/providers/ - Create provider profile
- GET /api/providers/{uuid}/ - Get provider detail
- PUT /api/providers/{uuid}/ - Update provider (owner only)
- PATCH /api/providers/{uuid}/ - Partial update provider
- DELETE /api/providers/{uuid}/ - Delete provider (owner only)
- GET /api/providers/{uuid}/services/ - Get provider's services
- GET /api/providers/{uuid}/reviews/ - Get provider's reviews

Services:
- GET /api/services/ - List all services (with filters)
- POST /api/services/ - Create service (provider only)
- GET /api/services/{uuid}/ - Get service detail
- PUT /api/services/{uuid}/ - Update service (owner only)
- PATCH /api/services/{uuid}/ - Partial update service
- DELETE /api/services/{uuid}/ - Delete service (owner only)
- GET /api/services/{uuid}/comments/ - Get service comments
- POST /api/services/{uuid}/like/ - Like/unlike service

Service Requests:
- GET /api/requests/ - List requests (my requests by default)
- GET /api/requests/?all=true - List all open requests
- POST /api/requests/ - Create request
- GET /api/requests/{uuid}/ - Get request detail
- PUT /api/requests/{uuid}/ - Update request (owner only)
- GET /api/requests/{uuid}/proposals/ - Get request proposals

Proposals:
- GET /api/proposals/ - List proposals (filtered by user)
- POST /api/proposals/ - Submit proposal (provider only)
- GET /api/proposals/{id}/ - Get proposal detail
- POST /api/proposals/{id}/accept/ - Accept proposal (client only)

Contracts:
- GET /api/contracts/ - List contracts (filtered by user)
- GET /api/contracts/{id}/ - Get contract detail
- POST /api/contracts/{id}/update_status/ - Update contract status

Comments/Reviews:
- GET /api/comments/ - List all comments
- POST /api/comments/ - Create comment
- GET /api/comments/{id}/ - Get comment detail

Interview Scheduling (Appointments):
- GET /api/appointments/ - List my appointments
- POST /api/appointments/ - Create appointment
- GET /api/appointments/{id}/ - Get appointment detail
- PUT /api/appointments/{id}/ - Update appointment
- DELETE /api/appointments/{id}/ - Delete appointment

Companies:
- GET /api/companies/ - List all companies
- POST /api/companies/ - Create company
- GET /api/companies/{id}/ - Get company detail
- PUT /api/companies/{id}/ - Update company (owner only)

Filters & Pagination:
- ?page=2 - Pagination
- ?page_size=20 - Custom page size
- ?search=web - Search
- ?ordering=-created_at - Ordering
- ?category=1 - Filter by category
- ?min_price=100&max_price=500 - Price range
- ?status=active - Filter by status
"""
