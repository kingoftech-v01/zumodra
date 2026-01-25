"""
URL configuration for jobs_public app.

Implements dual-layer architecture with nested namespaces:
- Frontend: frontend:jobs_public:view_name
- API: api:v1:jobs_public:resource-name

Strictly follows URL_AND_VIEW_CONVENTIONS.md - ZERO DEVIATIONS PERMITTED.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import template_views
from .api import views as api_views

# ============================================================================
# API LAYER - DRF ViewSets and Endpoints
# ============================================================================

# DRF Router for ViewSets
api_router = DefaultRouter()
api_router.register(
    r'jobs',
    api_views.PublicJobCatalogViewSet,
    basename='job'  # Singular form for URL reversal
)

# API URL Patterns
api_urlpatterns = [
    # Router URLs (job-list, job-detail, custom actions)
    path('', include(api_router.urls)),
]

# ============================================================================
# FRONTEND LAYER - HTML Template Views
# ============================================================================

frontend_urlpatterns = [
    # List Views
    path(
        '',
        template_views.job_list_default,
        name='job_list'
    ),
    path(
        'grid/',
        template_views.job_list_grid,
        name='job_list_grid'
    ),
    path(
        'list/',
        template_views.job_list_list,
        name='job_list_list'
    ),

    # Map Views
    path(
        'map/',
        template_views.job_map_grid_v1,
        name='job_map'
    ),
    path(
        'map/v2/',
        template_views.job_map_grid_v2,
        name='job_map_v2'
    ),

    # Detail Views
    path(
        '<uuid:pk>/',
        template_views.job_detail_v1,
        name='job_detail'
    ),
    path(
        '<uuid:pk>/v2/',
        template_views.job_detail_v2,
        name='job_detail_v2'
    ),

    # AJAX/HTMX Endpoints (Frontend-only, returns HTML fragments)
    path(
        'wishlist/toggle/<int:job_id>/',
        template_views.wishlist_toggle,
        name='wishlist_toggle'
    ),
]

# ============================================================================
# ROOT URL CONFIGURATION - Dual-Layer Architecture
# ============================================================================

app_name = 'jobs_public'

urlpatterns = [
    # API Layer (Namespace: api:v1:jobs_public:*)
    path('api/', include((api_urlpatterns, 'api'))),

    # Frontend Layer (Namespace: frontend:jobs_public:*)
    path('', include((frontend_urlpatterns, 'frontend'))),
]
