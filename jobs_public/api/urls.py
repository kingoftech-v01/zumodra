"""
Jobs Public Catalog API URLs.

API endpoints for the public job catalog (cross-tenant job browsing).
Provides RESTful API for job listings, search, filtering, and map views.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import PublicJobCatalogViewSet


# Create DRF router for viewsets
router = DefaultRouter()
router.register(r'jobs', PublicJobCatalogViewSet, basename='publicjob')

app_name = 'jobs_public_api'

urlpatterns = [
    # ViewSet routes (includes list, detail, map_data, nearby, increment_view)
    # GET /api/v1/public/jobs/ - List all public jobs
    # GET /api/v1/public/jobs/{uuid}/ - Job detail
    # GET /api/v1/public/jobs/map_data/ - Jobs for map display
    # GET /api/v1/public/jobs/nearby/?lat=X&lng=Y&radius=50 - Nearby jobs
    # POST /api/v1/public/jobs/{uuid}/increment_view/ - Increment view count
    path('', include(router.urls)),
]
