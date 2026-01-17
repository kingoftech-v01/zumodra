"""
URL configuration for Public Job Catalog API.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import PublicJobCatalogViewSet

app_name = 'ats_public'

router = DefaultRouter()
router.register(r'jobs', PublicJobCatalogViewSet, basename='public-job')

urlpatterns = [
    path('', include(router.urls)),
]
