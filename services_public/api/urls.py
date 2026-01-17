"""
URL configuration for Public Service Catalog API.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import PublicServiceCatalogViewSet

app_name = 'services_public'

router = DefaultRouter()
router.register(r'providers', PublicServiceCatalogViewSet, basename='public-provider')

urlpatterns = [
    path('', include(router.urls)),
]
