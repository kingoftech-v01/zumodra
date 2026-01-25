"""
Services Public URLs

URL routing for public service catalog (frontend HTML + REST API).

URL Structure:
    Frontend (HTML):
        - /browse-services/ → List view
        - /browse-services/map/ → Map view
        - /browse-services/<uuid>/ → Detail view

    API (JSON):
        - /browse-services/api/services/ → List services
        - /browse-services/api/services/{uuid}/ → Service detail
        - /browse-services/api/services/search/ → Search
        - /browse-services/api/services/nearby/ → Geographic search
        - /browse-services/api/services/featured/ → Featured services
        - /browse-services/api/services/categories/ → Categories list
        - /browse-services/api/services/{uuid}/similar/ → Similar services
        - /browse-services/api/images/ → Service images
        - /browse-services/api/pricing-tiers/ → Pricing tiers
        - /browse-services/api/portfolio/ → Portfolio items
        - /browse-services/api/reviews/ → Reviews
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views_frontend
from . import views_api

app_name = 'services_public'

# DRF Router for API endpoints
router = DefaultRouter()
router.register(r'services', views_api.PublicServiceViewSet, basename='service')
router.register(r'images', views_api.PublicServiceImageViewSet, basename='image')
router.register(r'pricing-tiers', views_api.PublicServicePricingTierViewSet, basename='pricing-tier')
router.register(r'portfolio', views_api.PublicServicePortfolioViewSet, basename='portfolio')
router.register(r'reviews', views_api.PublicServiceReviewViewSet, basename='review')

# Frontend URLs (HTML templates)
frontend_patterns = [
    path('', views_frontend.service_list_view, name='service_list'),
    path('map/', views_frontend.service_map_view, name='service_map'),
    path('<uuid:service_uuid>/', views_frontend.service_detail_view, name='service_detail'),
]

# API URLs (REST API JSON)
api_patterns = [
    path('', include(router.urls)),
]

# Combined URL patterns
urlpatterns = [
    path('', include(frontend_patterns)),
    path('api/', include(api_patterns)),
]
