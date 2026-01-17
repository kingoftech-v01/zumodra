"""
Services API URLs.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .viewsets import (
    ServiceCategoryViewSet,
    ServiceTagViewSet,
    ServiceProviderViewSet,
    ServiceViewSet,
    ClientRequestViewSet,
    ServiceProposalViewSet,
    ServiceContractViewSet,
    ServiceReviewViewSet,
    MarketplaceAnalyticsView,
)

app_name = 'services'

router = DefaultRouter()

# Categories & Tags
router.register(r'categories', ServiceCategoryViewSet, basename='category')
router.register(r'tags', ServiceTagViewSet, basename='tag')

# Providers
router.register(r'providers', ServiceProviderViewSet, basename='provider')

# Services
router.register(r'services', ServiceViewSet, basename='service')

# Client Requests
router.register(r'requests', ClientRequestViewSet, basename='request')

# Proposals
router.register(r'proposals', ServiceProposalViewSet, basename='proposal')

# Contracts
router.register(r'contracts', ServiceContractViewSet, basename='contract')

# Reviews
router.register(r'reviews', ServiceReviewViewSet, basename='review')

urlpatterns = [
    path('', include(router.urls)),
    path('analytics/', MarketplaceAnalyticsView.as_view(), name='analytics'),
]
