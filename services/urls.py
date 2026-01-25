"""
Services URLs

URL routing for services app (frontend HTML + REST API).

URL Structure:
    Frontend (HTML):
        - /services/ → Service listing (browse services)
        - /services/service/<uuid>/ → Service detail
        - /services/providers/ → Provider browsing
        - /services/provider/<uuid>/ → Provider profile
        - /services/provider/dashboard/ → Provider dashboard
        - /services/contract/<id>/ → Contract detail
        - ... (see frontend_patterns below)

    API (JSON):
        - /services/api/providers/ → Provider list/CRUD
        - /services/api/providers/me/ → Current user's provider profile
        - /services/api/services/ → Service list/CRUD
        - /services/api/services/my-services/ → User's services
        - /services/api/services/{uuid}/publish/ → Publish to marketplace
        - /services/api/contracts/ → Contract list/CRUD
        - /services/api/reviews/ → Reviews
        - ... (see API router below)
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views_frontend
from . import views_api

app_name = 'services'

# ==================== DRF ROUTER FOR API ENDPOINTS ====================

router = DefaultRouter()

# Provider endpoints
router.register(r'providers', views_api.ServiceProviderViewSet, basename='api_provider')

# Service endpoints
router.register(r'services', views_api.ServiceViewSet, basename='api_service')

# Category & Tag endpoints
router.register(r'categories', views_api.ServiceCategoryViewSet, basename='api_category')
router.register(r'tags', views_api.ServiceTagViewSet, basename='api_tag')

# Image endpoints
router.register(r'images', views_api.ServiceImageViewSet, basename='api_image')

# Pricing tier endpoints
router.register(r'pricing-tiers', views_api.ServicePricingTierViewSet, basename='api_pricing_tier')

# Portfolio endpoints
router.register(r'portfolio', views_api.ProviderPortfolioViewSet, basename='api_portfolio')

# Review endpoints
router.register(r'reviews', views_api.ServiceReviewViewSet, basename='api_review')

# Contract endpoints
router.register(r'contracts', views_api.ServiceContractViewSet, basename='api_contract')

# Contract message endpoints
router.register(r'messages', views_api.ContractMessageViewSet, basename='api_message')

# Cross-tenant request endpoints
router.register(
    r'cross-tenant-requests',
    views_api.CrossTenantServiceRequestViewSet,
    basename='api_cross_tenant_request'
)


# ==================== FRONTEND URLs (HTML TEMPLATES) ====================

frontend_patterns = [
    # ==================== SERVICE BROWSING ====================
    path('', views_frontend.browse_services, name='service_list'),
    path('service/<uuid:service_uuid>/', views_frontend.service_detail, name='service_detail'),
    path('service/<uuid:service_uuid>/like/', views_frontend.like_service, name='like_service'),
    path('nearby/', views_frontend.browse_nearby_services, name='browse_nearby_services'),
    path('search/ajax/', views_frontend.search_services_ajax, name='search_services_ajax'),

    # ==================== PROVIDER BROWSING & PROFILE ====================
    path('providers/', views_frontend.browse_providers, name='browse_providers'),
    path('provider/dashboard/', views_frontend.provider_dashboard, name='provider_dashboard'),
    path('provider/create/', views_frontend.create_provider_profile, name='create_provider_profile'),
    path('provider/edit/', views_frontend.edit_provider_profile, name='edit_provider_profile'),
    path('provider/<uuid:provider_uuid>/', views_frontend.provider_profile_view, name='provider_profile_view'),

    # ==================== SERVICE CRUD (Provider) ====================
    path('service/create/', views_frontend.create_service, name='create_service'),
    path('service/<uuid:service_uuid>/edit/', views_frontend.edit_service, name='edit_service'),
    path('service/<uuid:service_uuid>/delete/', views_frontend.delete_service, name='delete_service'),

    # ==================== CLIENT REQUESTS ====================
    path('request/create/', views_frontend.create_service_request, name='create_service_request'),
    path('request/my-requests/', views_frontend.my_requests, name='my_requests'),
    path('request/<uuid:request_uuid>/', views_frontend.view_request, name='view_request'),
    path('request/<uuid:request_uuid>/submit-proposal/', views_frontend.submit_proposal, name='submit_proposal'),
    path('proposal/<int:proposal_id>/accept/', views_frontend.accept_proposal, name='accept_proposal'),

    # ==================== CONTRACTS ====================
    path('contract/<int:contract_id>/', views_frontend.view_contract, name='view_contract'),
    path('contracts/', views_frontend.my_contracts, name='my_contracts'),
    path('contract/<int:contract_id>/update-status/', views_frontend.update_contract_status, name='update_contract_status'),
    path('contract/<int:contract_id>/fund/', views_frontend.fund_contract, name='fund_contract'),

    # ==================== DISPUTES ====================
    path('contract/<int:contract_id>/dispute/', views_frontend.create_dispute, name='create_dispute'),
    path('dispute/<int:dispute_id>/', views_frontend.view_dispute, name='view_dispute'),

    # ==================== REVIEWS ====================
    path('service/<uuid:service_uuid>/review/', views_frontend.add_review, name='add_review'),
]


# ==================== API URLs (REST API JSON) ====================

api_patterns = [
    path('', include(router.urls)),
]


# ==================== COMBINED URL PATTERNS ====================

urlpatterns = [
    # Frontend HTML views (no prefix)
    path('', include(frontend_patterns)),

    # API REST views (prefixed with api/)
    path('api/', include(api_patterns)),
]
