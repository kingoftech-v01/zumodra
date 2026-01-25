"""
Services Frontend URLs

Frontend-only URL patterns for the services app.
These URLs are included in core.urls_frontend for the /app/services/ namespace.
"""

from django.urls import path
from . import views_frontend

app_name = 'services'

urlpatterns = [
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
