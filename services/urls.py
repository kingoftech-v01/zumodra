from django.urls import path
from .views import *

app_name = 'services'

urlpatterns = [
    # ==================== SERVICE BROWSING ====================
    path('', browse_services, name='service_list'),  # Main service listing page
    path('service/<uuid:service_uuid>/', service_detail, name='service_detail'),
    path('service/<uuid:service_uuid>/like/', like_service, name='like_service'),
    path('nearby/', browse_nearby_services, name='browse_nearby_services'),
    path('search/ajax/', search_services_ajax, name='search_services_ajax'),

    # ==================== PROVIDER PROFILE ====================
    path('provider/dashboard/', provider_dashboard, name='provider_dashboard'),
    path('provider/create/', create_provider_profile, name='create_provider_profile'),
    path('provider/edit/', edit_provider_profile, name='edit_provider_profile'),
    path('provider/<uuid:provider_uuid>/', provider_profile_view, name='provider_profile_view'),

    # ==================== SERVICE CRUD (Provider) ====================
    path('service/create/', create_service, name='create_service'),
    path('service/<uuid:service_uuid>/edit/', edit_service, name='edit_service'),
    path('service/<uuid:service_uuid>/delete/', delete_service, name='delete_service'),

    # ==================== CLIENT REQUESTS ====================
    path('request/create/', create_service_request, name='create_service_request'),
    path('request/my-requests/', my_requests, name='my_requests'),
    path('request/<uuid:request_uuid>/', view_request, name='view_request'),
    path('request/<uuid:request_uuid>/submit-proposal/', submit_proposal, name='submit_proposal'),
    path('proposal/<int:proposal_id>/accept/', accept_proposal, name='accept_proposal'),

    # ==================== CONTRACTS ====================
    path('contract/<int:contract_id>/', view_contract, name='view_contract'),
    path('contracts/', my_contracts, name='my_contracts'),
    path('contract/<int:contract_id>/update-status/', update_contract_status, name='update_contract_status'),
    path('contract/<int:contract_id>/fund/', fund_contract, name='fund_contract'),

    # ==================== DISPUTES ====================
    path('contract/<int:contract_id>/dispute/', create_dispute, name='create_dispute'),
    path('dispute/<int:dispute_id>/', view_dispute, name='view_dispute'),

    # ==================== REVIEWS ====================
    path('service/<uuid:service_uuid>/review/', add_review, name='add_review'),
]
