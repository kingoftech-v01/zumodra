"""
Marketing Campaigns Frontend URLs
"""

from django.urls import path
from .template_views import (
    MarketingCampaignsDashboardView,
    ContactListView,
    ContactDetailView,
    CampaignListView,
    CampaignDetailView,
    VisitEventsListView,
    HTMXCampaignStatsView,
)

app_name = 'marketing_campaigns'

urlpatterns = [
    # Dashboard
    path('', MarketingCampaignsDashboardView.as_view(), name='dashboard'),

    # Contacts
    path('contacts/', ContactListView.as_view(), name='contact-list'),
    path('contacts/<uuid:pk>/', ContactDetailView.as_view(), name='contact-detail'),

    # Campaigns
    path('campaigns/', CampaignListView.as_view(), name='campaign-list'),
    path('campaigns/<uuid:pk>/', CampaignDetailView.as_view(), name='campaign-detail'),

    # Visit Events
    path('visits/', VisitEventsListView.as_view(), name='visit-events'),

    # HTMX partials
    path('htmx/stats/', HTMXCampaignStatsView.as_view(), name='htmx-stats'),
]
