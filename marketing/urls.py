"""
Marketing App URL Configuration.

Template views for:
- Dashboard with analytics
- Prospects/Leads management
- Newsletter campaigns
"""

from django.urls import path

from .views import (
    MarketingDashboardView,
    ProspectsListView,
    CampaignsListView,
)

app_name = 'marketing'

urlpatterns = [
    path('', MarketingDashboardView.as_view(), name='dashboard'),
    path('prospects/', ProspectsListView.as_view(), name='prospects-list'),
    path('campaigns/', CampaignsListView.as_view(), name='campaigns-list'),
]
