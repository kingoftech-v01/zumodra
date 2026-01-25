"""
Tax Frontend URLs
"""

from django.urls import path
from .template_views import (
    TaxDashboardView,
    AvalaraConfigDetailView,
    TaxRateListView,
    TaxCalculationListView,
    TaxCalculationDetailView,
    TaxExemptionListView,
    TaxExemptionDetailView,
    TaxRemittanceListView,
    TaxRemittanceDetailView,
    TaxReportListView,
    TaxReportDetailView,
    HTMXTaxStatsView,
)

app_name = 'tax'

urlpatterns = [
    # Dashboard
    path('', TaxDashboardView.as_view(), name='dashboard'),

    # Avalara Configuration
    path('config/avalara/', AvalaraConfigDetailView.as_view(), name='avalara-config'),

    # Tax Rates
    path('rates/', TaxRateListView.as_view(), name='rate-list'),

    # Tax Calculations
    path('calculations/', TaxCalculationListView.as_view(), name='calculation-list'),
    path('calculations/<uuid:pk>/', TaxCalculationDetailView.as_view(), name='calculation-detail'),

    # Tax Exemptions
    path('exemptions/', TaxExemptionListView.as_view(), name='exemption-list'),
    path('exemptions/<uuid:pk>/', TaxExemptionDetailView.as_view(), name='exemption-detail'),

    # Tax Remittances
    path('remittances/', TaxRemittanceListView.as_view(), name='remittance-list'),
    path('remittances/<uuid:pk>/', TaxRemittanceDetailView.as_view(), name='remittance-detail'),

    # Tax Reports
    path('reports/', TaxReportListView.as_view(), name='report-list'),
    path('reports/<uuid:pk>/', TaxReportDetailView.as_view(), name='report-detail'),

    # HTMX Partials
    path('htmx/stats/', HTMXTaxStatsView.as_view(), name='htmx-stats'),
]
