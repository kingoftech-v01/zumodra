"""
Tax API URLs
"""

from rest_framework.routers import DefaultRouter
from .viewsets import (
    AvalaraConfigViewSet,
    TaxRateViewSet,
    TaxCalculationViewSet,
    TaxExemptionViewSet,
    TaxRemittanceViewSet,
    TaxReportViewSet,
)

app_name = 'tax'

router = DefaultRouter()
router.register(r'avalara-config', AvalaraConfigViewSet, basename='avalara-config')
router.register(r'rates', TaxRateViewSet, basename='rate')
router.register(r'calculations', TaxCalculationViewSet, basename='calculation')
router.register(r'exemptions', TaxExemptionViewSet, basename='exemption')
router.register(r'remittances', TaxRemittanceViewSet, basename='remittance')
router.register(r'reports', TaxReportViewSet, basename='report')

urlpatterns = router.urls
