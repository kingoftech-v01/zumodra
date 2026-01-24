"""
Payroll API URLs
"""

from rest_framework.routers import DefaultRouter
from .viewsets import (
    PayrollRunViewSet,
    EmployeePaymentViewSet,
    DirectDepositViewSet,
    PayStubViewSet,
    PayrollDeductionViewSet,
    PayrollTaxViewSet,
)

app_name = 'payroll'

router = DefaultRouter()
router.register(r'runs', PayrollRunViewSet, basename='payroll-run')
router.register(r'payments', EmployeePaymentViewSet, basename='employee-payment')
router.register(r'direct-deposits', DirectDepositViewSet, basename='direct-deposit')
router.register(r'paystubs', PayStubViewSet, basename='paystub')
router.register(r'deductions', PayrollDeductionViewSet, basename='deduction')
router.register(r'taxes', PayrollTaxViewSet, basename='tax')

urlpatterns = router.urls
