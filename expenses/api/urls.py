"""
Expenses API URLs
"""

from rest_framework.routers import DefaultRouter
from .viewsets import (
    ExpenseCategoryViewSet,
    ExpenseReportViewSet,
    ExpenseLineItemViewSet,
    ExpenseApprovalViewSet,
    ReimbursementViewSet,
    MileageRateViewSet,
)

app_name = 'expenses'

router = DefaultRouter()
router.register(r'categories', ExpenseCategoryViewSet, basename='category')
router.register(r'reports', ExpenseReportViewSet, basename='report')
router.register(r'line-items', ExpenseLineItemViewSet, basename='line-item')
router.register(r'approvals', ExpenseApprovalViewSet, basename='approval')
router.register(r'reimbursements', ReimbursementViewSet, basename='reimbursement')
router.register(r'mileage-rates', MileageRateViewSet, basename='mileage-rate')

urlpatterns = router.urls
