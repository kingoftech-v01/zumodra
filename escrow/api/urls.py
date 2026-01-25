"""
Escrow API URLs
"""

from rest_framework.routers import DefaultRouter
from .viewsets import (
    EscrowTransactionViewSet,
    MilestonePaymentViewSet,
    EscrowReleaseViewSet,
    DisputeViewSet,
    EscrowPayoutViewSet,
    EscrowAuditViewSet,
)

app_name = 'escrow'

router = DefaultRouter()
router.register(r'transactions', EscrowTransactionViewSet, basename='escrow-transaction')
router.register(r'milestones', MilestonePaymentViewSet, basename='milestone')
router.register(r'releases', EscrowReleaseViewSet, basename='release')
router.register(r'disputes', DisputeViewSet, basename='dispute')
router.register(r'payouts', EscrowPayoutViewSet, basename='payout')
router.register(r'audit', EscrowAuditViewSet, basename='audit')

urlpatterns = router.urls
