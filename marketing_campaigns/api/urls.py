"""
Marketing Campaigns API URLs

DRF router configuration for marketing campaigns API.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .viewsets import (
    ContactViewSet,
    MarketingCampaignViewSet,
    MessageArticleViewSet,
    CampaignAttachmentViewSet,
    CampaignTrackingViewSet,
    VisitEventViewSet,
    ConversionEventViewSet,
    AggregatedStatsViewSet,
    ContactSegmentViewSet,
)

app_name = 'marketing_campaigns'

router = DefaultRouter()

# Contact management
router.register(r'contacts', ContactViewSet, basename='contact')
router.register(r'segments', ContactSegmentViewSet, basename='segment')

# Campaign management
router.register(r'campaigns', MarketingCampaignViewSet, basename='campaign')
router.register(r'articles', MessageArticleViewSet, basename='article')
router.register(r'attachments', CampaignAttachmentViewSet, basename='attachment')

# Tracking
router.register(r'tracking', CampaignTrackingViewSet, basename='tracking')
router.register(r'visits', VisitEventViewSet, basename='visit')
router.register(r'conversions', ConversionEventViewSet, basename='conversion')
router.register(r'stats', AggregatedStatsViewSet, basename='stats')

urlpatterns = router.urls
