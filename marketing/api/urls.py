"""
Marketing API URLs.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .viewsets import (
    VisitEventViewSet,
    AggregatedStatsViewSet,
    ProspectViewSet,
    NewsletterCampaignViewSet,
    NewsletterSubscriberViewSet,
    ConversionEventViewSet,
    MarketingAnalyticsView,
)

app_name = 'marketing-api'

router = DefaultRouter()

# Visit tracking
router.register(r'visits', VisitEventViewSet, basename='visit')
router.register(r'stats', AggregatedStatsViewSet, basename='aggregated-stats')

# Prospects/Leads
router.register(r'prospects', ProspectViewSet, basename='prospect')

# Newsletter
router.register(r'campaigns', NewsletterCampaignViewSet, basename='campaign')
router.register(r'subscribers', NewsletterSubscriberViewSet, basename='subscriber')

# Conversions
router.register(r'conversions', ConversionEventViewSet, basename='conversion')

urlpatterns = [
    path('', include(router.urls)),
    path('analytics/', MarketingAnalyticsView.as_view(), name='analytics'),
]
