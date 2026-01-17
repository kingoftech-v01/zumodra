"""
Newsletter API URLs.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .viewsets import (
    NewsletterViewSet,
    SubscriptionViewSet,
    ArticleViewSet,
    MessageViewSet,
    SubmissionViewSet,
    NewsletterStatsView,
)

app_name = 'newsletter'

router = DefaultRouter()

# Newsletters
router.register(r'newsletters', NewsletterViewSet, basename='newsletter')

# Subscriptions
router.register(r'subscriptions', SubscriptionViewSet, basename='subscription')

# Articles
router.register(r'articles', ArticleViewSet, basename='article')

# Messages
router.register(r'messages', MessageViewSet, basename='message')

# Submissions
router.register(r'submissions', SubmissionViewSet, basename='submission')

urlpatterns = [
    path('', include(router.urls)),
    path('stats/', NewsletterStatsView.as_view(), name='stats'),
]
