"""
Security API URLs.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .viewsets import (
    AuditLogViewSet,
    SecurityEventViewSet,
    FailedLoginViewSet,
    UserSessionViewSet,
    PasswordResetRequestViewSet,
    SecurityAnalyticsView,
)

app_name = 'security'

router = DefaultRouter()

# Audit and logging
router.register(r'audit-logs', AuditLogViewSet, basename='audit-log')
router.register(r'security-events', SecurityEventViewSet, basename='security-event')
router.register(r'failed-logins', FailedLoginViewSet, basename='failed-login')

# Session management
router.register(r'sessions', UserSessionViewSet, basename='user-session')

# Password resets
router.register(r'password-resets', PasswordResetRequestViewSet, basename='password-reset')

urlpatterns = [
    path('', include(router.urls)),
    path('analytics/', SecurityAnalyticsView.as_view(), name='analytics'),
]
