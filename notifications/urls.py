"""
URL configuration for notifications app.

Includes both traditional Django views and REST API endpoints.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

app_name = 'notifications'

# REST API Router
router = DefaultRouter()
router.register(r'notifications', views.NotificationViewSet, basename='notification')
router.register(r'notification-preferences', views.NotificationPreferenceViewSet, basename='notification-preference')
router.register(r'notification-templates', views.NotificationTemplateViewSet, basename='notification-template')
router.register(r'notification-channels', views.NotificationChannelViewSet, basename='notification-channel')
router.register(r'notification-types', views.NotificationTypeViewSet, basename='notification-type')
router.register(r'scheduled-notifications', views.ScheduledNotificationViewSet, basename='scheduled-notification')

# Traditional Django URL patterns
urlpatterns = [
    # List and manage notifications (template views)
    path('', views.notification_list, name='notification_list'),
    path('<int:notification_id>/read/', views.notification_mark_read, name='mark_read'),
    path('mark-all-read/', views.notification_mark_all_read, name='mark_all_read'),
    path('<int:notification_id>/delete/', views.notification_delete, name='delete'),

    # Preferences (template view)
    path('preferences/', views.notification_preferences, name='notification_preferences'),

    # Simple API endpoints (legacy, for backward compatibility)
    path('api/count/', views.notification_count_api, name='count_api'),

    # Unsubscribe (public, no auth required)
    path('unsubscribe/<uuid:token>/', views.unsubscribe_view, name='unsubscribe'),

    # REST API routes
    path('api/', include(router.urls)),

    # Bulk notifications endpoint
    path('api/bulk/', views.BulkNotificationView.as_view(), name='bulk_notification'),
]
