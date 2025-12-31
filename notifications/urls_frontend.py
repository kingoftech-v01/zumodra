"""
Notifications Frontend URL Configuration.

Routes for notification template views and HTMX endpoints.
"""

from django.urls import path

from .template_views import (
    # List views
    NotificationListView,
    NotificationFullListView,

    # Action views
    MarkNotificationReadView,
    MarkAllNotificationsReadView,
    DismissNotificationView,
    DeleteNotificationView,

    # Count and toast
    NotificationCountView,
    ToastNotificationView,

    # Preferences
    NotificationPreferencesView,
    UpdateNotificationPreferencesView,
    UnsubscribeView,
)

app_name = 'notifications'

urlpatterns = [
    # ===== NOTIFICATION LIST =====
    path('', NotificationFullListView.as_view(), name='list'),

    # ===== HTMX ENDPOINTS =====
    # Dropdown partial
    path('htmx/dropdown/', NotificationListView.as_view(), name='htmx-dropdown'),

    # Count badge
    path('htmx/count/', NotificationCountView.as_view(), name='htmx-count'),

    # Toast notification
    path('htmx/toast/<uuid:pk>/', ToastNotificationView.as_view(), name='htmx-toast'),

    # ===== NOTIFICATION ACTIONS =====
    path('<uuid:pk>/read/', MarkNotificationReadView.as_view(), name='mark-read'),
    path('<uuid:pk>/dismiss/', DismissNotificationView.as_view(), name='dismiss'),
    path('<uuid:pk>/delete/', DeleteNotificationView.as_view(), name='delete'),
    path('mark-all-read/', MarkAllNotificationsReadView.as_view(), name='mark-all-read'),

    # ===== PREFERENCES =====
    path('preferences/', NotificationPreferencesView.as_view(), name='preferences'),
    path('preferences/update/', UpdateNotificationPreferencesView.as_view(), name='update-preferences'),

    # ===== UNSUBSCRIBE (Public) =====
    path('unsubscribe/<uuid:token>/', UnsubscribeView.as_view(), name='unsubscribe'),
]
