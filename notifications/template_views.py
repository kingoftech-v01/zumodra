"""
Notification Template Views - HTMX endpoints for notifications.

This module implements template-based views for:
- Notification dropdown/list
- Mark notifications as read
- Notification preferences
- Real-time notification updates

All views are optimized for HTMX partial responses.
"""

import json
import logging

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.utils import timezone
from django.views import View
from django.views.generic import TemplateView, ListView, UpdateView

from .models import Notification, NotificationPreference

logger = logging.getLogger(__name__)


# =============================================================================
# NOTIFICATION LIST VIEWS
# =============================================================================

class NotificationListView(LoginRequiredMixin, View):
    """
    HTMX partial for notification dropdown/list.

    Returns the 10 most recent unread notifications for the header dropdown.
    """

    def get(self, request):
        user = request.user

        # Get unread notifications (limited for dropdown)
        notifications = Notification.objects.filter(
            recipient=user,
            is_read=False
        ).select_related('channel').order_by('-created_at')[:10]

        # Get total unread count
        unread_count = Notification.objects.filter(
            recipient=user,
            is_read=False
        ).count()

        context = {
            'notifications': notifications,
            'unread_count': unread_count,
        }

        if request.headers.get('HX-Request'):
            return render(request, 'partials/_notification_list.html', context)

        return JsonResponse({
            'notifications': [
                {
                    'id': str(n.uuid),
                    'title': n.title,
                    'message': n.message[:100],
                    'type': n.notification_type,
                    'created_at': n.created_at.isoformat(),
                    'action_url': n.action_url,
                }
                for n in notifications
            ],
            'unread_count': unread_count,
        })


class NotificationFullListView(LoginRequiredMixin, ListView):
    """
    Full notifications page with pagination and filtering.
    """
    model = Notification
    template_name = 'notifications/list.html'
    context_object_name = 'notifications'
    paginate_by = 25

    def get_queryset(self):
        queryset = Notification.objects.filter(
            recipient=self.request.user
        ).select_related('channel').order_by('-created_at')

        # Filter by read status
        status = self.request.GET.get('status')
        if status == 'unread':
            queryset = queryset.filter(is_read=False)
        elif status == 'read':
            queryset = queryset.filter(is_read=True)

        # Filter by type
        notification_type = self.request.GET.get('type')
        if notification_type:
            queryset = queryset.filter(notification_type=notification_type)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get notification type counts
        type_counts = Notification.objects.filter(
            recipient=self.request.user
        ).values('notification_type').annotate(
            count=Count('id')
        ).order_by('-count')

        context['type_counts'] = type_counts
        context['notification_types'] = Notification.NOTIFICATION_TYPES

        # Current filters
        context['current_filters'] = {
            'status': self.request.GET.get('status', ''),
            'type': self.request.GET.get('type', ''),
        }

        # Stats
        context['stats'] = {
            'total': Notification.objects.filter(recipient=self.request.user).count(),
            'unread': Notification.objects.filter(recipient=self.request.user, is_read=False).count(),
        }

        return context


# =============================================================================
# NOTIFICATION ACTION VIEWS
# =============================================================================

class MarkNotificationReadView(LoginRequiredMixin, View):
    """
    Mark a single notification as read.

    Returns empty response for HTMX with trigger to update UI.
    """

    def post(self, request, pk):
        notification = get_object_or_404(
            Notification,
            pk=pk,
            recipient=request.user
        )

        notification.mark_as_read()

        if request.headers.get('HX-Request'):
            response = HttpResponse(status=204)
            response['HX-Trigger'] = json.dumps({
                'notificationRead': {
                    'id': str(notification.pk),
                    'unread_count': Notification.objects.filter(
                        recipient=request.user, is_read=False
                    ).count(),
                }
            })
            return response

        return JsonResponse({'status': 'success'})


class MarkAllNotificationsReadView(LoginRequiredMixin, View):
    """
    Mark all notifications as read.
    """

    def post(self, request):
        updated = Notification.objects.filter(
            recipient=request.user,
            is_read=False
        ).update(
            is_read=True,
            read_at=timezone.now()
        )

        if request.headers.get('HX-Request'):
            response = HttpResponse(status=204)
            response['HX-Trigger'] = json.dumps({
                'allNotificationsRead': {
                    'updated_count': updated,
                }
            })
            return response

        return JsonResponse({'status': 'success', 'updated': updated})


class DismissNotificationView(LoginRequiredMixin, View):
    """
    Dismiss a notification (hide without marking as read).
    """

    def post(self, request, pk):
        notification = get_object_or_404(
            Notification,
            pk=pk,
            recipient=request.user
        )

        notification.dismiss()

        if request.headers.get('HX-Request'):
            response = HttpResponse(status=204)
            response['HX-Trigger'] = 'notificationDismissed'
            return response

        return JsonResponse({'status': 'success'})


class DeleteNotificationView(LoginRequiredMixin, View):
    """
    Delete a notification permanently.
    """

    def post(self, request, pk):
        notification = get_object_or_404(
            Notification,
            pk=pk,
            recipient=request.user
        )

        notification.delete()

        if request.headers.get('HX-Request'):
            response = HttpResponse(status=204)
            response['HX-Trigger'] = 'notificationDeleted'
            return response

        return JsonResponse({'status': 'success'})


# =============================================================================
# NOTIFICATION COUNT VIEW
# =============================================================================

class NotificationCountView(LoginRequiredMixin, View):
    """
    Get current unread notification count.

    Used for polling or WebSocket fallback.
    """

    def get(self, request):
        count = Notification.objects.filter(
            recipient=request.user,
            is_read=False
        ).count()

        if request.headers.get('HX-Request'):
            return render(request, 'partials/_notification_badge.html', {
                'unread_count': count
            })

        return JsonResponse({'unread_count': count})


# =============================================================================
# NOTIFICATION PREFERENCES
# =============================================================================

class NotificationPreferencesView(LoginRequiredMixin, TemplateView):
    """
    View and edit notification preferences.
    """
    template_name = 'notifications/preferences.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get or create preferences
        preferences, created = NotificationPreference.objects.get_or_create(
            user=self.request.user,
            defaults={
                'notifications_enabled': True,
                'channel_preferences': {
                    'email': True,
                    'in_app': True,
                    'push': False,
                    'sms': False,
                },
                'type_preferences': {},
            }
        )

        context['preferences'] = preferences
        context['notification_types'] = Notification.NOTIFICATION_TYPES

        # Group notification types by category
        type_categories = {
            'HR & Recruitment': [
                'application_received', 'application_reviewed', 'interview_scheduled',
                'interview_reminder', 'interview_cancelled', 'offer_sent',
                'offer_accepted', 'offer_declined', 'onboarding_task_due', 'onboarding_complete'
            ],
            'Time & Attendance': [
                'time_off_requested', 'time_off_approved', 'time_off_denied',
                'timesheet_reminder', 'timesheet_approved'
            ],
            'Messages & Communication': [
                'new_message', 'message_reply'
            ],
            'Appointments': [
                'appointment_booked', 'appointment_reminder',
                'appointment_cancelled', 'appointment_rescheduled'
            ],
            'Account & Security': [
                'account_created', 'password_changed', 'login_alert',
                'two_factor_enabled', 'account_suspended'
            ],
        }

        context['type_categories'] = type_categories

        return context


class UpdateNotificationPreferencesView(LoginRequiredMixin, View):
    """
    Update notification preferences via HTMX.
    """

    def post(self, request):
        preferences, created = NotificationPreference.objects.get_or_create(
            user=request.user
        )

        # Parse form data
        field = request.POST.get('field')
        value = request.POST.get('value')

        if field == 'notifications_enabled':
            preferences.notifications_enabled = value == 'true'

        elif field == 'quiet_hours_enabled':
            preferences.quiet_hours_enabled = value == 'true'

        elif field == 'quiet_hours_start':
            from django.utils.dateparse import parse_time
            preferences.quiet_hours_start = parse_time(value)

        elif field == 'quiet_hours_end':
            from django.utils.dateparse import parse_time
            preferences.quiet_hours_end = parse_time(value)

        elif field == 'email_digest_frequency':
            preferences.email_digest_frequency = value

        elif field.startswith('channel_'):
            channel = field.replace('channel_', '')
            channel_prefs = preferences.channel_preferences.copy()
            channel_prefs[channel] = value == 'true'
            preferences.channel_preferences = channel_prefs

        elif field.startswith('type_'):
            # Format: type_notification_type_channel
            parts = field.split('_', 2)
            if len(parts) == 3:
                _, notification_type, channel = parts
                type_prefs = preferences.type_preferences.copy()
                if notification_type not in type_prefs:
                    type_prefs[notification_type] = {}
                type_prefs[notification_type][channel] = value == 'true'
                preferences.type_preferences = type_prefs

        preferences.save()

        if request.headers.get('HX-Request'):
            response = HttpResponse(status=204)
            response['HX-Trigger'] = 'preferencesUpdated'
            return response

        return JsonResponse({'status': 'success'})


class UnsubscribeView(View):
    """
    Handle unsubscribe links (no login required).
    """

    def get(self, request, token):
        try:
            preferences = NotificationPreference.objects.get(unsubscribe_token=token)

            notification_type = request.GET.get('type')
            if notification_type:
                # Unsubscribe from specific type
                if notification_type not in preferences.unsubscribed_types:
                    preferences.unsubscribed_types.append(notification_type)
                    preferences.save()
                message = f'You have been unsubscribed from {notification_type} notifications.'
            else:
                # Global unsubscribe
                preferences.global_unsubscribe = True
                preferences.save()
                message = 'You have been unsubscribed from all notifications.'

            return render(request, 'notifications/unsubscribe_success.html', {
                'message': message
            })

        except NotificationPreference.DoesNotExist:
            return render(request, 'notifications/unsubscribe_error.html', {
                'message': 'Invalid unsubscribe link.'
            })


# =============================================================================
# TOAST NOTIFICATION VIEW
# =============================================================================

class ToastNotificationView(LoginRequiredMixin, View):
    """
    View for rendering toast notifications via HTMX.

    Used when a new notification arrives to show a toast.
    """

    def get(self, request, pk):
        notification = get_object_or_404(
            Notification,
            pk=pk,
            recipient=request.user
        )

        return render(request, 'partials/_notification_toast.html', {
            'notification': notification
        })
