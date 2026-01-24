"""
Notification Views and ViewSets.

Provides tenant-aware REST API views and traditional Django views for notifications.
Uses base classes from api.base for consistent tenant handling and response formats.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse, HttpResponse
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.utils import timezone
from django.views import View
from django.views.decorators.http import require_POST
from django.utils.translation import gettext_lazy as _

from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter

from api.base import (
    TenantAwareViewSet,
    TenantAwareReadOnlyViewSet,
    TenantAwareAPIView,
    APIResponse,
    StandardPagination,
    CursorBasedPagination,
)
from .models import (
    Notification,
    NotificationChannel,
    NotificationTemplate,
    NotificationPreference,
    ScheduledNotification,
)
from .api.serializers import (
    NotificationListSerializer,
    NotificationSerializer,
    NotificationDetailSerializer,
    NotificationCreateSerializer,
    BulkNotificationSerializer,
    NotificationActionSerializer,
    NotificationChannelSerializer,
    NotificationTemplateListSerializer,
    NotificationTemplateDetailSerializer,
    NotificationPreferenceSerializer,
    NotificationPreferenceUpdateSerializer,
    ScheduledNotificationSerializer,
    NotificationStatsSerializer,
    UnsubscribeSerializer,
    RegisterDeviceSerializer,
    NotificationTypeSerializer,
    UnreadCountSerializer,
)
from .services import notification_service


# =============================================================================
# PAGINATION
# =============================================================================

class NotificationPagination(CursorBasedPagination):
    """
    Cursor-based pagination for notifications.
    Optimized for real-time data and infinite scroll.
    """
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100
    ordering = '-created_at'


class StandardNotificationPagination(StandardPagination):
    """Standard page-based pagination for notifications."""
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


# =============================================================================
# API VIEWSETS
# =============================================================================

class NotificationViewSet(TenantAwareViewSet):
    """
    ViewSet for managing user notifications.

    Provides list, retrieve, mark_read, dismiss, and bulk actions.
    Notifications are automatically scoped to the authenticated user.

    Endpoints:
    - GET /notifications/ - List user's notifications
    - GET /notifications/{id}/ - Get notification detail
    - POST /notifications/ - Create notification (staff only)
    - POST /notifications/{id}/mark_read/ - Mark as read
    - POST /notifications/{id}/mark_unread/ - Mark as unread
    - POST /notifications/{id}/dismiss/ - Dismiss notification
    - POST /notifications/mark_all_read/ - Mark all as read
    - POST /notifications/dismiss_all/ - Dismiss all
    - POST /notifications/bulk_action/ - Bulk actions
    - GET /notifications/unread_count/ - Get unread count
    - GET /notifications/stats/ - Get notification statistics
    """

    serializer_class = NotificationListSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = NotificationPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['notification_type', 'status', 'priority', 'is_read', 'is_dismissed']
    search_fields = ['title', 'message']
    ordering_fields = ['created_at', 'priority', 'is_read']
    ordering = ['-created_at']
    tenant_field = None  # Notifications are user-scoped, not tenant-scoped

    def get_queryset(self):
        """Filter notifications to current user only."""
        return Notification.objects.filter(
            recipient=self.request.user
        ).select_related('channel', 'sender', 'template')

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return NotificationDetailSerializer
        if self.action == 'create':
            return NotificationCreateSerializer
        return NotificationListSerializer

    def create(self, request, *args, **kwargs):
        """
        Create a new notification (admin/staff only).

        Sends notification through configured channels.
        """
        if not request.user.is_staff:
            return APIResponse.forbidden(
                message=_("Only staff can create notifications"),
                required_permission='notifications.add_notification'
            )

        serializer = NotificationCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        from django.contrib.auth import get_user_model
        User = get_user_model()

        recipient = User.objects.get(pk=serializer.validated_data['recipient_id'])

        results = notification_service.send_notification(
            recipient=recipient,
            notification_type=serializer.validated_data['notification_type'],
            title=serializer.validated_data['title'],
            message=serializer.validated_data['message'],
            channels=serializer.validated_data.get('channels'),
            sender=request.user,
            action_url=serializer.validated_data.get('action_url', ''),
            action_text=serializer.validated_data.get('action_text', 'View'),
            priority=serializer.validated_data.get('priority', 'normal'),
            context_data=serializer.validated_data.get('context_data', {}),
            template_name=serializer.validated_data.get('template_name'),
        )

        return APIResponse.created(
            data={
                'success': any(r.success for r in results),
                'results': [
                    {
                        'channel': r.channel_type,
                        'success': r.success,
                        'notification_id': r.notification_id,
                        'error': r.error_message,
                    }
                    for r in results
                ]
            },
            message=_("Notification sent successfully")
        )

    @action(detail=True, methods=['post'])
    def mark_read(self, request, pk=None):
        """Mark a notification as read."""
        notification = self.get_object()
        notification.mark_as_read()

        # Broadcast unread count update via WebSocket
        self._broadcast_unread_count_update(request.user)

        return APIResponse.success(
            data={'is_read': True},
            message=_("Notification marked as read")
        )

    @action(detail=True, methods=['post'])
    def mark_unread(self, request, pk=None):
        """Mark a notification as unread."""
        notification = self.get_object()
        notification.mark_as_unread()

        self._broadcast_unread_count_update(request.user)

        return APIResponse.success(
            data={'is_read': False},
            message=_("Notification marked as unread")
        )

    @action(detail=True, methods=['post'])
    def dismiss(self, request, pk=None):
        """Dismiss a notification."""
        notification = self.get_object()
        notification.dismiss()

        self._broadcast_unread_count_update(request.user)

        return APIResponse.success(
            data={'is_dismissed': True},
            message=_("Notification dismissed")
        )

    @action(detail=False, methods=['post'])
    def mark_all_read(self, request):
        """Mark all notifications as read for current user."""
        count = notification_service.mark_all_as_read(request.user)

        self._broadcast_unread_count_update(request.user)

        return APIResponse.success(
            data={'count': count, 'unread_count': 0},
            message=_("%(count)d notifications marked as read") % {'count': count}
        )

    @action(detail=False, methods=['post'])
    def dismiss_all(self, request):
        """Dismiss all notifications for current user."""
        count = notification_service.dismiss_all(request.user)

        self._broadcast_unread_count_update(request.user)

        return APIResponse.success(
            data={'count': count},
            message=_("%(count)d notifications dismissed") % {'count': count}
        )

    @action(detail=False, methods=['post'])
    def bulk_action(self, request):
        """Perform bulk actions on multiple notifications."""
        serializer = NotificationActionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        action_type = serializer.validated_data['action']
        notification_ids = serializer.validated_data.get('notification_ids', [])

        if action_type == 'mark_all_read':
            count = notification_service.mark_all_as_read(request.user)
            self._broadcast_unread_count_update(request.user)
            return APIResponse.success(
                data={'count': count},
                message=_("All notifications marked as read")
            )

        if action_type == 'dismiss_all':
            count = notification_service.dismiss_all(request.user)
            self._broadcast_unread_count_update(request.user)
            return APIResponse.success(
                data={'count': count},
                message=_("All notifications dismissed")
            )

        # Filter to only user's notifications
        notifications = Notification.objects.filter(
            id__in=notification_ids,
            recipient=request.user
        )

        if action_type == 'mark_read':
            count = notifications.update(
                is_read=True,
                read_at=timezone.now(),
                status='read'
            )
        elif action_type == 'mark_unread':
            count = notifications.update(
                is_read=False,
                read_at=None,
                status='delivered'
            )
        elif action_type == 'dismiss':
            count = notifications.update(
                is_dismissed=True,
                dismissed_at=timezone.now()
            )
        else:
            return APIResponse.error(
                message=_("Invalid action"),
                error_code="INVALID_ACTION"
            )

        self._broadcast_unread_count_update(request.user)

        return APIResponse.success(
            data={'count': count},
            message=_("Bulk action completed")
        )

    @action(detail=False, methods=['get'])
    def unread_count(self, request):
        """
        Get count of unread notifications.

        Used for notification badge updates.
        Returns count and timestamp of last notification.
        """
        count = notification_service.get_unread_count(request.user)

        last_notification = Notification.objects.filter(
            recipient=request.user,
            is_read=False
        ).order_by('-created_at').first()

        return APIResponse.success(
            data={
                'unread_count': count,
                'last_notification_at': last_notification.created_at if last_notification else None
            }
        )

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """
        Get notification statistics for current user.

        Returns counts by type, channel, status, and priority.
        """
        queryset = self.get_queryset()

        stats = {
            'total_notifications': queryset.count(),
            'unread_count': queryset.filter(is_read=False).count(),
            'read_count': queryset.filter(is_read=True).count(),
            'dismissed_count': queryset.filter(is_dismissed=True).count(),
            'by_type': dict(
                queryset.values('notification_type')
                .annotate(count=Count('id'))
                .values_list('notification_type', 'count')
            ),
            'by_channel': dict(
                queryset.values('channel__channel_type')
                .annotate(count=Count('id'))
                .values_list('channel__channel_type', 'count')
            ),
            'by_status': dict(
                queryset.values('status')
                .annotate(count=Count('id'))
                .values_list('status', 'count')
            ),
            'by_priority': dict(
                queryset.values('priority')
                .annotate(count=Count('id'))
                .values_list('priority', 'count')
            ),
            'recent_notifications': NotificationListSerializer(
                queryset[:5], many=True, context=self.get_serializer_context()
            ).data,
        }

        return APIResponse.success(data=stats)

    def _broadcast_unread_count_update(self, user):
        """Broadcast unread count update via WebSocket."""
        try:
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync

            channel_layer = get_channel_layer()
            count = notification_service.get_unread_count(user)

            async_to_sync(channel_layer.group_send)(
                f"notifications_{user.id}",
                {
                    'type': 'unread_count_update',
                    'count': count,
                }
            )
        except Exception:
            # WebSocket broadcast is optional, don't fail the request
            pass


class NotificationPreferenceViewSet(TenantAwareViewSet):
    """
    ViewSet for managing notification preferences.

    Users can manage their notification preferences including:
    - Channel preferences (email, SMS, push, in-app)
    - Type preferences (which notifications to receive)
    - Quiet hours
    - Digest frequency

    Endpoints:
    - GET /notification-preferences/ - Get current preferences
    - PUT /notification-preferences/{id}/ - Update preferences
    - POST /notification-preferences/register_device/ - Register device for push
    - POST /notification-preferences/unsubscribe/ - Unsubscribe from notifications
    """

    serializer_class = NotificationPreferenceSerializer
    permission_classes = [permissions.IsAuthenticated]
    tenant_field = None  # Preferences are user-scoped

    def get_queryset(self):
        return NotificationPreference.objects.filter(user=self.request.user)

    def get_object(self):
        """Get or create preferences for current user."""
        obj, _ = NotificationPreference.objects.get_or_create(user=self.request.user)
        return obj

    def list(self, request, *args, **kwargs):
        """Return current user's preferences."""
        obj = self.get_object()
        serializer = self.get_serializer(obj)
        return APIResponse.success(data=serializer.data)

    def update(self, request, *args, **kwargs):
        """Update current user's preferences."""
        obj = self.get_object()
        serializer = NotificationPreferenceUpdateSerializer(
            obj, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return APIResponse.updated(
            data=NotificationPreferenceSerializer(obj).data,
            message=_("Notification preferences updated")
        )

    @action(detail=False, methods=['post'])
    def register_device(self, request):
        """
        Register a device for push notifications.

        Supports both FCM (Firebase) and APNS (Apple) tokens.
        """
        serializer = RegisterDeviceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=request.user)
        return APIResponse.success(
            message=_("Device registered for push notifications")
        )

    @action(detail=False, methods=['post'])
    def unsubscribe(self, request):
        """
        Unsubscribe from specific notification types or globally.

        Requires valid unsubscribe token.
        """
        serializer = UnsubscribeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data['token']
        notification_type = serializer.validated_data.get('notification_type')
        global_unsub = serializer.validated_data.get('global_unsubscribe', False)

        try:
            prefs = NotificationPreference.objects.get(unsubscribe_token=token)

            if global_unsub:
                prefs.global_unsubscribe = True
            elif notification_type:
                if notification_type not in prefs.unsubscribed_types:
                    prefs.unsubscribed_types.append(notification_type)

            prefs.save()
            return APIResponse.success(
                message=_("Successfully unsubscribed")
            )

        except NotificationPreference.DoesNotExist:
            return APIResponse.not_found(
                message=_("Invalid unsubscribe token")
            )


class NotificationTypeViewSet(viewsets.ViewSet):
    """
    Admin ViewSet for managing notification types.

    Lists all available notification types with their configurations.
    """

    permission_classes = [permissions.IsAdminUser]

    def list(self, request):
        """Get all available notification types."""
        types = [
            {
                'value': value,
                'label': str(label),
                'category': self._get_category(value),
                'description': self._get_description(value),
                'default_channels': self._get_default_channels(value),
                'is_system': self._is_system_type(value),
            }
            for value, label in Notification.NOTIFICATION_TYPES
        ]

        return APIResponse.success(data=types)

    def _get_category(self, notification_type):
        """Get category for notification type."""
        categories = {
            'application_': 'HR & Recruitment',
            'interview_': 'HR & Recruitment',
            'offer_': 'HR & Recruitment',
            'onboarding_': 'HR & Recruitment',
            'time_': 'Time & Attendance',
            'timesheet_': 'Time & Attendance',
            'proposal_': 'Services & Contracts',
            'contract_': 'Services & Contracts',
            'payment_': 'Payments & Finance',
            'invoice_': 'Payments & Finance',
            'escrow_': 'Payments & Finance',
            'refund_': 'Payments & Finance',
            'review_': 'Reviews & Ratings',
            'message_': 'Messages',
            'new_message': 'Messages',
            'appointment_': 'Appointments',
            'account_': 'Account & Security',
            'password_': 'Account & Security',
            'login_': 'Account & Security',
            'two_factor_': 'Account & Security',
            'system_': 'System',
            'feature_': 'System',
            'policy_': 'System',
            'welcome_': 'Marketing',
            'weekly_': 'Marketing',
            'daily_': 'Marketing',
            'promotional': 'Marketing',
            'event_': 'Marketing',
        }

        for prefix, category in categories.items():
            if notification_type.startswith(prefix):
                return category
        return 'Other'

    def _get_description(self, notification_type):
        """Get description for notification type."""
        descriptions = {
            'new_message': 'New message received',
            'payment_received': 'Payment received confirmation',
            'contract_created': 'New contract created',
            'appointment_booked': 'New appointment booked',
        }
        return descriptions.get(notification_type, '')

    def _get_default_channels(self, notification_type):
        """Get default channels for notification type."""
        # System/security notifications go to all channels
        if notification_type in ['login_alert', 'password_changed', 'two_factor_enabled']:
            return ['email', 'in_app', 'push']
        # Payment notifications are important
        if notification_type.startswith('payment_') or notification_type.startswith('escrow_'):
            return ['email', 'in_app', 'push']
        # Default to email and in-app
        return ['email', 'in_app']

    def _is_system_type(self, notification_type):
        """Check if notification type is a system type."""
        return notification_type.startswith('system_') or notification_type.startswith('policy_')


class NotificationTemplateViewSet(TenantAwareViewSet):
    """
    ViewSet for managing notification templates (admin only).

    Endpoints:
    - GET /notification-templates/ - List templates
    - POST /notification-templates/ - Create template
    - GET /notification-templates/{id}/ - Get template detail
    - PUT /notification-templates/{id}/ - Update template
    - DELETE /notification-templates/{id}/ - Delete template
    - POST /notification-templates/{id}/preview/ - Preview template with context
    - GET /notification-templates/types/ - Get available template types
    """

    queryset = NotificationTemplate.objects.all()
    permission_classes = [permissions.IsAdminUser]
    pagination_class = StandardNotificationPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['template_type', 'channel', 'language', 'is_active']
    search_fields = ['name', 'subject', 'description']
    ordering_fields = ['name', 'template_type', 'created_at']
    ordering = ['template_type', 'channel', 'language']
    tenant_field = None  # Templates are global

    def get_serializer_class(self):
        if self.action in ['list']:
            return NotificationTemplateListSerializer
        return NotificationTemplateDetailSerializer

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def preview(self, request, pk=None):
        """Preview a template with sample context."""
        template = self.get_object()
        context = request.data.get('context', template.default_context)

        try:
            return APIResponse.success(
                data={
                    'subject': template.render_subject(context),
                    'body': template.render_body(context),
                    'html_body': template.render_html_body(context),
                }
            )
        except Exception as e:
            return APIResponse.error(
                message=str(e),
                error_code="TEMPLATE_RENDER_ERROR"
            )

    @action(detail=False, methods=['get'])
    def types(self, request):
        """Get all available template types."""
        return APIResponse.success(
            data=[
                {'value': value, 'label': str(label)}
                for value, label in NotificationTemplate.TEMPLATE_TYPES
            ]
        )


class NotificationChannelViewSet(TenantAwareViewSet):
    """
    ViewSet for managing notification channels (admin only).

    Endpoints:
    - GET /notification-channels/ - List channels
    - POST /notification-channels/ - Create channel
    - GET /notification-channels/{id}/ - Get channel detail
    - PUT /notification-channels/{id}/ - Update channel
    - DELETE /notification-channels/{id}/ - Delete channel
    - GET /notification-channels/types/ - Get available channel types
    """

    queryset = NotificationChannel.objects.all()
    serializer_class = NotificationChannelSerializer
    permission_classes = [permissions.IsAdminUser]
    tenant_field = None  # Channels are global

    @action(detail=False, methods=['get'])
    def types(self, request):
        """Get all available channel types."""
        return APIResponse.success(
            data=[
                {'value': value, 'label': str(label)}
                for value, label in NotificationChannel.CHANNEL_TYPES
            ]
        )


class ScheduledNotificationViewSet(TenantAwareViewSet):
    """
    ViewSet for managing scheduled notifications.

    Endpoints:
    - GET /scheduled-notifications/ - List scheduled notifications
    - POST /scheduled-notifications/ - Create scheduled notification
    - GET /scheduled-notifications/{id}/ - Get detail
    - PUT /scheduled-notifications/{id}/ - Update
    - DELETE /scheduled-notifications/{id}/ - Delete
    - POST /scheduled-notifications/{id}/cancel/ - Cancel scheduled notification
    - POST /scheduled-notifications/{id}/activate/ - Activate scheduled notification
    """

    serializer_class = ScheduledNotificationSerializer
    permission_classes = [permissions.IsAdminUser]
    pagination_class = StandardNotificationPagination
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['is_active', 'is_processed', 'recurrence']
    ordering_fields = ['scheduled_at', 'created_at']
    ordering = ['scheduled_at']
    tenant_field = None

    def get_queryset(self):
        return ScheduledNotification.objects.select_related(
            'template', 'recipient', 'created_by'
        )

    def perform_create(self, serializer):
        instance = serializer.save(created_by=self.request.user)
        instance.calculate_next_run()
        instance.save()

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel a scheduled notification."""
        scheduled = self.get_object()
        scheduled.is_active = False
        scheduled.save()
        return APIResponse.success(
            message=_("Scheduled notification cancelled")
        )

    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        """Activate a scheduled notification."""
        scheduled = self.get_object()
        scheduled.is_active = True
        scheduled.save()
        return APIResponse.success(
            message=_("Scheduled notification activated")
        )


class BulkNotificationView(TenantAwareAPIView):
    """
    API view for sending bulk notifications.

    POST /notifications/bulk/

    Send the same notification to multiple users at once.
    Admin only.
    """

    permission_classes = [permissions.IsAdminUser]

    def post(self, request):
        """Send notifications to multiple users."""
        serializer = BulkNotificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        from django.contrib.auth import get_user_model
        User = get_user_model()

        recipients = User.objects.filter(
            uuid__in=serializer.validated_data['recipient_ids']
        )

        results = notification_service.send_bulk_notification(
            recipients=list(recipients),
            notification_type=serializer.validated_data['notification_type'],
            title=serializer.validated_data['title'],
            message=serializer.validated_data['message'],
            channels=serializer.validated_data.get('channels'),
            sender=request.user,
            action_url=serializer.validated_data.get('action_url', ''),
            priority=serializer.validated_data.get('priority', 'normal'),
            context_data=serializer.validated_data.get('context', {}),
        )

        success_count = sum(
            1 for user_results in results.values()
            if any(r.success for r in user_results)
        )

        return APIResponse.success(
            data={
                'total_recipients': len(serializer.validated_data['recipient_ids']),
                'success_count': success_count,
                'failed_count': len(results) - success_count,
            },
            message=_("Bulk notification sent to %(count)d users") % {'count': success_count}
        )


# =============================================================================
# TRADITIONAL DJANGO VIEWS
# =============================================================================

@login_required
def notification_list(request):
    """List all notifications for the current user."""
    notifications = Notification.objects.filter(
        recipient=request.user
    ).select_related('channel', 'sender')

    # Filter by read/unread
    filter_type = request.GET.get('filter', 'all')
    if filter_type == 'unread':
        notifications = notifications.filter(is_read=False)
    elif filter_type == 'read':
        notifications = notifications.filter(is_read=True)

    # Filter by type
    notification_type = request.GET.get('type')
    if notification_type:
        notifications = notifications.filter(notification_type=notification_type)

    # Pagination
    paginator = Paginator(notifications, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    # Count unread
    unread_count = Notification.objects.filter(
        recipient=request.user,
        is_read=False
    ).count()

    context = {
        'notifications': page_obj,
        'unread_count': unread_count,
        'filter_type': filter_type,
        'notification_types': dict(Notification.NOTIFICATION_TYPES),
    }
    return render(request, 'notifications/notification_list.html', context)


@login_required
def notification_mark_read(request, notification_id):
    """Mark a notification as read."""
    notification = get_object_or_404(
        Notification,
        id=notification_id,
        recipient=request.user
    )
    notification.mark_as_read()

    # If AJAX request, return JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'success': True, 'is_read': True})

    # Otherwise redirect to action URL or back to notifications
    if notification.action_url:
        return redirect(notification.action_url)
    return redirect('notifications:notification_list')


@login_required
@require_POST
def notification_mark_all_read(request):
    """Mark all notifications as read."""
    count = notification_service.mark_all_as_read(request.user)

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'success': True, 'count': count})

    return redirect('notifications:notification_list')


@login_required
def notification_delete(request, notification_id):
    """Delete/dismiss a notification."""
    notification = get_object_or_404(
        Notification,
        id=notification_id,
        recipient=request.user
    )

    if request.method == 'POST':
        notification.dismiss()

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': True})

        return redirect('notifications:notification_list')

    context = {'notification': notification}
    return render(request, 'notifications/notification_delete.html', context)


@login_required
def notification_preferences(request):
    """Manage notification preferences."""
    preferences, created = NotificationPreference.objects.get_or_create(
        user=request.user
    )

    if request.method == 'POST':
        # Update preferences from form
        preferences.notifications_enabled = request.POST.get('notifications_enabled') == 'on'
        preferences.quiet_hours_enabled = request.POST.get('quiet_hours_enabled') == 'on'

        if request.POST.get('quiet_hours_start'):
            preferences.quiet_hours_start = request.POST.get('quiet_hours_start')
        if request.POST.get('quiet_hours_end'):
            preferences.quiet_hours_end = request.POST.get('quiet_hours_end')

        preferences.timezone = request.POST.get('timezone', 'UTC')
        preferences.email_digest_frequency = request.POST.get('email_digest_frequency', 'realtime')
        preferences.phone_number = request.POST.get('phone_number', '')

        # Update channel preferences
        channel_prefs = {}
        for channel_type, _ in NotificationChannel.CHANNEL_TYPES:
            channel_prefs[channel_type] = request.POST.get(f'channel_{channel_type}') == 'on'
        preferences.channel_preferences = channel_prefs

        preferences.save()
        return redirect('notifications:notification_preferences')

    # Get available channels
    channels = NotificationChannel.objects.filter(is_active=True)

    context = {
        'preferences': preferences,
        'channels': channels,
        'notification_types': dict(Notification.NOTIFICATION_TYPES),
    }
    return render(request, 'notifications/notification_preferences.html', context)


@login_required
def notification_count_api(request):
    """API endpoint to get unread notification count."""
    count = notification_service.get_unread_count(request.user)
    return JsonResponse({'unread_count': count})


def unsubscribe_view(request, token):
    """Public view for unsubscribing from notifications."""
    try:
        prefs = NotificationPreference.objects.get(unsubscribe_token=token)
    except NotificationPreference.DoesNotExist:
        return render(request, 'notifications/unsubscribe_invalid.html')

    if request.method == 'POST':
        notification_type = request.POST.get('notification_type')
        global_unsub = request.POST.get('global_unsubscribe') == 'on'

        if global_unsub:
            prefs.global_unsubscribe = True
        elif notification_type:
            if notification_type not in prefs.unsubscribed_types:
                prefs.unsubscribed_types.append(notification_type)

        prefs.save()
        return render(request, 'notifications/unsubscribe_success.html')

    context = {
        'notification_types': dict(Notification.NOTIFICATION_TYPES),
        'token': token,
    }
    return render(request, 'notifications/unsubscribe.html', context)
