"""
Finance Webhooks API ViewSets
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.utils import timezone
from datetime import timedelta

from core.viewsets import SecureTenantViewSet, SecureReadOnlyViewSet
from ..models import (
    WebhookEvent,
    WebhookRetry,
    WebhookSignature,
    WebhookEventType,
)
from .serializers import (
    WebhookEventListSerializer,
    WebhookEventDetailSerializer,
    WebhookRetryListSerializer,
    WebhookRetryDetailSerializer,
    WebhookSignatureListSerializer,
    WebhookSignatureDetailSerializer,
    WebhookEventTypeListSerializer,
    WebhookEventTypeDetailSerializer,
    WebhookEventTypeCreateSerializer,
)


class WebhookEventViewSet(SecureReadOnlyViewSet):
    """
    Webhook event monitoring - read-only.
    Enterprise feature for debugging webhook integrations.
    """
    queryset = WebhookEvent.objects.select_related('content_type').order_by('-received_at')
    filterset_fields = ['source', 'status', 'event_type', 'signature_verified']
    search_fields = ['webhook_id', 'event_id', 'event_type']
    ordering = ['-received_at']
    lookup_field = 'webhook_id'
    lookup_url_kwarg = 'webhook_id'

    def get_queryset(self):
        """Only admin roles can access webhook events"""
        queryset = super().get_queryset()

        # Only PDG, supervisor, or HR manager can access
        allowed_roles = ['pdg', 'supervisor', 'hr_manager']
        if not (self.request.user.is_staff or
                hasattr(self.request.user, 'tenant_user') and
                self.request.user.tenant_user.role in allowed_roles):
            return WebhookEvent.objects.none()

        return queryset

    def get_serializer_class(self):
        if self.action == 'list':
            return WebhookEventListSerializer
        return WebhookEventDetailSerializer

    @action(detail=True, methods=['post'])
    def retry(self, request, webhook_id=None):
        """
        Manually retry failed webhook processing.
        Creates retry record and triggers reprocessing.
        """
        event = self.get_object()

        if event.status not in ['failed', 'pending']:
            return Response({
                'detail': 'Can only retry failed or pending webhooks'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Create retry record
        retry = WebhookRetry.objects.create(
            webhook_event=event,
            retry_number=event.retry_count + 1,
            succeeded=False,
            next_retry_at=WebhookRetry.calculate_next_retry(event.retry_count + 1)
        )

        # Increment event retry count
        event.increment_retry()

        return Response({
            'detail': 'Webhook retry initiated',
            'retry_id': retry.id,
            'retry_number': retry.retry_number,
            'next_retry_at': retry.next_retry_at,
            'note': 'Reprocessing would be handled by background task'
        }, status=status.HTTP_202_ACCEPTED)

    @action(detail=True, methods=['get'])
    def payload(self, request, webhook_id=None):
        """Get full webhook payload (large JSON data)"""
        event = self.get_object()

        return Response({
            'webhook_id': event.webhook_id,
            'source': event.source,
            'event_type': event.event_type,
            'payload': event.payload
        })

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get webhook statistics"""
        # Last 24 hours
        twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
        recent_events = WebhookEvent.objects.filter(
            received_at__gte=twenty_four_hours_ago
        )

        # Last 7 days
        seven_days_ago = timezone.now() - timedelta(days=7)
        weekly_events = WebhookEvent.objects.filter(
            received_at__gte=seven_days_ago
        )

        return Response({
            'last_24h': {
                'total': recent_events.count(),
                'succeeded': recent_events.filter(status='succeeded').count(),
                'failed': recent_events.filter(status='failed').count(),
                'pending': recent_events.filter(status='pending').count(),
            },
            'last_7d': {
                'total': weekly_events.count(),
                'succeeded': weekly_events.filter(status='succeeded').count(),
                'failed': weekly_events.filter(status='failed').count(),
                'pending': weekly_events.filter(status='pending').count(),
            },
            'all_time': {
                'total': WebhookEvent.objects.count(),
                'failed': WebhookEvent.objects.filter(status='failed').count(),
            }
        })


class WebhookRetryViewSet(SecureReadOnlyViewSet):
    """
    Webhook retry monitoring - read-only.
    View retry attempts and their outcomes.
    """
    queryset = WebhookRetry.objects.select_related('webhook_event').order_by('-retry_at')
    filterset_fields = ['succeeded', 'webhook_event']
    search_fields = ['error_message']
    ordering = ['-retry_at']

    def get_queryset(self):
        """Only admin roles can access retry logs"""
        queryset = super().get_queryset()

        # Only PDG, supervisor, or HR manager can access
        allowed_roles = ['pdg', 'supervisor', 'hr_manager']
        if not (self.request.user.is_staff or
                hasattr(self.request.user, 'tenant_user') and
                self.request.user.tenant_user.role in allowed_roles):
            return WebhookRetry.objects.none()

        return queryset

    def get_serializer_class(self):
        if self.action == 'list':
            return WebhookRetryListSerializer
        return WebhookRetryDetailSerializer


class WebhookSignatureViewSet(SecureReadOnlyViewSet):
    """
    Webhook signature verification log - read-only.
    Security audit trail for webhook signatures.
    """
    queryset = WebhookSignature.objects.select_related('webhook_event').order_by('-timestamp')
    filterset_fields = ['verified', 'algorithm']
    search_fields = ['ip_address', 'user_agent']
    ordering = ['-timestamp']

    def get_queryset(self):
        """Only admin roles can access signature logs"""
        queryset = super().get_queryset()

        # Only PDG, supervisor, or HR manager can access
        allowed_roles = ['pdg', 'supervisor', 'hr_manager']
        if not (self.request.user.is_staff or
                hasattr(self.request.user, 'tenant_user') and
                self.request.user.tenant_user.role in allowed_roles):
            return WebhookSignature.objects.none()

        return queryset

    def get_serializer_class(self):
        if self.action == 'list':
            return WebhookSignatureListSerializer
        return WebhookSignatureDetailSerializer

    @action(detail=False, methods=['get'])
    def failed_verifications(self, request):
        """Get recent failed signature verifications (security monitoring)"""
        twenty_four_hours_ago = timezone.now() - timedelta(hours=24)

        failed_sigs = WebhookSignature.objects.filter(
            verified=False,
            timestamp__gte=twenty_four_hours_ago
        ).select_related('webhook_event')

        serializer = self.get_serializer(failed_sigs, many=True)

        return Response({
            'count': failed_sigs.count(),
            'failed_verifications': serializer.data
        })


class WebhookEventTypeViewSet(SecureTenantViewSet):
    """
    Webhook event type configuration.
    Admin-only management of supported webhook event types.
    """
    queryset = WebhookEventType.objects.order_by('source', 'event_type')
    filterset_fields = ['source', 'is_enabled', 'auto_retry']
    search_fields = ['event_type', 'description']
    ordering = ['source', 'event_type']

    def get_queryset(self):
        """Only PDG (owner) can access event type configuration"""
        queryset = super().get_queryset()

        # Only PDG can access
        if not (self.request.user.is_staff or
                hasattr(self.request.user, 'tenant_user') and
                self.request.user.tenant_user.role == 'pdg'):
            return WebhookEventType.objects.none()

        return queryset

    def get_serializer_class(self):
        if self.action == 'list':
            return WebhookEventTypeListSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return WebhookEventTypeCreateSerializer
        return WebhookEventTypeDetailSerializer

    @action(detail=True, methods=['post'])
    def enable(self, request, pk=None):
        """Enable event type processing"""
        event_type = self.get_object()

        event_type.is_enabled = True
        event_type.save(update_fields=['is_enabled', 'updated_at'])

        return Response({
            'detail': f'Event type {event_type.event_type} enabled',
            'is_enabled': True
        })

    @action(detail=True, methods=['post'])
    def disable(self, request, pk=None):
        """Disable event type processing"""
        event_type = self.get_object()

        event_type.is_enabled = False
        event_type.save(update_fields=['is_enabled', 'updated_at'])

        return Response({
            'detail': f'Event type {event_type.event_type} disabled',
            'is_enabled': False
        })

    @action(detail=True, methods=['get'])
    def recent_events(self, request, pk=None):
        """Get recent events of this type"""
        event_type_obj = self.get_object()

        # Last 7 days
        seven_days_ago = timezone.now() - timedelta(days=7)
        events = WebhookEvent.objects.filter(
            source=event_type_obj.source,
            event_type=event_type_obj.event_type,
            received_at__gte=seven_days_ago
        ).order_by('-received_at')[:50]

        serializer = WebhookEventListSerializer(events, many=True)

        return Response({
            'event_type': event_type_obj.event_type,
            'source': event_type_obj.source,
            'count': events.count(),
            'events': serializer.data
        })
