"""
Outbound Webhook System

Sends webhooks to external services when data changes in the application.
Supports:
- Multiple webhook subscriptions per tenant
- Event filtering by app and event type
- Retry logic with exponential backoff
- Signature verification for secure delivery
"""

import hashlib
import hmac
import json
import logging
import secrets
import uuid
from datetime import timedelta
from typing import Any, Dict, List, Optional

import requests
from django.conf import settings
from django.db import models
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.postgres.fields import ArrayField

from tenants.models import Tenant

logger = logging.getLogger(__name__)


# =============================================================================
# OUTBOUND WEBHOOK MODELS
# =============================================================================

class OutboundWebhook(models.Model):
    """
    Configuration for outbound webhooks to external services.
    Each subscription can filter by app and event types.
    """

    class Status(models.TextChoices):
        ACTIVE = 'active', _('Active')
        INACTIVE = 'inactive', _('Inactive')
        SUSPENDED = 'suspended', _('Suspended - Too Many Failures')

    # Identity
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Tenant association
    tenant = models.ForeignKey(
        'tenants.Tenant',
        on_delete=models.CASCADE,
        related_name='outbound_webhooks',
        help_text=_('Tenant this webhook belongs to')
    )

    # Webhook configuration
    name = models.CharField(
        max_length=255,
        help_text=_('Display name for this webhook')
    )
    description = models.TextField(
        blank=True,
        help_text=_('Optional description')
    )
    url = models.URLField(
        max_length=2048,
        help_text=_('URL to send webhooks to')
    )

    # Security
    secret = models.CharField(
        max_length=255,
        help_text=_('Secret for signing webhook payloads')
    )

    # Event filtering
    subscribed_apps = ArrayField(
        models.CharField(max_length=50),
        default=list,
        blank=True,
        help_text=_('Apps to subscribe to (empty = all apps)')
    )
    subscribed_events = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True,
        help_text=_('Event types to subscribe to (empty = all events)')
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.ACTIVE
    )
    is_enabled = models.BooleanField(default=True)

    # Statistics
    total_sent = models.PositiveIntegerField(default=0)
    total_successful = models.PositiveIntegerField(default=0)
    total_failed = models.PositiveIntegerField(default=0)
    consecutive_failures = models.PositiveIntegerField(default=0)
    last_sent_at = models.DateTimeField(null=True, blank=True)
    last_success_at = models.DateTimeField(null=True, blank=True)
    last_failure_at = models.DateTimeField(null=True, blank=True)

    # Headers
    custom_headers = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Custom headers to include in webhook requests')
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_webhooks'
    )

    class Meta:
        verbose_name = _('Outbound Webhook')
        verbose_name_plural = _('Outbound Webhooks')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['tenant', 'status']),
            models.Index(fields=['tenant', 'is_enabled']),
        ]

    def __str__(self):
        return f"{self.name} ({self.tenant.name})"

    def save(self, *args, **kwargs):
        if not self.secret:
            self.secret = secrets.token_hex(32)
        super().save(*args, **kwargs)

    @property
    def is_active(self):
        return self.status == self.Status.ACTIVE and self.is_enabled

    def should_receive_event(self, app_name: str, event_type: str) -> bool:
        """Check if this webhook should receive the given event."""
        if not self.is_active:
            return False

        # Check app filter
        if self.subscribed_apps and app_name not in self.subscribed_apps:
            return False

        # Check event filter
        if self.subscribed_events and event_type not in self.subscribed_events:
            return False

        return True

    def generate_signature(self, payload: str) -> str:
        """Generate HMAC-SHA256 signature for payload."""
        return hmac.new(
            self.secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

    def record_success(self):
        """Record successful delivery."""
        self.total_sent += 1
        self.total_successful += 1
        self.consecutive_failures = 0
        self.last_sent_at = timezone.now()
        self.last_success_at = timezone.now()
        if self.status == self.Status.SUSPENDED:
            self.status = self.Status.ACTIVE
        self.save(update_fields=[
            'total_sent', 'total_successful', 'consecutive_failures',
            'last_sent_at', 'last_success_at', 'status'
        ])

    def record_failure(self):
        """Record failed delivery."""
        self.total_sent += 1
        self.total_failed += 1
        self.consecutive_failures += 1
        self.last_sent_at = timezone.now()
        self.last_failure_at = timezone.now()

        # Suspend after 10 consecutive failures
        if self.consecutive_failures >= 10:
            self.status = self.Status.SUSPENDED

        self.save(update_fields=[
            'total_sent', 'total_failed', 'consecutive_failures',
            'last_sent_at', 'last_failure_at', 'status'
        ])


class OutboundWebhookDelivery(models.Model):
    """
    Tracks individual outbound webhook delivery attempts.
    """

    class Status(models.TextChoices):
        PENDING = 'pending', _('Pending')
        SENDING = 'sending', _('Sending')
        DELIVERED = 'delivered', _('Delivered')
        FAILED = 'failed', _('Failed')
        RETRYING = 'retrying', _('Retrying')

    # Identity
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Webhook link
    webhook = models.ForeignKey(
        OutboundWebhook,
        on_delete=models.CASCADE,
        related_name='deliveries'
    )

    # Event details
    app_name = models.CharField(max_length=50)
    event_type = models.CharField(max_length=100)
    event_id = models.CharField(max_length=255, blank=True)

    # Payload
    payload = models.JSONField(default=dict)

    # Delivery status
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING
    )
    status_message = models.TextField(blank=True)

    # Response
    response_status_code = models.PositiveIntegerField(null=True, blank=True)
    response_body = models.TextField(blank=True)
    response_time_ms = models.PositiveIntegerField(null=True, blank=True)

    # Retry
    retry_count = models.PositiveIntegerField(default=0)
    max_retries = models.PositiveIntegerField(default=5)
    next_retry_at = models.DateTimeField(null=True, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Outbound Webhook Delivery')
        verbose_name_plural = _('Outbound Webhook Deliveries')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['webhook', '-created_at']),
            models.Index(fields=['status', 'next_retry_at']),
        ]

    def __str__(self):
        return f"{self.app_name}.{self.event_type} -> {self.webhook.name}"

    @property
    def can_retry(self):
        return self.retry_count < self.max_retries

    def mark_sending(self):
        self.status = self.Status.SENDING
        self.sent_at = timezone.now()
        self.save(update_fields=['status', 'sent_at'])

    def mark_delivered(self, status_code: int, response_body: str, response_time_ms: int):
        self.status = self.Status.DELIVERED
        self.response_status_code = status_code
        self.response_body = response_body[:10000]  # Limit stored response
        self.response_time_ms = response_time_ms
        self.completed_at = timezone.now()
        self.save()
        self.webhook.record_success()

    def mark_failed(self, message: str, status_code: int = None, response_body: str = None):
        self.status = self.Status.FAILED
        self.status_message = message
        self.response_status_code = status_code
        self.response_body = (response_body or '')[:10000]
        self.retry_count += 1
        self.completed_at = timezone.now()

        if self.can_retry:
            backoff_minutes = 2 ** (self.retry_count - 1)
            self.next_retry_at = timezone.now() + timedelta(minutes=backoff_minutes)
            self.status = self.Status.RETRYING

        self.save()
        self.webhook.record_failure()


# =============================================================================
# WEBHOOK EVENT TYPES
# =============================================================================

# Define all supported webhook events by app
WEBHOOK_EVENTS = {
    'accounts': [
        'user.created',
        'user.updated',
        'user.deleted',
        'user.activated',
        'user.deactivated',
        'tenant_user.created',
        'tenant_user.updated',
        'tenant_user.deleted',
        'tenant_user.role_changed',
    ],
    'ats': [
        'job.created',
        'job.updated',
        'job.published',
        'job.closed',
        'job.deleted',
        'candidate.created',
        'candidate.updated',
        'candidate.deleted',
        'application.created',
        'application.updated',
        'application.status_changed',
        'application.deleted',
        'interview.scheduled',
        'interview.updated',
        'interview.completed',
        'interview.cancelled',
        'offer.created',
        'offer.sent',
        'offer.accepted',
        'offer.declined',
    ],
    'hr_core': [
        'employee.created',
        'employee.updated',
        'employee.terminated',
        'timeoff.requested',
        'timeoff.approved',
        'timeoff.rejected',
        'onboarding.started',
        'onboarding.completed',
    ],
    'services': [
        'service.created',
        'service.updated',
        'service.deleted',
        'provider.created',
        'provider.verified',
        'provider.updated',
        'contract.created',
        'contract.updated',
        'contract.completed',
        'contract.cancelled',
        'proposal.submitted',
        'proposal.accepted',
        'proposal.rejected',
        'review.created',
    ],
    'finance': [
        'payment.created',
        'payment.completed',
        'payment.failed',
        'invoice.created',
        'invoice.paid',
        'subscription.created',
        'subscription.updated',
        'subscription.cancelled',
    ],
    'appointment': [
        'appointment.booked',
        'appointment.updated',
        'appointment.cancelled',
        'appointment.completed',
        'appointment.no_show',
    ],
    'messages_sys': [
        'message.created',
        'conversation.created',
    ],
    'notifications': [
        'notification.created',
        'notification.read',
    ],
    'blog': [
        'post.created',
        'post.published',
        'post.updated',
        'post.deleted',
        'comment.created',
    ],
    'newsletter': [
        'newsletter.created',
        'subscription.created',
        'subscription.cancelled',
        'message.sent',
    ],
    'security': [
        'login.success',
        'login.failed',
        'password.changed',
        'mfa.enabled',
        'mfa.disabled',
    ],
}


def get_all_events() -> List[str]:
    """Get list of all available webhook events."""
    events = []
    for app, app_events in WEBHOOK_EVENTS.items():
        for event in app_events:
            events.append(f"{app}.{event}")
    return events


# =============================================================================
# WEBHOOK DISPATCHER
# =============================================================================

def dispatch_webhook(
    tenant_id: int,
    app_name: str,
    event_type: str,
    data: Dict[str, Any],
    event_id: str = None
) -> int:
    """
    Dispatch webhook to all subscribed endpoints for a tenant.

    Args:
        tenant_id: ID of the tenant
        app_name: Name of the app (e.g., 'ats', 'hr_core')
        event_type: Type of event (e.g., 'job.created')
        data: Event data payload
        event_id: Optional unique event identifier

    Returns:
        Number of webhooks queued for delivery
    """
    from .tasks import deliver_outbound_webhook

    webhooks = OutboundWebhook.objects.filter(
        tenant_id=tenant_id,
        is_enabled=True,
        status__in=[OutboundWebhook.Status.ACTIVE]
    )

    queued = 0
    for webhook in webhooks:
        if webhook.should_receive_event(app_name, event_type):
            # Create delivery record
            delivery = OutboundWebhookDelivery.objects.create(
                webhook=webhook,
                app_name=app_name,
                event_type=event_type,
                event_id=event_id or str(uuid.uuid4()),
                payload=data
            )

            # Queue for async delivery
            deliver_outbound_webhook.delay(str(delivery.id))
            queued += 1

    if queued:
        logger.info(f"Dispatched {queued} webhooks for {app_name}.{event_type}")

    return queued


def send_webhook_sync(delivery: OutboundWebhookDelivery) -> bool:
    """
    Synchronously send a webhook delivery.
    Used by Celery task and for testing.

    Returns:
        True if delivery was successful
    """
    import time

    webhook = delivery.webhook
    delivery.mark_sending()

    # Build payload
    payload = {
        'event_id': delivery.event_id,
        'event_type': f"{delivery.app_name}.{delivery.event_type}",
        'timestamp': timezone.now().isoformat(),
        'tenant_id': str(webhook.tenant_id),
        'data': delivery.payload
    }
    payload_json = json.dumps(payload, default=str)

    # Generate signature
    signature = webhook.generate_signature(payload_json)

    # Build headers
    headers = {
        'Content-Type': 'application/json',
        'X-Webhook-Signature': f"sha256={signature}",
        'X-Webhook-Event': f"{delivery.app_name}.{delivery.event_type}",
        'X-Webhook-ID': str(delivery.id),
        'X-Webhook-Timestamp': str(int(time.time())),
        'User-Agent': 'Zumodra-Webhook/1.0',
    }
    headers.update(webhook.custom_headers)

    # Send request
    start_time = time.time()
    try:
        response = requests.post(
            webhook.url,
            data=payload_json,
            headers=headers,
            timeout=30
        )
        response_time_ms = int((time.time() - start_time) * 1000)

        if response.status_code >= 200 and response.status_code < 300:
            delivery.mark_delivered(
                status_code=response.status_code,
                response_body=response.text,
                response_time_ms=response_time_ms
            )
            return True
        else:
            delivery.mark_failed(
                message=f"HTTP {response.status_code}",
                status_code=response.status_code,
                response_body=response.text
            )
            return False

    except requests.Timeout:
        delivery.mark_failed(message="Request timeout")
        return False
    except requests.ConnectionError as e:
        delivery.mark_failed(message=f"Connection error: {str(e)}")
        return False
    except Exception as e:
        logger.exception(f"Webhook delivery error: {e}")
        delivery.mark_failed(message=str(e))
        return False


# =============================================================================
# WEBHOOK API SERIALIZERS
# =============================================================================

from rest_framework import serializers


class OutboundWebhookSerializer(serializers.ModelSerializer):
    """Serializer for OutboundWebhook model."""

    available_apps = serializers.SerializerMethodField()
    available_events = serializers.SerializerMethodField()

    class Meta:
        model = OutboundWebhook
        fields = [
            'id', 'name', 'description', 'url', 'status', 'is_enabled',
            'subscribed_apps', 'subscribed_events', 'custom_headers',
            'total_sent', 'total_successful', 'total_failed',
            'last_sent_at', 'last_success_at', 'last_failure_at',
            'created_at', 'updated_at',
            'available_apps', 'available_events'
        ]
        read_only_fields = [
            'id', 'status', 'total_sent', 'total_successful', 'total_failed',
            'last_sent_at', 'last_success_at', 'last_failure_at',
            'created_at', 'updated_at'
        ]

    def get_available_apps(self, obj):
        return list(WEBHOOK_EVENTS.keys())

    def get_available_events(self, obj):
        return get_all_events()


class OutboundWebhookCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating OutboundWebhook."""

    class Meta:
        model = OutboundWebhook
        fields = ['name', 'description', 'url', 'subscribed_apps', 'subscribed_events', 'custom_headers']

    def create(self, validated_data):
        validated_data['tenant'] = self.context['request'].tenant
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)


class OutboundWebhookDeliverySerializer(serializers.ModelSerializer):
    """Serializer for OutboundWebhookDelivery model."""

    class Meta:
        model = OutboundWebhookDelivery
        fields = [
            'id', 'app_name', 'event_type', 'event_id',
            'status', 'status_message',
            'response_status_code', 'response_time_ms',
            'retry_count', 'next_retry_at',
            'created_at', 'sent_at', 'completed_at'
        ]


class WebhookTestSerializer(serializers.Serializer):
    """Serializer for testing webhook endpoint."""
    pass


# =============================================================================
# WEBHOOK API VIEWSETS
# =============================================================================

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated


class OutboundWebhookViewSet(viewsets.ModelViewSet):
    """ViewSet for managing outbound webhooks."""

    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        tenant = getattr(self.request, 'tenant', None)
        if not tenant:
            return OutboundWebhook.objects.none()
        return OutboundWebhook.objects.filter(tenant=tenant)

    def get_serializer_class(self):
        if self.action == 'create':
            return OutboundWebhookCreateSerializer
        return OutboundWebhookSerializer

    @action(detail=True, methods=['post'])
    def test(self, request, pk=None):
        """Send a test webhook to verify the endpoint."""
        webhook = self.get_object()

        # Create test delivery
        delivery = OutboundWebhookDelivery.objects.create(
            webhook=webhook,
            app_name='test',
            event_type='ping',
            event_id=str(uuid.uuid4()),
            payload={'message': 'This is a test webhook', 'timestamp': timezone.now().isoformat()}
        )

        # Send synchronously
        success = send_webhook_sync(delivery)

        return Response({
            'success': success,
            'delivery_id': str(delivery.id),
            'status_code': delivery.response_status_code,
            'response_time_ms': delivery.response_time_ms,
            'message': delivery.status_message or 'Webhook delivered successfully'
        })

    @action(detail=True, methods=['post'])
    def enable(self, request, pk=None):
        """Enable a webhook."""
        webhook = self.get_object()
        webhook.is_enabled = True
        webhook.status = OutboundWebhook.Status.ACTIVE
        webhook.save()
        return Response({'status': 'enabled'})

    @action(detail=True, methods=['post'])
    def disable(self, request, pk=None):
        """Disable a webhook."""
        webhook = self.get_object()
        webhook.is_enabled = False
        webhook.save()
        return Response({'status': 'disabled'})

    @action(detail=True, methods=['get'])
    def deliveries(self, request, pk=None):
        """Get recent deliveries for this webhook."""
        webhook = self.get_object()
        deliveries = webhook.deliveries.all()[:50]
        serializer = OutboundWebhookDeliverySerializer(deliveries, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def events(self, request):
        """Get list of all available webhook events."""
        return Response({
            'apps': list(WEBHOOK_EVENTS.keys()),
            'events': WEBHOOK_EVENTS,
            'all_events': get_all_events()
        })


# Register with admin
from django.contrib import admin

@admin.register(OutboundWebhook)
class OutboundWebhookAdmin(admin.ModelAdmin):
    list_display = ['name', 'tenant', 'url', 'status', 'is_enabled', 'total_sent', 'total_failed']
    list_filter = ['status', 'is_enabled', 'tenant']
    search_fields = ['name', 'url']
    readonly_fields = ['id', 'secret', 'total_sent', 'total_successful', 'total_failed', 'created_at']


@admin.register(OutboundWebhookDelivery)
class OutboundWebhookDeliveryAdmin(admin.ModelAdmin):
    list_display = ['id', 'webhook', 'event_type', 'status', 'response_status_code', 'created_at']
    list_filter = ['status', 'app_name']
    search_fields = ['event_type', 'event_id']
    readonly_fields = ['id', 'payload', 'response_body']
