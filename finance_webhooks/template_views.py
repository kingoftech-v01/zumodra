"""
Finance Webhooks App Frontend Views - Webhook Event Monitoring
"""

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView, ListView, DetailView
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta

from tenants.mixins import TenantViewMixin
from core.mixins import HTMXMixin
from .models import (
    WebhookEvent,
    WebhookRetry,
    WebhookSignature,
    WebhookEventType,
    WebhookStatus,
    WebhookSource,
)


class WebhookDashboardView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """Main webhooks dashboard with monitoring stats"""
    template_name = 'finance_webhooks/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Recent events (last 24 hours)
        twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
        recent_events = WebhookEvent.objects.filter(
            received_at__gte=twenty_four_hours_ago
        )

        context['total_events_24h'] = recent_events.count()
        context['succeeded_events_24h'] = recent_events.filter(status='succeeded').count()
        context['failed_events_24h'] = recent_events.filter(status='failed').count()
        context['pending_events_24h'] = recent_events.filter(status='pending').count()

        # Events by source (last 24 hours)
        context['events_by_source'] = recent_events.values('source').annotate(
            count=Count('id')
        ).order_by('-count')

        # Failed events needing attention
        context['failed_events_count'] = WebhookEvent.objects.filter(
            status='failed'
        ).count()

        # Recent events list
        context['recent_events'] = WebhookEvent.objects.select_related(
            'content_type'
        ).order_by('-received_at')[:20]

        # Event types summary
        context['enabled_event_types'] = WebhookEventType.objects.filter(
            is_enabled=True
        ).count()

        context['total_event_types'] = WebhookEventType.objects.count()

        # Signature verification stats (last 24 hours)
        recent_signatures = WebhookSignature.objects.filter(
            timestamp__gte=twenty_four_hours_ago
        )
        context['verified_signatures_24h'] = recent_signatures.filter(verified=True).count()
        context['failed_signatures_24h'] = recent_signatures.filter(verified=False).count()

        return context


class WebhookEventListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all webhook events"""
    model = WebhookEvent
    template_name = 'finance_webhooks/event_list.html'
    partial_template_name = 'finance_webhooks/partials/_event_list.html'
    context_object_name = 'events'
    paginate_by = 50

    def get_queryset(self):
        queryset = WebhookEvent.objects.select_related(
            'content_type'
        ).order_by('-received_at')

        # Filter by source
        source = self.request.GET.get('source')
        if source:
            queryset = queryset.filter(source=source)

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        # Filter by event type
        event_type = self.request.GET.get('event_type')
        if event_type:
            queryset = queryset.filter(event_type=event_type)

        # Filter by date range
        start_date = self.request.GET.get('start_date')
        end_date = self.request.GET.get('end_date')
        if start_date:
            queryset = queryset.filter(received_at__gte=start_date)
        if end_date:
            queryset = queryset.filter(received_at__lte=end_date)

        # Search by webhook ID or event ID
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                Q(webhook_id__icontains=search) |
                Q(event_id__icontains=search) |
                Q(event_type__icontains=search)
            )

        return queryset


class WebhookEventDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Webhook event detail with full payload and processing history"""
    model = WebhookEvent
    template_name = 'finance_webhooks/event_detail.html'
    context_object_name = 'event'
    slug_field = 'webhook_id'
    slug_url_kwarg = 'webhook_id'

    def get_queryset(self):
        return WebhookEvent.objects.select_related('content_type').prefetch_related(
            'retries', 'signature_logs'
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        event = self.object

        # Retry history
        context['retries'] = event.retries.order_by('-retry_at')

        # Signature verification logs
        context['signature_logs'] = event.signature_logs.order_by('-timestamp')

        # Related event type configuration
        try:
            context['event_type_config'] = WebhookEventType.objects.get(
                source=event.source,
                event_type=event.event_type
            )
        except WebhookEventType.DoesNotExist:
            context['event_type_config'] = None

        return context


class WebhookRetryListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all webhook retries"""
    model = WebhookRetry
    template_name = 'finance_webhooks/retry_list.html'
    partial_template_name = 'finance_webhooks/partials/_retry_list.html'
    context_object_name = 'retries'
    paginate_by = 50

    def get_queryset(self):
        queryset = WebhookRetry.objects.select_related(
            'webhook_event'
        ).order_by('-retry_at')

        # Filter by success status
        succeeded = self.request.GET.get('succeeded')
        if succeeded == 'true':
            queryset = queryset.filter(succeeded=True)
        elif succeeded == 'false':
            queryset = queryset.filter(succeeded=False)

        # Filter by webhook event
        webhook_id = self.request.GET.get('webhook_id')
        if webhook_id:
            queryset = queryset.filter(webhook_event__webhook_id=webhook_id)

        return queryset


class WebhookSignatureListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all signature verification logs"""
    model = WebhookSignature
    template_name = 'finance_webhooks/signature_list.html'
    partial_template_name = 'finance_webhooks/partials/_signature_list.html'
    context_object_name = 'signatures'
    paginate_by = 50

    def get_queryset(self):
        queryset = WebhookSignature.objects.select_related(
            'webhook_event'
        ).order_by('-timestamp')

        # Filter by verification status
        verified = self.request.GET.get('verified')
        if verified == 'true':
            queryset = queryset.filter(verified=True)
        elif verified == 'false':
            queryset = queryset.filter(verified=False)

        # Filter by date range
        start_date = self.request.GET.get('start_date')
        end_date = self.request.GET.get('end_date')
        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        if end_date:
            queryset = queryset.filter(timestamp__lte=end_date)

        return queryset


class WebhookEventTypeListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all webhook event type configurations"""
    model = WebhookEventType
    template_name = 'finance_webhooks/event_type_list.html'
    partial_template_name = 'finance_webhooks/partials/_event_type_list.html'
    context_object_name = 'event_types'
    paginate_by = 50

    def get_queryset(self):
        queryset = WebhookEventType.objects.order_by('source', 'event_type')

        # Filter by source
        source = self.request.GET.get('source')
        if source:
            queryset = queryset.filter(source=source)

        # Filter by enabled status
        is_enabled = self.request.GET.get('is_enabled')
        if is_enabled == 'true':
            queryset = queryset.filter(is_enabled=True)
        elif is_enabled == 'false':
            queryset = queryset.filter(is_enabled=False)

        # Search
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                Q(event_type__icontains=search) |
                Q(description__icontains=search)
            )

        return queryset


class WebhookEventTypeDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Event type detail with configuration and statistics"""
    model = WebhookEventType
    template_name = 'finance_webhooks/event_type_detail.html'
    context_object_name = 'event_type'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        event_type_obj = self.object

        # Events of this type (last 30 days)
        thirty_days_ago = timezone.now() - timedelta(days=30)
        events = WebhookEvent.objects.filter(
            source=event_type_obj.source,
            event_type=event_type_obj.event_type,
            received_at__gte=thirty_days_ago
        )

        context['total_events'] = events.count()
        context['succeeded_events'] = events.filter(status='succeeded').count()
        context['failed_events'] = events.filter(status='failed').count()
        context['pending_events'] = events.filter(status='pending').count()

        # Recent events of this type
        context['recent_events'] = events.order_by('-received_at')[:20]

        return context


class HTMXWebhookStatsView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """HTMX partial for real-time webhook stats"""
    template_name = 'finance_webhooks/partials/_stats.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Last 24 hours stats
        twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
        recent_events = WebhookEvent.objects.filter(
            received_at__gte=twenty_four_hours_ago
        )

        context['total_events'] = recent_events.count()
        context['succeeded_count'] = recent_events.filter(status='succeeded').count()
        context['failed_count'] = recent_events.filter(status='failed').count()
        context['pending_count'] = recent_events.filter(status='pending').count()

        # Failed events needing attention (all time)
        context['failed_total'] = WebhookEvent.objects.filter(status='failed').count()

        # Latest event
        try:
            latest = WebhookEvent.objects.latest('received_at')
            context['latest_event'] = latest
            context['latest_event_time'] = latest.received_at
        except WebhookEvent.DoesNotExist:
            context['latest_event'] = None

        return context
