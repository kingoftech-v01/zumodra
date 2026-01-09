"""
Marketing API ViewSets.

Provides ViewSets for:
- Visit tracking (admin only)
- Prospects/Leads management
- Newsletter campaigns
- Conversion events
- Marketing analytics
"""

from datetime import timedelta
from decimal import Decimal

from django.db.models import Count, Sum, Q
from django.utils import timezone
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django_filters import rest_framework as filters

from ..models import (
    VisitEvent,
    AggregatedStats,
    Prospect,
    NewsletterCampaign,
    NewsletterSubscriber,
    NewsletterTracking,
    ConversionEvent,
)
from ..serializers import (
    VisitEventListSerializer,
    VisitEventDetailSerializer,
    AggregatedStatsSerializer,
    ProspectListSerializer,
    ProspectDetailSerializer,
    ProspectCreateSerializer,
    ProspectUpdateSerializer,
    NewsletterCampaignListSerializer,
    NewsletterCampaignDetailSerializer,
    NewsletterCampaignCreateSerializer,
    NewsletterSubscriberListSerializer,
    NewsletterSubscriberDetailSerializer,
    NewsletterSubscriberCreateSerializer,
    NewsletterTrackingSerializer,
    ConversionEventListSerializer,
    ConversionEventDetailSerializer,
    ConversionEventCreateSerializer,
    MarketingAnalyticsSerializer,
)


# =============================================================================
# VISIT EVENT VIEWSET
# =============================================================================

class VisitEventFilter(filters.FilterSet):
    """Filter for visit events."""
    country = filters.CharFilter()
    device_type = filters.CharFilter()
    utm_source = filters.CharFilter()
    utm_campaign = filters.CharFilter()
    date_from = filters.DateFilter(field_name='timestamp', lookup_expr='date__gte')
    date_to = filters.DateFilter(field_name='timestamp', lookup_expr='date__lte')

    class Meta:
        model = VisitEvent
        fields = ['country', 'device_type', 'utm_source', 'utm_campaign', 'date_from', 'date_to']


class VisitEventViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for visit events (read-only, admin only).
    """
    queryset = VisitEvent.objects.all()
    permission_classes = [permissions.IsAdminUser]
    filterset_class = VisitEventFilter
    ordering_fields = ['timestamp', 'country']
    ordering = ['-timestamp']

    def get_serializer_class(self):
        if self.action == 'list':
            return VisitEventListSerializer
        return VisitEventDetailSerializer

    @action(detail=False, methods=['get'])
    def by_source(self, request):
        """Get visits grouped by UTM source."""
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)

        stats = VisitEvent.objects.filter(
            timestamp__gte=since
        ).values('utm_source').annotate(
            visits=Count('id')
        ).order_by('-visits')[:10]

        total = sum(s['visits'] for s in stats)
        result = [{
            'utm_source': s['utm_source'] or 'Direct',
            'visits': s['visits'],
            'percentage': round(s['visits'] / total * 100, 1) if total else 0
        } for s in stats]

        return Response(result)

    @action(detail=False, methods=['get'])
    def by_country(self, request):
        """Get visits grouped by country."""
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)

        stats = VisitEvent.objects.filter(
            timestamp__gte=since
        ).values('country').annotate(
            visits=Count('id')
        ).order_by('-visits')[:10]

        total = sum(s['visits'] for s in stats)
        result = [{
            'country': s['country'],
            'visits': s['visits'],
            'percentage': round(s['visits'] / total * 100, 1) if total else 0
        } for s in stats]

        return Response(result)

    @action(detail=False, methods=['get'])
    def by_device(self, request):
        """Get visits grouped by device type."""
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)

        stats = VisitEvent.objects.filter(
            timestamp__gte=since
        ).values('device_type').annotate(
            visits=Count('id')
        ).order_by('-visits')

        total = sum(s['visits'] for s in stats)
        result = [{
            'device_type': s['device_type'],
            'visits': s['visits'],
            'percentage': round(s['visits'] / total * 100, 1) if total else 0
        } for s in stats]

        return Response(result)


# =============================================================================
# AGGREGATED STATS VIEWSET
# =============================================================================

class AggregatedStatsViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for aggregated stats (read-only, admin only).
    """
    queryset = AggregatedStats.objects.all()
    serializer_class = AggregatedStatsSerializer
    permission_classes = [permissions.IsAdminUser]
    ordering_fields = ['date', 'total_visits']
    ordering = ['-date']


# =============================================================================
# PROSPECT VIEWSET
# =============================================================================

class ProspectFilter(filters.FilterSet):
    """Filter for prospects."""
    status = filters.CharFilter()
    source = filters.CharFilter(lookup_expr='icontains')
    email = filters.CharFilter(lookup_expr='icontains')
    company = filters.CharFilter(lookup_expr='icontains')
    added_after = filters.DateFilter(field_name='added_on', lookup_expr='date__gte')
    added_before = filters.DateFilter(field_name='added_on', lookup_expr='date__lte')

    class Meta:
        model = Prospect
        fields = ['status', 'source', 'email', 'company', 'added_after', 'added_before']


class ProspectViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing prospects/leads.
    """
    queryset = Prospect.objects.all()
    permission_classes = [permissions.IsAdminUser]
    filterset_class = ProspectFilter
    search_fields = ['email', 'first_name', 'last_name', 'company']
    ordering_fields = ['added_on', 'email', 'status']
    ordering = ['-added_on']

    def get_serializer_class(self):
        if self.action == 'list':
            return ProspectListSerializer
        elif self.action == 'create':
            return ProspectCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return ProspectUpdateSerializer
        return ProspectDetailSerializer

    @action(detail=True, methods=['post'])
    def mark_contacted(self, request, pk=None):
        """Mark prospect as contacted."""
        prospect = self.get_object()
        prospect.status = 'contacted'
        prospect.save(update_fields=['status'])
        return Response({'status': 'contacted', 'message': 'Prospect marked as contacted'})

    @action(detail=True, methods=['post'])
    def mark_qualified(self, request, pk=None):
        """Mark prospect as qualified."""
        prospect = self.get_object()
        prospect.status = 'qualified'
        prospect.save(update_fields=['status'])
        return Response({'status': 'qualified', 'message': 'Prospect marked as qualified'})

    @action(detail=True, methods=['post'])
    def mark_converted(self, request, pk=None):
        """Mark prospect as converted."""
        prospect = self.get_object()
        prospect.status = 'converted'
        prospect.save(update_fields=['status'])
        return Response({'status': 'converted', 'message': 'Prospect marked as converted'})

    @action(detail=True, methods=['post'])
    def disqualify(self, request, pk=None):
        """Mark prospect as disqualified."""
        prospect = self.get_object()
        prospect.status = 'disqualified'
        prospect.save(update_fields=['status'])
        return Response({'status': 'disqualified', 'message': 'Prospect disqualified'})

    @action(detail=False, methods=['get'])
    def by_status(self, request):
        """Get prospects count by status."""
        stats = Prospect.objects.values('status').annotate(count=Count('id'))
        return Response({s['status']: s['count'] for s in stats})


# =============================================================================
# NEWSLETTER CAMPAIGN VIEWSET
# =============================================================================

class NewsletterCampaignViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing newsletter campaigns.
    """
    queryset = NewsletterCampaign.objects.all()
    permission_classes = [permissions.IsAdminUser]
    search_fields = ['title', 'subject']
    ordering_fields = ['created_on', 'sent_on', 'scheduled_for']
    ordering = ['-created_on']

    def get_serializer_class(self):
        if self.action == 'list':
            return NewsletterCampaignListSerializer
        elif self.action == 'create':
            return NewsletterCampaignCreateSerializer
        return NewsletterCampaignDetailSerializer

    @action(detail=True, methods=['post'])
    def send(self, request, pk=None):
        """Send the newsletter campaign."""
        campaign = self.get_object()
        if campaign.sent:
            return Response(
                {'error': 'Campaign has already been sent'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Mark as sent (actual sending would be done by a Celery task)
        campaign.sent = True
        campaign.sent_on = timezone.now()
        campaign.save(update_fields=['sent', 'sent_on'])

        return Response({
            'status': 'sent',
            'message': 'Campaign queued for sending',
            'sent_on': campaign.sent_on
        })

    @action(detail=True, methods=['get'])
    def tracking(self, request, pk=None):
        """Get tracking data for a campaign."""
        campaign = self.get_object()
        tracking = NewsletterTracking.objects.filter(campaign=campaign)
        serializer = NewsletterTrackingSerializer(tracking, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get overall campaign statistics."""
        campaigns = NewsletterCampaign.objects.filter(sent=True)
        total_sent = campaigns.count()

        if total_sent == 0:
            return Response({
                'total_campaigns': 0,
                'avg_open_rate': 0,
                'avg_click_rate': 0
            })

        tracking = NewsletterTracking.objects.filter(campaign__sent=True)
        total_emails = tracking.count()
        total_opened = tracking.filter(opened=True).count()
        total_clicked = tracking.filter(clicked=True).count()

        return Response({
            'total_campaigns': total_sent,
            'total_emails_sent': total_emails,
            'avg_open_rate': round(total_opened / total_emails * 100, 1) if total_emails else 0,
            'avg_click_rate': round(total_clicked / total_emails * 100, 1) if total_emails else 0,
        })


# =============================================================================
# NEWSLETTER SUBSCRIBER VIEWSET
# =============================================================================

class NewsletterSubscriberFilter(filters.FilterSet):
    """Filter for newsletter subscribers."""
    active = filters.BooleanFilter()
    subscribed_after = filters.DateFilter(field_name='subscribed_on', lookup_expr='date__gte')
    subscribed_before = filters.DateFilter(field_name='subscribed_on', lookup_expr='date__lte')

    class Meta:
        model = NewsletterSubscriber
        fields = ['active', 'subscribed_after', 'subscribed_before']


class NewsletterSubscriberViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing newsletter subscribers.
    """
    queryset = NewsletterSubscriber.objects.all()
    permission_classes = [permissions.IsAdminUser]
    filterset_class = NewsletterSubscriberFilter
    search_fields = ['email']
    ordering_fields = ['subscribed_on', 'email']
    ordering = ['-subscribed_on']

    def get_serializer_class(self):
        if self.action == 'list':
            return NewsletterSubscriberListSerializer
        elif self.action == 'create':
            return NewsletterSubscriberCreateSerializer
        return NewsletterSubscriberDetailSerializer

    @action(detail=True, methods=['post'])
    def unsubscribe(self, request, pk=None):
        """Unsubscribe a subscriber."""
        subscriber = self.get_object()
        subscriber.active = False
        subscriber.unsubscribed_on = timezone.now()
        subscriber.save(update_fields=['active', 'unsubscribed_on'])
        return Response({'status': 'unsubscribed', 'message': 'Subscriber has been unsubscribed'})

    @action(detail=True, methods=['post'])
    def resubscribe(self, request, pk=None):
        """Resubscribe a subscriber."""
        subscriber = self.get_object()
        subscriber.active = True
        subscriber.unsubscribed_on = None
        subscriber.save(update_fields=['active', 'unsubscribed_on'])
        return Response({'status': 'resubscribed', 'message': 'Subscriber has been resubscribed'})


# =============================================================================
# CONVERSION EVENT VIEWSET
# =============================================================================

class ConversionEventFilter(filters.FilterSet):
    """Filter for conversion events."""
    event_name = filters.CharFilter()
    marketing_id = filters.CharFilter()
    date_from = filters.DateFilter(field_name='timestamp', lookup_expr='date__gte')
    date_to = filters.DateFilter(field_name='timestamp', lookup_expr='date__lte')
    min_value = filters.NumberFilter(field_name='value', lookup_expr='gte')
    max_value = filters.NumberFilter(field_name='value', lookup_expr='lte')

    class Meta:
        model = ConversionEvent
        fields = ['event_name', 'marketing_id', 'date_from', 'date_to', 'min_value', 'max_value']


class ConversionEventViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing conversion events.
    """
    queryset = ConversionEvent.objects.all()
    permission_classes = [permissions.IsAdminUser]
    filterset_class = ConversionEventFilter
    search_fields = ['event_name', 'marketing_id']
    ordering_fields = ['timestamp', 'value', 'event_name']
    ordering = ['-timestamp']

    def get_serializer_class(self):
        if self.action == 'list':
            return ConversionEventListSerializer
        elif self.action == 'create':
            return ConversionEventCreateSerializer
        return ConversionEventDetailSerializer

    @action(detail=False, methods=['get'])
    def by_event(self, request):
        """Get conversions grouped by event name."""
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)

        stats = ConversionEvent.objects.filter(
            timestamp__gte=since
        ).values('event_name').annotate(
            count=Count('id'),
            total_value=Sum('value')
        ).order_by('-count')

        return Response([{
            'event_name': s['event_name'],
            'count': s['count'],
            'total_value': float(s['total_value'] or 0)
        } for s in stats])

    @action(detail=False, methods=['get'])
    def revenue(self, request):
        """Get total revenue from conversions."""
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)

        result = ConversionEvent.objects.filter(
            timestamp__gte=since,
            event_name='purchase'
        ).aggregate(
            total=Sum('value'),
            count=Count('id')
        )

        return Response({
            'total_revenue': float(result['total'] or 0),
            'total_purchases': result['count'],
            'period_days': days
        })


# =============================================================================
# MARKETING ANALYTICS VIEW
# =============================================================================

class MarketingAnalyticsView(APIView):
    """
    API view for marketing analytics dashboard.
    """
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        """Get marketing analytics summary."""
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)

        # Visit stats
        visits = VisitEvent.objects.filter(timestamp__gte=since)
        total_visits = visits.count()
        unique_visitors = visits.values('marketing_id').distinct().count()

        # Prospect stats
        prospects = Prospect.objects.all()
        total_prospects = prospects.count()
        new_prospects = prospects.filter(added_on__gte=since).count()

        # Conversion stats
        conversions = ConversionEvent.objects.filter(timestamp__gte=since)
        total_conversions = conversions.filter(event_name='purchase').count()
        total_revenue = conversions.filter(event_name='purchase').aggregate(
            total=Sum('value')
        )['total'] or Decimal('0')

        conversion_rate = 0
        if unique_visitors > 0:
            conversion_rate = round(total_conversions / unique_visitors * 100, 2)

        # Subscriber stats
        subscribers = NewsletterSubscriber.objects.all()
        total_subscribers = subscribers.count()
        active_subscribers = subscribers.filter(active=True).count()

        # Campaign stats
        campaigns = NewsletterCampaign.objects.filter(sent=True)
        campaigns_sent = campaigns.filter(sent_on__gte=since).count()

        # Calculate average open and click rates
        tracking = NewsletterTracking.objects.filter(campaign__sent=True)
        total_tracking = tracking.count()
        if total_tracking > 0:
            avg_open_rate = round(tracking.filter(opened=True).count() / total_tracking * 100, 1)
            avg_click_rate = round(tracking.filter(clicked=True).count() / total_tracking * 100, 1)
        else:
            avg_open_rate = 0
            avg_click_rate = 0

        data = {
            'total_visits': total_visits,
            'unique_visitors': unique_visitors,
            'total_prospects': total_prospects,
            'new_prospects': new_prospects,
            'conversion_rate': conversion_rate,
            'total_revenue': total_revenue,
            'total_subscribers': total_subscribers,
            'active_subscribers': active_subscribers,
            'campaigns_sent': campaigns_sent,
            'avg_open_rate': avg_open_rate,
            'avg_click_rate': avg_click_rate,
        }

        serializer = MarketingAnalyticsSerializer(data)
        return Response(serializer.data)
