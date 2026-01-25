"""
Marketing Campaigns API ViewSets

DRF ViewSets for marketing campaigns CRUD operations.
"""
from rest_framework import viewsets, filters, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.db.models import Q

from core.viewsets import SecureTenantViewSet
from ..models import (
    Contact,
    MarketingCampaign,
    MessageArticle,
    CampaignAttachment,
    CampaignTracking,
    VisitEvent,
    ConversionEvent,
    AggregatedStats,
    ContactSegment,
)
from .serializers import (
    ContactListSerializer,
    ContactDetailSerializer,
    ContactCreateSerializer,
    MarketingCampaignListSerializer,
    MarketingCampaignDetailSerializer,
    MarketingCampaignCreateSerializer,
    MessageArticleSerializer,
    CampaignAttachmentSerializer,
    CampaignTrackingSerializer,
    VisitEventSerializer,
    ConversionEventSerializer,
    AggregatedStatsSerializer,
    ContactSegmentSerializer,
)


# =============================================================================
# CONTACT VIEWSETS
# =============================================================================

class ContactViewSet(SecureTenantViewSet):
    """
    ViewSet for managing contacts (leads and subscribers).

    Endpoints:
    - GET /api/v1/marketing-campaigns/contacts/ - List all contacts
    - POST /api/v1/marketing-campaigns/contacts/ - Create contact
    - GET /api/v1/marketing-campaigns/contacts/<id>/ - Contact detail
    - PUT/PATCH /api/v1/marketing-campaigns/contacts/<id>/ - Update contact
    - DELETE /api/v1/marketing-campaigns/contacts/<id>/ - Delete contact
    - POST /api/v1/marketing-campaigns/contacts/<id>/subscribe/ - Subscribe contact
    - POST /api/v1/marketing-campaigns/contacts/<id>/unsubscribe/ - Unsubscribe contact
    """
    queryset = Contact.objects.select_related('user').all()
    filterset_fields = ['status', 'subscribed', 'unsubscribed', 'source']
    search_fields = ['email', 'first_name', 'last_name', 'company']
    ordering_fields = ['added_at', 'email', 'status']
    ordering = ['-added_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return ContactListSerializer
        elif self.action == 'create':
            return ContactCreateSerializer
        return ContactDetailSerializer

    @action(detail=True, methods=['post'])
    def subscribe(self, request, pk=None):
        """Mark contact as subscribed."""
        contact = self.get_object()
        contact.subscribe()
        serializer = self.get_serializer(contact)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def unsubscribe(self, request, pk=None):
        """Mark contact as unsubscribed."""
        contact = self.get_object()
        contact.unsubscribe()
        serializer = self.get_serializer(contact)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def subscribers(self, request):
        """Get all subscribed contacts."""
        queryset = self.filter_queryset(
            self.get_queryset().filter(subscribed=True, unsubscribed=False)
        )
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


# =============================================================================
# CAMPAIGN VIEWSETS
# =============================================================================

class MarketingCampaignViewSet(SecureTenantViewSet):
    """
    ViewSet for managing marketing campaigns.

    Endpoints:
    - GET /api/v1/marketing-campaigns/campaigns/ - List all campaigns
    - POST /api/v1/marketing-campaigns/campaigns/ - Create campaign
    - GET /api/v1/marketing-campaigns/campaigns/<id>/ - Campaign detail
    - PUT/PATCH /api/v1/marketing-campaigns/campaigns/<id>/ - Update campaign
    - DELETE /api/v1/marketing-campaigns/campaigns/<id>/ - Delete campaign
    - POST /api/v1/marketing-campaigns/campaigns/<id>/send/ - Send campaign
    - POST /api/v1/marketing-campaigns/campaigns/<id>/schedule/ - Schedule campaign
    - POST /api/v1/marketing-campaigns/campaigns/<id>/cancel/ - Cancel campaign
    """
    queryset = MarketingCampaign.objects.prefetch_related('articles', 'attachments').all()
    filterset_fields = ['status', 'campaign_type', 'sent']
    search_fields = ['title', 'subject']
    ordering_fields = ['created_at', 'scheduled_for', 'sent_at']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return MarketingCampaignListSerializer
        elif self.action == 'create':
            return MarketingCampaignCreateSerializer
        return MarketingCampaignDetailSerializer

    @action(detail=True, methods=['post'])
    def send(self, request, pk=None):
        """Send campaign immediately."""
        campaign = self.get_object()

        if campaign.sent:
            return Response(
                {'detail': 'Campaign already sent.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Mark as sending
        campaign.sending = True
        campaign.status = 'sending'
        campaign.save(update_fields=['sending', 'status'])

        # TODO: Trigger async task to send emails
        # from ..tasks import send_campaign_emails
        # send_campaign_emails.delay(campaign.id)

        return Response({'detail': 'Campaign sending started.'})

    @action(detail=True, methods=['post'])
    def schedule(self, request, pk=None):
        """Schedule campaign for later sending."""
        campaign = self.get_object()
        scheduled_for = request.data.get('scheduled_for')

        if not scheduled_for:
            return Response(
                {'detail': 'scheduled_for is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        campaign.scheduled_for = scheduled_for
        campaign.status = 'scheduled'
        campaign.save(update_fields=['scheduled_for', 'status'])

        serializer = self.get_serializer(campaign)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel scheduled campaign."""
        campaign = self.get_object()

        if campaign.sent:
            return Response(
                {'detail': 'Cannot cancel already sent campaign.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        campaign.status = 'cancelled'
        campaign.save(update_fields=['status'])

        serializer = self.get_serializer(campaign)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def analytics(self, request, pk=None):
        """Get campaign analytics."""
        campaign = self.get_object()

        data = {
            'total_recipients': campaign.total_recipients,
            'total_sent': campaign.total_sent,
            'total_opens': campaign.total_opens,
            'total_clicks': campaign.total_clicks,
            'open_rate': round((campaign.total_opens / campaign.total_sent) * 100, 2) if campaign.total_sent > 0 else 0,
            'click_rate': round((campaign.total_clicks / campaign.total_sent) * 100, 2) if campaign.total_sent > 0 else 0,
            'sent_at': campaign.sent_at,
        }

        return Response(data)


class MessageArticleViewSet(SecureTenantViewSet):
    """ViewSet for campaign message articles."""
    queryset = MessageArticle.objects.select_related('campaign').all()
    serializer_class = MessageArticleSerializer
    filterset_fields = ['campaign']
    ordering = ['campaign', 'sortorder']


class CampaignAttachmentViewSet(SecureTenantViewSet):
    """ViewSet for campaign attachments."""
    queryset = CampaignAttachment.objects.select_related('campaign').all()
    serializer_class = CampaignAttachmentSerializer
    filterset_fields = ['campaign']


# =============================================================================
# TRACKING VIEWSETS
# =============================================================================

class CampaignTrackingViewSet(SecureTenantViewSet):
    """ViewSet for campaign engagement tracking."""
    queryset = CampaignTracking.objects.select_related('contact', 'campaign').all()
    serializer_class = CampaignTrackingSerializer
    filterset_fields = ['contact', 'campaign', 'opened', 'clicked']
    ordering = ['-opened_at']

    @action(detail=False, methods=['get'])
    def by_campaign(self, request):
        """Get tracking stats grouped by campaign."""
        campaign_id = request.query_params.get('campaign_id')
        if not campaign_id:
            return Response(
                {'detail': 'campaign_id parameter required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        queryset = self.filter_queryset(
            self.get_queryset().filter(campaign_id=campaign_id)
        )

        data = {
            'total_recipients': queryset.count(),
            'total_opens': queryset.filter(opened=True).count(),
            'total_clicks': queryset.filter(clicked=True).count(),
        }

        return Response(data)


class VisitEventViewSet(SecureTenantViewSet):
    """ViewSet for visit tracking events."""
    queryset = VisitEvent.objects.all()
    serializer_class = VisitEventSerializer
    filterset_fields = ['marketing_id', 'country', 'device_type', 'browser', 'os']
    search_fields = ['path', 'utm_source', 'utm_campaign']
    ordering = ['-timestamp']


class ConversionEventViewSet(SecureTenantViewSet):
    """ViewSet for conversion events."""
    queryset = ConversionEvent.objects.all()
    serializer_class = ConversionEventSerializer
    filterset_fields = ['marketing_id', 'event_name']
    search_fields = ['event_name']
    ordering = ['-timestamp']


class AggregatedStatsViewSet(SecureTenantViewSet):
    """ViewSet for aggregated statistics."""
    queryset = AggregatedStats.objects.all()
    serializer_class = AggregatedStatsSerializer
    filterset_fields = ['date', 'country', 'device_type']
    ordering = ['-date']

    @action(detail=False, methods=['get'])
    def date_range(self, request):
        """Get stats for a date range."""
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')

        if not start_date or not end_date:
            return Response(
                {'detail': 'start_date and end_date parameters required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        queryset = self.filter_queryset(
            self.get_queryset().filter(date__gte=start_date, date__lte=end_date)
        )

        # Aggregate totals
        totals = {
            'total_visits': sum(s.total_visits for s in queryset),
            'total_conversions': sum(s.total_conversions for s in queryset),
            'total_revenue': sum(s.total_revenue for s in queryset),
        }

        totals['conversion_rate'] = round(
            (totals['total_conversions'] / totals['total_visits']) * 100, 2
        ) if totals['total_visits'] > 0 else 0

        return Response(totals)


# =============================================================================
# SEGMENT VIEWSETS
# =============================================================================

class ContactSegmentViewSet(SecureTenantViewSet):
    """
    ViewSet for managing contact segments.

    Endpoints:
    - GET /api/v1/marketing-campaigns/segments/ - List all segments
    - POST /api/v1/marketing-campaigns/segments/ - Create segment
    - GET /api/v1/marketing-campaigns/segments/<id>/ - Segment detail
    - PUT/PATCH /api/v1/marketing-campaigns/segments/<id>/ - Update segment
    - DELETE /api/v1/marketing-campaigns/segments/<id>/ - Delete segment
    - POST /api/v1/marketing-campaigns/segments/<id>/calculate/ - Recalculate segment count
    """
    queryset = ContactSegment.objects.all()
    serializer_class = ContactSegmentSerializer
    search_fields = ['name', 'description']
    ordering = ['name']

    @action(detail=True, methods=['post'])
    def calculate(self, request, pk=None):
        """Recalculate segment contact count."""
        segment = self.get_object()

        # TODO: Apply filters from segment.filters JSON to get count
        # For now, just return current count
        segment.last_calculated_at = timezone.now()
        segment.save(update_fields=['last_calculated_at'])

        serializer = self.get_serializer(segment)
        return Response(serializer.data)
