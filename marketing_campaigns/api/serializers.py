"""
Marketing Campaigns API Serializers

DRF serializers for marketing campaigns API endpoints.
"""
from rest_framework import serializers
from django.utils.translation import gettext_lazy as _

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


# =============================================================================
# CONTACT SERIALIZERS
# =============================================================================

class ContactListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for contact list."""

    full_name = serializers.CharField(source='get_full_name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = Contact
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'company', 'status', 'status_display', 'subscribed',
            'unsubscribed', 'source', 'added_at',
        ]
        read_only_fields = ['id', 'full_name', 'status_display', 'added_at']


class ContactDetailSerializer(serializers.ModelSerializer):
    """Full contact detail serializer."""

    full_name = serializers.CharField(source='get_full_name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = Contact
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'company', 'phone', 'user', 'status', 'status_display',
            'source', 'subscribed', 'subscribed_at', 'unsubscribed',
            'unsubscribed_at', 'activation_code', 'subscribe_date',
            'unsubscribe_date', 'mailchimp_id', 'mailchimp_synced_at',
            'ip_address', 'added_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'full_name', 'status_display', 'subscribed_at',
            'unsubscribed_at', 'mailchimp_synced_at', 'added_at', 'updated_at',
        ]


class ContactCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating contacts."""

    class Meta:
        model = Contact
        fields = [
            'email', 'first_name', 'last_name', 'company', 'phone',
            'status', 'source', 'subscribed', 'ip_address',
        ]

    def validate_email(self, value):
        """Validate email uniqueness per tenant."""
        request = self.context.get('request')
        if request and hasattr(request, 'tenant'):
            if Contact.objects.filter(tenant=request.tenant, email=value).exists():
                raise serializers.ValidationError(_('Contact with this email already exists.'))
        return value


# =============================================================================
# CAMPAIGN SERIALIZERS
# =============================================================================

class MessageArticleSerializer(serializers.ModelSerializer):
    """Serializer for campaign message articles."""

    class Meta:
        model = MessageArticle
        fields = [
            'id', 'campaign', 'title', 'text', 'url',
            'image', 'sortorder',
        ]
        read_only_fields = ['id']


class CampaignAttachmentSerializer(serializers.ModelSerializer):
    """Serializer for campaign attachments."""

    class Meta:
        model = CampaignAttachment
        fields = ['id', 'campaign', 'file']
        read_only_fields = ['id']


class MarketingCampaignListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for campaign list."""

    status_display = serializers.CharField(source='get_status_display', read_only=True)
    campaign_type_display = serializers.CharField(source='get_campaign_type_display', read_only=True)
    open_rate = serializers.SerializerMethodField()
    click_rate = serializers.SerializerMethodField()

    class Meta:
        model = MarketingCampaign
        fields = [
            'id', 'title', 'slug', 'campaign_type', 'campaign_type_display',
            'subject', 'status', 'status_display', 'scheduled_for',
            'sent', 'sent_at', 'total_recipients', 'total_sent',
            'total_opens', 'total_clicks', 'open_rate', 'click_rate',
            'created_at',
        ]
        read_only_fields = [
            'id', 'status_display', 'campaign_type_display', 'sent', 'sent_at',
            'total_sent', 'total_opens', 'total_clicks', 'open_rate',
            'click_rate', 'created_at',
        ]

    def get_open_rate(self, obj):
        """Calculate open rate percentage."""
        if obj.total_sent > 0:
            return round((obj.total_opens / obj.total_sent) * 100, 2)
        return 0

    def get_click_rate(self, obj):
        """Calculate click rate percentage."""
        if obj.total_sent > 0:
            return round((obj.total_clicks / obj.total_sent) * 100, 2)
        return 0


class MarketingCampaignDetailSerializer(serializers.ModelSerializer):
    """Full campaign detail serializer."""

    status_display = serializers.CharField(source='get_status_display', read_only=True)
    campaign_type_display = serializers.CharField(source='get_campaign_type_display', read_only=True)
    articles = MessageArticleSerializer(many=True, read_only=True)
    attachments = CampaignAttachmentSerializer(many=True, read_only=True)
    open_rate = serializers.SerializerMethodField()
    click_rate = serializers.SerializerMethodField()

    class Meta:
        model = MarketingCampaign
        fields = [
            'id', 'title', 'slug', 'campaign_type', 'campaign_type_display',
            'subject', 'content', 'status', 'status_display', 'scheduled_for',
            'sent', 'sent_at', 'sending', 'sender_name', 'sender_email',
            'send_html', 'total_recipients', 'total_sent', 'total_opens',
            'total_clicks', 'open_rate', 'click_rate', 'articles',
            'attachments', 'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'status_display', 'campaign_type_display', 'sent', 'sent_at',
            'sending', 'total_sent', 'total_opens', 'total_clicks',
            'open_rate', 'click_rate', 'articles', 'attachments',
            'created_at', 'updated_at',
        ]

    def get_open_rate(self, obj):
        """Calculate open rate percentage."""
        if obj.total_sent > 0:
            return round((obj.total_opens / obj.total_sent) * 100, 2)
        return 0

    def get_click_rate(self, obj):
        """Calculate click rate percentage."""
        if obj.total_sent > 0:
            return round((obj.total_clicks / obj.total_sent) * 100, 2)
        return 0


class MarketingCampaignCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating campaigns."""

    class Meta:
        model = MarketingCampaign
        fields = [
            'title', 'slug', 'campaign_type', 'subject', 'content',
            'scheduled_for', 'sender_name', 'sender_email', 'send_html',
            'total_recipients',
        ]


# =============================================================================
# TRACKING SERIALIZERS
# =============================================================================

class CampaignTrackingSerializer(serializers.ModelSerializer):
    """Serializer for campaign engagement tracking."""

    contact_email = serializers.EmailField(source='contact.email', read_only=True)
    campaign_title = serializers.CharField(source='campaign.title', read_only=True)

    class Meta:
        model = CampaignTracking
        fields = [
            'id', 'contact', 'contact_email', 'campaign', 'campaign_title',
            'opened', 'opened_at', 'clicked', 'clicked_at',
            'open_count', 'click_count',
        ]
        read_only_fields = [
            'id', 'contact_email', 'campaign_title', 'opened', 'opened_at',
            'clicked', 'clicked_at', 'open_count', 'click_count',
        ]


class VisitEventSerializer(serializers.ModelSerializer):
    """Serializer for visit tracking events."""

    class Meta:
        model = VisitEvent
        fields = [
            'id', 'timestamp', 'marketing_id', 'ip_address', 'country',
            'device_type', 'browser', 'os', 'path', 'method',
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_content',
            'utm_term', 'ref',
        ]
        read_only_fields = ['id', 'timestamp']


class ConversionEventSerializer(serializers.ModelSerializer):
    """Serializer for conversion events."""

    class Meta:
        model = ConversionEvent
        fields = [
            'id', 'marketing_id', 'event_name', 'value', 'timestamp', 'metadata',
        ]
        read_only_fields = ['id', 'timestamp']


class AggregatedStatsSerializer(serializers.ModelSerializer):
    """Serializer for aggregated statistics."""

    conversion_rate = serializers.SerializerMethodField()

    class Meta:
        model = AggregatedStats
        fields = [
            'id', 'date', 'country', 'device_type', 'total_visits',
            'total_conversions', 'total_revenue', 'conversion_rate',
        ]
        read_only_fields = ['id', 'conversion_rate']

    def get_conversion_rate(self, obj):
        """Calculate conversion rate percentage."""
        if obj.total_visits > 0:
            return round((obj.total_conversions / obj.total_visits) * 100, 2)
        return 0


# =============================================================================
# SEGMENT SERIALIZERS
# =============================================================================

class ContactSegmentSerializer(serializers.ModelSerializer):
    """Serializer for contact segments."""

    class Meta:
        model = ContactSegment
        fields = [
            'id', 'name', 'description', 'filters', 'contact_count',
            'last_calculated_at', 'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'contact_count', 'last_calculated_at',
            'created_at', 'updated_at',
        ]
