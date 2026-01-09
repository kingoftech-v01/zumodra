"""
Marketing App Serializers.

Provides serializers for:
- Visit tracking
- Prospects/Leads
- Newsletter campaigns
- Conversion events
"""

from rest_framework import serializers

from .models import (
    VisitEvent,
    AggregatedStats,
    Prospect,
    NewsletterCampaign,
    NewsletterSubscriber,
    NewsletterTracking,
    ConversionEvent,
)


# =============================================================================
# VISIT EVENT SERIALIZERS
# =============================================================================

class VisitEventListSerializer(serializers.ModelSerializer):
    """List serializer for visit events."""

    class Meta:
        model = VisitEvent
        fields = [
            'id', 'timestamp', 'marketing_id', 'country', 'device_type',
            'browser', 'path', 'utm_source', 'utm_campaign'
        ]


class VisitEventDetailSerializer(serializers.ModelSerializer):
    """Detail serializer for visit events."""

    class Meta:
        model = VisitEvent
        fields = '__all__'


# =============================================================================
# AGGREGATED STATS SERIALIZERS
# =============================================================================

class AggregatedStatsSerializer(serializers.ModelSerializer):
    """Serializer for aggregated stats."""

    class Meta:
        model = AggregatedStats
        fields = ['id', 'date', 'country', 'device_type', 'total_visits']


# =============================================================================
# PROSPECT SERIALIZERS
# =============================================================================

class ProspectListSerializer(serializers.ModelSerializer):
    """List serializer for prospects."""
    full_name = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = Prospect
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'company', 'source', 'status', 'status_display', 'added_on'
        ]

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or obj.email


class ProspectDetailSerializer(serializers.ModelSerializer):
    """Detail serializer for prospects."""
    full_name = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = Prospect
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'company', 'phone', 'source', 'status', 'status_display', 'added_on'
        ]

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or obj.email


class ProspectCreateSerializer(serializers.ModelSerializer):
    """Create serializer for prospects."""

    class Meta:
        model = Prospect
        fields = ['email', 'first_name', 'last_name', 'company', 'phone', 'source']


class ProspectUpdateSerializer(serializers.ModelSerializer):
    """Update serializer for prospects (status changes)."""

    class Meta:
        model = Prospect
        fields = ['first_name', 'last_name', 'company', 'phone', 'source', 'status']


# =============================================================================
# NEWSLETTER CAMPAIGN SERIALIZERS
# =============================================================================

class NewsletterCampaignListSerializer(serializers.ModelSerializer):
    """List serializer for newsletter campaigns."""
    stats = serializers.SerializerMethodField()

    class Meta:
        model = NewsletterCampaign
        fields = [
            'id', 'title', 'subject', 'created_on', 'scheduled_for',
            'sent', 'sent_on', 'stats'
        ]

    def get_stats(self, obj):
        tracking = NewsletterTracking.objects.filter(campaign=obj)
        total = tracking.count()
        if total == 0:
            return {'sent': 0, 'opened': 0, 'clicked': 0, 'open_rate': 0, 'click_rate': 0}

        opened = tracking.filter(opened=True).count()
        clicked = tracking.filter(clicked=True).count()
        return {
            'sent': total,
            'opened': opened,
            'clicked': clicked,
            'open_rate': round(opened / total * 100, 1) if total else 0,
            'click_rate': round(clicked / total * 100, 1) if total else 0,
        }


class NewsletterCampaignDetailSerializer(serializers.ModelSerializer):
    """Detail serializer for newsletter campaigns."""
    stats = serializers.SerializerMethodField()

    class Meta:
        model = NewsletterCampaign
        fields = [
            'id', 'title', 'subject', 'content', 'created_on',
            'scheduled_for', 'sent', 'sent_on', 'stats'
        ]

    def get_stats(self, obj):
        tracking = NewsletterTracking.objects.filter(campaign=obj)
        total = tracking.count()
        if total == 0:
            return {'sent': 0, 'opened': 0, 'clicked': 0, 'open_rate': 0, 'click_rate': 0}

        opened = tracking.filter(opened=True).count()
        clicked = tracking.filter(clicked=True).count()
        return {
            'sent': total,
            'opened': opened,
            'clicked': clicked,
            'open_rate': round(opened / total * 100, 1) if total else 0,
            'click_rate': round(clicked / total * 100, 1) if total else 0,
        }


class NewsletterCampaignCreateSerializer(serializers.ModelSerializer):
    """Create serializer for newsletter campaigns."""

    class Meta:
        model = NewsletterCampaign
        fields = ['title', 'subject', 'content', 'scheduled_for']


# =============================================================================
# NEWSLETTER SUBSCRIBER SERIALIZERS
# =============================================================================

class NewsletterSubscriberListSerializer(serializers.ModelSerializer):
    """List serializer for newsletter subscribers."""

    class Meta:
        model = NewsletterSubscriber
        fields = ['id', 'email', 'subscribed_on', 'active']


class NewsletterSubscriberDetailSerializer(serializers.ModelSerializer):
    """Detail serializer for newsletter subscribers."""
    campaigns_received = serializers.SerializerMethodField()

    class Meta:
        model = NewsletterSubscriber
        fields = [
            'id', 'email', 'subscribed_on', 'unsubscribed_on',
            'active', 'campaigns_received'
        ]

    def get_campaigns_received(self, obj):
        return obj.newslettertracking_set.count()


class NewsletterSubscriberCreateSerializer(serializers.ModelSerializer):
    """Create serializer for newsletter subscribers."""

    class Meta:
        model = NewsletterSubscriber
        fields = ['email']


# =============================================================================
# NEWSLETTER TRACKING SERIALIZERS
# =============================================================================

class NewsletterTrackingSerializer(serializers.ModelSerializer):
    """Serializer for newsletter tracking."""
    subscriber_email = serializers.CharField(source='subscriber.email', read_only=True)
    campaign_title = serializers.CharField(source='campaign.title', read_only=True)

    class Meta:
        model = NewsletterTracking
        fields = [
            'id', 'subscriber', 'subscriber_email', 'campaign', 'campaign_title',
            'opened', 'opened_on', 'clicked', 'clicked_on'
        ]


# =============================================================================
# CONVERSION EVENT SERIALIZERS
# =============================================================================

class ConversionEventListSerializer(serializers.ModelSerializer):
    """List serializer for conversion events."""

    class Meta:
        model = ConversionEvent
        fields = ['id', 'marketing_id', 'event_name', 'value', 'timestamp']


class ConversionEventDetailSerializer(serializers.ModelSerializer):
    """Detail serializer for conversion events."""

    class Meta:
        model = ConversionEvent
        fields = ['id', 'marketing_id', 'event_name', 'value', 'timestamp', 'metadata']


class ConversionEventCreateSerializer(serializers.ModelSerializer):
    """Create serializer for conversion events."""

    class Meta:
        model = ConversionEvent
        fields = ['marketing_id', 'event_name', 'value', 'metadata']


# =============================================================================
# ANALYTICS SERIALIZERS
# =============================================================================

class MarketingAnalyticsSerializer(serializers.Serializer):
    """Serializer for marketing analytics summary."""
    total_visits = serializers.IntegerField()
    unique_visitors = serializers.IntegerField()
    total_prospects = serializers.IntegerField()
    new_prospects = serializers.IntegerField()
    conversion_rate = serializers.FloatField()
    total_revenue = serializers.DecimalField(max_digits=12, decimal_places=2)
    total_subscribers = serializers.IntegerField()
    active_subscribers = serializers.IntegerField()
    campaigns_sent = serializers.IntegerField()
    avg_open_rate = serializers.FloatField()
    avg_click_rate = serializers.FloatField()


class TrafficBySourceSerializer(serializers.Serializer):
    """Serializer for traffic by source."""
    utm_source = serializers.CharField()
    visits = serializers.IntegerField()
    percentage = serializers.FloatField()


class TrafficByCountrySerializer(serializers.Serializer):
    """Serializer for traffic by country."""
    country = serializers.CharField()
    visits = serializers.IntegerField()
    percentage = serializers.FloatField()


class TrafficByDeviceSerializer(serializers.Serializer):
    """Serializer for traffic by device."""
    device_type = serializers.CharField()
    visits = serializers.IntegerField()
    percentage = serializers.FloatField()
