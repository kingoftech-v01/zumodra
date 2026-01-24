"""Admin interface for marketing_campaigns app."""

from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from .models import (
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


class MessageArticleInline(admin.TabularInline):
    """Inline admin for campaign articles."""
    model = MessageArticle
    extra = 1
    fields = ('sortorder', 'title', 'text', 'url', 'image')
    ordering = ['sortorder']


class CampaignAttachmentInline(admin.TabularInline):
    """Inline admin for campaign attachments."""
    model = CampaignAttachment
    extra = 0
    fields = ('file',)


@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    """Admin interface for Contact model."""
    list_display = ('email', 'full_name_display', 'status', 'subscribed', 'tenant', 'added_at')
    list_filter = ('status', 'subscribed', 'unsubscribed', 'added_at', 'tenant')
    search_fields = ('email', 'first_name', 'last_name', 'company')
    readonly_fields = ('added_at', 'updated_at', 'mailchimp_synced_at')
    fieldsets = (
        (_('Contact Information'), {
            'fields': ('email', 'first_name', 'last_name', 'company', 'phone', 'user')
        }),
        (_('Status'), {
            'fields': ('status', 'source')
        }),
        (_('Subscription'), {
            'fields': ('subscribed', 'subscribed_at', 'unsubscribed', 'unsubscribed_at', 'activation_code')
        }),
        (_('Mailchimp'), {
            'fields': ('mailchimp_id', 'mailchimp_synced_at'),
            'classes': ('collapse',)
        }),
        (_('Tracking'), {
            'fields': ('ip_address',),
            'classes': ('collapse',)
        }),
        (_('Timestamps'), {
            'fields': ('added_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def full_name_display(self, obj):
        return obj.get_full_name()
    full_name_display.short_description = _('Name')


@admin.register(MarketingCampaign)
class MarketingCampaignAdmin(admin.ModelAdmin):
    """Admin interface for MarketingCampaign model."""
    list_display = ('title', 'campaign_type', 'status', 'scheduled_for', 'sent', 'total_recipients', 'tenant')
    list_filter = ('campaign_type', 'status', 'sent', 'created_at', 'tenant')
    search_fields = ('title', 'subject')
    readonly_fields = ('created_at', 'updated_at', 'sent_at', 'total_sent', 'total_opens', 'total_clicks')
    inlines = [MessageArticleInline, CampaignAttachmentInline]
    prepopulated_fields = {'slug': ('title',)}

    fieldsets = (
        (_('Campaign Information'), {
            'fields': ('title', 'slug', 'campaign_type', 'status')
        }),
        (_('Email Content'), {
            'fields': ('subject', 'content', 'sender_name', 'sender_email', 'send_html')
        }),
        (_('Scheduling'), {
            'fields': ('scheduled_for',)
        }),
        (_('Sending Status'), {
            'fields': ('sent', 'sent_at', 'sending'),
            'classes': ('collapse',)
        }),
        (_('Statistics'), {
            'fields': ('total_recipients', 'total_sent', 'total_opens', 'total_clicks'),
            'classes': ('collapse',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(CampaignTracking)
class CampaignTrackingAdmin(admin.ModelAdmin):
    """Admin interface for CampaignTracking model."""
    list_display = ('contact', 'campaign', 'opened', 'clicked', 'open_count', 'click_count')
    list_filter = ('opened', 'clicked', 'tenant')
    search_fields = ('contact__email', 'campaign__title')
    readonly_fields = ('opened_at', 'clicked_at', 'open_count', 'click_count')


@admin.register(VisitEvent)
class VisitEventAdmin(admin.ModelAdmin):
    """Admin interface for VisitEvent model."""
    list_display = ('timestamp', 'tenant', 'path', 'country', 'device_type', 'utm_campaign')
    list_filter = ('timestamp', 'country', 'device_type', 'tenant')
    search_fields = ('path', 'marketing_id', 'utm_campaign')
    readonly_fields = ('timestamp',)
    fieldsets = (
        (_('Visit Information'), {
            'fields': ('timestamp', 'path', 'method', 'marketing_id')
        }),
        (_('Network'), {
            'fields': ('ip_address', 'country')
        }),
        (_('Device'), {
            'fields': ('device_type', 'browser', 'os')
        }),
        (_('UTM Tracking'), {
            'fields': ('utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term', 'ref'),
            'classes': ('collapse',)
        }),
    )


@admin.register(ConversionEvent)
class ConversionEventAdmin(admin.ModelAdmin):
    """Admin interface for ConversionEvent model."""
    list_display = ('timestamp', 'tenant', 'event_name', 'value', 'marketing_id')
    list_filter = ('event_name', 'timestamp', 'tenant')
    search_fields = ('event_name', 'marketing_id')
    readonly_fields = ('timestamp',)


@admin.register(AggregatedStats)
class AggregatedStatsAdmin(admin.ModelAdmin):
    """Admin interface for AggregatedStats model."""
    list_display = ('date', 'tenant', 'country', 'total_visits', 'total_conversions', 'total_revenue')
    list_filter = ('date', 'country', 'tenant')
    readonly_fields = ('date', 'total_visits', 'total_conversions', 'total_revenue')


@admin.register(ContactSegment)
class ContactSegmentAdmin(admin.ModelAdmin):
    """Admin interface for ContactSegment model."""
    list_display = ('name', 'contact_count', 'tenant', 'last_calculated_at')
    list_filter = ('tenant', 'created_at')
    search_fields = ('name', 'description')
    readonly_fields = ('contact_count', 'last_calculated_at', 'created_at', 'updated_at')
