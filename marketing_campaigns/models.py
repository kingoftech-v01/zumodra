"""
Marketing Campaigns Models

Unified models merging marketing/ and newsletter/ apps with tenant isolation.

Architecture:
- Contact: Unified (Prospect + Subscription + NewsletterSubscriber)
- MarketingCampaign: Unified (NewsletterCampaign + Message + Submission)
- CampaignMessage: Rich email content (from newsletter.Message)
- MessageArticle: Content blocks (from newsletter.Article)
- CampaignTracking: Engagement tracking (unified)
- VisitEvent: Visitor tracking (now tenant-scoped)
- ConversionEvent: Conversion tracking (now tenant-scoped)
- AggregatedStats: Analytics (now per-tenant)

All models inherit from TenantAwareModel for multi-tenant isolation.
"""

import logging
import uuid
from datetime import datetime
from typing import Optional, List
from abc import abstractmethod, ABC

from django.db import models
from django.conf import settings
from django.contrib.sites.models import Site
from django.core.exceptions import ValidationError
from django.core.mail import EmailMultiAlternatives
from django.template.loader import select_template
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.urls import reverse

from core.db.models import TenantAwareModel
from tenants.models import Tenant

logger = logging.getLogger(__name__)

AUTH_USER_MODEL = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')


# =============================================================================
# CONTACT MANAGEMENT (Unified: Prospect + Subscription)
# =============================================================================

class ContactStatus(models.TextChoices):
    """Contact lifecycle status."""
    NEW = 'new', _('New')
    CONTACTED = 'contacted', _('Contacted')
    QUALIFIED = 'qualified', _('Qualified')
    SUBSCRIBED = 'subscribed', _('Subscribed')
    UNSUBSCRIBED = 'unsubscribed', _('Unsubscribed')
    CONVERTED = 'converted', _('Converted')
    DISQUALIFIED = 'disqualified', _('Disqualified')


class Contact(TenantAwareModel):
    """
    Unified contact model (Prospect + Subscription + NewsletterSubscriber).

    Replaces:
    - marketing.Prospect
    - newsletter.Subscription
    - marketing.NewsletterSubscriber

    Workflow: visitor → lead → subscriber → customer
    """
    # Identification
    email = models.EmailField(verbose_name=_('E-mail'))
    first_name = models.CharField(max_length=128, blank=True, verbose_name=_('First name'))
    last_name = models.CharField(max_length=128, blank=True, verbose_name=_('Last name'))
    company = models.CharField(max_length=256, blank=True, verbose_name=_('Company'))
    phone = models.CharField(max_length=32, blank=True, verbose_name=_('Phone'))

    # Optional user link (for authenticated subscribers)
    user = models.ForeignKey(
        AUTH_USER_MODEL,
        blank=True, null=True,
        on_delete=models.SET_NULL,
        related_name='marketing_contacts',
        verbose_name=_('User')
    )

    # Status and lifecycle
    status = models.CharField(
        max_length=32,
        choices=ContactStatus.choices,
        default=ContactStatus.NEW,
        db_index=True,
        verbose_name=_('Status')
    )
    source = models.CharField(
        max_length=256,
        blank=True,
        verbose_name=_('Source'),
        help_text=_('Lead source or campaign')
    )

    # Subscription info
    subscribed = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name=_('Subscribed'),
        help_text=_('Whether contact is subscribed to email campaigns')
    )
    subscribed_at = models.DateTimeField(
        blank=True, null=True,
        verbose_name=_('Subscribed at')
    )
    unsubscribed = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name=_('Unsubscribed')
    )
    unsubscribed_at = models.DateTimeField(
        blank=True, null=True,
        verbose_name=_('Unsubscribed at')
    )

    # Double opt-in activation
    activation_code = models.CharField(
        max_length=40,
        blank=True,
        verbose_name=_('Activation code'),
        help_text=_('Code for confirming subscription')
    )
    subscribe_date = models.DateTimeField(
        blank=True, null=True,
        db_index=True,
        verbose_name=_('Subscription request date')
    )
    unsubscribe_date = models.DateTimeField(
        blank=True, null=True,
        db_index=True,
        verbose_name=_('Unsubscription date')
    )

    # Mailchimp sync
    mailchimp_id = models.CharField(
        max_length=255,
        blank=True,
        verbose_name=_('Mailchimp ID'),
        help_text=_('Mailchimp subscriber ID')
    )
    mailchimp_synced_at = models.DateTimeField(
        blank=True, null=True,
        verbose_name=_('Last synced to Mailchimp')
    )

    # Tracking
    ip_address = models.GenericIPAddressField(
        blank=True, null=True,
        verbose_name=_('IP Address')
    )

    # Timestamps
    added_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Added at'))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_('Updated at'))

    class Meta:
        verbose_name = _('Contact')
        verbose_name_plural = _('Contacts')
        unique_together = ('tenant', 'email')
        indexes = [
            models.Index(fields=['tenant', 'email']),
            models.Index(fields=['tenant', 'status']),
            models.Index(fields=['tenant', 'subscribed']),
            models.Index(fields=['added_at']),
        ]
        ordering = ['-added_at']

    def __str__(self):
        if self.first_name or self.last_name:
            return f"{self.first_name} {self.last_name} <{self.email}>"
        return self.email

    def get_full_name(self):
        """Return full name or email."""
        if self.first_name or self.last_name:
            return f"{self.first_name} {self.last_name}".strip()
        return self.email

    def subscribe(self):
        """Mark contact as subscribed."""
        self.subscribed = True
        self.unsubscribed = False
        self.subscribed_at = timezone.now()
        self.status = ContactStatus.SUBSCRIBED
        self.save(update_fields=['subscribed', 'unsubscribed', 'subscribed_at', 'status'])

    def unsubscribe(self):
        """Mark contact as unsubscribed."""
        self.subscribed = False
        self.unsubscribed = True
        self.unsubscribed_at = timezone.now()
        self.status = ContactStatus.UNSUBSCRIBED
        self.save(update_fields=['subscribed', 'unsubscribed', 'unsubscribed_at', 'status'])


# =============================================================================
# CAMPAIGN MANAGEMENT (Unified: NewsletterCampaign + Message + Submission)
# =============================================================================

class CampaignType(models.TextChoices):
    """Campaign type choices."""
    NEWSLETTER = 'newsletter', _('Newsletter')
    EMAIL_SEQUENCE = 'email_sequence', _('Email Sequence')
    TRIGGERED = 'triggered', _('Triggered')
    ANNOUNCEMENT = 'announcement', _('Announcement')


class CampaignStatus(models.TextChoices):
    """Campaign status choices."""
    DRAFT = 'draft', _('Draft')
    SCHEDULED = 'scheduled', _('Scheduled')
    SENDING = 'sending', _('Sending')
    SENT = 'sent', _('Sent')
    CANCELLED = 'cancelled', _('Cancelled')


class MarketingCampaign(TenantAwareModel):
    """
    Unified campaign model (NewsletterCampaign + Message + Submission).

    Replaces:
    - marketing.NewsletterCampaign
    - newsletter.Message
    - newsletter.Submission
    """
    # Basic info
    title = models.CharField(max_length=256, verbose_name=_('Campaign title'))
    slug = models.SlugField(max_length=255, blank=True, verbose_name=_('Slug'))
    campaign_type = models.CharField(
        max_length=32,
        choices=CampaignType.choices,
        default=CampaignType.NEWSLETTER,
        verbose_name=_('Campaign type')
    )

    # Email content
    subject = models.CharField(max_length=256, verbose_name=_('Email subject'))
    content = models.TextField(blank=True, verbose_name=_('Content'))  # Simple content

    # Status and scheduling
    status = models.CharField(
        max_length=32,
        choices=CampaignStatus.choices,
        default=CampaignStatus.DRAFT,
        db_index=True,
        verbose_name=_('Status')
    )
    scheduled_for = models.DateTimeField(
        blank=True, null=True,
        verbose_name=_('Scheduled for')
    )

    # Sending info
    sent = models.BooleanField(default=False, verbose_name=_('Sent'))
    sent_at = models.DateTimeField(blank=True, null=True, verbose_name=_('Sent at'))
    sending = models.BooleanField(default=False, verbose_name=_('Currently sending'))

    # Email settings
    sender_name = models.CharField(max_length=200, blank=True, verbose_name=_('Sender name'))
    sender_email = models.EmailField(blank=True, verbose_name=_('Sender email'))
    send_html = models.BooleanField(default=True, verbose_name=_('Send HTML email'))

    # Tracking
    total_recipients = models.PositiveIntegerField(default=0, verbose_name=_('Total recipients'))
    total_sent = models.PositiveIntegerField(default=0, verbose_name=_('Total sent'))
    total_opens = models.PositiveIntegerField(default=0, verbose_name=_('Total opens'))
    total_clicks = models.PositiveIntegerField(default=0, verbose_name=_('Total clicks'))

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Created at'))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_('Updated at'))

    class Meta:
        verbose_name = _('Marketing Campaign')
        verbose_name_plural = _('Marketing Campaigns')
        indexes = [
            models.Index(fields=['tenant', 'status']),
            models.Index(fields=['tenant', 'scheduled_for']),
            models.Index(fields=['created_at']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} ({self.get_status_display()})"


class MessageArticle(models.Model):
    """
    Content block for campaign messages (from newsletter.Article).

    Allows rich, structured email content with multiple sections.
    """
    campaign = models.ForeignKey(
        MarketingCampaign,
        on_delete=models.CASCADE,
        related_name='articles',
        verbose_name=_('Campaign')
    )

    # Content
    title = models.CharField(max_length=200, blank=True, verbose_name=_('Title'))
    text = models.TextField(verbose_name=_('Text'))
    url = models.URLField(
        blank=True,
        verbose_name=_('Link'),
        help_text=_('Optional link for this article')
    )

    # Media
    image = models.ImageField(
        upload_to='campaign_articles/',
        blank=True, null=True,
        verbose_name=_('Image')
    )

    # Ordering
    sortorder = models.PositiveIntegerField(
        default=0,
        db_index=True,
        verbose_name=_('Sort order')
    )

    class Meta:
        verbose_name = _('Campaign Article')
        verbose_name_plural = _('Campaign Articles')
        ordering = ['sortorder']
        unique_together = ('campaign', 'sortorder')

    def __str__(self):
        return f"{self.campaign.title} - Article {self.sortorder}"


class CampaignAttachment(models.Model):
    """
    File attachments for campaigns (from newsletter.Attachment).
    """
    campaign = models.ForeignKey(
        MarketingCampaign,
        on_delete=models.CASCADE,
        related_name='attachments',
        verbose_name=_('Campaign')
    )

    file = models.FileField(
        upload_to='campaign_attachments/',
        verbose_name=_('File')
    )

    class Meta:
        verbose_name = _('Campaign Attachment')
        verbose_name_plural = _('Campaign Attachments')

    def __str__(self):
        return f"{self.campaign.title} - {self.file.name}"


# =============================================================================
# ENGAGEMENT TRACKING
# =============================================================================

class CampaignTracking(TenantAwareModel):
    """
    Campaign engagement tracking (merge of marketing.NewsletterTracking).

    Tracks opens, clicks, and other engagement metrics per contact per campaign.
    """
    contact = models.ForeignKey(
        Contact,
        on_delete=models.CASCADE,
        related_name='campaign_tracking',
        verbose_name=_('Contact')
    )
    campaign = models.ForeignKey(
        MarketingCampaign,
        on_delete=models.CASCADE,
        related_name='tracking',
        verbose_name=_('Campaign')
    )

    # Engagement
    opened = models.BooleanField(default=False, verbose_name=_('Opened'))
    opened_at = models.DateTimeField(blank=True, null=True, verbose_name=_('Opened at'))
    clicked = models.BooleanField(default=False, verbose_name=_('Clicked'))
    clicked_at = models.DateTimeField(blank=True, null=True, verbose_name=_('Clicked at'))

    # Tracking
    open_count = models.PositiveIntegerField(default=0, verbose_name=_('Open count'))
    click_count = models.PositiveIntegerField(default=0, verbose_name=_('Click count'))

    class Meta:
        verbose_name = _('Campaign Tracking')
        verbose_name_plural = _('Campaign Tracking')
        unique_together = ('tenant', 'contact', 'campaign')
        indexes = [
            models.Index(fields=['tenant', 'campaign', 'opened']),
            models.Index(fields=['tenant', 'contact']),
        ]

    def __str__(self):
        return f"{self.contact.email} - {self.campaign.title}"


# =============================================================================
# VISITOR TRACKING (now tenant-scoped)
# =============================================================================

class VisitEvent(TenantAwareModel):
    """
    Visitor tracking events (from marketing.VisitEvent, now tenant-aware).

    Tracks all visits to tenant domains with UTM params, device info, GeoIP.
    """
    timestamp = models.DateTimeField(auto_now_add=True, verbose_name=_('Timestamp'))
    marketing_id = models.CharField(
        max_length=32,
        db_index=True,
        blank=True,
        verbose_name=_('Marketing ID'),
        help_text=_('Anonymous visitor tracking ID')
    )

    # Network info
    ip_address = models.GenericIPAddressField(verbose_name=_('IP Address'))
    country = models.CharField(max_length=2, db_index=True, blank=True, verbose_name=_('Country'))

    # Device info
    device_type = models.CharField(max_length=32, blank=True, verbose_name=_('Device type'))
    browser = models.CharField(max_length=32, blank=True, verbose_name=_('Browser'))
    os = models.CharField(max_length=32, blank=True, verbose_name=_('OS'))

    # Request info
    path = models.CharField(max_length=256, verbose_name=_('Path'))
    method = models.CharField(max_length=8, default='GET', verbose_name=_('HTTP Method'))

    # UTM tracking
    utm_source = models.CharField(max_length=128, blank=True, null=True, verbose_name=_('UTM Source'))
    utm_medium = models.CharField(max_length=128, blank=True, null=True, verbose_name=_('UTM Medium'))
    utm_campaign = models.CharField(max_length=128, blank=True, null=True, verbose_name=_('UTM Campaign'))
    utm_content = models.CharField(max_length=128, blank=True, null=True, verbose_name=_('UTM Content'))
    utm_term = models.CharField(max_length=128, blank=True, null=True, verbose_name=_('UTM Term'))
    ref = models.CharField(max_length=128, blank=True, null=True, verbose_name=_('Referrer'))

    class Meta:
        verbose_name = _('Visit Event')
        verbose_name_plural = _('Visit Events')
        indexes = [
            models.Index(fields=['tenant', 'marketing_id']),
            models.Index(fields=['tenant', 'country']),
            models.Index(fields=['tenant', 'timestamp']),
            models.Index(fields=['device_type']),
        ]
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.tenant.name} - {self.path} ({self.timestamp})"


# =============================================================================
# CONVERSION TRACKING (now tenant-scoped)
# =============================================================================

class ConversionEvent(TenantAwareModel):
    """
    Conversion tracking (from marketing.ConversionEvent, now tenant-aware).

    Tracks key events: purchase, signup, subscription, etc.
    """
    marketing_id = models.CharField(
        max_length=32,
        db_index=True,
        blank=True,
        verbose_name=_('Marketing ID')
    )
    event_name = models.CharField(
        max_length=128,
        verbose_name=_('Event name'),
        help_text=_('E.g., purchase, signup, subscription')
    )
    value = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        blank=True, null=True,
        verbose_name=_('Value')
    )
    timestamp = models.DateTimeField(default=timezone.now, verbose_name=_('Timestamp'))
    metadata = models.JSONField(
        blank=True, null=True,
        verbose_name=_('Metadata'),
        help_text=_('Additional event data (product ID, campaign, etc.)')
    )

    class Meta:
        verbose_name = _('Conversion Event')
        verbose_name_plural = _('Conversion Events')
        indexes = [
            models.Index(fields=['tenant', 'marketing_id']),
            models.Index(fields=['tenant', 'event_name']),
            models.Index(fields=['timestamp']),
        ]
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.tenant.name} - {self.event_name} ({self.value or 'N/A'})"


# =============================================================================
# ANALYTICS (now tenant-scoped)
# =============================================================================

class AggregatedStats(TenantAwareModel):
    """
    Aggregated statistics (from marketing.AggregatedStats, now tenant-aware).

    Pre-computed daily stats for fast dashboard queries.
    """
    date = models.DateField(db_index=True, verbose_name=_('Date'))
    country = models.CharField(max_length=2, db_index=True, blank=True, verbose_name=_('Country'))
    device_type = models.CharField(max_length=32, blank=True, verbose_name=_('Device type'))

    # Metrics
    total_visits = models.IntegerField(default=0, verbose_name=_('Total visits'))
    total_conversions = models.IntegerField(default=0, verbose_name=_('Total conversions'))
    total_revenue = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0,
        verbose_name=_('Total revenue')
    )

    class Meta:
        verbose_name = _('Aggregated Stats')
        verbose_name_plural = _('Aggregated Stats')
        unique_together = ('tenant', 'date', 'country', 'device_type')
        indexes = [
            models.Index(fields=['tenant', 'date']),
        ]
        ordering = ['-date']

    def __str__(self):
        return f"{self.tenant.name} - {self.date} ({self.total_visits} visits)"


# =============================================================================
# CONTACT SEGMENTS (NEW - for targeted campaigns)
# =============================================================================

class ContactSegment(TenantAwareModel):
    """
    Contact segments for targeted campaign sending.

    Allows dynamic filtering of contacts for campaigns.
    """
    name = models.CharField(max_length=200, verbose_name=_('Segment name'))
    description = models.TextField(blank=True, verbose_name=_('Description'))

    # Filter criteria (JSON)
    filters = models.JSONField(
        default=dict,
        verbose_name=_('Filters'),
        help_text=_('JSON filter criteria for contacts')
    )

    # Cached count
    contact_count = models.PositiveIntegerField(default=0, verbose_name=_('Contact count'))
    last_calculated_at = models.DateTimeField(
        blank=True, null=True,
        verbose_name=_('Last calculated at')
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Created at'))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_('Updated at'))

    class Meta:
        verbose_name = _('Contact Segment')
        verbose_name_plural = _('Contact Segments')
        indexes = [
            models.Index(fields=['tenant', 'name']),
        ]
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.contact_count} contacts)"
