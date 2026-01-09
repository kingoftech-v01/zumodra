"""
Careers Models - Public Career Pages

This module implements:
- Tenant-branded career sites with subdomain/custom domain support
- Public job listings
- Application forms with GDPR compliance
- Job alerts with email subscriptions
- Candidate portal
"""

import re
import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _
from django.core.validators import (
    RegexValidator, FileExtensionValidator, MinLengthValidator
)
from django.core.exceptions import ValidationError

from tenants.mixins import TenantAwareModelMixin


# =============================================================================
# VALIDATORS
# =============================================================================

def validate_hex_color(value):
    """Validate hex color format."""
    if not re.match(r'^#[0-9A-Fa-f]{6}$', value):
        raise ValidationError(
            _('%(value)s is not a valid hex color (e.g., #3B82F6)'),
            params={'value': value},
        )


def validate_subdomain(value):
    """Validate subdomain format."""
    if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', value):
        raise ValidationError(
            _('Subdomain must be lowercase alphanumeric with optional hyphens, '
              '2-63 characters, not starting or ending with hyphen.')
        )
    reserved = ['www', 'api', 'admin', 'app', 'mail', 'ftp', 'cdn', 'static']
    if value in reserved:
        raise ValidationError(
            _('%(value)s is a reserved subdomain.'),
            params={'value': value},
        )


class FileSizeValidator:
    """
    Validator for maximum file size.

    This is a class-based validator that Django can serialize for migrations.
    It implements the `deconstruct()` method required for migration serialization.
    """

    def __init__(self, max_size_mb: int):
        self.max_size_mb = max_size_mb

    def __call__(self, value):
        if value.size > self.max_size_mb * 1024 * 1024:
            raise ValidationError(
                _('File size must be under %(max)s MB.'),
                params={'max': self.max_size_mb},
            )

    def __eq__(self, other):
        return (
            isinstance(other, FileSizeValidator) and
            self.max_size_mb == other.max_size_mb
        )

    def deconstruct(self):
        """
        Return a 3-tuple (path, args, kwargs) for migration serialization.
        Django uses this to reconstruct the validator in migration files.
        """
        return (
            'careers.models.FileSizeValidator',
            (self.max_size_mb,),
            {},
        )


# =============================================================================
# CAREER SITE MODEL
# =============================================================================

class CareerSite(TenantAwareModelMixin, models.Model):
    """
    Tenant-specific career site configuration.
    Supports subdomain-based and custom domain routing.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Domain Configuration
    subdomain = models.CharField(
        max_length=63,
        unique=True,
        validators=[validate_subdomain],
        help_text=_('Subdomain for career site (e.g., "acme" for acme.careers.zumodra.com)')
    )
    custom_domain = models.CharField(
        max_length=255,
        blank=True,
        unique=True,
        null=True,
        help_text=_('Custom domain (e.g., "careers.acme.com")')
    )
    custom_domain_verified = models.BooleanField(
        default=False,
        help_text=_('Whether custom domain DNS is verified')
    )
    custom_domain_ssl = models.BooleanField(
        default=False,
        help_text=_('Whether SSL certificate is active for custom domain')
    )

    # Basic Info
    company_name = models.CharField(max_length=200)
    tagline = models.CharField(max_length=300, blank=True)
    description = models.TextField(blank=True)

    # Branding
    logo = models.ImageField(
        upload_to='career_sites/logos/',
        blank=True,
        null=True,
        validators=[FileSizeValidator(5)]
    )
    favicon = models.ImageField(
        upload_to='career_sites/favicons/',
        blank=True,
        null=True,
        validators=[FileSizeValidator(1)]
    )
    cover_image = models.ImageField(
        upload_to='career_sites/covers/',
        blank=True,
        null=True,
        validators=[FileSizeValidator(10)]
    )

    # Colors (with validation)
    primary_color = models.CharField(
        max_length=7,
        default='#3B82F6',
        validators=[validate_hex_color]
    )
    secondary_color = models.CharField(
        max_length=7,
        default='#1E40AF',
        validators=[validate_hex_color]
    )
    accent_color = models.CharField(
        max_length=7,
        default='#10B981',
        validators=[validate_hex_color]
    )
    text_color = models.CharField(
        max_length=7,
        default='#1F2937',
        validators=[validate_hex_color]
    )
    background_color = models.CharField(
        max_length=7,
        default='#FFFFFF',
        validators=[validate_hex_color]
    )

    # Custom CSS/JS
    custom_css = models.TextField(
        blank=True,
        help_text=_('Custom CSS for career site styling')
    )
    custom_head_scripts = models.TextField(
        blank=True,
        help_text=_('Custom scripts to include in <head>')
    )

    # Hero Section
    hero_title = models.CharField(max_length=200, blank=True)
    hero_subtitle = models.CharField(max_length=500, blank=True)
    hero_cta_text = models.CharField(
        max_length=50,
        default='View Open Positions'
    )
    hero_cta_url = models.URLField(blank=True)

    # About/Company Section
    about_company = models.TextField(
        blank=True,
        help_text=_('Rich text description of company')
    )
    company_video_url = models.URLField(
        blank=True,
        help_text=_('YouTube or Vimeo embed URL')
    )

    # Benefits
    benefits_title = models.CharField(max_length=200, default='Why Join Us')
    benefits_sections = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of benefit sections with icon, title, description')
    )

    # Culture/Values
    culture_title = models.CharField(max_length=200, default='Our Culture')
    culture_content = models.TextField(blank=True)
    values = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of company values with icon, title, description')
    )

    # Team Section
    show_team_section = models.BooleanField(default=False)
    team_title = models.CharField(max_length=200, default='Meet the Team')
    team_members = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of team members with photo, name, title, bio')
    )

    # Testimonials
    show_testimonials = models.BooleanField(default=False)
    testimonials = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of employee testimonials with quote, name, title, photo')
    )

    # Social Links
    linkedin_url = models.URLField(blank=True)
    twitter_url = models.URLField(blank=True)
    facebook_url = models.URLField(blank=True)
    instagram_url = models.URLField(blank=True)
    glassdoor_url = models.URLField(blank=True)
    youtube_url = models.URLField(blank=True)

    # SEO
    meta_title = models.CharField(
        max_length=60,
        blank=True,
        help_text=_('SEO title (max 60 chars)')
    )
    meta_description = models.CharField(
        max_length=160,
        blank=True,
        help_text=_('SEO description (max 160 chars)')
    )
    meta_keywords = models.CharField(max_length=500, blank=True)
    og_image = models.ImageField(
        upload_to='career_sites/og/',
        blank=True,
        null=True,
        validators=[FileSizeValidator(5)],
        help_text=_('Open Graph image for social sharing (1200x630 recommended)')
    )
    canonical_url = models.URLField(
        blank=True,
        help_text=_('Canonical URL if different from site URL')
    )

    # Analytics
    google_analytics_id = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('Google Analytics 4 Measurement ID (G-XXXXXXXXXX)')
    )
    google_tag_manager_id = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('Google Tag Manager ID (GTM-XXXXXX)')
    )
    facebook_pixel_id = models.CharField(max_length=50, blank=True)
    linkedin_insight_tag = models.CharField(max_length=50, blank=True)

    # Settings
    is_active = models.BooleanField(
        default=True,
        help_text=_('Whether career site is publicly accessible')
    )
    is_published = models.BooleanField(
        default=False,
        help_text=_('Whether career site is published and visible')
    )
    require_account = models.BooleanField(
        default=False,
        help_text=_('Require candidates to create account before applying')
    )
    show_salary_range = models.BooleanField(
        default=False,
        help_text=_('Show salary ranges on job listings')
    )
    allow_general_applications = models.BooleanField(
        default=True,
        help_text=_('Allow applications even without specific job')
    )

    # GDPR/Privacy
    gdpr_consent_text = models.TextField(
        blank=True,
        default=_('I consent to the processing of my personal data for recruitment purposes.')
    )
    privacy_policy_url = models.URLField(
        blank=True,
        help_text=_('Link to privacy policy')
    )
    terms_url = models.URLField(
        blank=True,
        help_text=_('Link to terms and conditions')
    )
    data_retention_days = models.PositiveIntegerField(
        default=365,
        help_text=_('Number of days to retain candidate data')
    )

    # Application Settings
    default_application_form = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Default application form fields configuration')
    )
    allowed_resume_formats = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of allowed file extensions for resumes')
    )
    max_resume_size_mb = models.PositiveIntegerField(
        default=10,
        help_text=_('Maximum resume file size in MB')
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    published_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Career Site')
        verbose_name_plural = _('Career Sites')
        ordering = ['company_name']

    def __str__(self):
        return f"{self.company_name} Career Site ({self.subdomain})"

    def save(self, *args, **kwargs):
        # Set published_at when first published
        if self.is_published and not self.published_at:
            self.published_at = timezone.now()
        # Generate subdomain from company name if not set
        if not self.subdomain:
            self.subdomain = slugify(self.company_name)[:63]
        # Set default allowed resume formats
        if not self.allowed_resume_formats:
            self.allowed_resume_formats = ['pdf', 'doc', 'docx']
        super().save(*args, **kwargs)

    @property
    def site_url(self):
        """Get the full URL for this career site."""
        if self.custom_domain and self.custom_domain_verified:
            protocol = 'https' if self.custom_domain_ssl else 'http'
            return f"{protocol}://{self.custom_domain}"
        # Use subdomain on main careers domain from centralized config
        base_domain = getattr(settings, 'CAREERS_BASE_DOMAIN', '')
        if not base_domain:
            # Fall back to constructing from PRIMARY_DOMAIN
            primary = getattr(settings, 'PRIMARY_DOMAIN', 'localhost')
            base_domain = f"careers.{primary}"
        # Use http for localhost (development), https for production
        protocol = 'http' if 'localhost' in base_domain else 'https'
        return f"{protocol}://{self.subdomain}.{base_domain}"

    def get_active_jobs_count(self):
        """Return count of active job listings."""
        return self.job_listings.filter(
            job__status='open',
            published_at__isnull=False
        ).exclude(
            expires_at__lt=timezone.now()
        ).count()


# =============================================================================
# CAREER PAGE MODEL (Legacy - kept for backward compatibility)
# =============================================================================

class CareerPage(models.Model):
    """
    Tenant-specific career page configuration.
    Controls branding, content, and settings for public job pages.

    Note: This is the legacy model. New implementations should use CareerSite.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Basic Info
    title = models.CharField(max_length=200, default='Careers')
    tagline = models.CharField(max_length=300, blank=True)
    description = models.TextField(blank=True)

    # Branding
    logo = models.ImageField(upload_to='career_logos/', blank=True, null=True)
    cover_image = models.ImageField(upload_to='career_covers/', blank=True, null=True)
    favicon = models.ImageField(upload_to='career_favicons/', blank=True, null=True)

    # Colors
    primary_color = models.CharField(max_length=7, default='#3B82F6')
    secondary_color = models.CharField(max_length=7, default='#1E40AF')
    accent_color = models.CharField(max_length=7, default='#10B981')
    text_color = models.CharField(max_length=7, default='#1F2937')
    background_color = models.CharField(max_length=7, default='#FFFFFF')

    # Custom CSS
    custom_css = models.TextField(blank=True)

    # Content Sections
    show_company_info = models.BooleanField(default=True)
    company_description = models.TextField(blank=True)
    show_benefits = models.BooleanField(default=True)
    benefits_content = models.TextField(blank=True)
    show_culture = models.BooleanField(default=True)
    culture_content = models.TextField(blank=True)
    show_values = models.BooleanField(default=True)
    values_content = models.JSONField(default=list, blank=True)
    show_team = models.BooleanField(default=False)
    team_members = models.JSONField(default=list, blank=True)

    # Social Links
    linkedin_url = models.URLField(blank=True)
    twitter_url = models.URLField(blank=True)
    facebook_url = models.URLField(blank=True)
    instagram_url = models.URLField(blank=True)
    glassdoor_url = models.URLField(blank=True)

    # SEO
    meta_title = models.CharField(max_length=200, blank=True)
    meta_description = models.TextField(blank=True, max_length=500)
    meta_keywords = models.CharField(max_length=500, blank=True)
    og_image = models.ImageField(upload_to='career_og/', blank=True, null=True)

    # Settings
    is_active = models.BooleanField(default=True)
    require_account = models.BooleanField(
        default=False,
        help_text=_('Require candidates to create account before applying')
    )
    show_salary_range = models.BooleanField(default=False)
    allow_general_applications = models.BooleanField(
        default=True,
        help_text=_('Allow applications even without specific job')
    )
    gdpr_consent_text = models.TextField(
        blank=True,
        help_text=_('Custom GDPR/privacy consent text')
    )

    # Analytics
    google_analytics_id = models.CharField(max_length=50, blank=True)
    facebook_pixel_id = models.CharField(max_length=50, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Career Page')
        verbose_name_plural = _('Career Pages')

    def __str__(self):
        return self.title


class CareerPageSection(models.Model):
    """Custom content sections for career pages."""

    class SectionType(models.TextChoices):
        TEXT = 'text', _('Text Block')
        IMAGE = 'image', _('Image')
        VIDEO = 'video', _('Video')
        TESTIMONIAL = 'testimonial', _('Testimonial')
        FAQ = 'faq', _('FAQ')
        CTA = 'cta', _('Call to Action')
        STATS = 'stats', _('Statistics')
        GALLERY = 'gallery', _('Image Gallery')

    career_page = models.ForeignKey(
        CareerPage,
        on_delete=models.CASCADE,
        related_name='sections'
    )
    title = models.CharField(max_length=200)
    section_type = models.CharField(
        max_length=20,
        choices=SectionType.choices,
        default=SectionType.TEXT
    )
    content = models.JSONField(default=dict)
    order = models.PositiveIntegerField(default=0)
    is_visible = models.BooleanField(default=True)

    class Meta:
        verbose_name = _('Career Page Section')
        verbose_name_plural = _('Career Page Sections')
        ordering = ['order']

    def __str__(self):
        return f"{self.career_page.title} - {self.title}"


# =============================================================================
# CAREER CUSTOM PAGE MODEL
# =============================================================================

class CareerCustomPage(models.Model):
    """Custom content pages within a career site."""

    career_site = models.ForeignKey(
        CareerSite,
        on_delete=models.CASCADE,
        related_name='custom_pages'
    )
    title = models.CharField(max_length=200)
    slug = models.SlugField(max_length=200)
    content = models.TextField(
        blank=True,
        help_text=_('Page content (supports HTML/Markdown)')
    )
    meta_title = models.CharField(max_length=60, blank=True)
    meta_description = models.CharField(max_length=160, blank=True)
    is_published = models.BooleanField(default=False)
    show_in_nav = models.BooleanField(
        default=True,
        help_text=_('Show page in navigation menu')
    )
    nav_order = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Career Custom Page')
        verbose_name_plural = _('Career Custom Pages')
        ordering = ['nav_order', 'title']
        unique_together = ['career_site', 'slug']

    def __str__(self):
        return f"{self.career_site.company_name} - {self.title}"

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.title)
        super().save(*args, **kwargs)


# =============================================================================
# JOB LISTING MODEL
# =============================================================================

class JobListing(models.Model):
    """
    Public-facing job listing view.
    Wraps JobPosting with public display settings.
    """

    job = models.OneToOneField(
        'ats.JobPosting',
        on_delete=models.CASCADE,
        related_name='public_listing'
    )

    # Link to career site (optional for backward compatibility)
    career_site = models.ForeignKey(
        CareerSite,
        on_delete=models.CASCADE,
        related_name='job_listings',
        null=True,
        blank=True
    )

    # Custom URL
    custom_slug = models.SlugField(max_length=200, blank=True)

    # Display Settings
    show_company_name = models.BooleanField(default=True)
    show_department = models.BooleanField(default=True)
    show_team_size = models.BooleanField(default=False)
    show_application_count = models.BooleanField(default=False)
    application_count_threshold = models.PositiveIntegerField(
        default=10,
        help_text=_('Show "10+ applicants" instead of exact count')
    )

    # Application Form
    custom_application_form = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Custom form fields configuration')
    )

    # Visibility
    is_featured = models.BooleanField(default=False)
    feature_priority = models.PositiveIntegerField(default=0)

    # Tracking
    view_count = models.PositiveIntegerField(default=0)
    apply_click_count = models.PositiveIntegerField(default=0)

    # Timestamps
    published_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Job Listing')
        verbose_name_plural = _('Job Listings')
        ordering = ['-is_featured', '-feature_priority', '-published_at']

    def __str__(self):
        return self.job.title

    @property
    def is_expired(self):
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at

    @property
    def is_active(self):
        """Check if listing is currently active."""
        if not self.published_at:
            return False
        if self.is_expired:
            return False
        return self.job.status == 'open'

    def increment_view(self):
        self.view_count += 1
        self.save(update_fields=['view_count'])

    def increment_apply_click(self):
        self.apply_click_count += 1
        self.save(update_fields=['apply_click_count'])


# =============================================================================
# JOB VIEW TRACKING MODEL
# =============================================================================

class JobView(models.Model):
    """Track individual job listing views for analytics."""

    job_listing = models.ForeignKey(
        JobListing,
        on_delete=models.CASCADE,
        related_name='views'
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    referrer = models.URLField(blank=True, max_length=2000)
    session_key = models.CharField(max_length=40, blank=True)

    # UTM tracking
    utm_source = models.CharField(max_length=100, blank=True)
    utm_medium = models.CharField(max_length=100, blank=True)
    utm_campaign = models.CharField(max_length=100, blank=True)
    utm_term = models.CharField(max_length=100, blank=True)
    utm_content = models.CharField(max_length=100, blank=True)

    # Timestamp
    viewed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Job View')
        verbose_name_plural = _('Job Views')
        ordering = ['-viewed_at']
        indexes = [
            models.Index(fields=['job_listing', 'viewed_at']),
            models.Index(fields=['viewed_at']),
        ]

    def __str__(self):
        return f"View on {self.job_listing} at {self.viewed_at}"


# =============================================================================
# PUBLIC APPLICATION MODEL
# =============================================================================

class PublicApplication(models.Model):
    """
    Public job application from career page.
    Creates Candidate and Application records in ATS.
    """

    class ApplicationStatus(models.TextChoices):
        PENDING = 'pending', _('Pending Processing')
        PROCESSED = 'processed', _('Processed to ATS')
        DUPLICATE = 'duplicate', _('Duplicate Application')
        SPAM = 'spam', _('Marked as Spam')
        ERROR = 'error', _('Processing Error')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Link to career site
    career_site = models.ForeignKey(
        CareerSite,
        on_delete=models.CASCADE,
        related_name='applications',
        null=True,
        blank=True
    )

    job_listing = models.ForeignKey(
        JobListing,
        on_delete=models.CASCADE,
        related_name='public_applications',
        null=True,
        blank=True
    )

    # Applicant Info
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.CharField(max_length=30, blank=True)

    # Application Content
    resume = models.FileField(
        upload_to='public_resumes/',
        validators=[
            FileExtensionValidator(allowed_extensions=['pdf', 'doc', 'docx']),
        ]
    )
    cover_letter = models.TextField(blank=True)
    custom_answers = models.JSONField(default=dict, blank=True)
    linkedin_url = models.URLField(blank=True)
    portfolio_url = models.URLField(blank=True)

    # GDPR Consent (enhanced)
    privacy_consent = models.BooleanField(default=False)
    privacy_consent_text = models.TextField(
        blank=True,
        help_text=_('The consent text that was shown to the applicant')
    )
    marketing_consent = models.BooleanField(default=False)
    consent_timestamp = models.DateTimeField(null=True, blank=True)
    consent_ip = models.GenericIPAddressField(null=True, blank=True)

    # Processing
    status = models.CharField(
        max_length=20,
        choices=ApplicationStatus.choices,
        default=ApplicationStatus.PENDING
    )
    processed_at = models.DateTimeField(null=True, blank=True)
    ats_candidate = models.ForeignKey(
        'ats.Candidate',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    ats_application = models.ForeignKey(
        'ats.Application',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    processing_error = models.TextField(blank=True)

    # Spam Detection
    spam_score = models.FloatField(
        default=0.0,
        help_text=_('Spam probability score (0-1)')
    )
    honeypot_triggered = models.BooleanField(default=False)
    submission_time_seconds = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text=_('Time taken to submit form in seconds')
    )

    # Tracking
    source = models.CharField(max_length=100, blank=True)
    utm_source = models.CharField(max_length=100, blank=True)
    utm_medium = models.CharField(max_length=100, blank=True)
    utm_campaign = models.CharField(max_length=100, blank=True)
    utm_term = models.CharField(max_length=100, blank=True)
    utm_content = models.CharField(max_length=100, blank=True)
    referrer = models.URLField(blank=True, max_length=2000)
    user_agent = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    # Timestamps
    submitted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Public Application')
        verbose_name_plural = _('Public Applications')
        ordering = ['-submitted_at']
        indexes = [
            models.Index(fields=['email', 'job_listing']),
            models.Index(fields=['status', 'submitted_at']),
        ]

    def __str__(self):
        job_title = self.job_listing.job.title if self.job_listing else 'General'
        return f"{self.first_name} {self.last_name} - {job_title}"

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def is_likely_spam(self):
        """Check if application is likely spam based on various signals."""
        # Honeypot triggered
        if self.honeypot_triggered:
            return True
        # Submitted too quickly (less than 5 seconds)
        if self.submission_time_seconds and self.submission_time_seconds < 5:
            return True
        # High spam score
        if self.spam_score >= 0.8:
            return True
        return False

    def process_to_ats(self):
        """
        Process public application into ATS system.
        Creates or updates Candidate and creates Application.
        """
        from ats.models import Candidate, Application

        try:
            # Check for spam
            if self.is_likely_spam():
                self.status = self.ApplicationStatus.SPAM
                self.save()
                return False

            # Find or create candidate
            candidate, created = Candidate.objects.get_or_create(
                email=self.email,
                defaults={
                    'first_name': self.first_name,
                    'last_name': self.last_name,
                    'phone': self.phone,
                    'resume': self.resume,
                    'linkedin_url': self.linkedin_url,
                    'source': Candidate.Source.CAREER_PAGE,
                    'source_detail': self.source or self.utm_source or '',
                }
            )

            if not created:
                # Update existing candidate info
                candidate.phone = self.phone or candidate.phone
                candidate.linkedin_url = self.linkedin_url or candidate.linkedin_url
                candidate.save()

            self.ats_candidate = candidate

            # Create application if job specified
            if self.job_listing:
                # Check for duplicate application
                existing = Application.objects.filter(
                    candidate=candidate,
                    job=self.job_listing.job
                ).first()

                if existing:
                    self.status = self.ApplicationStatus.DUPLICATE
                    self.ats_application = existing
                else:
                    application = Application.objects.create(
                        candidate=candidate,
                        job=self.job_listing.job,
                        cover_letter=self.cover_letter,
                        custom_answers=self.custom_answers,
                        utm_source=self.utm_source,
                        utm_medium=self.utm_medium,
                        utm_campaign=self.utm_campaign,
                        referrer_url=self.referrer,
                    )
                    self.ats_application = application
                    self.status = self.ApplicationStatus.PROCESSED

            else:
                self.status = self.ApplicationStatus.PROCESSED

            self.processed_at = timezone.now()
            self.save()

            return True

        except Exception as e:
            self.status = self.ApplicationStatus.ERROR
            self.processing_error = str(e)
            self.save()
            return False


# =============================================================================
# JOB ALERT MODEL
# =============================================================================

class JobAlert(models.Model):
    """
    Job alert subscription for email notifications.
    Allows candidates to subscribe to new job postings matching their criteria.
    """

    class AlertFrequency(models.TextChoices):
        INSTANT = 'instant', _('Instant')
        DAILY = 'daily', _('Daily Digest')
        WEEKLY = 'weekly', _('Weekly Digest')

    class AlertStatus(models.TextChoices):
        PENDING = 'pending', _('Pending Confirmation')
        ACTIVE = 'active', _('Active')
        PAUSED = 'paused', _('Paused')
        UNSUBSCRIBED = 'unsubscribed', _('Unsubscribed')

    public_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Link to career site
    career_site = models.ForeignKey(
        CareerSite,
        on_delete=models.CASCADE,
        related_name='job_alerts'
    )

    # Subscriber Info
    email = models.EmailField()
    name = models.CharField(max_length=200, blank=True)

    # Subscription Tokens (for secure confirmation/unsubscribe links)
    confirmation_token = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        help_text=_('Token for email confirmation link')
    )
    unsubscribe_token = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        help_text=_('Token for unsubscribe link')
    )

    # Alert Preferences
    frequency = models.CharField(
        max_length=20,
        choices=AlertFrequency.choices,
        default=AlertFrequency.WEEKLY
    )

    # Filter Criteria (all optional - empty means match all)
    departments = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of department/category names to match')
    )
    job_types = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of job types (full_time, part_time, etc.)')
    )
    locations = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of location strings to match')
    )
    keywords = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of keywords to match in job title/description')
    )
    remote_only = models.BooleanField(
        default=False,
        help_text=_('Only include remote-friendly positions')
    )
    min_salary = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Minimum salary filter')
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=AlertStatus.choices,
        default=AlertStatus.PENDING
    )

    # Tracking
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    last_sent_at = models.DateTimeField(null=True, blank=True)
    last_job_sent_id = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text=_('ID of last job included in alert email')
    )
    emails_sent_count = models.PositiveIntegerField(default=0)
    emails_opened_count = models.PositiveIntegerField(default=0)
    emails_clicked_count = models.PositiveIntegerField(default=0)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    unsubscribed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Job Alert')
        verbose_name_plural = _('Job Alerts')
        ordering = ['-created_at']
        unique_together = ['career_site', 'email']
        indexes = [
            models.Index(fields=['status', 'frequency']),
            models.Index(fields=['confirmation_token']),
            models.Index(fields=['unsubscribe_token']),
        ]

    def __str__(self):
        return f"Job Alert: {self.email} ({self.career_site.subdomain})"

    def confirm(self):
        """Confirm the subscription."""
        self.status = self.AlertStatus.ACTIVE
        self.confirmed_at = timezone.now()
        self.save(update_fields=['status', 'confirmed_at'])

    def unsubscribe(self):
        """Unsubscribe from alerts."""
        self.status = self.AlertStatus.UNSUBSCRIBED
        self.unsubscribed_at = timezone.now()
        self.save(update_fields=['status', 'unsubscribed_at'])

    def pause(self):
        """Pause the subscription."""
        self.status = self.AlertStatus.PAUSED
        self.save(update_fields=['status'])

    def resume(self):
        """Resume a paused subscription."""
        if self.status == self.AlertStatus.PAUSED:
            self.status = self.AlertStatus.ACTIVE
            self.save(update_fields=['status'])

    def matches_job(self, job_listing):
        """
        Check if a job listing matches this alert's criteria.

        Args:
            job_listing: JobListing instance to check

        Returns:
            bool: True if job matches criteria
        """
        job = job_listing.job

        # Check departments/categories
        if self.departments:
            job_category = getattr(job.category, 'name', '') if job.category else ''
            if not any(dept.lower() in job_category.lower() for dept in self.departments):
                return False

        # Check job types
        if self.job_types:
            if job.job_type not in self.job_types:
                return False

        # Check locations
        if self.locations:
            job_location = f"{job.location_city} {job.location_state} {job.location_country}".lower()
            if not any(loc.lower() in job_location for loc in self.locations):
                return False

        # Check remote only
        if self.remote_only:
            if job.remote_policy not in ['remote', 'hybrid', 'flexible']:
                return False

        # Check keywords
        if self.keywords:
            searchable_text = f"{job.title} {job.description}".lower()
            if not any(kw.lower() in searchable_text for kw in self.keywords):
                return False

        # Check minimum salary
        if self.min_salary:
            if job.salary_min and job.salary_min < self.min_salary:
                return False

        return True


# =============================================================================
# TALENT POOL MODELS
# =============================================================================

class TalentPool(models.Model):
    """
    Talent pools for organizing candidates.
    Allows recruiters to save candidates for future opportunities.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    is_public = models.BooleanField(
        default=False,
        help_text=_('Allow candidates to self-join')
    )
    auto_add_criteria = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Auto-add candidates matching criteria')
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Talent Pool')
        verbose_name_plural = _('Talent Pools')

    def __str__(self):
        return self.name


class TalentPoolMember(models.Model):
    """Candidates in a talent pool."""

    pool = models.ForeignKey(
        TalentPool,
        on_delete=models.CASCADE,
        related_name='members'
    )
    candidate = models.ForeignKey(
        'ats.Candidate',
        on_delete=models.CASCADE,
        related_name='talent_pools'
    )
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    added_at = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True)

    class Meta:
        verbose_name = _('Talent Pool Member')
        verbose_name_plural = _('Talent Pool Members')
        unique_together = ['pool', 'candidate']

    def __str__(self):
        return f"{self.candidate.full_name} in {self.pool.name}"
