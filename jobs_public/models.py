"""
ATS Public Catalog Models.

Provides denormalized public job catalog for browsing without tenant context.

This app lives in SHARED_APPS (public schema) and is synced from tenant-specific
JobPosting instances via Django signals and Celery tasks.
"""

import uuid
from django.db import models
from django.utils.translation import gettext_lazy as _


class PublicJobCatalog(models.Model):
    """
    Denormalized public job listing for cross-tenant browsing.

    Synced from tenant JobPosting instances when published_on_career_page=True.
    Optimized for fast filtering, searching, and browsing without tenant context.

    Security:
        - No sensitive data (salary optionally visible)
        - HTML content sanitized before sync
        - Application redirects to tenant domain for authentication

    Sync Triggers:
        - JobPosting saved with published_on_career_page=True → sync
        - JobPosting updated → re-sync
        - JobPosting deleted or marked private → remove from catalog
    """

    # ===== Identity =====
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Primary key for public catalog entry"
    )

    jobposting_uuid = models.UUIDField(
        unique=True,
        db_index=True,
        help_text="UUID of source JobPosting in tenant schema"
    )

    # ===== Source Tenant Info =====
    tenant_id = models.IntegerField(
        db_index=True,
        help_text="ID of source tenant"
    )

    tenant_schema_name = models.CharField(
        max_length=100,
        db_index=True,
        help_text="Schema name of source tenant"
    )

    company_name = models.CharField(
        max_length=255,
        db_index=True,
        help_text="Company name from tenant"
    )

    company_logo_url = models.URLField(
        blank=True,
        help_text="Company logo URL (if available)"
    )

    # ===== Job Details =====
    title = models.CharField(
        max_length=255,
        db_index=True,
        help_text="Job title"
    )

    description_html = models.TextField(
        help_text="Sanitized HTML job description"
    )

    employment_type = models.CharField(
        max_length=50,
        db_index=True,
        blank=True,
        help_text="Employment type: full-time, part-time, contract, etc."
    )

    # ===== Location =====
    location_city = models.CharField(
        max_length=100,
        db_index=True,
        blank=True,
        help_text="Job location city"
    )

    location_state = models.CharField(
        max_length=100,
        blank=True,
        help_text="Job location state/province"
    )

    location_country = models.CharField(
        max_length=100,
        db_index=True,
        default='',
        blank=True,
        help_text="Job location country"
    )

    is_remote = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Whether job allows remote work"
    )

    # ===== Salary (Optional) =====
    salary_min = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Minimum salary (optional)"
    )

    salary_max = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Maximum salary (optional)"
    )

    salary_currency = models.CharField(
        max_length=3,
        default='USD',
        help_text="Salary currency code (ISO 4217)"
    )

    salary_period = models.CharField(
        max_length=35,
        default='yearly',
        help_text="Salary payment period (hourly, daily, weekly, monthly, yearly)"
    )

    show_salary = models.BooleanField(
        default=False,
        help_text="Whether salary is publicly visible"
    )

    # ===== Job Overview (for template requirements) =====
    experience_level = models.CharField(
        max_length=50,
        blank=True,
        db_index=True,
        help_text="Experience level (entry, mid, senior, etc.)"
    )

    hours_per_week = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        help_text="Expected hours per week"
    )

    years_of_experience = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        help_text="Required years of experience"
    )

    english_level = models.CharField(
        max_length=50,
        blank=True,
        help_text="Required English proficiency (basic, conversational, fluent, native)"
    )

    # ===== Rich Content (stored as JSON lists of strings) =====
    responsibilities_list = models.JSONField(
        default=list,
        help_text="List of job responsibilities (bullet points)"
    )

    requirements_list = models.JSONField(
        default=list,
        help_text="List of job requirements (bullet points)"
    )

    qualifications_list = models.JSONField(
        default=list,
        help_text="List of preferred qualifications (bullet points)"
    )

    benefits_list = models.JSONField(
        default=list,
        help_text="List of benefits (bullet points)"
    )

    # ===== Media =====
    image_gallery = models.JSONField(
        default=list,
        help_text="List of image URLs for job gallery"
    )

    video_url = models.URLField(
        blank=True,
        help_text="Promotional video URL (YouTube, Vimeo, etc.)"
    )

    # ===== Geocoding for Map Display =====
    latitude = models.FloatField(
        null=True,
        blank=True,
        db_index=True,
        help_text="Latitude coordinate for map display"
    )

    longitude = models.FloatField(
        null=True,
        blank=True,
        db_index=True,
        help_text="Longitude coordinate for map display"
    )

    # ===== Metadata =====
    expiration_date = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        help_text="Application deadline"
    )

    view_count = models.PositiveIntegerField(
        default=0,
        db_index=True,
        help_text="Number of times job has been viewed"
    )

    application_count = models.PositiveIntegerField(
        default=0,
        db_index=True,
        help_text="Number of applications received"
    )

    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text="Whether job is currently active"
    )

    is_expired = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Whether job has expired"
    )

    is_featured = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Whether job is featured"
    )

    # ===== Company Information (denormalized from Tenant) =====
    company_rating = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Company rating (1.00-5.00)"
    )

    company_established_date = models.DateField(
        null=True,
        blank=True,
        help_text="Company founding date"
    )

    company_industry = models.CharField(
        max_length=100,
        blank=True,
        help_text="Company industry"
    )

    company_size = models.CharField(
        max_length=50,
        blank=True,
        help_text="Company size (employee count range)"
    )

    company_website = models.URLField(blank=True, help_text="Company website URL")
    company_linkedin = models.URLField(blank=True, help_text="Company LinkedIn URL")
    company_twitter = models.URLField(blank=True, help_text="Company Twitter/X URL")
    company_facebook = models.URLField(blank=True, help_text="Company Facebook URL")
    company_instagram = models.URLField(blank=True, help_text="Company Instagram URL")
    company_pinterest = models.URLField(blank=True, help_text="Company Pinterest URL")

    # ===== Categories & Skills (Denormalized for Fast Filtering) =====
    category_names = models.JSONField(
        default=list,
        help_text="List of category names (e.g., ['Engineering', 'Product'])"
    )

    category_slugs = models.JSONField(
        default=list,
        db_index=True,
        help_text="List of category slugs for filtering (e.g., ['engineering', 'product'])"
    )

    required_skills = models.JSONField(
        default=list,
        help_text="List of required skill names (e.g., ['Python', 'Django', 'React'])"
    )

    # ===== Metadata =====
    published_at = models.DateTimeField(
        db_index=True,
        help_text="When job was published on career page"
    )

    synced_at = models.DateTimeField(
        auto_now=True,
        help_text="When this catalog entry was last synced from tenant"
    )

    # ===== Application URL =====
    application_url = models.URLField(
        help_text="URL to apply for this job (redirects to tenant domain)"
    )

    class Meta:
        db_table = 'ats_public_job_catalog'
        verbose_name = _("Public Job Catalog Entry")
        verbose_name_plural = _("Public Job Catalog Entries")

        indexes = [
            models.Index(fields=['title'], name='ats_pub_title_idx'),
            models.Index(fields=['location_city', 'location_state'], name='ats_pub_location_idx'),
            models.Index(fields=['employment_type', 'is_remote'], name='ats_pub_type_idx'),
            models.Index(fields=['-published_at'], name='ats_pub_published_idx'),
            models.Index(fields=['company_name'], name='ats_pub_company_idx'),
            models.Index(fields=['latitude', 'longitude'], name='ats_pub_geo_idx'),
            models.Index(fields=['experience_level'], name='ats_pub_exp_idx'),
            models.Index(fields=['-view_count'], name='ats_pub_views_idx'),
            models.Index(fields=['expiration_date'], name='ats_pub_expiry_idx'),
            models.Index(fields=['is_active', 'is_expired'], name='ats_pub_active_idx'),
            models.Index(fields=['is_featured', '-published_at'], name='ats_pub_featured_idx'),
        ]

        ordering = ['-published_at']

    def __str__(self):
        return f"{self.title} at {self.company_name}"

    def get_absolute_url(self):
        """Get URL for viewing this job in public catalog."""
        from django.urls import reverse
        return reverse('ats_public:job_detail', kwargs={'jobposting_uuid': self.jobposting_uuid})

    def get_application_url(self):
        """Get URL for applying to this job (redirects to tenant domain)."""
        return self.application_url

    @property
    def has_salary_info(self):
        """Check if salary information is available."""
        return self.salary_min is not None or self.salary_max is not None

    @property
    def salary_display(self):
        """Display formatted salary with visibility check."""
        if not self.show_salary or not self.has_salary_info:
            return None

        currency_symbols = {'USD': '$', 'CAD': '$', 'EUR': '€', 'GBP': '£'}
        symbol = currency_symbols.get(self.salary_currency, self.salary_currency)

        if self.salary_min and self.salary_max:
            return f"{symbol}{self.salary_min:,.0f} - {symbol}{self.salary_max:,.0f}"
        elif self.salary_min:
            return f"{symbol}{self.salary_min:,.0f}+"
        elif self.salary_max:
            return f"Up to {symbol}{self.salary_max:,.0f}"

        return None

    @property
    def salary_range_display(self):
        """Display formatted salary range (legacy, kept for compatibility)."""
        if not self.has_salary_info:
            return "Not specified"

        if self.salary_min and self.salary_max:
            return f"{self.salary_currency} {self.salary_min:,.0f} - {self.salary_max:,.0f}"
        elif self.salary_min:
            return f"{self.salary_currency} {self.salary_min:,.0f}+"
        elif self.salary_max:
            return f"Up to {self.salary_currency} {self.salary_max:,.0f}"

        return "Not specified"

    @property
    def location_display(self):
        """Display formatted location."""
        parts = []

        if self.location_city:
            parts.append(self.location_city)

        if self.location_state:
            parts.append(self.location_state)

        if self.location_country:
            parts.append(self.location_country)

        location = ", ".join(parts) if parts else "Location not specified"

        if self.is_remote:
            location += " (Remote)"

        return location

    @property
    def is_expired_computed(self):
        """Check if job has expired based on expiration_date."""
        if not self.expiration_date:
            return False
        from django.utils import timezone
        return timezone.now() > self.expiration_date

    def increment_view_count(self):
        """Atomically increment view count to track job popularity."""
        from django.db.models import F
        PublicJobCatalog.objects.filter(pk=self.pk).update(view_count=F('view_count') + 1)
