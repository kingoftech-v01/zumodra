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
    def salary_range_display(self):
        """Display formatted salary range."""
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
