"""
Services Public Catalog Models.

Provides denormalized public service/provider catalog for browsing without tenant context.

This app lives in SHARED_APPS (public schema) and is synced from tenant-specific
ServiceProvider instances via Django signals and Celery tasks.
"""

import uuid
from django.contrib.gis.db import models as gis_models
from django.db import models
from django.utils.translation import gettext_lazy as _


class PublicServiceCatalog(gis_models.Model):
    """
    Denormalized public service listing for cross-tenant marketplace browsing.

    Synced from tenant ServiceProvider instances when marketplace_enabled=True.
    Optimized for fast filtering, searching, and geo-queries without tenant context.

    Security:
        - No sensitive data (contact info, bank account, etc.)
        - HTML content sanitized before sync
        - Booking redirects to tenant domain for authentication

    Sync Triggers:
        - ServiceProvider saved with marketplace_enabled=True → sync
        - ServiceProvider updated → re-sync
        - ServiceProvider deleted or marked private → remove from catalog
    """

    # ===== Identity =====
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Primary key for public catalog entry"
    )

    provider_uuid = models.UUIDField(
        unique=True,
        db_index=True,
        help_text="UUID of source ServiceProvider in tenant schema"
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

    provider_name = models.CharField(
        max_length=255,
        db_index=True,
        help_text="Provider display name"
    )

    provider_avatar_url = models.URLField(
        blank=True,
        help_text="Provider avatar/logo URL (if available)"
    )

    # ===== Service Details =====
    bio = models.TextField(
        blank=True,
        help_text="Sanitized HTML provider bio/description"
    )

    tagline = models.CharField(
        max_length=255,
        blank=True,
        help_text="Short tagline or headline"
    )

    provider_type = models.CharField(
        max_length=100,
        db_index=True,
        blank=True,
        help_text="Provider type: individual, company, etc."
    )

    # ===== Location =====
    location_city = models.CharField(
        max_length=100,
        db_index=True,
        blank=True,
        help_text="Provider location city"
    )

    location_state = models.CharField(
        max_length=100,
        blank=True,
        help_text="Provider location state/province"
    )

    location_country = models.CharField(
        max_length=100,
        db_index=True,
        default='',
        blank=True,
        help_text="Provider location country"
    )

    location = gis_models.PointField(
        geography=True,
        null=True,
        blank=True,
        srid=4326,
        help_text="Geographic location (PostGIS Point for geo-queries)"
    )

    can_work_remotely = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Whether provider can work remotely"
    )

    can_work_onsite = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Whether provider can work on-site"
    )

    # ===== Pricing =====
    hourly_rate = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Hourly rate (optional)"
    )

    minimum_budget = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Minimum project budget (optional)"
    )

    currency = models.CharField(
        max_length=3,
        default='USD',
        help_text="Currency code (ISO 4217)"
    )

    # ===== Categories & Skills (Denormalized for Fast Filtering) =====
    category_names = models.JSONField(
        default=list,
        help_text="List of category names (e.g., ['Web Development', 'Design'])"
    )

    category_slugs = models.JSONField(
        default=list,
        db_index=True,
        help_text="List of category slugs for filtering (e.g., ['web-dev', 'design'])"
    )

    skills_data = models.JSONField(
        default=list,
        help_text="List of skill objects: [{'name': 'Python', 'level': 'expert', 'years_experience': 5}]"
    )

    # ===== Stats (Denormalized for Performance) =====
    rating_avg = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        null=True,
        blank=True,
        db_index=True,
        help_text="Average rating from reviews"
    )

    total_reviews = models.IntegerField(
        default=0,
        db_index=True,
        help_text="Total number of reviews"
    )

    completed_jobs_count = models.IntegerField(
        default=0,
        help_text="Number of completed jobs/contracts"
    )

    response_rate = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Response rate percentage"
    )

    avg_response_time_hours = models.IntegerField(
        null=True,
        blank=True,
        help_text="Average response time in hours"
    )

    # ===== Availability & Status =====
    availability_status = models.CharField(
        max_length=50,
        default='available',
        db_index=True,
        help_text="Availability status: available, busy, unavailable"
    )

    is_verified = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Whether provider is verified"
    )

    is_featured = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Whether provider is featured in marketplace"
    )

    is_accepting_work = models.BooleanField(
        default=True,
        db_index=True,
        help_text="Whether provider is accepting new service requests and contracts"
    )

    # ===== Metadata =====
    published_at = models.DateTimeField(
        db_index=True,
        help_text="When provider was published to marketplace"
    )

    synced_at = models.DateTimeField(
        auto_now=True,
        help_text="When this catalog entry was last synced from tenant"
    )

    # ===== Booking URL =====
    booking_url = models.URLField(
        help_text="URL to book/contact this provider (redirects to tenant domain)"
    )

    class Meta:
        db_table = 'services_public_catalog'
        verbose_name = _("Public Service Catalog Entry")
        verbose_name_plural = _("Public Service Catalog Entries")

        indexes = [
            models.Index(fields=['provider_name'], name='svc_pub_provider_idx'),
            models.Index(fields=['provider_type', 'can_work_remotely'], name='svc_pub_type_idx'),
            models.Index(fields=['location_city', 'location_state'], name='svc_pub_location_idx'),
            models.Index(fields=['-rating_avg', '-total_reviews'], name='svc_pub_rating_idx'),
            models.Index(fields=['-published_at'], name='svc_pub_published_idx'),
            models.Index(fields=['availability_status', 'is_accepting_work'], name='svc_pub_availability_idx'),
        ]

        ordering = ['-published_at']

    def __str__(self):
        return f"{self.provider_name} ({self.provider_type})"

    def get_absolute_url(self):
        """Get URL for viewing this provider in public catalog."""
        from django.urls import reverse
        return reverse('services_public:provider_detail', kwargs={'provider_uuid': self.provider_uuid})

    def get_booking_url(self):
        """Get URL for booking this provider (redirects to tenant domain)."""
        return self.booking_url

    @property
    def has_pricing_info(self):
        """Check if pricing information is available."""
        return self.hourly_rate is not None or self.minimum_budget is not None

    @property
    def pricing_display(self):
        """Display formatted pricing."""
        if not self.has_pricing_info:
            return "Contact for pricing"

        if self.hourly_rate:
            return f"{self.currency} {self.hourly_rate:,.0f}/hour"
        elif self.minimum_budget:
            return f"Min {self.currency} {self.minimum_budget:,.0f}"

        return "Contact for pricing"

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

        work_modes = []
        if self.can_work_remotely:
            work_modes.append("Remote")
        if self.can_work_onsite:
            work_modes.append("On-site")

        if work_modes:
            location += f" ({', '.join(work_modes)})"

        return location

    @property
    def rating_display(self):
        """Display formatted rating."""
        if self.rating_avg:
            return f"{self.rating_avg:.1f}/5.0 ({self.total_reviews} reviews)"
        return "No reviews yet"

    @property
    def skills_list(self):
        """Get list of skill names only."""
        if not self.skills_data:
            return []
        return [skill.get('name') for skill in self.skills_data if isinstance(skill, dict) and 'name' in skill]
