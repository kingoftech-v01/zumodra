"""
Services Public Catalog Models.

Provides denormalized public service/provider catalog for browsing without tenant context.

This app lives in SHARED_APPS (public schema) and is synced from tenant-specific
ServiceProvider instances via Django signals and Celery tasks.
"""

import uuid
from django.contrib.gis.db import models as gis_models
from django.core.validators import MinValueValidator, MaxValueValidator
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


# =============================================================================
# SERVICE-CENTRIC PUBLIC CATALOG MODELS
# =============================================================================


class PublicService(gis_models.Model):
    """
    Denormalized public service listing for cross-tenant marketplace browsing.

    This model represents individual SERVICES (not providers) in the public catalog.
    Synced from tenant Service instances when is_public=True and is_active=True.
    Optimized for fast filtering, searching, and geo-queries without tenant context.

    Security:
        - No sensitive data (contact info, payment details, etc.)
        - HTML content sanitized before sync
        - Booking redirects to tenant domain for authentication

    Sync Triggers:
        - Service.is_public changes to True → sync
        - Service updated → re-sync if is_public=True
        - Service.is_public changes to False → remove
        - Service deleted → remove
        - Provider.marketplace_enabled changes to False → remove
    """

    # ===== Identity =====
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Primary key for public service entry"
    )

    service_uuid = models.UUIDField(
        unique=True,
        db_index=True,
        help_text="UUID of source Service in tenant schema"
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

    # ===== Service Core Data =====
    name = models.CharField(
        max_length=255,
        db_index=True,
        help_text="Service title"
    )

    slug = models.SlugField(
        max_length=255,
        help_text="URL-friendly slug"
    )

    description = models.TextField(
        blank=True,
        help_text="Sanitized HTML service description"
    )

    short_description = models.CharField(
        max_length=300,
        blank=True,
        help_text="Brief summary for list views"
    )

    # ===== Provider Info (Denormalized) =====
    provider_uuid = models.UUIDField(
        db_index=True,
        help_text="UUID of ServiceProvider in tenant schema"
    )

    provider_name = models.CharField(
        max_length=255,
        db_index=True,
        help_text="Provider display name"
    )

    provider_avatar_url = models.URLField(
        blank=True,
        help_text="Provider avatar URL"
    )

    provider_type = models.CharField(
        max_length=100,
        db_index=True,
        blank=True,
        help_text="Provider type: individual, agency, company"
    )

    provider_rating_avg = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        null=True,
        blank=True,
        db_index=True,
        help_text="Provider's average rating"
    )

    provider_total_reviews = models.IntegerField(
        default=0,
        help_text="Provider's total number of reviews"
    )

    provider_completed_jobs_count = models.IntegerField(
        default=0,
        help_text="Provider's completed jobs count"
    )

    # ===== Category =====
    category_name = models.CharField(
        max_length=100,
        db_index=True,
        blank=True,
        help_text="Category name for display"
    )

    category_slug = models.SlugField(
        max_length=100,
        db_index=True,
        blank=True,
        help_text="Category slug for filtering"
    )

    category_full_path = models.CharField(
        max_length=500,
        blank=True,
        help_text="Full category hierarchy path (e.g., 'Web > Design > UI/UX')"
    )

    # ===== Pricing =====
    service_type = models.CharField(
        max_length=20,
        db_index=True,
        help_text="fixed, hourly, or custom"
    )

    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        db_index=True,
        help_text="Starting price (from lowest tier or base price)"
    )

    price_min = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        db_index=True,
        help_text="Minimum price for custom quotes"
    )

    price_max = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        db_index=True,
        help_text="Maximum price (from highest tier)"
    )

    currency = models.CharField(
        max_length=3,
        default='CAD',
        db_index=True,
        help_text="Currency code (ISO 4217)"
    )

    # ===== Delivery =====
    delivery_type = models.CharField(
        max_length=20,
        db_index=True,
        help_text="remote, onsite, or hybrid"
    )

    duration_days = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        db_index=True,
        help_text="Estimated delivery time in days (from fastest tier)"
    )

    revisions_included = models.PositiveSmallIntegerField(
        default=1,
        help_text="Number of revisions (from base tier)"
    )

    # ===== Media =====
    thumbnail_url = models.URLField(
        blank=True,
        help_text="Primary thumbnail image URL"
    )

    video_url = models.URLField(
        blank=True,
        help_text="Optional promotional video URL"
    )

    # ===== Tags (Denormalized for Fast Search) =====
    tags_list = models.JSONField(
        default=list,
        help_text="List of tag names for filtering/search"
    )

    # ===== Services Offered List =====
    services_list = models.JSONField(
        default=list,
        help_text="List of service offerings (e.g., ['Figma to HTML', 'PSD to HTML'])"
    )

    # ===== Location (PostGIS for geo queries) =====
    location_city = models.CharField(
        max_length=100,
        db_index=True,
        blank=True,
        help_text="Service provider location city"
    )

    location_state = models.CharField(
        max_length=100,
        blank=True,
        help_text="Service provider location state/province"
    )

    location_country = models.CharField(
        max_length=100,
        db_index=True,
        default='',
        blank=True,
        help_text="Service provider location country"
    )

    location = gis_models.PointField(
        geography=True,
        null=True,
        blank=True,
        srid=4326,
        help_text="Geographic location (PostGIS Point for geo-queries)"
    )

    # ===== Rating Stats (Denormalized from Reviews) =====
    rating_avg = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        null=True,
        blank=True,
        db_index=True,
        help_text="Average rating from SERVICE reviews"
    )

    total_reviews = models.IntegerField(
        default=0,
        db_index=True,
        help_text="Total number of SERVICE reviews"
    )

    # Rating breakdown for 5-star display
    rating_breakdown = models.JSONField(
        default=dict,
        help_text="Rating breakdown: {'5': 70, '4': 20, '3': 10, '2': 0, '1': 0} (percentages)"
    )

    # ===== Availability & Status =====
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text="Service is active and available for booking"
    )

    is_featured = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Featured in marketplace"
    )

    provider_is_verified = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Provider is KYC verified"
    )

    provider_availability_status = models.CharField(
        max_length=50,
        default='available',
        db_index=True,
        help_text="Provider availability: available, busy, unavailable"
    )

    # ===== Stats =====
    view_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of views in public marketplace"
    )

    order_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of orders placed"
    )

    # ===== Metadata =====
    published_at = models.DateTimeField(
        db_index=True,
        help_text="When service was published to marketplace"
    )

    synced_at = models.DateTimeField(
        auto_now=True,
        help_text="When this catalog entry was last synced from tenant"
    )

    # ===== Booking URL =====
    booking_url = models.URLField(
        help_text="URL to book/contact for this service (redirects to tenant domain)"
    )

    detail_url = models.URLField(
        help_text="URL to view service details (redirects to tenant domain)"
    )

    class Meta:
        db_table = 'services_public_service'
        verbose_name = _("Public Service")
        verbose_name_plural = _("Public Services")

        indexes = [
            models.Index(fields=['name'], name='ps_name_idx'),
            models.Index(fields=['category_slug'], name='ps_category_idx'),
            models.Index(fields=['service_type', 'price'], name='ps_type_price_idx'),
            models.Index(fields=['-rating_avg', '-total_reviews'], name='ps_rating_idx'),
            models.Index(fields=['-published_at'], name='ps_published_idx'),
            models.Index(fields=['is_active', 'is_featured'], name='ps_status_idx'),
            models.Index(fields=['location_city', 'location_state'], name='ps_location_idx'),
            models.Index(fields=['tenant_schema_name'], name='ps_tenant_idx'),
            models.Index(fields=['provider_uuid'], name='ps_provider_idx'),
        ]

        ordering = ['-is_featured', '-published_at']

    def __str__(self):
        return f"{self.name} by {self.provider_name}"

    @property
    def has_pricing_info(self):
        """Check if pricing information is available."""
        return self.price is not None or self.price_min is not None

    @property
    def pricing_display(self):
        """Display formatted pricing."""
        if not self.has_pricing_info:
            return "Contact for pricing"

        if self.price:
            return f"{self.currency} {self.price:,.0f}"
        elif self.price_min and self.price_max:
            return f"{self.currency} {self.price_min:,.0f} - {self.price_max:,.0f}"
        elif self.price_min:
            return f"From {self.currency} {self.price_min:,.0f}"

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

        return ", ".join(parts) if parts else "Location not specified"

    @property
    def rating_display(self):
        """Display formatted rating."""
        if self.rating_avg:
            return f"{self.rating_avg:.1f}/5.0 ({self.total_reviews} reviews)"
        return "No reviews yet"


class PublicServiceImage(models.Model):
    """
    Service gallery images for public catalog.

    Synced from tenant ServiceImage instances.
    Stores denormalized image data for fast loading without tenant context.
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )

    service = models.ForeignKey(
        PublicService,
        on_delete=models.CASCADE,
        related_name='images',
        help_text="Parent public service"
    )

    image_url = models.URLField(
        help_text="Image URL (CDN or tenant storage)"
    )

    alt_text = models.CharField(
        max_length=125,
        blank=True,
        help_text="Image alt text for accessibility"
    )

    description = models.CharField(
        max_length=255,
        blank=True,
        help_text="Image description"
    )

    sort_order = models.PositiveIntegerField(
        default=0,
        db_index=True,
        help_text="Display order in gallery"
    )

    class Meta:
        db_table = 'services_public_service_image'
        verbose_name = _("Public Service Image")
        verbose_name_plural = _("Public Service Images")
        ordering = ['sort_order']
        indexes = [
            models.Index(fields=['service', 'sort_order'], name='psi_service_order_idx'),
        ]

    def __str__(self):
        return f"Image for {self.service.name} (#{self.sort_order})"


class PublicServicePricingTier(models.Model):
    """
    Pricing tiers for services (Starter, Professional, Executive, etc.).

    Maps to pricing packages defined in tenant schema.
    Allows services to offer multiple pricing options with different features.
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )

    service = models.ForeignKey(
        PublicService,
        on_delete=models.CASCADE,
        related_name='pricing_tiers',
        help_text="Parent public service"
    )

    name = models.CharField(
        max_length=100,
        help_text="Tier name (e.g., Starter, Professional, Executive)"
    )

    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        help_text="Tier price"
    )

    currency = models.CharField(
        max_length=3,
        default='CAD',
        help_text="Currency code"
    )

    delivery_time_days = models.PositiveSmallIntegerField(
        help_text="Delivery time in days for this tier"
    )

    revisions = models.PositiveSmallIntegerField(
        help_text="Number of revisions included (0 = unlimited)"
    )

    # Features as JSON for flexibility
    features = models.JSONField(
        default=dict,
        help_text="""
        Feature list with boolean/text values:
        {
            'printable_resolution': true,
            'logo_design': true,
            'branding': false,
            'mockup': false,
            'vector_file': true,
            'source_files': true,
            'support_lifetime': true,
            'custom_feature_name': 'Custom value'
        }
        """
    )

    sort_order = models.PositiveIntegerField(
        default=0,
        db_index=True,
        help_text="Display order (usually price ascending)"
    )

    is_recommended = models.BooleanField(
        default=False,
        help_text="Highlight this tier as recommended"
    )

    class Meta:
        db_table = 'services_public_pricing_tier'
        verbose_name = _("Public Service Pricing Tier")
        verbose_name_plural = _("Public Service Pricing Tiers")
        ordering = ['sort_order']
        indexes = [
            models.Index(fields=['service', 'sort_order'], name='pst_service_order_idx'),
        ]

    def __str__(self):
        return f"{self.service.name} - {self.name} ({self.currency} {self.price})"


class PublicServicePortfolio(models.Model):
    """
    Provider portfolio images associated with service.

    Shows provider's past work relevant to this service.
    Synced from provider portfolio in tenant schema.
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )

    service = models.ForeignKey(
        PublicService,
        on_delete=models.CASCADE,
        related_name='portfolio_images',
        help_text="Parent public service"
    )

    image_url = models.URLField(
        help_text="Portfolio image URL"
    )

    title = models.CharField(
        max_length=200,
        blank=True,
        help_text="Portfolio piece title"
    )

    description = models.TextField(
        blank=True,
        help_text="Portfolio piece description"
    )

    sort_order = models.PositiveIntegerField(
        default=0,
        db_index=True,
        help_text="Display order in portfolio grid"
    )

    # Optional: grid layout hints
    grid_col_span = models.PositiveSmallIntegerField(
        default=1,
        help_text="Grid column span (1-3)"
    )

    grid_row_span = models.PositiveSmallIntegerField(
        default=1,
        help_text="Grid row span (1-2)"
    )

    class Meta:
        db_table = 'services_public_portfolio'
        verbose_name = _("Public Service Portfolio Image")
        verbose_name_plural = _("Public Service Portfolio Images")
        ordering = ['sort_order']
        indexes = [
            models.Index(fields=['service', 'sort_order'], name='psp_service_order_idx'),
        ]

    def __str__(self):
        return f"Portfolio for {self.service.name}: {self.title or 'Untitled'}"


class PublicServiceReview(models.Model):
    """
    Denormalized service reviews for public display.

    Synced from tenant ServiceReview instances.
    Contains only non-sensitive review data for public display.
    Reviewer information is anonymized for privacy.
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )

    service = models.ForeignKey(
        PublicService,
        on_delete=models.CASCADE,
        related_name='reviews',
        help_text="Parent public service"
    )

    review_uuid = models.UUIDField(
        unique=True,
        help_text="UUID of source review in tenant schema"
    )

    # Reviewer Info (Anonymized)
    reviewer_name = models.CharField(
        max_length=100,
        help_text="Reviewer display name (e.g., 'Jeremy L.')"
    )

    reviewer_avatar_url = models.URLField(
        blank=True,
        help_text="Reviewer avatar URL"
    )

    reviewer_is_verified = models.BooleanField(
        default=False,
        help_text="Verified purchaser badge"
    )

    # Rating
    rating = models.PositiveSmallIntegerField(
        db_index=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        help_text="Overall rating (1-5)"
    )

    rating_communication = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        help_text="Communication rating"
    )

    rating_quality = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        help_text="Quality rating"
    )

    rating_timeliness = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        help_text="Timeliness rating"
    )

    # Content
    title = models.CharField(
        max_length=200,
        blank=True,
        help_text="Review title"
    )

    content = models.TextField(
        blank=True,
        help_text="Sanitized review text"
    )

    # Provider Response
    provider_response = models.TextField(
        blank=True,
        help_text="Provider's response to review"
    )

    provider_responded_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When provider responded"
    )

    # Metadata
    created_at = models.DateTimeField(
        db_index=True,
        help_text="Review creation date"
    )

    helpful_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of 'helpful' votes"
    )

    class Meta:
        db_table = 'services_public_review'
        verbose_name = _("Public Service Review")
        verbose_name_plural = _("Public Service Reviews")
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['service', '-created_at'], name='psr_service_date_idx'),
            models.Index(fields=['service', '-rating'], name='psr_service_rating_idx'),
        ]

    def __str__(self):
        return f"Review by {self.reviewer_name} for {self.service.name} ({self.rating}/5)"
