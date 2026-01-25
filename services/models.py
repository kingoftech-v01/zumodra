"""
Services Models - Zumodra Freelance Marketplace

This module implements the core freelance marketplace functionality:
- Service categories and tags
- Provider profiles with skills, location, and ratings
- Services offered by providers
- Client requests and matching
- Service contracts with escrow integration
- Reviews and messaging

All models inherit from TenantAwareModel for multi-tenant isolation.

MIGRATION NOTE: This replaces the previous D-prefixed models.
Backwards compatibility aliases are provided at the bottom of this file.
"""

import uuid
from decimal import Decimal

from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator, MaxValueValidator, FileExtensionValidator, MaxLengthValidator
from django.contrib.gis.db import models as gis_models
from django.contrib.gis.geos import Point

from core.db.models import TenantAwareModel, TenantSoftDeleteModel
from core.db.managers import TenantAwareManager

# Lazy import to avoid circular imports
def get_skill_model():
    from configurations.models import Skill
    return Skill

def get_company_model():
    from configurations.models import Company
    return Company


# =============================================================================
# SERVICE CATEGORY & TAXONOMY
# =============================================================================

class ServiceCategory(TenantAwareModel):
    """
    Hierarchical categorization of services.
    Supports nested sub-categories for better organization.
    """
    name = models.CharField(
        max_length=100,
        help_text=_("Category name")
    )
    slug = models.SlugField(max_length=100, blank=True)
    parent = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='subcategories',
        help_text=_("Parent category for hierarchy")
    )
    description = models.TextField(blank=True)
    icon = models.CharField(max_length=50, blank=True, help_text=_("Icon class name"))
    color = models.CharField(max_length=7, default='#3B82F6')
    sort_order = models.PositiveIntegerField(default=0)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Service Category")
        verbose_name_plural = _("Service Categories")
        ordering = ['sort_order', 'name']
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'slug'],
                name='services_category_unique_tenant_slug'
            )
        ]

    def __str__(self):
        if self.parent:
            return f"{self.parent.name} > {self.name}"
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            from django.utils.text import slugify
            self.slug = slugify(self.name)[:100]
        super().save(*args, **kwargs)

    @property
    def full_path(self) -> str:
        """Return the full category path."""
        path_parts = [self.name]
        parent = self.parent
        while parent:
            path_parts.insert(0, parent.name)
            parent = parent.parent
        return ' > '.join(path_parts)

    @property
    def depth(self) -> int:
        """Return depth in hierarchy (0 for root)."""
        level = 0
        parent = self.parent
        while parent:
            level += 1
            parent = parent.parent
        return level


class ServiceTag(TenantAwareModel):
    """
    Tags for services to enable search and filtering.
    """
    name = models.CharField(max_length=50)
    slug = models.SlugField(max_length=50, blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Service Tag")
        verbose_name_plural = _("Service Tags")
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'slug'],
                name='services_tag_unique_tenant_slug'
            )
        ]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            from django.utils.text import slugify
            self.slug = slugify(self.name)[:50]
        super().save(*args, **kwargs)


class ServiceImage(TenantAwareModel):
    """
    Images associated with services.
    """
    image = models.ImageField(
        upload_to='service_images/',
        validators=[
            FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'gif', 'webp'])
        ],
        help_text=_("Allowed formats: JPG, PNG, GIF, WebP. Max size: 10MB")
    )
    description = models.CharField(max_length=255, blank=True)
    alt_text = models.CharField(max_length=125, blank=True)
    sort_order = models.PositiveIntegerField(default=0)

    def clean(self):
        super().clean()
        if self.image and hasattr(self.image, 'size'):
            if self.image.size > 10 * 1024 * 1024:  # 10MB
                raise ValidationError(_("Image file size must be less than 10MB."))

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Service Image")
        verbose_name_plural = _("Service Images")
        ordering = ['sort_order']

    def __str__(self):
        return f"Image: {self.description or self.pk}"


# =============================================================================
# PROVIDER PROFILE
# =============================================================================

class ProviderSkill(TenantAwareModel):
    """
    Links a skill to a provider with proficiency level.
    """
    class SkillLevel(models.TextChoices):
        BEGINNER = 'beginner', _('Beginner')
        INTERMEDIATE = 'intermediate', _('Intermediate')
        ADVANCED = 'advanced', _('Advanced')
        EXPERT = 'expert', _('Expert')

    provider = models.ForeignKey(
        'ServiceProvider',
        on_delete=models.CASCADE,
        related_name='provider_skills'
    )
    skill = models.ForeignKey(
        'configurations.Skill',
        on_delete=models.CASCADE,
        related_name='provider_skills'
    )
    level = models.CharField(
        max_length=20,
        choices=SkillLevel.choices,
        default=SkillLevel.BEGINNER,
        db_index=True  # Index for filtering skills by level
    )
    years_experience = models.PositiveSmallIntegerField(default=0)
    is_verified = models.BooleanField(
        default=False,
        db_index=True  # Index for finding verified skills
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Provider Skill")
        verbose_name_plural = _("Provider Skills")
        constraints = [
            models.UniqueConstraint(
                fields=['provider', 'skill'],
                name='services_providerskill_unique_provider_skill'
            )
        ]

    def __str__(self):
        return f"{self.provider.display_name} - {self.skill.name} ({self.get_level_display()})"


class ServiceProvider(TenantAwareModel):
    """
    Profile for service providers (freelancers, agencies, consultants).

    Integrates with:
    - accounts.KYCVerification for identity verification
    - accounts.TrustScore for reputation scoring
    - finance.ConnectedAccount for Stripe payouts
    """
    class AvailabilityStatus(models.TextChoices):
        AVAILABLE = 'available', _('Available')
        BUSY = 'busy', _('Busy')
        UNAVAILABLE = 'unavailable', _('Unavailable')
        ON_VACATION = 'on_vacation', _('On Vacation')

    class ProviderType(models.TextChoices):
        INDIVIDUAL = 'individual', _('Individual Freelancer')
        AGENCY = 'agency', _('Agency')
        COMPANY = 'company', _('Company')

    # Identity
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='service_provider'
    )
    company = models.ForeignKey(
        'configurations.Company',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='service_providers'
    )
    provider_type = models.CharField(
        max_length=20,
        choices=ProviderType.choices,
        default=ProviderType.INDIVIDUAL
    )
    display_name = models.CharField(max_length=255, blank=True)

    # Profile
    bio = models.TextField(blank=True, validators=[MaxLengthValidator(2000)])
    tagline = models.CharField(max_length=200, blank=True)
    avatar = models.ImageField(upload_to='provider_avatars/', blank=True, null=True)
    cover_image = models.ImageField(upload_to='provider_covers/', blank=True, null=True)

    # Categories & Skills
    categories = models.ManyToManyField(ServiceCategory, blank=True, related_name='providers')

    # Location (PostGIS)
    address = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    postal_code = models.CharField(max_length=20, blank=True)
    country = models.CharField(max_length=100, blank=True, default='CA')
    location = gis_models.PointField(geography=True, null=True, blank=True, srid=4326)
    location_lat = models.FloatField(null=True, blank=True)
    location_lng = models.FloatField(null=True, blank=True)

    # Pricing
    hourly_rate = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        db_index=True,  # Index for filtering providers by hourly rate
        help_text=_("Default hourly rate")
    )
    minimum_budget = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        db_index=True,  # Index for filtering providers by minimum budget
        help_text=_("Minimum project budget")
    )
    currency = models.CharField(
        max_length=3,
        default='CAD',
        db_index=True  # Index for currency-based filtering
    )

    # Ratings & Stats
    rating_avg = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        default=Decimal('0.00'),
        validators=[MinValueValidator(0), MaxValueValidator(5)]
    )
    total_reviews = models.PositiveIntegerField(default=0)
    completed_jobs_count = models.PositiveIntegerField(default=0)
    total_earnings = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal('0.00'))
    response_rate = models.PositiveSmallIntegerField(default=0, help_text=_("Response rate %"))
    avg_response_time_hours = models.PositiveSmallIntegerField(default=24)

    # Status & Verification
    availability_status = models.CharField(
        max_length=20,
        choices=AvailabilityStatus.choices,
        default=AvailabilityStatus.AVAILABLE,
        db_index=True  # Index for filtering providers by availability status
    )
    is_verified = models.BooleanField(
        default=False,
        db_index=True,  # Index for finding KYC-verified providers
        help_text=_("KYC verified")
    )
    is_featured = models.BooleanField(
        default=False,
        db_index=True  # Index for finding featured providers in marketplace
    )

    # MARKETPLACE VISIBILITY
    marketplace_enabled = models.BooleanField(
        default=False,
        help_text=_('Provider can publish services to public marketplace')
    )

    # DEPRECATED - Use marketplace_enabled instead
    is_private = models.BooleanField(
        default=False,
        help_text=_("DEPRECATED: Use marketplace_enabled instead. Only visible via direct link")
    )

    is_accepting_work = models.BooleanField(
        default=True,
        help_text=_("Provider is currently accepting new service requests and contracts")
    )
    can_work_remotely = models.BooleanField(default=True)
    can_work_onsite = models.BooleanField(default=False)

    # Stripe Connect
    stripe_account_id = models.CharField(max_length=255, blank=True)
    stripe_onboarding_complete = models.BooleanField(default=False)
    stripe_payouts_enabled = models.BooleanField(default=False)

    # Timestamps
    last_active_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True  # Index for tracking active providers
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Service Provider")
        verbose_name_plural = _("Service Providers")
        ordering = ['-rating_avg', '-completed_jobs_count']

    def __str__(self):
        return self.display_name or self.user.get_full_name() or self.user.email

    def save(self, *args, **kwargs):
        # Set display name if not provided
        if not self.display_name:
            if self.company:
                self.display_name = self.company.name
            else:
                full_name = self.user.get_full_name()
                self.display_name = full_name or self.user.username

        # Geocode address if changed and location not set
        if self.address and (not self.location_lat or not self.location_lng):
            self._geocode_address()

        super().save(*args, **kwargs)

    def _geocode_address(self):
        """Geocode the address to lat/lng coordinates."""
        try:
            from geopy.geocoders import Nominatim
            full_address = ", ".join(filter(None, [
                self.address, self.city, self.state, self.postal_code, self.country
            ]))
            if full_address:
                geolocator = Nominatim(user_agent="zumodra_app")
                location = geolocator.geocode(full_address, timeout=10)
                if location:
                    self.location = Point(location.longitude, location.latitude)
                    self.location_lat = location.latitude
                    self.location_lng = location.longitude
        except Exception as e:
            # Log but don't fail - geocoding is optional
            import logging
            logging.warning(f"Geocoding failed for {self.display_name}: {e}")

    @property
    def full_address(self) -> str:
        """Return formatted full address."""
        parts = filter(None, [
            self.address, self.city, self.state, self.postal_code, self.country
        ])
        return ', '.join(parts)

    @property
    def coordinates(self):
        """Return coordinates as tuple if available."""
        if self.location_lat and self.location_lng:
            return (float(self.location_lat), float(self.location_lng))
        return None

    def update_rating(self):
        """Recalculate rating from reviews."""
        from django.db.models import Avg
        reviews = self.reviews.all()
        if reviews.exists():
            avg = reviews.aggregate(avg=Avg('rating'))['avg']
            self.rating_avg = Decimal(str(round(avg, 2)))
            self.total_reviews = reviews.count()
            self.save(update_fields=['rating_avg', 'total_reviews'])


# =============================================================================
# SERVICE
# =============================================================================

class Service(TenantAwareModel):
    """
    A service offered by a provider.
    """
    class ServiceType(models.TextChoices):
        FIXED_PRICE = 'fixed', _('Fixed Price')
        HOURLY = 'hourly', _('Hourly Rate')
        CUSTOM = 'custom', _('Custom Quote')

    class DeliveryType(models.TextChoices):
        REMOTE = 'remote', _('Remote')
        ONSITE = 'onsite', _('On-Site')
        HYBRID = 'hybrid', _('Hybrid')

    # Identity
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    provider = models.ForeignKey(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name='services'
    )
    category = models.ForeignKey(
        ServiceCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='services'
    )

    # Details
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    short_description = models.CharField(max_length=300, blank=True)

    # Pricing
    service_type = models.CharField(
        max_length=20,
        choices=ServiceType.choices,
        default=ServiceType.FIXED_PRICE,
        db_index=True  # Index for filtering services by pricing model
    )
    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        db_index=True,  # Index for price range filtering
        help_text=_("Price for fixed-price services")
    )
    price_min = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        db_index=True,  # Index for custom quote price filtering
        help_text=_("Minimum price for custom quotes")
    )
    price_max = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        db_index=True  # Index for price ceiling filtering
    )
    currency = models.CharField(
        max_length=3,
        default='CAD',
        db_index=True  # Index for currency-based filtering
    )

    # Delivery
    delivery_type = models.CharField(
        max_length=20,
        choices=DeliveryType.choices,
        default=DeliveryType.REMOTE,
        db_index=True  # Index for filtering services by delivery type
    )
    duration_days = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        db_index=True,  # Index for filtering services by duration
        help_text=_("Estimated delivery time in days")
    )
    revisions_included = models.PositiveSmallIntegerField(default=1)

    # Media
    thumbnail = models.ImageField(upload_to='service_thumbnails/', blank=True, null=True)
    images = models.ManyToManyField(ServiceImage, blank=True, related_name='services')
    video_url = models.URLField(blank=True)

    # Tags
    tags = models.ManyToManyField(ServiceTag, blank=True, related_name='services')

    # Status
    is_active = models.BooleanField(
        default=True,
        db_index=True,  # Index for finding active services
        help_text=_('Service is active and available for booking within tenant')
    )
    is_featured = models.BooleanField(
        default=False,
        db_index=True,  # Index for finding featured services in marketplace
        help_text=_('Featured services appear prominently in tenant marketplace')
    )

    # PUBLIC MARKETPLACE FIELDS
    is_public = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('Publish to public marketplace (visible to all users/companies)')
    )
    published_to_catalog = models.BooleanField(
        default=False,
        help_text=_('Service is currently synced to public catalog')
    )
    catalog_synced_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('Last sync timestamp with public catalog')
    )

    # Stats
    view_count = models.PositiveIntegerField(default=0)
    order_count = models.PositiveIntegerField(default=0)

    # Geolocation (for provider location-based features)
    location_coordinates = gis_models.PointField(
        srid=4326,
        null=True,
        blank=True,
        help_text=_('Geographic coordinates for service location (lon, lat)')
    )
    geocode_attempted = models.BooleanField(
        default=False,
        help_text=_('Whether geocoding has been attempted')
    )
    geocode_error = models.CharField(
        max_length=255,
        blank=True,
        default='',
        help_text=_('Error message if geocoding failed')
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Service")
        verbose_name_plural = _("Services")
        ordering = ['-is_featured', '-created_at']
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'provider', 'slug'],
                name='services_service_unique_tenant_provider_slug'
            )
        ]

    def __str__(self):
        return f"{self.name} by {self.provider.display_name}"

    def save(self, *args, **kwargs):
        if not self.slug:
            from django.utils.text import slugify
            base_slug = slugify(self.name)[:240]
            self.slug = base_slug
        super().save(*args, **kwargs)


class ServiceLike(TenantAwareModel):
    """
    Tracks users who have liked/favorited a service.
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='liked_services'
    )
    service = models.ForeignKey(
        Service,
        on_delete=models.CASCADE,
        related_name='likes'
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Service Like")
        verbose_name_plural = _("Service Likes")
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'service'],
                name='services_like_unique_user_service'
            )
        ]

    def __str__(self):
        return f"{self.user.email} likes {self.service.name}"


class ServicePricingTier(TenantAwareModel):
    """
    Pricing tiers/packages for services.

    Allows services to offer multiple pricing options (e.g., Starter, Professional, Executive)
    with different features, delivery times, and revision counts.

    This data is synced to the public catalog when service.is_public=True.
    """
    service = models.ForeignKey(
        Service,
        on_delete=models.CASCADE,
        related_name='pricing_tiers',
        help_text=_("Parent service")
    )

    name = models.CharField(
        max_length=100,
        help_text=_("Tier name (e.g., Starter, Professional, Executive)")
    )

    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        help_text=_("Tier price")
    )

    delivery_time_days = models.PositiveSmallIntegerField(
        help_text=_("Delivery time in days for this tier")
    )

    revisions = models.PositiveSmallIntegerField(
        help_text=_("Number of revisions included (0 = unlimited)")
    )

    features = models.JSONField(
        default=dict,
        help_text=_(
            "Feature list with boolean/text values: "
            "{'printable_resolution': true, 'logo_design': true, ...}"
        )
    )

    sort_order = models.PositiveIntegerField(
        default=0,
        db_index=True,
        help_text=_("Display order (usually price ascending)")
    )

    is_recommended = models.BooleanField(
        default=False,
        help_text=_("Highlight this tier as recommended")
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Service Pricing Tier")
        verbose_name_plural = _("Service Pricing Tiers")
        ordering = ['service', 'sort_order']
        constraints = [
            models.UniqueConstraint(
                fields=['service', 'name'],
                name='services_pricing_tier_unique_service_name'
            )
        ]

    def __str__(self):
        currency = self.service.currency if hasattr(self.service, 'currency') else 'CAD'
        return f"{self.service.name} - {self.name} ({currency} {self.price})"


class ProviderPortfolio(TenantAwareModel):
    """
    Provider portfolio items.

    Stores portfolio images and descriptions for providers to showcase their past work.
    This data is synced to the public catalog when associated services are made public.
    """
    provider = models.ForeignKey(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name='portfolio',
        help_text=_("Provider who owns this portfolio item")
    )

    image = models.ImageField(
        upload_to='provider_portfolio/',
        help_text=_("Portfolio image")
    )

    title = models.CharField(
        max_length=200,
        blank=True,
        help_text=_("Portfolio piece title")
    )

    description = models.TextField(
        blank=True,
        help_text=_("Portfolio piece description")
    )

    sort_order = models.PositiveIntegerField(
        default=0,
        db_index=True,
        help_text=_("Display order in portfolio grid")
    )

    grid_col_span = models.PositiveSmallIntegerField(
        default=1,
        validators=[MinValueValidator(1), MaxValueValidator(3)],
        help_text=_("Grid column span (1-3)")
    )

    grid_row_span = models.PositiveSmallIntegerField(
        default=1,
        validators=[MinValueValidator(1), MaxValueValidator(2)],
        help_text=_("Grid row span (1-2)")
    )

    created_at = models.DateTimeField(auto_now_add=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Provider Portfolio Item")
        verbose_name_plural = _("Provider Portfolio Items")
        ordering = ['provider', 'sort_order']

    def __str__(self):
        return f"{self.provider.display_name} - {self.title or 'Untitled'}"


# =============================================================================
# CLIENT REQUESTS & MATCHING
# =============================================================================

class ClientRequest(TenantAwareModel):
    """
    A client's request for services, used for matching with providers.
    """
    class RequestStatus(models.TextChoices):
        OPEN = 'open', _('Open')
        IN_PROGRESS = 'in_progress', _('In Progress')
        CLOSED = 'closed', _('Closed')
        CANCELLED = 'cancelled', _('Cancelled')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    client = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='service_requests'
    )
    title = models.CharField(max_length=255)
    description = models.TextField()
    category = models.ForeignKey(
        ServiceCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    required_skills = models.ManyToManyField(
        'configurations.Skill',
        blank=True,
        related_name='client_requests'
    )

    # Budget
    budget_min = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    budget_max = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    currency = models.CharField(max_length=3, default='CAD')

    # Location preferences
    location_lat = models.FloatField(null=True, blank=True)
    location_lng = models.FloatField(null=True, blank=True)
    location_radius_km = models.PositiveSmallIntegerField(null=True, blank=True)
    remote_allowed = models.BooleanField(default=True)

    # Timeline
    deadline = models.DateField(null=True, blank=True)

    # Status
    status = models.CharField(
        max_length=20,
        choices=RequestStatus.choices,
        default=RequestStatus.OPEN,
        db_index=True  # Index for filtering client requests by status
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Client Request")
        verbose_name_plural = _("Client Requests")
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} by {self.client.email}"


class CrossTenantServiceRequest(TenantAwareModel):
    """
    Service request from one tenant to another tenant's public service.

    This model represents a cross-tenant hiring request - when a user from
    Company A wants to hire Company B for a public service. The request lives
    in the REQUESTING tenant's schema (Company A) to ensure data ownership
    and proper isolation.

    UPDATED: Now supports two hiring contexts:
    - ORGANIZATIONAL: User hiring on behalf of their tenant/organization
    - PERSONAL: User hiring for themselves (personal use)

    Flow:
    1. User in Company A browses PublicServiceCatalog (public schema)
    2. Finds service from Company B
    3. Creates CrossTenantServiceRequest in Company A's schema (with hiring_context)
    4. System notifies Company B (async Celery task)
    5. Company B reviews request in their dashboard
    6. If accepted, creates ServiceContract in Company A's schema
    """

    class RequestStatus(models.TextChoices):
        PENDING = 'pending', _('Pending Review')
        ACCEPTED = 'accepted', _('Accepted')
        REJECTED = 'rejected', _('Rejected')
        CONVERTED = 'converted', _('Converted to Contract')
        CANCELLED = 'cancelled', _('Cancelled')

    class HiringContext(models.TextChoices):
        ORGANIZATIONAL = 'organizational', _('On behalf of tenant/organization')
        PERSONAL = 'personal', _('Personal user hiring')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Requesting Party (lives in this tenant's schema)
    client = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='cross_tenant_requests_sent',
        help_text=_('User requesting the service')
    )

    # Target Service (in another tenant's schema)
    target_service_uuid = models.UUIDField(
        db_index=True,
        help_text=_('UUID of service in target tenant schema')
    )
    target_tenant_schema = models.CharField(
        max_length=63,
        help_text=_('Schema name of target tenant (provider)')
    )
    target_provider_uuid = models.UUIDField(
        help_text=_('UUID of provider in target tenant schema')
    )

    # Request Details
    title = models.CharField(
        max_length=255,
        help_text=_('Request title/summary')
    )
    description = models.TextField(
        help_text=_('Detailed description of service requirements')
    )
    budget = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Proposed budget for the service')
    )
    currency = models.CharField(max_length=3, default='CAD')
    deadline = models.DateField(
        null=True,
        blank=True,
        help_text=_('Desired completion date')
    )

    # Attachments (optional)
    attachment_1 = models.FileField(
        upload_to='cross_tenant_requests/',
        blank=True,
        null=True,
        help_text=_('Supporting document or file')
    )
    attachment_2 = models.FileField(
        upload_to='cross_tenant_requests/',
        blank=True,
        null=True
    )

    # Status & Response
    status = models.CharField(
        max_length=20,
        choices=RequestStatus.choices,
        default=RequestStatus.PENDING,
        db_index=True  # Index for filtering cross-tenant requests by status
    )
    hiring_context = models.CharField(
        max_length=20,
        choices=HiringContext.choices,
        default=HiringContext.ORGANIZATIONAL,
        db_index=True,  # Index for distinguishing organizational vs personal hiring
        help_text=_('Is this request for organization or personal use?')
    )
    provider_response = models.TextField(
        blank=True,
        help_text=_('Provider response message')
    )
    responded_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,  # Index for tracking provider response timestamps
        help_text=_('When provider responded')
    )

    # Contract Reference (if converted)
    contract = models.ForeignKey(
        'ServiceContract',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='originating_cross_tenant_request',
        help_text=_('Resulting contract if request was accepted')
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Cross-Tenant Service Request")
        verbose_name_plural = _("Cross-Tenant Service Requests")
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', '-created_at'], name='cross_req_status_created'),
            models.Index(fields=['target_tenant_schema'], name='cross_req_target_tenant'),
        ]

    def __str__(self):
        return f"{self.title} (→ {self.target_tenant_schema})"

    def notify_provider_tenant(self):
        """
        Send notification to provider in their tenant schema.

        Uses async Celery task to switch schemas and create notification.
        The notification will appear in the provider's dashboard allowing them
        to review and respond to the cross-tenant request.
        """
        from services.tasks import notify_cross_tenant_request

        notify_cross_tenant_request.delay(
            target_schema=self.target_tenant_schema,
            request_uuid=str(self.uuid),
            requesting_tenant_schema=self.tenant.schema_name
        )

    @property
    def is_pending(self):
        """Check if request is awaiting provider response."""
        return self.status == self.RequestStatus.PENDING

    @property
    def is_resolved(self):
        """Check if request has been answered (accepted/rejected/converted)."""
        return self.status in [
            self.RequestStatus.ACCEPTED,
            self.RequestStatus.REJECTED,
            self.RequestStatus.CONVERTED
        ]


class ProviderMatch(TenantAwareModel):
    """
    Stores a match between a ClientRequest and a ServiceProvider.
    Score computed by AI or heuristics.
    """
    client_request = models.ForeignKey(
        ClientRequest,
        on_delete=models.CASCADE,
        related_name='matches'
    )
    provider = models.ForeignKey(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name='matches'
    )
    score = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        help_text=_("Match score 0-1")
    )
    score_breakdown = models.JSONField(default=dict, blank=True)
    viewed_by_client = models.BooleanField(default=False)
    accepted_by_client = models.BooleanField(default=False)
    rejected_by_client = models.BooleanField(default=False)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Provider Match")
        verbose_name_plural = _("Provider Matches")
        ordering = ['-score']
        constraints = [
            models.UniqueConstraint(
                fields=['client_request', 'provider'],
                name='services_match_unique_request_provider'
            )
        ]

    def __str__(self):
        return f"Match: {self.client_request.title} <> {self.provider.display_name} ({self.score})"


# =============================================================================
# PROPOSALS & CONTRACTS
# =============================================================================

class ServiceProposal(TenantAwareModel):
    """
    A proposal from a provider responding to a client request.
    """
    class ProposalStatus(models.TextChoices):
        PENDING = 'pending', _('Pending')
        ACCEPTED = 'accepted', _('Accepted')
        REJECTED = 'rejected', _('Rejected')
        WITHDRAWN = 'withdrawn', _('Withdrawn')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    client_request = models.ForeignKey(
        ClientRequest,
        on_delete=models.CASCADE,
        related_name='proposals'
    )
    provider = models.ForeignKey(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name='proposals'
    )

    # Pricing
    proposed_rate = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        db_index=True  # Index for filtering proposals by rate
    )
    rate_type = models.CharField(
        max_length=20,
        choices=[('fixed', 'Fixed'), ('hourly', 'Hourly')],
        default='fixed',
        db_index=True  # Index for filtering proposals by rate type
    )
    estimated_hours = models.PositiveSmallIntegerField(null=True, blank=True)

    # Details
    cover_letter = models.TextField(validators=[MaxLengthValidator(10000)])
    proposed_timeline_days = models.PositiveSmallIntegerField(null=True, blank=True)
    attachments = models.JSONField(default=list, blank=True)

    # Status
    status = models.CharField(
        max_length=20,
        choices=ProposalStatus.choices,
        default=ProposalStatus.PENDING,
        db_index=True  # Index for filtering proposals by status
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Service Proposal")
        verbose_name_plural = _("Service Proposals")
        ordering = ['-created_at']
        constraints = [
            models.UniqueConstraint(
                fields=['client_request', 'provider'],
                name='services_proposal_unique_request_provider'
            )
        ]

    def __str__(self):
        return f"Proposal by {self.provider.display_name} for {self.client_request.title}"


class ServiceContract(TenantAwareModel):
    """
    A contract between client and provider with escrow integration.

    Linked to escrow.EscrowTransaction for secure payment handling.
    """
    class ContractStatus(models.TextChoices):
        DRAFT = 'draft', _('Draft')
        PENDING_PAYMENT = 'pending_payment', _('Pending Payment')
        FUNDED = 'funded', _('Funded (Escrow)')
        IN_PROGRESS = 'in_progress', _('In Progress')
        DELIVERED = 'delivered', _('Delivered')
        REVISION_REQUESTED = 'revision_requested', _('Revision Requested')
        COMPLETED = 'completed', _('Completed')
        DISPUTED = 'disputed', _('Disputed')
        CANCELLED = 'cancelled', _('Cancelled')
        REFUNDED = 'refunded', _('Refunded')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Parties
    client = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='client_contracts'
    )
    provider = models.ForeignKey(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name='provider_contracts'
    )

    # Origin (optional - may come from proposal or direct booking)
    proposal = models.OneToOneField(
        ServiceProposal,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='contract'
    )
    service = models.ForeignKey(
        Service,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='contracts'
    )
    client_request = models.ForeignKey(
        ClientRequest,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='contracts'
    )

    # Contract Details
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    agreed_rate = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        db_index=True  # Index for filtering contracts by agreed rate
    )
    rate_type = models.CharField(
        max_length=20,
        choices=[('fixed', 'Fixed'), ('hourly', 'Hourly')],
        default='fixed',
        db_index=True  # Index for filtering contracts by rate type
    )
    currency = models.CharField(
        max_length=3,
        default='CAD',
        db_index=True  # Index for currency-based filtering
    )
    agreed_deadline = models.DateField(
        null=True,
        blank=True,
        db_index=True  # Index for deadline-based filtering and sorting
    )
    revisions_allowed = models.PositiveSmallIntegerField(default=1)
    revisions_used = models.PositiveSmallIntegerField(default=0)

    # Escrow Integration
    escrow_transaction = models.OneToOneField(
        'escrow.EscrowTransaction',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='service_contract'
    )
    platform_fee_percent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('10.00'),
        help_text=_("Platform fee percentage")
    )

    # Status & Dates
    status = models.CharField(
        max_length=20,
        choices=ContractStatus.choices,
        default=ContractStatus.DRAFT,
        db_index=True  # Index for filtering contracts by status
    )
    started_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True  # Index for filtering active/completed contracts
    )
    delivered_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True  # Index for tracking delivery dates
    )
    completed_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True  # Index for finding completed contracts
    )
    cancelled_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True  # Index for tracking cancellations
    )
    cancellation_reason = models.TextField(blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Service Contract")
        verbose_name_plural = _("Service Contracts")
        ordering = ['-created_at']

    def __str__(self):
        return f"Contract: {self.title} ({self.client.email} <> {self.provider.display_name})"

    def start(self):
        """Start the contract after escrow is funded."""
        if self.status == self.ContractStatus.FUNDED:
            self.status = self.ContractStatus.IN_PROGRESS
            self.started_at = timezone.now()
            self.save(update_fields=['status', 'started_at'])

    def deliver(self):
        """Mark as delivered by provider."""
        if self.status == self.ContractStatus.IN_PROGRESS:
            self.status = self.ContractStatus.DELIVERED
            self.delivered_at = timezone.now()
            self.save(update_fields=['status', 'delivered_at'])

    def complete(self):
        """Complete the contract and release escrow."""
        if self.status == self.ContractStatus.DELIVERED:
            self.status = self.ContractStatus.COMPLETED
            self.completed_at = timezone.now()
            self.save(update_fields=['status', 'completed_at'])

            # Release escrow funds
            if self.escrow_transaction:
                self.escrow_transaction.status = 'released'
                self.escrow_transaction.released_at = timezone.now()
                self.escrow_transaction.save()

    def cancel(self, reason=''):
        """Cancel the contract."""
        self.status = self.ContractStatus.CANCELLED
        self.cancelled_at = timezone.now()
        self.cancellation_reason = reason
        self.save(update_fields=['status', 'cancelled_at', 'cancellation_reason'])

    @property
    def provider_payout_amount(self):
        """Calculate provider's payout after platform fee."""
        if self.agreed_rate:
            fee = self.agreed_rate * (self.platform_fee_percent / 100)
            return self.agreed_rate - fee
        return Decimal('0.00')


# =============================================================================
# REVIEWS & MESSAGES
# =============================================================================

class ServiceReview(TenantAwareModel):
    """
    Review for a completed service contract.
    """
    contract = models.OneToOneField(
        ServiceContract,
        on_delete=models.CASCADE,
        related_name='review'
    )
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='service_reviews_given'
    )
    provider = models.ForeignKey(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name='reviews'
    )

    # Ratings
    rating = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    rating_communication = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True,
        blank=True
    )
    rating_quality = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True,
        blank=True
    )
    rating_timeliness = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True,
        blank=True
    )

    # Content
    title = models.CharField(max_length=200, blank=True)
    content = models.TextField(blank=True, validators=[MaxLengthValidator(5000)])

    # Response
    provider_response = models.TextField(blank=True, validators=[MaxLengthValidator(5000)])
    provider_responded_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True  # Index for tracking provider response timestamps
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Service Review")
        verbose_name_plural = _("Service Reviews")
        ordering = ['-created_at']

    def __str__(self):
        return f"Review by {self.reviewer.email} for {self.provider.display_name}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Update provider's rating
        self.provider.update_rating()


class ContractMessage(TenantAwareModel):
    """
    Messages exchanged within a service contract.
    """
    contract = models.ForeignKey(
        ServiceContract,
        on_delete=models.CASCADE,
        related_name='messages'
    )
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='contract_messages_sent'
    )
    content = models.TextField()
    attachments = models.JSONField(default=list, blank=True)
    is_system_message = models.BooleanField(
        default=False,
        db_index=True  # Index for filtering system vs user messages
    )
    read_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True  # Index for finding unread messages
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Contract Message")
        verbose_name_plural = _("Contract Messages")
        ordering = ['created_at']

    def __str__(self):
        return f"Message in {self.contract.title} by {self.sender}"


# =============================================================================
# AUDIT LOGGING
# =============================================================================

try:
    from auditlog.registry import auditlog

    # Register all models for audit logging
    auditlog.register(ServiceCategory)
    auditlog.register(ServiceTag)
    auditlog.register(ServiceImage)
    auditlog.register(ProviderSkill)
    auditlog.register(ServiceProvider)
    auditlog.register(Service)
    auditlog.register(ServiceLike)
    auditlog.register(ClientRequest)
    auditlog.register(ProviderMatch)
    auditlog.register(ServiceProposal)
    auditlog.register(ServiceContract)
    auditlog.register(ServiceReview)
    auditlog.register(ContractMessage)
except ImportError:
    pass  # auditlog not installed


# =============================================================================
# BACKWARDS COMPATIBILITY ALIASES
# =============================================================================
# These aliases maintain backwards compatibility with the old D-prefixed names
# and the dashboard_service models. New code should use the canonical names above.

# Old services app aliases (D-prefixed)
DServiceCategory = ServiceCategory
DServicesTag = ServiceTag
DServicesPicture = ServiceImage
DServiceProviderProfile = ServiceProvider
DService = Service
DServiceLike = ServiceLike
DServiceRequest = ClientRequest
DServiceProposal = ServiceProposal
DServiceContract = ServiceContract
DServiceComment = ServiceReview
DServiceMessage = ContractMessage
Match = ProviderMatch

# dashboard_service aliases
ServiceProviderProfile = ServiceProvider
ServicesTag = ServiceTag
ServicesPicture = ServiceImage
ServiceRequest = ClientRequest
ServiceComment = ServiceReview
ServiceMessage = ContractMessage

__all__ = [
    # Canonical names
    'ServiceCategory',
    'ServiceTag',
    'ServiceImage',
    'ProviderSkill',
    'ServiceProvider',
    'Service',
    'ServiceLike',
    'ClientRequest',
    'ProviderMatch',
    'ServiceProposal',
    'ServiceContract',
    'ServiceReview',
    'ContractMessage',

    # Backwards compatibility
    'DServiceCategory',
    'DServicesTag',
    'DServicesPicture',
    'DServiceProviderProfile',
    'DService',
    'DServiceLike',
    'DServiceRequest',
    'DServiceProposal',
    'DServiceContract',
    'DServiceComment',
    'DServiceMessage',
    'Match',
    'ServiceProviderProfile',
    'ServicesTag',
    'ServicesPicture',
    'ServiceRequest',
    'ServiceComment',
    'ServiceMessage',
]
