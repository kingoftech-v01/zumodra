"""
Services API Serializers

Django REST Framework serializers for the services app API.
These serializers are tenant-aware and used by authenticated providers/clients
to manage services, bookings, reviews, etc.
"""

from rest_framework import serializers
from decimal import Decimal
from .models import (
    ServiceCategory,
    ServiceTag,
    ServiceImage,
    ProviderSkill,
    ServiceProvider,
    Service,
    ServiceLike,
    ServicePricingTier,
    ProviderPortfolio,
    ClientRequest,
    CrossTenantServiceRequest,
    ProviderMatch,
    ServiceProposal,
    ServiceContract,
    ServiceReview,
    ContractMessage,
)


# ==================== CATEGORY & TAG SERIALIZERS ====================


class ServiceCategorySerializer(serializers.ModelSerializer):
    """
    Serializer for service categories.

    Includes hierarchy information and full path.
    """
    full_path = serializers.ReadOnlyField()
    depth = serializers.ReadOnlyField()
    subcategories = serializers.SerializerMethodField()

    class Meta:
        model = ServiceCategory
        fields = [
            'id',
            'uuid',
            'name',
            'slug',
            'parent',
            'description',
            'icon',
            'color',
            'sort_order',
            'full_path',
            'depth',
            'subcategories',
        ]
        read_only_fields = ['uuid', 'full_path', 'depth', 'subcategories']

    def get_subcategories(self, obj):
        """Get immediate subcategories (non-recursive for performance)."""
        subcats = obj.subcategories.all()[:10]  # Limit to prevent N+1
        return ServiceCategorySerializer(subcats, many=True, read_only=True).data


class ServiceTagSerializer(serializers.ModelSerializer):
    """Serializer for service tags."""

    class Meta:
        model = ServiceTag
        fields = ['id', 'uuid', 'name', 'slug']
        read_only_fields = ['uuid']


class ServiceImageSerializer(serializers.ModelSerializer):
    """Serializer for service images."""

    image_url = serializers.SerializerMethodField()

    class Meta:
        model = ServiceImage
        fields = [
            'id',
            'uuid',
            'image',
            'image_url',
            'description',
            'alt_text',
            'sort_order',
        ]
        read_only_fields = ['uuid', 'image_url']

    def get_image_url(self, obj):
        """Get absolute URL for image."""
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
            return obj.image.url
        return None


# ==================== PROVIDER SERIALIZERS ====================


class ProviderSkillSerializer(serializers.ModelSerializer):
    """Serializer for provider skills with proficiency levels."""

    skill_name = serializers.CharField(source='skill.name', read_only=True)

    class Meta:
        model = ProviderSkill
        fields = [
            'id',
            'uuid',
            'skill',
            'skill_name',
            'level',
            'years_experience',
            'is_verified',
        ]
        read_only_fields = ['uuid', 'skill_name']


class ServiceProviderListSerializer(serializers.ModelSerializer):
    """
    Lightweight provider serializer for list views.

    Returns minimal fields for performance.
    """

    coordinates = serializers.ReadOnlyField()
    full_address = serializers.ReadOnlyField()
    avatar_url = serializers.SerializerMethodField()

    class Meta:
        model = ServiceProvider
        fields = [
            'uuid',
            'display_name',
            'provider_type',
            'tagline',
            'avatar_url',
            'city',
            'state',
            'country',
            'coordinates',
            'full_address',
            'rating_avg',
            'total_reviews',
            'completed_jobs_count',
            'availability_status',
            'is_verified',
            'is_featured',
        ]
        read_only_fields = fields

    def get_avatar_url(self, obj):
        """Get absolute URL for avatar."""
        if obj.avatar:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.avatar.url)
            return obj.avatar.url
        return None


class ServiceProviderDetailSerializer(serializers.ModelSerializer):
    """
    Complete provider serializer with all relations.

    Used for provider profile detail views.
    """

    coordinates = serializers.ReadOnlyField()
    full_address = serializers.ReadOnlyField()
    avatar_url = serializers.SerializerMethodField()
    cover_image_url = serializers.SerializerMethodField()
    categories = ServiceCategorySerializer(many=True, read_only=True)
    provider_skills = ProviderSkillSerializer(many=True, read_only=True)
    portfolio = serializers.SerializerMethodField()

    class Meta:
        model = ServiceProvider
        fields = [
            'uuid',
            'user',
            'company',
            'provider_type',
            'display_name',
            'bio',
            'tagline',
            'avatar_url',
            'cover_image_url',
            'categories',
            'provider_skills',
            'address',
            'city',
            'state',
            'postal_code',
            'country',
            'coordinates',
            'full_address',
            'hourly_rate',
            'minimum_budget',
            'currency',
            'rating_avg',
            'total_reviews',
            'completed_jobs_count',
            'total_earnings',
            'response_rate',
            'avg_response_time_hours',
            'availability_status',
            'is_verified',
            'is_featured',
            'marketplace_enabled',
            'is_accepting_work',
            'can_work_remotely',
            'can_work_onsite',
            'last_active_at',
            'portfolio',
        ]
        read_only_fields = [
            'uuid', 'user', 'coordinates', 'full_address', 'avatar_url',
            'cover_image_url', 'rating_avg', 'total_reviews',
            'completed_jobs_count', 'total_earnings', 'portfolio'
        ]

    def get_avatar_url(self, obj):
        """Get absolute URL for avatar."""
        if obj.avatar:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.avatar.url)
            return obj.avatar.url
        return None

    def get_cover_image_url(self, obj):
        """Get absolute URL for cover image."""
        if obj.cover_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.cover_image.url)
            return obj.cover_image.url
        return None

    def get_portfolio(self, obj):
        """Get portfolio items for this provider."""
        portfolio_items = obj.portfolio.all()[:12]  # Limit for performance
        return ProviderPortfolioSerializer(portfolio_items, many=True, context=self.context).data


class ServiceProviderUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating provider profile.

    Used by providers to update their own profile.
    """

    class Meta:
        model = ServiceProvider
        fields = [
            'provider_type',
            'display_name',
            'bio',
            'tagline',
            'avatar',
            'cover_image',
            'address',
            'city',
            'state',
            'postal_code',
            'country',
            'hourly_rate',
            'minimum_budget',
            'currency',
            'availability_status',
            'marketplace_enabled',
            'is_accepting_work',
            'can_work_remotely',
            'can_work_onsite',
        ]


# ==================== SERVICE SERIALIZERS ====================


class ServicePricingTierSerializer(serializers.ModelSerializer):
    """Serializer for service pricing tiers/packages."""

    features_list = serializers.SerializerMethodField()
    currency = serializers.CharField(source='service.currency', read_only=True)

    class Meta:
        model = ServicePricingTier
        fields = [
            'id',
            'uuid',
            'service',
            'name',
            'price',
            'currency',
            'delivery_time_days',
            'revisions',
            'features',
            'features_list',
            'sort_order',
            'is_recommended',
        ]
        read_only_fields = ['uuid', 'currency', 'features_list']

    def get_features_list(self, obj):
        """Convert features dict to list format for frontend."""
        if not obj.features:
            return []
        return [
            {'name': key, 'value': value, 'included': bool(value)}
            for key, value in obj.features.items()
        ]


class ProviderPortfolioSerializer(serializers.ModelSerializer):
    """Serializer for provider portfolio items."""

    image_url = serializers.SerializerMethodField()

    class Meta:
        model = ProviderPortfolio
        fields = [
            'id',
            'uuid',
            'provider',
            'image',
            'image_url',
            'title',
            'description',
            'sort_order',
            'grid_col_span',
            'grid_row_span',
            'created_at',
        ]
        read_only_fields = ['uuid', 'image_url', 'created_at']

    def get_image_url(self, obj):
        """Get absolute URL for portfolio image."""
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
            return obj.image.url
        return None


class ServiceListSerializer(serializers.ModelSerializer):
    """
    Lightweight service serializer for list views.

    Returns minimal fields for performance in list endpoints.
    """

    provider_name = serializers.CharField(source='provider.display_name', read_only=True)
    provider_avatar_url = serializers.SerializerMethodField()
    category_name = serializers.CharField(source='category.name', read_only=True)
    category_slug = serializers.CharField(source='category.slug', read_only=True)
    thumbnail_url = serializers.SerializerMethodField()
    tags_list = serializers.SerializerMethodField()

    class Meta:
        model = Service
        fields = [
            'uuid',
            'name',
            'slug',
            'short_description',
            'provider',
            'provider_name',
            'provider_avatar_url',
            'category',
            'category_name',
            'category_slug',
            'thumbnail_url',
            'service_type',
            'price',
            'price_min',
            'price_max',
            'currency',
            'delivery_type',
            'duration_days',
            'tags_list',
            'is_active',
            'is_featured',
            'is_public',
            'view_count',
            'order_count',
        ]
        read_only_fields = [
            'uuid', 'slug', 'provider_name', 'provider_avatar_url',
            'category_name', 'category_slug', 'thumbnail_url', 'tags_list',
            'view_count', 'order_count'
        ]

    def get_provider_avatar_url(self, obj):
        """Get provider avatar URL."""
        if obj.provider and obj.provider.avatar:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.provider.avatar.url)
            return obj.provider.avatar.url
        return None

    def get_thumbnail_url(self, obj):
        """Get thumbnail URL."""
        if obj.thumbnail:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.thumbnail.url)
            return obj.thumbnail.url
        return None

    def get_tags_list(self, obj):
        """Get list of tag names."""
        return [tag.name for tag in obj.tags.all()[:10]]  # Limit for performance


class ServiceDetailSerializer(serializers.ModelSerializer):
    """
    Complete service serializer with all relations.

    Includes images, pricing tiers, provider info, reviews, etc.
    Used for service detail endpoints.
    """

    provider = ServiceProviderListSerializer(read_only=True)
    category = ServiceCategorySerializer(read_only=True)
    images = ServiceImageSerializer(many=True, read_only=True)
    pricing_tiers = ServicePricingTierSerializer(many=True, read_only=True)
    tags = ServiceTagSerializer(many=True, read_only=True)
    thumbnail_url = serializers.SerializerMethodField()
    tags_list = serializers.SerializerMethodField()

    class Meta:
        model = Service
        fields = [
            'uuid',
            'provider',
            'category',
            'name',
            'slug',
            'description',
            'short_description',
            'service_type',
            'price',
            'price_min',
            'price_max',
            'currency',
            'delivery_type',
            'duration_days',
            'revisions_included',
            'thumbnail',
            'thumbnail_url',
            'images',
            'video_url',
            'tags',
            'tags_list',
            'pricing_tiers',
            'is_active',
            'is_featured',
            'is_public',
            'published_to_catalog',
            'catalog_synced_at',
            'view_count',
            'order_count',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'uuid', 'slug', 'provider', 'thumbnail_url', 'tags_list',
            'published_to_catalog', 'catalog_synced_at', 'view_count',
            'order_count', 'created_at', 'updated_at'
        ]

    def get_thumbnail_url(self, obj):
        """Get thumbnail URL."""
        if obj.thumbnail:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.thumbnail.url)
            return obj.thumbnail.url
        return None

    def get_tags_list(self, obj):
        """Get list of tag names."""
        return [tag.name for tag in obj.tags.all()]


class ServiceCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating services.

    Used by providers to create new services.
    Provider is automatically set from request.user.
    """

    tags_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False,
        help_text="List of tag IDs"
    )

    images_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False,
        help_text="List of image IDs"
    )

    class Meta:
        model = Service
        fields = [
            'name',
            'category',
            'description',
            'short_description',
            'service_type',
            'price',
            'price_min',
            'price_max',
            'currency',
            'delivery_type',
            'duration_days',
            'revisions_included',
            'thumbnail',
            'video_url',
            'tags_ids',
            'images_ids',
            'is_active',
            'is_featured',
            'is_public',
        ]

    def create(self, validated_data):
        """Create service and handle many-to-many relationships."""
        tags_ids = validated_data.pop('tags_ids', [])
        images_ids = validated_data.pop('images_ids', [])

        # Provider is set from request.user in view
        service = Service.objects.create(**validated_data)

        # Add tags
        if tags_ids:
            service.tags.set(ServiceTag.objects.filter(id__in=tags_ids))

        # Add images
        if images_ids:
            service.images.set(ServiceImage.objects.filter(id__in=images_ids))

        return service


class ServiceUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating services.

    Used by providers to update their own services.
    """

    tags_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False
    )

    images_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False
    )

    class Meta:
        model = Service
        fields = [
            'name',
            'category',
            'description',
            'short_description',
            'service_type',
            'price',
            'price_min',
            'price_max',
            'currency',
            'delivery_type',
            'duration_days',
            'revisions_included',
            'thumbnail',
            'video_url',
            'tags_ids',
            'images_ids',
            'is_active',
            'is_featured',
            'is_public',
        ]

    def update(self, instance, validated_data):
        """Update service and handle many-to-many relationships."""
        tags_ids = validated_data.pop('tags_ids', None)
        images_ids = validated_data.pop('images_ids', None)

        # Update fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Update tags if provided
        if tags_ids is not None:
            instance.tags.set(ServiceTag.objects.filter(id__in=tags_ids))

        # Update images if provided
        if images_ids is not None:
            instance.images.set(ServiceImage.objects.filter(id__in=images_ids))

        return instance


# ==================== REVIEW SERIALIZERS ====================


class ServiceReviewSerializer(serializers.ModelSerializer):
    """Serializer for service reviews."""

    reviewer_name = serializers.SerializerMethodField()
    reviewer_avatar_url = serializers.SerializerMethodField()
    provider_name = serializers.CharField(source='provider.display_name', read_only=True)

    class Meta:
        model = ServiceReview
        fields = [
            'id',
            'uuid',
            'contract',
            'reviewer',
            'reviewer_name',
            'reviewer_avatar_url',
            'provider',
            'provider_name',
            'rating',
            'rating_communication',
            'rating_quality',
            'rating_timeliness',
            'title',
            'content',
            'provider_response',
            'provider_responded_at',
            'created_at',
        ]
        read_only_fields = [
            'uuid', 'reviewer', 'reviewer_name', 'reviewer_avatar_url',
            'provider', 'provider_name', 'provider_response',
            'provider_responded_at', 'created_at'
        ]

    def get_reviewer_name(self, obj):
        """Get reviewer display name (anonymize if needed)."""
        if obj.reviewer:
            return obj.reviewer.get_full_name() or obj.reviewer.username
        return "Anonymous"

    def get_reviewer_avatar_url(self, obj):
        """Get reviewer avatar URL."""
        # In future, can link to user profile avatar
        return None


class ServiceReviewResponseSerializer(serializers.Serializer):
    """Serializer for provider responding to a review."""

    provider_response = serializers.CharField(
        max_length=5000,
        required=True,
        help_text="Provider's response to the review"
    )


# ==================== BOOKING/CONTRACT SERIALIZERS ====================


class ServiceContractListSerializer(serializers.ModelSerializer):
    """
    Lightweight contract serializer for list views.

    Used in bookings lists, contract management dashboards.
    """

    client_name = serializers.SerializerMethodField()
    provider_name = serializers.CharField(source='provider.display_name', read_only=True)
    service_name = serializers.CharField(source='service.name', read_only=True)

    class Meta:
        model = ServiceContract
        fields = [
            'uuid',
            'client',
            'client_name',
            'provider',
            'provider_name',
            'service',
            'service_name',
            'title',
            'agreed_rate',
            'rate_type',
            'currency',
            'agreed_deadline',
            'status',
            'started_at',
            'delivered_at',
            'completed_at',
            'created_at',
        ]
        read_only_fields = fields

    def get_client_name(self, obj):
        """Get client display name."""
        if obj.client:
            return obj.client.get_full_name() or obj.client.username
        return None


class ServiceContractDetailSerializer(serializers.ModelSerializer):
    """
    Complete contract serializer with all details.

    Includes escrow info, messages, reviews, etc.
    """

    client_name = serializers.SerializerMethodField()
    provider = ServiceProviderListSerializer(read_only=True)
    service = ServiceListSerializer(read_only=True)
    proposal = serializers.PrimaryKeyRelatedField(read_only=True)
    provider_payout_amount = serializers.ReadOnlyField()

    class Meta:
        model = ServiceContract
        fields = [
            'uuid',
            'client',
            'client_name',
            'provider',
            'service',
            'proposal',
            'client_request',
            'title',
            'description',
            'agreed_rate',
            'rate_type',
            'currency',
            'agreed_deadline',
            'revisions_allowed',
            'revisions_used',
            'escrow_transaction',
            'platform_fee_percent',
            'provider_payout_amount',
            'status',
            'started_at',
            'delivered_at',
            'completed_at',
            'cancelled_at',
            'cancellation_reason',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'uuid', 'client', 'client_name', 'provider', 'service',
            'proposal', 'provider_payout_amount', 'status', 'started_at',
            'delivered_at', 'completed_at', 'cancelled_at', 'created_at',
            'updated_at'
        ]

    def get_client_name(self, obj):
        """Get client display name."""
        if obj.client:
            return obj.client.get_full_name() or obj.client.username
        return None


class ServiceContractCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating service contracts/bookings.

    Used when client books a service directly (not through proposal).
    """

    class Meta:
        model = ServiceContract
        fields = [
            'service',
            'title',
            'description',
            'agreed_rate',
            'rate_type',
            'currency',
            'agreed_deadline',
            'revisions_allowed',
        ]

    def validate(self, data):
        """Validate contract data."""
        if data['agreed_rate'] <= 0:
            raise serializers.ValidationError("Agreed rate must be positive.")

        if data.get('agreed_deadline') and data['agreed_deadline'] < timezone.now().date():
            raise serializers.ValidationError("Deadline cannot be in the past.")

        return data

    def create(self, validated_data):
        """Create contract with client from request."""
        # Client is set from request.user in view
        # Provider is set from service.provider
        contract = ServiceContract.objects.create(**validated_data)
        return contract


class ContractMessageSerializer(serializers.ModelSerializer):
    """Serializer for contract messages."""

    sender_name = serializers.SerializerMethodField()

    class Meta:
        model = ContractMessage
        fields = [
            'id',
            'uuid',
            'contract',
            'sender',
            'sender_name',
            'content',
            'attachments',
            'is_system_message',
            'read_at',
            'created_at',
        ]
        read_only_fields = ['uuid', 'sender', 'sender_name', 'is_system_message', 'created_at']

    def get_sender_name(self, obj):
        """Get sender display name."""
        if obj.is_system_message:
            return "System"
        if obj.sender:
            return obj.sender.get_full_name() or obj.sender.username
        return "Unknown"


# ==================== CROSS-TENANT REQUEST SERIALIZERS ====================


class CrossTenantServiceRequestSerializer(serializers.ModelSerializer):
    """
    Serializer for cross-tenant service requests.

    Used when a user from one tenant requests a service from another tenant.
    """

    class Meta:
        model = CrossTenantServiceRequest
        fields = [
            'uuid',
            'client',
            'target_service_uuid',
            'target_tenant_schema',
            'target_provider_uuid',
            'title',
            'description',
            'budget',
            'currency',
            'deadline',
            'attachment_1',
            'attachment_2',
            'status',
            'hiring_context',
            'provider_response',
            'responded_at',
            'contract',
            'created_at',
        ]
        read_only_fields = [
            'uuid', 'client', 'status', 'provider_response',
            'responded_at', 'contract', 'created_at'
        ]


# ==================== IMPORT TIMEZONE ====================
from django.utils import timezone
