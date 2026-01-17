"""
Services App Serializers - Zumodra Freelance Marketplace.

Provides serializers for:
- Service categories and taxonomy
- Provider profiles and skills
- Services offered
- Client requests and proposals
- Contracts with escrow integration
- Reviews and messaging
"""

from decimal import Decimal
from rest_framework import serializers
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field

from core.serializers import TenantAwareSerializer
from core.validators import sanitize_html

from .models import (
    ServiceCategory,
    ServiceTag,
    ServiceImage,
    ProviderSkill,
    ServiceProvider,
    Service,
    ServiceLike,
    ClientRequest,
    ProviderMatch,
    ServiceProposal,
    ServiceContract,
    ServiceReview,
    ContractMessage,
)


# =============================================================================
# USER MINIMAL SERIALIZER (for nested representations)
# =============================================================================

class UserMinimalSerializer(serializers.Serializer):
    """Minimal user representation for nested serializers."""
    id = serializers.IntegerField(read_only=True)
    email = serializers.EmailField(read_only=True)
    full_name = serializers.SerializerMethodField()
    avatar_url = serializers.SerializerMethodField()

    @extend_schema_field(OpenApiTypes.STR)
    def get_full_name(self, obj):
        return obj.get_full_name() or obj.email.split('@')[0]

    @extend_schema_field(OpenApiTypes.STR)
    def get_avatar_url(self, obj):
        if hasattr(obj, 'avatar') and obj.avatar:
            return obj.avatar.url
        return None


# =============================================================================
# CATEGORY & TAXONOMY SERIALIZERS
# =============================================================================

class ServiceCategorySerializer(TenantAwareSerializer):
    """Serializer for service categories."""
    subcategories = serializers.SerializerMethodField()
    full_path = serializers.CharField(read_only=True)
    depth = serializers.IntegerField(read_only=True)

    class Meta:
        model = ServiceCategory
        fields = [
            'id', 'name', 'slug', 'parent', 'description',
            'icon', 'color', 'sort_order', 'subcategories',
            'full_path', 'depth', 'created_at', 'updated_at'
        ]
        read_only_fields = ['slug', 'created_at', 'updated_at']

    @extend_schema_field(OpenApiTypes.STR)
    def get_subcategories(self, obj):
        subcats = obj.subcategories.all()
        if subcats.exists():
            return ServiceCategoryListSerializer(subcats, many=True).data
        return []


class ServiceCategoryListSerializer(TenantAwareSerializer):
    """Lightweight category serializer for lists."""
    class Meta:
        model = ServiceCategory
        fields = ['id', 'name', 'slug', 'icon', 'color', 'sort_order']


class ServiceTagSerializer(TenantAwareSerializer):
    """Serializer for service tags."""
    class Meta:
        model = ServiceTag
        fields = ['id', 'name', 'slug', 'created_at']
        read_only_fields = ['slug', 'created_at']


class ServiceImageSerializer(TenantAwareSerializer):
    """Serializer for service images."""
    class Meta:
        model = ServiceImage
        fields = ['id', 'image', 'description', 'alt_text', 'sort_order']


# =============================================================================
# PROVIDER SERIALIZERS
# =============================================================================

class ProviderSkillSerializer(TenantAwareSerializer):
    """Serializer for provider skills with proficiency."""
    skill_name = serializers.CharField(source='skill.name', read_only=True)
    skill_category = serializers.CharField(source='skill.category', read_only=True)

    class Meta:
        model = ProviderSkill
        fields = [
            'id', 'skill', 'skill_name', 'skill_category',
            'level', 'years_experience', 'is_verified'
        ]


class ServiceProviderListSerializer(TenantAwareSerializer):
    """Lightweight provider serializer for lists."""
    categories = ServiceCategoryListSerializer(many=True, read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)

    class Meta:
        model = ServiceProvider
        fields = [
            'id', 'uuid', 'display_name', 'avatar', 'tagline',
            'provider_type', 'city', 'country', 'hourly_rate',
            'currency', 'rating_avg', 'total_reviews',
            'completed_jobs_count', 'availability_status',
            'is_verified', 'is_featured', 'categories', 'user_email'
        ]


class ServiceProviderDetailSerializer(TenantAwareSerializer):
    """Full provider serializer with all details."""
    user = UserMinimalSerializer(read_only=True)
    categories = ServiceCategoryListSerializer(many=True, read_only=True)
    provider_skills = ProviderSkillSerializer(many=True, read_only=True)
    full_address = serializers.CharField(read_only=True)
    coordinates = serializers.SerializerMethodField()
    tenant_type = serializers.CharField(source='tenant.tenant_type', read_only=True)

    class Meta:
        model = ServiceProvider
        fields = [
            'id', 'uuid', 'user', 'company', 'provider_type',
            'display_name', 'bio', 'tagline', 'avatar', 'cover_image',
            'categories', 'provider_skills',
            'address', 'city', 'state', 'postal_code', 'country',
            'full_address', 'coordinates', 'location_lat', 'location_lng',
            'hourly_rate', 'minimum_budget', 'currency',
            'rating_avg', 'total_reviews', 'completed_jobs_count',
            'total_earnings', 'response_rate', 'avg_response_time_hours',
            'availability_status', 'is_verified', 'is_featured',
            'is_private', 'is_accepting_projects',
            'can_work_remotely', 'can_work_onsite',
            'stripe_onboarding_complete', 'stripe_payouts_enabled',
            'last_active_at', 'created_at', 'updated_at', 'tenant_type'
        ]
        read_only_fields = [
            'uuid', 'rating_avg', 'total_reviews', 'completed_jobs_count',
            'total_earnings', 'stripe_onboarding_complete',
            'stripe_payouts_enabled', 'created_at', 'updated_at'
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_coordinates(self, obj):
        return obj.coordinates

    def validate_bio(self, value):
        return sanitize_html(value) if value else value


class ServiceProviderCreateSerializer(TenantAwareSerializer):
    """Serializer for creating a provider profile."""
    class Meta:
        model = ServiceProvider
        fields = [
            'provider_type', 'display_name', 'bio', 'tagline',
            'address', 'city', 'state', 'postal_code', 'country',
            'hourly_rate', 'minimum_budget', 'currency',
            'can_work_remotely', 'can_work_onsite'
        ]

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


# =============================================================================
# SERVICE SERIALIZERS
# =============================================================================

class ServiceListSerializer(TenantAwareSerializer):
    """Lightweight service serializer for lists."""
    provider_name = serializers.CharField(source='provider.display_name', read_only=True)
    provider_rating = serializers.DecimalField(
        source='provider.rating_avg', max_digits=3, decimal_places=2, read_only=True
    )
    category_name = serializers.CharField(source='category.name', read_only=True)
    tags = ServiceTagSerializer(many=True, read_only=True)

    class Meta:
        model = Service
        fields = [
            'id', 'uuid', 'name', 'slug', 'short_description',
            'thumbnail', 'service_type', 'price', 'price_min', 'price_max',
            'currency', 'delivery_type', 'duration_days',
            'provider', 'provider_name', 'provider_rating',
            'category', 'category_name', 'tags',
            'is_active', 'is_featured', 'view_count', 'order_count'
        ]


class ServiceDetailSerializer(TenantAwareSerializer):
    """Full service serializer with all details."""
    provider = ServiceProviderListSerializer(read_only=True)
    category = ServiceCategorySerializer(read_only=True)
    tags = ServiceTagSerializer(many=True, read_only=True)
    images = ServiceImageSerializer(many=True, read_only=True)
    tenant_type = serializers.CharField(source='tenant.tenant_type', read_only=True)
    provider_tenant_type = serializers.CharField(source='provider.tenant.tenant_type', read_only=True)

    class Meta:
        model = Service
        fields = [
            'id', 'uuid', 'provider', 'category',
            'name', 'slug', 'description', 'short_description',
            'service_type', 'price', 'price_min', 'price_max', 'currency',
            'delivery_type', 'duration_days', 'revisions_included',
            'thumbnail', 'images', 'video_url', 'tags',
            'is_active', 'is_featured', 'view_count', 'order_count',
            'created_at', 'updated_at', 'tenant_type', 'provider_tenant_type'
        ]
        read_only_fields = [
            'uuid', 'slug', 'view_count', 'order_count',
            'created_at', 'updated_at'
        ]


class ServiceCreateSerializer(TenantAwareSerializer):
    """Serializer for creating services."""
    tags = serializers.PrimaryKeyRelatedField(
        queryset=ServiceTag.objects.all(), many=True, required=False
    )

    class Meta:
        model = Service
        fields = [
            'category', 'name', 'description', 'short_description',
            'service_type', 'price', 'price_min', 'price_max', 'currency',
            'delivery_type', 'duration_days', 'revisions_included',
            'thumbnail', 'video_url', 'tags', 'is_active'
        ]

    def validate_description(self, value):
        return sanitize_html(value) if value else value

    def create(self, validated_data):
        tags = validated_data.pop('tags', [])
        provider = ServiceProvider.objects.get(user=self.context['request'].user)
        validated_data['provider'] = provider
        service = super().create(validated_data)
        service.tags.set(tags)
        return service


class ServiceLikeSerializer(TenantAwareSerializer):
    """Serializer for service likes."""
    class Meta:
        model = ServiceLike
        fields = ['id', 'user', 'service', 'created_at']
        read_only_fields = ['user', 'created_at']


# =============================================================================
# CLIENT REQUEST SERIALIZERS
# =============================================================================

class ClientRequestListSerializer(TenantAwareSerializer):
    """Lightweight client request serializer for lists."""
    client_email = serializers.CharField(source='client.email', read_only=True)
    category_name = serializers.CharField(source='category.name', read_only=True)
    proposals_count = serializers.SerializerMethodField()

    class Meta:
        model = ClientRequest
        fields = [
            'id', 'uuid', 'title', 'category', 'category_name',
            'budget_min', 'budget_max', 'currency',
            'deadline', 'status', 'remote_allowed',
            'client', 'client_email', 'proposals_count', 'created_at'
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_proposals_count(self, obj):
        return obj.proposals.count()


class ClientRequestDetailSerializer(TenantAwareSerializer):
    """Full client request serializer."""
    client = UserMinimalSerializer(read_only=True)
    category = ServiceCategoryListSerializer(read_only=True)
    required_skills = serializers.SerializerMethodField()
    proposals_count = serializers.SerializerMethodField()
    matches_count = serializers.SerializerMethodField()

    class Meta:
        model = ClientRequest
        fields = [
            'id', 'uuid', 'client', 'title', 'description',
            'category', 'required_skills',
            'budget_min', 'budget_max', 'currency',
            'location_lat', 'location_lng', 'location_radius_km',
            'remote_allowed', 'deadline', 'status',
            'proposals_count', 'matches_count',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['uuid', 'created_at', 'updated_at']

    @extend_schema_field(OpenApiTypes.STR)
    def get_required_skills(self, obj):
        return list(obj.required_skills.values_list('name', flat=True))

    @extend_schema_field(OpenApiTypes.STR)
    def get_proposals_count(self, obj):
        return obj.proposals.count()

    @extend_schema_field(OpenApiTypes.STR)
    def get_matches_count(self, obj):
        return obj.matches.count()


class ClientRequestCreateSerializer(TenantAwareSerializer):
    """Serializer for creating client requests."""
    required_skills_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False,
        default=list
    )

    class Meta:
        model = ClientRequest
        fields = [
            'title', 'description', 'category', 'required_skills_ids',
            'budget_min', 'budget_max', 'currency',
            'location_lat', 'location_lng', 'location_radius_km',
            'remote_allowed', 'deadline'
        ]

    def validate_description(self, value):
        return sanitize_html(value) if value else value

    def create(self, validated_data):
        skill_ids = validated_data.pop('required_skills_ids', [])
        validated_data['client'] = self.context['request'].user
        request = super().create(validated_data)
        if skill_ids:
            from configurations.models import Skill
            skills = Skill.objects.filter(id__in=skill_ids)
            request.required_skills.set(skills)
        return request


# =============================================================================
# PROVIDER MATCH SERIALIZERS
# =============================================================================

class ProviderMatchSerializer(TenantAwareSerializer):
    """Serializer for provider matches."""
    provider = ServiceProviderListSerializer(read_only=True)

    class Meta:
        model = ProviderMatch
        fields = [
            'id', 'client_request', 'provider', 'score', 'score_breakdown',
            'viewed_by_client', 'accepted_by_client', 'rejected_by_client',
            'created_at'
        ]
        read_only_fields = ['score', 'score_breakdown', 'created_at']


# =============================================================================
# PROPOSAL SERIALIZERS
# =============================================================================

class ServiceProposalListSerializer(TenantAwareSerializer):
    """Lightweight proposal serializer for lists."""
    provider_name = serializers.CharField(source='provider.display_name', read_only=True)
    provider_rating = serializers.DecimalField(
        source='provider.rating_avg', max_digits=3, decimal_places=2, read_only=True
    )

    class Meta:
        model = ServiceProposal
        fields = [
            'id', 'uuid', 'client_request', 'provider',
            'provider_name', 'provider_rating',
            'proposed_rate', 'rate_type', 'estimated_hours',
            'proposed_timeline_days', 'status', 'created_at'
        ]


class ServiceProposalDetailSerializer(TenantAwareSerializer):
    """Full proposal serializer."""
    provider = ServiceProviderListSerializer(read_only=True)
    client_request = ClientRequestListSerializer(read_only=True)
    tenant_type = serializers.CharField(source='provider.tenant.tenant_type', read_only=True)

    class Meta:
        model = ServiceProposal
        fields = [
            'id', 'uuid', 'client_request', 'provider',
            'proposed_rate', 'rate_type', 'estimated_hours',
            'cover_letter', 'proposed_timeline_days', 'attachments',
            'status', 'created_at', 'updated_at', 'tenant_type'
        ]
        read_only_fields = ['uuid', 'created_at', 'updated_at']


class ServiceProposalCreateSerializer(TenantAwareSerializer):
    """Serializer for creating proposals."""
    class Meta:
        model = ServiceProposal
        fields = [
            'client_request', 'proposed_rate', 'rate_type',
            'estimated_hours', 'cover_letter', 'proposed_timeline_days'
        ]

    def validate_cover_letter(self, value):
        return sanitize_html(value) if value else value

    def create(self, validated_data):
        provider = ServiceProvider.objects.get(user=self.context['request'].user)
        validated_data['provider'] = provider
        return super().create(validated_data)


# =============================================================================
# CONTRACT SERIALIZERS
# =============================================================================

class ServiceContractListSerializer(TenantAwareSerializer):
    """Lightweight contract serializer for lists."""
    client_email = serializers.CharField(source='client.email', read_only=True)
    provider_name = serializers.CharField(source='provider.display_name', read_only=True)

    class Meta:
        model = ServiceContract
        fields = [
            'id', 'uuid', 'title', 'client', 'client_email',
            'provider', 'provider_name',
            'agreed_rate', 'rate_type', 'currency',
            'agreed_deadline', 'status',
            'started_at', 'completed_at', 'created_at'
        ]


class ServiceContractDetailSerializer(TenantAwareSerializer):
    """Full contract serializer with all details."""
    client = UserMinimalSerializer(read_only=True)
    provider = ServiceProviderListSerializer(read_only=True)
    service = ServiceListSerializer(read_only=True)
    provider_payout_amount = serializers.DecimalField(
        max_digits=10, decimal_places=2, read_only=True
    )
    client_tenant_type = serializers.CharField(source='tenant.tenant_type', read_only=True)
    provider_tenant_type = serializers.CharField(source='provider.tenant.tenant_type', read_only=True)

    class Meta:
        model = ServiceContract
        fields = [
            'id', 'uuid', 'client', 'provider',
            'proposal', 'service', 'client_request',
            'title', 'description',
            'agreed_rate', 'rate_type', 'currency',
            'agreed_deadline', 'revisions_allowed', 'revisions_used',
            'escrow_transaction', 'platform_fee_percent', 'provider_payout_amount',
            'status', 'started_at', 'delivered_at', 'completed_at',
            'cancelled_at', 'cancellation_reason',
            'created_at', 'updated_at', 'client_tenant_type', 'provider_tenant_type'
        ]
        read_only_fields = [
            'uuid', 'escrow_transaction', 'revisions_used',
            'started_at', 'delivered_at', 'completed_at',
            'cancelled_at', 'created_at', 'updated_at'
        ]


class ServiceContractCreateSerializer(TenantAwareSerializer):
    """Serializer for creating contracts."""
    class Meta:
        model = ServiceContract
        fields = [
            'provider', 'proposal', 'service', 'client_request',
            'title', 'description', 'agreed_rate', 'rate_type',
            'currency', 'agreed_deadline', 'revisions_allowed'
        ]

    def validate_description(self, value):
        return sanitize_html(value) if value else value

    def create(self, validated_data):
        validated_data['client'] = self.context['request'].user
        return super().create(validated_data)


class ContractActionSerializer(serializers.Serializer):
    """Serializer for contract actions (start, deliver, complete, cancel)."""
    action = serializers.ChoiceField(
        choices=['start', 'deliver', 'complete', 'cancel', 'request_revision']
    )
    reason = serializers.CharField(required=False, allow_blank=True)


# =============================================================================
# REVIEW SERIALIZERS
# =============================================================================

class ServiceReviewListSerializer(TenantAwareSerializer):
    """Lightweight review serializer for lists."""
    reviewer_name = serializers.SerializerMethodField()
    provider_name = serializers.CharField(source='provider.display_name', read_only=True)

    class Meta:
        model = ServiceReview
        fields = [
            'id', 'contract', 'reviewer', 'reviewer_name',
            'provider', 'provider_name',
            'rating', 'title', 'created_at'
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_reviewer_name(self, obj):
        return obj.reviewer.get_full_name() or obj.reviewer.email.split('@')[0]


class ServiceReviewDetailSerializer(TenantAwareSerializer):
    """Full review serializer."""
    reviewer = UserMinimalSerializer(read_only=True)
    provider = ServiceProviderListSerializer(read_only=True)

    class Meta:
        model = ServiceReview
        fields = [
            'id', 'contract', 'reviewer', 'provider',
            'rating', 'rating_communication', 'rating_quality', 'rating_timeliness',
            'title', 'content',
            'provider_response', 'provider_responded_at',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'provider_response', 'provider_responded_at',
            'created_at', 'updated_at'
        ]


class ServiceReviewCreateSerializer(TenantAwareSerializer):
    """Serializer for creating reviews."""
    class Meta:
        model = ServiceReview
        fields = [
            'contract', 'rating', 'rating_communication',
            'rating_quality', 'rating_timeliness',
            'title', 'content'
        ]

    def validate_content(self, value):
        return sanitize_html(value) if value else value

    def validate_contract(self, value):
        if value.status != 'completed':
            raise serializers.ValidationError(
                "Reviews can only be submitted for completed contracts."
            )
        if hasattr(value, 'review'):
            raise serializers.ValidationError(
                "A review already exists for this contract."
            )
        return value

    def create(self, validated_data):
        validated_data['reviewer'] = self.context['request'].user
        validated_data['provider'] = validated_data['contract'].provider
        return super().create(validated_data)


class ReviewResponseSerializer(serializers.Serializer):
    """Serializer for provider response to reviews."""
    response = serializers.CharField(max_length=5000)


# =============================================================================
# CONTRACT MESSAGE SERIALIZERS
# =============================================================================

class ContractMessageSerializer(TenantAwareSerializer):
    """Serializer for contract messages."""
    sender = UserMinimalSerializer(read_only=True)

    class Meta:
        model = ContractMessage
        fields = [
            'id', 'contract', 'sender', 'content',
            'attachments', 'is_system_message', 'read_at', 'created_at'
        ]
        read_only_fields = ['sender', 'is_system_message', 'read_at', 'created_at']


class ContractMessageCreateSerializer(TenantAwareSerializer):
    """Serializer for creating contract messages."""
    class Meta:
        model = ContractMessage
        fields = ['contract', 'content', 'attachments']

    def validate_content(self, value):
        return sanitize_html(value) if value else value

    def create(self, validated_data):
        validated_data['sender'] = self.context['request'].user
        return super().create(validated_data)


# =============================================================================
# STATISTICS & ANALYTICS SERIALIZERS
# =============================================================================

class ProviderStatsSerializer(serializers.Serializer):
    """Provider statistics serializer."""
    total_services = serializers.IntegerField()
    active_services = serializers.IntegerField()
    total_contracts = serializers.IntegerField()
    completed_contracts = serializers.IntegerField()
    total_earnings = serializers.DecimalField(max_digits=12, decimal_places=2)
    average_rating = serializers.DecimalField(max_digits=3, decimal_places=2)
    total_reviews = serializers.IntegerField()
    response_rate = serializers.IntegerField()


class MarketplaceStatsSerializer(serializers.Serializer):
    """Marketplace overview statistics serializer."""
    total_providers = serializers.IntegerField()
    verified_providers = serializers.IntegerField()
    total_services = serializers.IntegerField()
    active_requests = serializers.IntegerField()
    completed_contracts = serializers.IntegerField()
    total_gmv = serializers.DecimalField(max_digits=14, decimal_places=2)


# =============================================================================
# SEARCH & FILTER SERIALIZERS
# =============================================================================

class ServiceSearchSerializer(serializers.Serializer):
    """Serializer for service search parameters."""
    q = serializers.CharField(required=False, allow_blank=True)
    category = serializers.IntegerField(required=False)
    min_price = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False
    )
    max_price = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False
    )
    delivery_type = serializers.ChoiceField(
        choices=['remote', 'onsite', 'hybrid'], required=False
    )
    rating_min = serializers.DecimalField(
        max_digits=3, decimal_places=2, required=False
    )
    tags = serializers.ListField(
        child=serializers.IntegerField(), required=False
    )
    sort_by = serializers.ChoiceField(
        choices=['price_low', 'price_high', 'rating', 'newest', 'popular'],
        required=False, default='rating'
    )


class ProviderSearchSerializer(serializers.Serializer):
    """Serializer for provider search parameters."""
    q = serializers.CharField(required=False, allow_blank=True)
    category = serializers.IntegerField(required=False)
    skill = serializers.IntegerField(required=False)
    min_rate = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False
    )
    max_rate = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False
    )
    availability = serializers.ChoiceField(
        choices=['available', 'busy', 'unavailable', 'on_vacation'],
        required=False
    )
    city = serializers.CharField(required=False)
    country = serializers.CharField(required=False)
    rating_min = serializers.DecimalField(
        max_digits=3, decimal_places=2, required=False
    )
    verified_only = serializers.BooleanField(required=False, default=False)
    remote_ok = serializers.BooleanField(required=False)
    sort_by = serializers.ChoiceField(
        choices=['rating', 'reviews', 'price_low', 'price_high', 'newest'],
        required=False, default='rating'
    )
