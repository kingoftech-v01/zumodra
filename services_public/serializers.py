"""
Services Public API Serializers

Django REST Framework serializers for the public service catalog API.
All serializers are read-only since the public catalog is not directly editable.
"""

from rest_framework import serializers
from .models import (
    PublicService,
    PublicServiceImage,
    PublicServicePricingTier,
    PublicServicePortfolio,
    PublicServiceReview
)


# ==================== RELATED MODEL SERIALIZERS ====================


class PublicServiceImageSerializer(serializers.ModelSerializer):
    """Serializer for service gallery images."""

    class Meta:
        model = PublicServiceImage
        fields = [
            'id',
            'image_url',
            'alt_text',
            'description',
            'sort_order',
        ]
        read_only_fields = fields


class PublicServicePricingTierSerializer(serializers.ModelSerializer):
    """Serializer for service pricing tiers/packages."""

    features_list = serializers.SerializerMethodField()

    class Meta:
        model = PublicServicePricingTier
        fields = [
            'id',
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
        read_only_fields = fields

    def get_features_list(self, obj):
        """Convert features dict to list format for easier frontend consumption."""
        if not obj.features:
            return []
        return [
            {'name': key, 'value': value, 'included': value}
            for key, value in obj.features.items()
        ]


class PublicServicePortfolioSerializer(serializers.ModelSerializer):
    """Serializer for provider portfolio items."""

    class Meta:
        model = PublicServicePortfolio
        fields = [
            'id',
            'image_url',
            'title',
            'description',
            'sort_order',
            'grid_col_span',
            'grid_row_span',
        ]
        read_only_fields = fields


class PublicServiceReviewSerializer(serializers.ModelSerializer):
    """Serializer for service reviews."""

    class Meta:
        model = PublicServiceReview
        fields = [
            'id',
            'review_uuid',
            'reviewer_name',
            'reviewer_avatar_url',
            'reviewer_is_verified',
            'rating',
            'rating_communication',
            'rating_quality',
            'rating_timeliness',
            'title',
            'content',
            'provider_response',
            'provider_responded_at',
            'created_at',
            'helpful_count',
        ]
        read_only_fields = fields


# ==================== MAIN SERVICE SERIALIZERS ====================


class PublicServiceListSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for service list views.

    Returns minimal fields for performance in list endpoints.
    """

    class Meta:
        model = PublicService
        fields = [
            'service_uuid',
            'name',
            'slug',
            'short_description',
            'provider_name',
            'provider_avatar_url',
            'provider_is_verified',
            'category_name',
            'category_slug',
            'thumbnail_url',
            'price',
            'currency',
            'service_type',
            'rating_avg',
            'total_reviews',
            'is_featured',
            'is_accepting_work',
            'location_city',
            'location_state',
            'location_country',
            'detail_url',
        ]
        read_only_fields = fields


class PublicServiceDetailSerializer(serializers.ModelSerializer):
    """
    Complete serializer for service detail views.

    Includes all service data plus related models (images, pricing, portfolio, reviews).
    """

    images = PublicServiceImageSerializer(many=True, read_only=True)
    pricing_tiers = PublicServicePricingTierSerializer(many=True, read_only=True)
    portfolio_images = PublicServicePortfolioSerializer(many=True, read_only=True)
    reviews = PublicServiceReviewSerializer(many=True, read_only=True)

    class Meta:
        model = PublicService
        fields = '__all__'
        read_only_fields = '__all__'


class PublicServiceGeoSerializer(serializers.ModelSerializer):
    """
    GeoJSON serializer for map views.

    Returns services in GeoJSON FeatureCollection format for map rendering.
    Compatible with Leaflet.js and other mapping libraries.
    """

    class Meta:
        model = PublicService
        fields = [
            'service_uuid',
            'name',
            'provider_name',
            'category_name',
            'price',
            'currency',
            'rating_avg',
            'total_reviews',
            'thumbnail_url',
            'detail_url',
            'location_city',
            'location_state',
            'location_country',
            'location',
        ]
        read_only_fields = fields

    def to_representation(self, instance):
        """
        Convert service to GeoJSON Feature format.

        Returns:
            dict: GeoJSON Feature with Point geometry and service properties
        """
        # Get standard serialized data (excluding location for now)
        data = super().to_representation(instance)

        # Remove location from properties (we'll use it as geometry)
        data.pop('location', None)

        # Extract coordinates from PostGIS Point
        coordinates = None
        if instance.location:
            # PostGIS Point has x (longitude) and y (latitude)
            coordinates = [instance.location.x, instance.location.y]

        # Build GeoJSON Feature
        feature = {
            'type': 'Feature',
            'geometry': {
                'type': 'Point',
                'coordinates': coordinates
            } if coordinates else None,
            'properties': data
        }

        return feature


class PublicServiceSearchSerializer(serializers.ModelSerializer):
    """
    Search-optimized serializer with highlighted fields.

    Used for search endpoints with keyword matching.
    """

    match_score = serializers.FloatField(read_only=True, required=False)
    highlighted_name = serializers.CharField(read_only=True, required=False)

    class Meta:
        model = PublicService
        fields = [
            'service_uuid',
            'name',
            'highlighted_name',
            'short_description',
            'provider_name',
            'provider_avatar_url',
            'category_name',
            'thumbnail_url',
            'price',
            'rating_avg',
            'total_reviews',
            'match_score',
            'detail_url',
        ]
        read_only_fields = fields
