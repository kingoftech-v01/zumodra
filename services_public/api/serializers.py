"""
Serializers for Public Service Catalog API.

Provides read-only serializers for browsing public service provider listings.
"""

from rest_framework import serializers
from services_public.models import PublicServiceCatalog


class PublicServiceCatalogSerializer(serializers.ModelSerializer):
    """
    Serializer for public service catalog entries.

    Read-only serializer for browsing service providers without authentication.
    """

    location_display = serializers.SerializerMethodField()
    hourly_rate_display = serializers.SerializerMethodField()
    rating_display = serializers.SerializerMethodField()
    service_radius_display = serializers.SerializerMethodField()

    class Meta:
        model = PublicServiceCatalog
        fields = [
            'id',
            'provider_uuid',
            'tenant_schema_name',
            'business_name',
            'avatar_url',
            'description_html',
            'service_category_names',
            'service_category_slugs',
            'skills',
            'location_city',
            'location_state',
            'location_country',
            'location_display',
            'is_mobile',
            'service_radius_km',
            'service_radius_display',
            'hourly_rate',
            'currency',
            'hourly_rate_display',
            'accepts_online_payment',
            'rating',
            'rating_count',
            'rating_display',
            'completed_jobs',
            'is_active',
            'is_verified',
            'view_count',
            'published_at',
            'booking_url',
        ]
        read_only_fields = fields

    def get_location_display(self, obj):
        """Format location for display."""
        parts = [obj.location_city, obj.location_state, obj.location_country]
        location = ", ".join(filter(None, parts)) or "Location not specified"

        if obj.is_mobile and obj.service_radius_km:
            location += f" (+{obj.service_radius_km}km radius)"

        return location

    def get_hourly_rate_display(self, obj):
        """Format hourly rate for display."""
        if not obj.hourly_rate:
            return "Contact for pricing"

        currency_symbols = {
            'USD': '$',
            'EUR': '€',
            'GBP': '£',
            'CAD': 'C$',
        }
        symbol = currency_symbols.get(obj.currency, obj.currency)

        return f"{symbol}{obj.hourly_rate:.2f}/hour"

    def get_rating_display(self, obj):
        """Format rating with star representation."""
        if obj.rating_count == 0:
            return {
                'average': 0,
                'count': 0,
                'stars': '☆☆☆☆☆',
                'display': 'No ratings yet'
            }

        stars = '★' * int(obj.rating) + '☆' * (5 - int(obj.rating))

        return {
            'average': float(obj.rating),
            'count': obj.rating_count,
            'stars': stars,
            'display': f"{obj.rating:.1f} ({obj.rating_count} reviews)"
        }

    def get_service_radius_display(self, obj):
        """Format service radius for display."""
        if not obj.is_mobile or not obj.service_radius_km:
            return None
        return f"{obj.service_radius_km}km"


class PublicServiceCatalogListSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for service provider listing pages.

    Excludes heavy fields like full description for better performance.
    """

    location_display = serializers.SerializerMethodField()
    rating_summary = serializers.SerializerMethodField()

    class Meta:
        model = PublicServiceCatalog
        fields = [
            'id',
            'provider_uuid',
            'business_name',
            'avatar_url',
            'service_category_names',
            'location_city',
            'location_country',
            'location_display',
            'is_mobile',
            'hourly_rate',
            'currency',
            'rating',
            'rating_count',
            'rating_summary',
            'completed_jobs',
            'is_verified',
            'view_count',
        ]
        read_only_fields = fields

    def get_location_display(self, obj):
        """Format location for display."""
        parts = [obj.location_city, obj.location_country]
        return ", ".join(filter(None, parts)) or "Remote"

    def get_rating_summary(self, obj):
        """Get compact rating summary."""
        if obj.rating_count == 0:
            return None
        return {
            'average': float(obj.rating),
            'count': obj.rating_count,
        }
