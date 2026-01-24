"""
Serializers for Public Job Catalog API.

Provides read-only serializers for browsing public job listings.
"""

from rest_framework import serializers
from jobs_public.models import PublicJobCatalog


class PublicJobCatalogSerializer(serializers.ModelSerializer):
    """
    Serializer for public job catalog entries.

    Read-only serializer for browsing jobs without authentication.
    """

    location_display = serializers.CharField(read_only=True)
    salary_display = serializers.SerializerMethodField()
    is_expired = serializers.BooleanField(read_only=True)

    class Meta:
        model = PublicJobCatalog
        fields = [
            'id',
            'jobposting_uuid',
            'tenant_schema_name',
            'company_name',
            'company_logo_url',
            'title',
            'description_html',
            'employment_type',
            'location_city',
            'location_state',
            'location_country',
            'location_display',
            'is_remote',
            'salary_min',
            'salary_max',
            'salary_currency',
            'salary_display',
            'show_salary',
            'category_names',
            'category_slugs',
            'required_skills',
            'posted_at',
            'is_active',
            'is_featured',
            'is_expired',
            'view_count',
            'application_count',
            'application_url',
        ]
        read_only_fields = fields

    def get_salary_display(self, obj):
        """Format salary range for display."""
        if not obj.show_salary or not obj.salary_min:
            return None

        currency_symbols = {
            'USD': '$',
            'EUR': '€',
            'GBP': '£',
            'CAD': 'C$',
        }
        symbol = currency_symbols.get(obj.salary_currency, obj.salary_currency)

        if obj.salary_max and obj.salary_max != obj.salary_min:
            return f"{symbol}{obj.salary_min:,.0f} - {symbol}{obj.salary_max:,.0f}"
        return f"{symbol}{obj.salary_min:,.0f}"


class PublicJobCatalogListSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for job listing pages.

    Excludes heavy fields like full description for better performance.
    """

    location_display = serializers.CharField(read_only=True)

    class Meta:
        model = PublicJobCatalog
        fields = [
            'id',
            'jobposting_uuid',
            'company_name',
            'company_logo_url',
            'title',
            'employment_type',
            'location_city',
            'location_country',
            'location_display',
            'is_remote',
            'salary_min',
            'salary_max',
            'salary_currency',
            'show_salary',
            'category_names',
            'posted_at',
            'is_featured',
            'view_count',
        ]
        read_only_fields = fields
