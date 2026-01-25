"""
Projects Public Serializers - DRF serializers for public catalog API.

This module provides read-only serializers for public project browsing.
"""

from rest_framework import serializers
from .models import PublicProjectCatalog, PublicProjectStats


# ============================================================================
# PUBLIC PROJECT CATALOG SERIALIZERS
# ============================================================================

class PublicProjectCatalogListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for project listings."""

    is_accepting_proposals = serializers.BooleanField(read_only=True)
    budget_range_display = serializers.CharField(read_only=True)
    duration_display = serializers.CharField(read_only=True)

    class Meta:
        model = PublicProjectCatalog
        fields = [
            'uuid',
            'title',
            'short_description',
            'category_name',
            'category_slug',
            'required_skills',
            'experience_level',
            'budget_type',
            'budget_min',
            'budget_max',
            'budget_currency',
            'budget_range_display',
            'location_type',
            'location_city',
            'location_country',
            'company_name',
            'company_logo_url',
            'estimated_duration_weeks',
            'duration_display',
            'deadline',
            'proposal_count',
            'max_proposals',
            'is_accepting_proposals',
            'is_featured',
            'published_at',
            'project_url',
            'application_url',
        ]


class PublicProjectCatalogSerializer(serializers.ModelSerializer):
    """Full serializer for project detail."""

    is_accepting_proposals = serializers.BooleanField(read_only=True)
    budget_range_display = serializers.CharField(read_only=True)
    duration_display = serializers.CharField(read_only=True)

    class Meta:
        model = PublicProjectCatalog
        fields = [
            'uuid',
            'tenant_project_id',
            'tenant_id',
            'tenant_schema',
            'title',
            'description',
            'short_description',
            'category_name',
            'category_slug',
            'required_skills',
            'experience_level',
            'start_date',
            'end_date',
            'estimated_duration_weeks',
            'duration_display',
            'deadline',
            'budget_type',
            'budget_min',
            'budget_max',
            'budget_currency',
            'budget_range_display',
            'location_type',
            'location_city',
            'location_country',
            'location_coordinates',
            'company_name',
            'company_logo_url',
            'company_domain',
            'max_proposals',
            'proposal_count',
            'proposal_deadline',
            'is_open',
            'is_featured',
            'is_accepting_proposals',
            'published_at',
            'synced_at',
            'meta_title',
            'meta_description',
            'project_url',
            'application_url',
        ]


# ============================================================================
# PUBLIC PROJECT STATS SERIALIZERS
# ============================================================================

class PublicProjectStatsSerializer(serializers.ModelSerializer):
    """Serializer for project statistics."""

    class Meta:
        model = PublicProjectStats
        fields = [
            'snapshot_date',
            'total_projects',
            'open_projects',
            'total_companies',
            'by_category',
            'by_country',
            'by_budget_range',
            'avg_budget',
            'avg_duration_weeks',
            'avg_proposals_per_project',
            'created_at',
            'updated_at',
        ]
