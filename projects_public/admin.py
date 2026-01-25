"""
Projects Public Admin - Admin for public catalog.

Provides read-only admin interface for public project catalog.
Data is synced from tenant projects via Celery tasks.
"""

from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html

from .models import PublicProjectCatalog, PublicProjectStats


# ============================================================================
# PUBLIC PROJECT CATALOG
# ============================================================================

@admin.register(PublicProjectCatalog)
class PublicProjectCatalogAdmin(admin.ModelAdmin):
    """Admin for public project catalog (read-only)."""

    list_display = [
        'title',
        'company_name',
        'category_name',
        'budget_range_display',
        'location_display',
        'is_open',
        'proposal_status',
        'published_at'
    ]
    list_filter = [
        'is_open',
        'is_featured',
        'category_name',
        'experience_level',
        'budget_type',
        'location_type',
        'location_country',
        'published_at'
    ]
    search_fields = [
        'title',
        'description',
        'company_name',
        'required_skills'
    ]
    readonly_fields = [
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
        'deadline',
        'budget_type',
        'budget_min',
        'budget_max',
        'budget_currency',
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
        'published_at',
        'synced_at',
        'meta_title',
        'meta_description',
        'project_url',
        'application_url'
    ]
    date_hierarchy = 'published_at'

    # Make admin read-only (data synced from tenant schemas)
    def has_add_permission(self, request):
        """Prevent manual creation."""
        return False

    def has_delete_permission(self, request, obj=None):
        """Allow deletion of orphaned entries."""
        return request.user.is_superuser

    def has_change_permission(self, request, obj=None):
        """Only allow featured status change."""
        if obj and request.user.is_staff:
            return True
        return False

    # Custom fields
    fields = [
        'uuid',
        # Source
        ('tenant_id', 'tenant_project_id', 'tenant_schema'),
        # Project info
        'title',
        'description',
        'short_description',
        ('category_name', 'category_slug'),
        'required_skills',
        'experience_level',
        # Timeline
        ('start_date', 'end_date'),
        'estimated_duration_weeks',
        'deadline',
        # Budget
        ('budget_type', 'budget_min', 'budget_max', 'budget_currency'),
        # Location
        ('location_type', 'location_city', 'location_country'),
        'location_coordinates',
        # Company
        'company_name',
        'company_logo_url',
        'company_domain',
        # Application
        ('max_proposals', 'proposal_count'),
        'proposal_deadline',
        # Status
        ('is_open', 'is_featured'),
        # Publication
        ('published_at', 'synced_at'),
        # SEO
        ('meta_title', 'meta_description'),
        # Links
        ('project_url', 'application_url'),
    ]

    def location_display(self, obj):
        """Display location info."""
        if obj.location_type == 'REMOTE':
            return format_html('<span style="color: #10B981;">🌐 Remote</span>')
        if obj.location_city and obj.location_country:
            return f"{obj.location_city}, {obj.location_country}"
        elif obj.location_country:
            return obj.location_country
        return _('Not specified')
    location_display.short_description = _('Location')

    def proposal_status(self, obj):
        """Display proposal status."""
        if not obj.is_open:
            return format_html('<span style="color: gray;">Closed</span>')
        if obj.proposal_count >= obj.max_proposals:
            return format_html('<span style="color: orange;">Full ({}/{})</span>', obj.proposal_count, obj.max_proposals)
        return format_html(
            '<span style="color: green;">{}/{} proposals</span>',
            obj.proposal_count,
            obj.max_proposals
        )
    proposal_status.short_description = _('Proposals')


# ============================================================================
# PUBLIC PROJECT STATS
# ============================================================================

@admin.register(PublicProjectStats)
class PublicProjectStatsAdmin(admin.ModelAdmin):
    """Admin for public project statistics."""

    list_display = [
        'snapshot_date',
        'total_projects',
        'open_projects',
        'total_companies',
        'avg_budget',
        'updated_at'
    ]
    list_filter = ['snapshot_date']
    readonly_fields = [
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
        'updated_at'
    ]
    date_hierarchy = 'snapshot_date'

    # Make admin read-only (stats generated by Celery task)
    def has_add_permission(self, request):
        """Prevent manual creation."""
        return False

    def has_change_permission(self, request, obj=None):
        """Prevent manual modification."""
        return False

    def has_delete_permission(self, request, obj=None):
        """Allow cleanup of old stats."""
        return request.user.is_superuser

    fieldsets = (
        (_('Snapshot Info'), {
            'fields': ('snapshot_date',)
        }),
        (_('Overall Stats'), {
            'fields': (
                'total_projects',
                'open_projects',
                'total_companies'
            )
        }),
        (_('By Category'), {
            'fields': ('by_category',)
        }),
        (_('By Location'), {
            'fields': ('by_country',)
        }),
        (_('By Budget'), {
            'fields': ('by_budget_range',)
        }),
        (_('Averages'), {
            'fields': (
                'avg_budget',
                'avg_duration_weeks',
                'avg_proposals_per_project'
            )
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
