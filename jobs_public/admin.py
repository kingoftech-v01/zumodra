"""Admin configuration for ATS Public Catalog."""

from django.contrib import admin
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import PublicJobCatalog


@admin.register(PublicJobCatalog)
class PublicJobCatalogAdmin(admin.ModelAdmin):
    """Admin interface for public job catalog."""

    list_display = [
        'title',
        'company_name',
        'location_display_admin',
        'employment_type',
        'published_at',
        'tenant_link',
    ]
    list_filter = [
        'employment_type',
        'is_remote',
        'location_country',
        'published_at',
    ]
    search_fields = [
        'title',
        'company_name',
        'description_html',
        'location_city',
        'location_country',
        'tenant_schema_name',
    ]
    readonly_fields = [
        'id',
        'jobposting_uuid',
        'tenant_id',
        'tenant_schema_name',
        'synced_at',
        'application_url',
    ]
    fieldsets = (
        (_('Source Information'), {
            'fields': (
                'id',
                'jobposting_uuid',
                'tenant_id',
                'tenant_schema_name',
                'company_name',
                'company_logo_url',
            )
        }),
        (_('Job Details'), {
            'fields': (
                'title',
                'description_html',
                'employment_type',
            )
        }),
        (_('Location'), {
            'fields': (
                'location_city',
                'location_state',
                'location_country',
                'is_remote',
            )
        }),
        (_('Compensation'), {
            'fields': (
                'salary_min',
                'salary_max',
                'salary_currency',
            )
        }),
        (_('Categories & Skills'), {
            'fields': (
                'category_names',
                'category_slugs',
                'required_skills',
            )
        }),
        (_('Application'), {
            'fields': (
                'application_url',
            )
        }),
        (_('Metadata'), {
            'fields': (
                'published_at',
                'synced_at',
            ),
            'classes': ('collapse',)
        }),
    )
    date_hierarchy = 'published_at'
    ordering = ['-published_at']
    actions = []

    def location_display_admin(self, obj):
        """Display location in admin list."""
        if obj.is_remote:
            return _('Remote')
        parts = [obj.location_city, obj.location_state, obj.location_country]
        return ", ".join(filter(None, parts)) or _('Location not specified')
    location_display_admin.short_description = _('Location')

    def tenant_link(self, obj):
        """Display link to tenant schema."""
        return format_html(
            '<code>{}</code>',
            obj.tenant_schema_name
        )
    tenant_link.short_description = _('Tenant')
