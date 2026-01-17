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
        'posted_at',
        'is_active',
        'is_featured',
        'view_count',
        'tenant_link',
    ]
    list_filter = [
        'is_active',
        'is_featured',
        'employment_type',
        'is_remote',
        'location_country',
        'posted_at',
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
        'view_count',
        'application_count',
        'created_at',
        'updated_at',
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
                'show_salary',
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
                'application_count',
            )
        }),
        (_('Status & Visibility'), {
            'fields': (
                'is_active',
                'is_featured',
                'posted_at',
            )
        }),
        (_('Metadata'), {
            'fields': (
                'view_count',
                'created_at',
                'updated_at',
            ),
            'classes': ('collapse',)
        }),
    )
    date_hierarchy = 'posted_at'
    ordering = ['-posted_at']
    actions = ['mark_as_featured', 'mark_as_not_featured', 'mark_as_inactive']

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

    @admin.action(description=_('Mark selected jobs as featured'))
    def mark_as_featured(self, request, queryset):
        """Mark jobs as featured."""
        count = queryset.update(is_featured=True)
        self.message_user(request, _(f'{count} jobs marked as featured.'))

    @admin.action(description=_('Mark selected jobs as not featured'))
    def mark_as_not_featured(self, request, queryset):
        """Remove featured status from jobs."""
        count = queryset.update(is_featured=False)
        self.message_user(request, _(f'{count} jobs unmarked as featured.'))

    @admin.action(description=_('Mark selected jobs as inactive'))
    def mark_as_inactive(self, request, queryset):
        """Mark jobs as inactive."""
        count = queryset.update(is_active=False)
        self.message_user(request, _(f'{count} jobs marked as inactive.'))
