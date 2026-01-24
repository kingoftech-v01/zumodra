"""Admin configuration for Services Public Catalog."""

from django.contrib import admin
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import PublicServiceCatalog


@admin.register(PublicServiceCatalog)
class PublicServiceCatalogAdmin(admin.ModelAdmin):
    """Admin interface for public service catalog."""

    list_display = [
        'provider_name',
        'service_category_display',
        'location_display_admin',
        'rating_display',
        'is_verified',
        'completed_jobs_count',
        'tenant_link',
    ]
    list_filter = [
        'is_verified',
        'can_work_remotely',
        'can_work_onsite',
        'provider_type',
        'location_country',
        'published_at',
    ]
    search_fields = [
        'provider_name',
        'bio',
        'category_names',
        'location_city',
        'location_country',
        'tenant_schema_name',
    ]
    readonly_fields = [
        'id',
        'provider_uuid',
        'tenant_id',
        'tenant_schema_name',
        'rating_avg',
        'total_reviews',
        'completed_jobs_count',
        'synced_at',
        'booking_url',
    ]
    fieldsets = (
        (_('Source Information'), {
            'fields': (
                'id',
                'provider_uuid',
                'tenant_id',
                'tenant_schema_name',
            )
        }),
        (_('Provider Details'), {
            'fields': (
                'provider_name',
                'provider_avatar_url',
                'bio',
                'tagline',
                'provider_type',
            )
        }),
        (_('Service Information'), {
            'fields': (
                'category_names',
                'category_slugs',
                'skills_data',
            )
        }),
        (_('Location'), {
            'fields': (
                'location_city',
                'location_state',
                'location_country',
                'location',
                'can_work_remotely',
                'can_work_onsite',
            )
        }),
        (_('Pricing'), {
            'fields': (
                'hourly_rate',
                'minimum_budget',
                'currency',
            )
        }),
        (_('Ratings & Stats'), {
            'fields': (
                'rating_avg',
                'total_reviews',
                'completed_jobs_count',
                'response_rate',
                'avg_response_time_hours',
            )
        }),
        (_('Booking'), {
            'fields': (
                'booking_url',
            )
        }),
        (_('Status & Visibility'), {
            'fields': (
                'is_verified',
                'is_featured',
                'is_accepting_work',
                'availability_status',
                'published_at',
            )
        }),
        (_('Metadata'), {
            'fields': (
                'synced_at',
            ),
            'classes': ('collapse',)
        }),
    )
    date_hierarchy = 'published_at'
    ordering = ['-rating_avg', '-published_at']
    actions = ['mark_as_verified', 'mark_as_unverified', 'mark_as_featured']

    def service_category_display(self, obj):
        """Display service categories."""
        if obj.category_names:
            categories = obj.category_names[:2]  # Show first 2
            display = ", ".join(categories)
            if len(obj.category_names) > 2:
                display += f" (+{len(obj.category_names) - 2})"
            return display
        return _('N/A')
    service_category_display.short_description = _('Categories')

    def location_display_admin(self, obj):
        """Display location in admin list."""
        parts = [obj.location_city, obj.location_state, obj.location_country]
        location = ", ".join(filter(None, parts)) or _('Location not specified')
        if obj.can_work_remotely:
            location += " (Remote available)"
        return location
    location_display_admin.short_description = _('Location')

    def rating_display(self, obj):
        """Display rating with stars."""
        if not obj.rating_avg or obj.total_reviews == 0:
            return _('No ratings')
        stars = '★' * int(obj.rating_avg) + '☆' * (5 - int(obj.rating_avg))
        return format_html(
            '<span title="{:.1f} ({} reviews)">{}</span>',
            obj.rating_avg,
            obj.total_reviews,
            stars
        )
    rating_display.short_description = _('Rating')

    def tenant_link(self, obj):
        """Display link to tenant schema."""
        return format_html(
            '<code>{}</code>',
            obj.tenant_schema_name
        )
    tenant_link.short_description = _('Tenant')

    @admin.action(description=_('Mark selected providers as verified'))
    def mark_as_verified(self, request, queryset):
        """Mark providers as verified."""
        count = queryset.update(is_verified=True)
        self.message_user(request, _(f'{count} providers marked as verified.'))

    @admin.action(description=_('Mark selected providers as unverified'))
    def mark_as_unverified(self, request, queryset):
        """Remove verified status from providers."""
        count = queryset.update(is_verified=False)
        self.message_user(request, _(f'{count} providers unmarked as verified.'))

    @admin.action(description=_('Mark selected providers as featured'))
    def mark_as_featured(self, request, queryset):
        """Mark providers as featured."""
        count = queryset.update(is_featured=True)
        self.message_user(request, _(f'{count} providers marked as featured.'))
