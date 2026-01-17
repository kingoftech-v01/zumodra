"""Admin configuration for Services Public Catalog."""

from django.contrib import admin
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import PublicServiceCatalog


@admin.register(PublicServiceCatalog)
class PublicServiceCatalogAdmin(admin.ModelAdmin):
    """Admin interface for public service catalog."""

    list_display = [
        'business_name',
        'service_category_display',
        'location_display_admin',
        'rating_display',
        'is_active',
        'is_verified',
        'completed_jobs',
        'tenant_link',
    ]
    list_filter = [
        'is_active',
        'is_verified',
        'is_mobile',
        'accepts_online_payment',
        'location_country',
        'published_at',
    ]
    search_fields = [
        'business_name',
        'description_html',
        'service_category_names',
        'location_city',
        'location_country',
        'tenant_schema_name',
    ]
    readonly_fields = [
        'id',
        'provider_uuid',
        'tenant_id',
        'tenant_schema_name',
        'rating',
        'rating_count',
        'completed_jobs',
        'view_count',
        'created_at',
        'updated_at',
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
                'business_name',
                'avatar_url',
                'description_html',
            )
        }),
        (_('Service Information'), {
            'fields': (
                'service_category_names',
                'service_category_slugs',
                'skills',
            )
        }),
        (_('Location'), {
            'fields': (
                'location_city',
                'location_state',
                'location_country',
                'location',
                'is_mobile',
                'service_radius_km',
            )
        }),
        (_('Pricing'), {
            'fields': (
                'hourly_rate',
                'currency',
                'accepts_online_payment',
            )
        }),
        (_('Ratings & Stats'), {
            'fields': (
                'rating',
                'rating_count',
                'completed_jobs',
                'view_count',
            )
        }),
        (_('Booking'), {
            'fields': (
                'booking_url',
            )
        }),
        (_('Status & Visibility'), {
            'fields': (
                'is_active',
                'is_verified',
                'published_at',
            )
        }),
        (_('Metadata'), {
            'fields': (
                'created_at',
                'updated_at',
            ),
            'classes': ('collapse',)
        }),
    )
    date_hierarchy = 'published_at'
    ordering = ['-rating', '-published_at']
    actions = ['mark_as_verified', 'mark_as_unverified', 'mark_as_inactive']

    def service_category_display(self, obj):
        """Display service categories."""
        if obj.service_category_names:
            categories = obj.service_category_names[:2]  # Show first 2
            display = ", ".join(categories)
            if len(obj.service_category_names) > 2:
                display += f" (+{len(obj.service_category_names) - 2})"
            return display
        return _('N/A')
    service_category_display.short_description = _('Categories')

    def location_display_admin(self, obj):
        """Display location in admin list."""
        parts = [obj.location_city, obj.location_state, obj.location_country]
        location = ", ".join(filter(None, parts)) or _('Location not specified')
        if obj.is_mobile and obj.service_radius_km:
            location += f" (+{obj.service_radius_km}km)"
        return location
    location_display_admin.short_description = _('Location')

    def rating_display(self, obj):
        """Display rating with stars."""
        if obj.rating_count == 0:
            return _('No ratings')
        stars = '★' * int(obj.rating) + '☆' * (5 - int(obj.rating))
        return format_html(
            '<span title="{:.1f} ({} reviews)">{}</span>',
            obj.rating,
            obj.rating_count,
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

    @admin.action(description=_('Mark selected providers as inactive'))
    def mark_as_inactive(self, request, queryset):
        """Mark providers as inactive."""
        count = queryset.update(is_active=False)
        self.message_user(request, _(f'{count} providers marked as inactive.'))
