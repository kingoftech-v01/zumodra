"""
Tenants Admin - Admin configuration for multi-tenant management.
"""

from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone

from .models import (
    Plan, Tenant, TenantSettings, Domain,
    TenantInvitation, TenantUsage, AuditLog,
    Circusale, CircusaleUser
)


@admin.register(Plan)
class PlanAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'plan_type', 'price_monthly', 'price_yearly',
        'max_users', 'max_job_postings', 'is_active', 'is_popular'
    ]
    list_filter = ['plan_type', 'is_active', 'is_popular']
    search_fields = ['name', 'description']
    prepopulated_fields = {'slug': ('name',)}
    ordering = ['sort_order', 'price_monthly']

    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'slug', 'plan_type', 'description')
        }),
        ('Pricing', {
            'fields': (
                'price_monthly', 'price_yearly', 'currency',
                'stripe_product_id', 'stripe_price_id_monthly', 'stripe_price_id_yearly'
            )
        }),
        ('Limits', {
            'fields': (
                'max_users', 'max_job_postings', 'max_candidates_per_month',
                'max_circusales', 'storage_limit_gb'
            )
        }),
        ('Core Features', {
            'fields': (
                'feature_ats', 'feature_hr_core', 'feature_analytics',
                'feature_api_access', 'feature_custom_pipelines'
            )
        }),
        ('Advanced Features', {
            'fields': (
                'feature_ai_matching', 'feature_video_interviews',
                'feature_esignature', 'feature_sso', 'feature_audit_logs'
            ),
            'classes': ('collapse',)
        }),
        ('Enterprise Features', {
            'fields': (
                'feature_custom_branding', 'feature_priority_support',
                'feature_data_export', 'feature_bulk_actions',
                'feature_advanced_filters', 'feature_diversity_analytics',
                'feature_compliance_tools'
            ),
            'classes': ('collapse',)
        }),
        ('Display Options', {
            'fields': ('is_active', 'is_popular', 'sort_order')
        }),
    )


class TenantSettingsInline(admin.StackedInline):
    model = TenantSettings
    can_delete = False
    verbose_name_plural = 'Settings'


class TenantUsageInline(admin.TabularInline):
    model = TenantUsage
    can_delete = False
    readonly_fields = [
        'user_count', 'active_job_count', 'total_job_count',
        'candidate_count_this_month', 'circusale_count',
        'storage_used_bytes', 'api_calls_this_month', 'last_calculated_at'
    ]


class DomainInline(admin.TabularInline):
    model = Domain
    extra = 1


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'slug', 'status_badge', 'plan', 'owner_email',
        'trial_status', 'created_at'
    ]
    list_filter = ['status', 'plan', 'on_trial', 'created_at']
    search_fields = ['name', 'slug', 'owner_email', 'schema_name']
    readonly_fields = ['uuid', 'created_at', 'updated_at', 'activated_at', 'suspended_at']
    prepopulated_fields = {'slug': ('name',)}
    ordering = ['-created_at']
    inlines = [TenantSettingsInline, TenantUsageInline, DomainInline]

    fieldsets = (
        ('Identity', {
            'fields': ('uuid', 'name', 'slug', 'schema_name')
        }),
        ('Status & Plan', {
            'fields': ('status', 'plan', 'on_trial', 'trial_ends_at', 'paid_until')
        }),
        ('Stripe', {
            'fields': ('stripe_customer_id', 'stripe_subscription_id'),
            'classes': ('collapse',)
        }),
        ('Company Information', {
            'fields': (
                'owner_email', 'industry', 'company_size', 'website', 'logo'
            )
        }),
        ('Address', {
            'fields': (
                'address_line1', 'address_line2', 'city',
                'state', 'postal_code', 'country'
            ),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'activated_at', 'suspended_at'),
            'classes': ('collapse',)
        }),
    )

    def status_badge(self, obj):
        colors = {
            'active': 'green',
            'trial': 'blue',
            'pending': 'orange',
            'suspended': 'red',
            'cancelled': 'gray',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'

    def trial_status(self, obj):
        if not obj.on_trial:
            return format_html('<span style="color: gray;">N/A</span>')
        days = obj.trial_days_remaining
        if days > 7:
            color = 'green'
        elif days > 3:
            color = 'orange'
        else:
            color = 'red'
        return format_html(
            '<span style="color: {};">{} days left</span>',
            color, days
        )
    trial_status.short_description = 'Trial'


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    list_display = ['domain', 'tenant', 'is_primary', 'is_careers_domain', 'ssl_enabled']
    list_filter = ['is_primary', 'is_careers_domain', 'ssl_enabled']
    search_fields = ['domain', 'tenant__name']


@admin.register(TenantInvitation)
class TenantInvitationAdmin(admin.ModelAdmin):
    list_display = ['email', 'tenant', 'role', 'status', 'invited_by', 'created_at', 'expires_at']
    list_filter = ['status', 'role', 'tenant']
    search_fields = ['email', 'tenant__name']
    readonly_fields = ['uuid', 'token', 'created_at', 'accepted_at']


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['created_at', 'tenant', 'user', 'action', 'resource_type', 'ip_address']
    list_filter = ['action', 'resource_type', 'tenant', 'created_at']
    search_fields = ['description', 'resource_id', 'user__email']
    readonly_fields = [
        'uuid', 'tenant', 'user', 'action', 'resource_type', 'resource_id',
        'description', 'old_values', 'new_values', 'ip_address', 'user_agent', 'created_at'
    ]
    ordering = ['-created_at']

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


# =============================================================================
# CIRCUSALE (Business Units/Divisions)
# =============================================================================

class CircusaleUserInline(admin.TabularInline):
    """Inline for CircusaleUser within Circusale admin."""
    model = CircusaleUser
    extra = 1
    readonly_fields = ['uuid', 'joined_at']
    raw_id_fields = ['user']
    fields = ['user', 'role', 'is_primary', 'joined_at', 'uuid']


@admin.register(Circusale)
class CircusaleAdmin(admin.ModelAdmin):
    """
    Admin for Circusale model - Business units/divisions within a tenant.

    Circusales represent physical locations, branches, or organizational units
    within a tenant enterprise. They support hierarchical structures with
    parent-child relationships and geospatial coordinates for location-based
    service matching.
    """
    list_display = [
        'name', 'tenant', 'code', 'status_badge', 'parent',
        'city', 'country', 'is_headquarters_badge', 'accepts_applications_badge',
        'budget_display', 'member_count', 'created_at'
    ]
    list_filter = [
        'status', 'is_headquarters', 'accepts_applications',
        'country', 'tenant', 'created_at'
    ]
    search_fields = [
        'name', 'slug', 'code',
        'address_line1', 'city', 'state', 'postal_code',
        'tenant__name', 'manager_name', 'email'
    ]
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    prepopulated_fields = {'slug': ('name',)}
    raw_id_fields = ['tenant', 'parent']
    ordering = ['tenant', 'name']
    inlines = [CircusaleUserInline]
    list_select_related = ['tenant', 'parent']
    list_per_page = 25
    date_hierarchy = 'created_at'
    save_on_top = True

    fieldsets = (
        ('Identity', {
            'fields': ('uuid', 'tenant', 'name', 'slug', 'code', 'parent'),
            'description': 'Core identification fields for the circusale/division.'
        }),
        ('Status & Settings', {
            'fields': ('status', 'is_headquarters', 'accepts_applications', 'timezone'),
            'description': 'Operational status and configuration options.'
        }),
        ('Location', {
            'fields': (
                'address_line1', 'address_line2', 'city',
                'state', 'postal_code', 'country'
            ),
            'description': 'Physical address of the circusale location.'
        }),
        ('Geospatial Coordinates', {
            'fields': ('latitude', 'longitude'),
            'classes': ('collapse',),
            'description': 'Geographic coordinates for PostGIS-enabled location queries and service matching.'
        }),
        ('Budget & Finance', {
            'fields': ('budget', 'currency', 'cost_center'),
            'classes': ('collapse',),
            'description': 'Financial allocation and cost tracking information.'
        }),
        ('Contact Information', {
            'fields': ('phone', 'email', 'manager_name'),
            'classes': ('collapse',),
            'description': 'Primary contact details for the circusale.'
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',),
            'description': 'Record creation and modification timestamps.'
        }),
    )

    def status_badge(self, obj):
        """Display status with styled colored badge."""
        colors = {
            'active': '#28a745',      # Green
            'inactive': '#6c757d',    # Gray
            'pending': '#ffc107',     # Yellow/Orange
        }
        text_colors = {
            'active': '#ffffff',
            'inactive': '#ffffff',
            'pending': '#212529',
        }
        bg_color = colors.get(obj.status, '#6c757d')
        text_color = text_colors.get(obj.status, '#ffffff')
        return format_html(
            '<span style="background-color: {}; color: {}; padding: 4px 10px; '
            'border-radius: 4px; font-size: 11px; font-weight: 600; '
            'text-transform: uppercase; letter-spacing: 0.5px;">{}</span>',
            bg_color, text_color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'
    status_badge.admin_order_field = 'status'

    def is_headquarters_badge(self, obj):
        """Display headquarters status with styled badge."""
        if obj.is_headquarters:
            return format_html(
                '<span style="background-color: #17a2b8; color: #ffffff; padding: 4px 8px; '
                'border-radius: 4px; font-size: 10px; font-weight: 700; '
                'text-transform: uppercase;">HQ</span>'
            )
        return format_html('<span style="color: #adb5bd;">-</span>')
    is_headquarters_badge.short_description = 'HQ'
    is_headquarters_badge.admin_order_field = 'is_headquarters'

    def accepts_applications_badge(self, obj):
        """Display application acceptance status with styled badge."""
        if obj.accepts_applications:
            return format_html(
                '<span style="background-color: #28a745; color: #ffffff; padding: 4px 8px; '
                'border-radius: 4px; font-size: 10px; font-weight: 600;">OPEN</span>'
            )
        return format_html(
            '<span style="background-color: #dc3545; color: #ffffff; padding: 4px 8px; '
            'border-radius: 4px; font-size: 10px; font-weight: 600;">CLOSED</span>'
        )
    accepts_applications_badge.short_description = 'Applications'
    accepts_applications_badge.admin_order_field = 'accepts_applications'

    def budget_display(self, obj):
        """Display formatted budget with currency symbol."""
        if obj.budget and obj.budget > 0:
            return format_html(
                '<span style="font-family: \'Courier New\', monospace; font-weight: 600; '
                'color: #155724;">{} {:,.2f}</span>',
                obj.currency, obj.budget
            )
        return format_html('<span style="color: #adb5bd;">-</span>')
    budget_display.short_description = 'Budget'
    budget_display.admin_order_field = 'budget'

    def member_count(self, obj):
        """Display number of users assigned to this circusale."""
        count = obj.members.count()
        if count > 0:
            return format_html(
                '<span style="background-color: #e9ecef; color: #495057; padding: 3px 8px; '
                'border-radius: 12px; font-size: 11px; font-weight: 600;">{}</span>',
                count
            )
        return format_html('<span style="color: #adb5bd;">0</span>')
    member_count.short_description = 'Members'

    def get_queryset(self, request):
        """Optimize queryset with prefetch for member counts."""
        qs = super().get_queryset(request)
        return qs.prefetch_related('members')


@admin.register(CircusaleUser)
class CircusaleUserAdmin(admin.ModelAdmin):
    """
    Admin for CircusaleUser model - Links users to circusales with roles.

    Manages the many-to-many relationship between users and circusales,
    including role assignment and primary circusale designation for
    each user within the tenant organization.
    """
    list_display = [
        'user', 'circusale', 'tenant_display', 'role_badge',
        'is_primary_badge', 'joined_at'
    ]
    list_filter = [
        'role', 'is_primary',
        'circusale__tenant', 'circusale__status',
        'joined_at'
    ]
    search_fields = [
        'user__email', 'user__first_name', 'user__last_name',
        'circusale__name', 'circusale__code',
        'circusale__tenant__name'
    ]
    readonly_fields = ['uuid', 'joined_at']
    raw_id_fields = ['user', 'circusale']
    ordering = ['-joined_at']
    list_select_related = ['user', 'circusale', 'circusale__tenant']
    list_per_page = 25
    date_hierarchy = 'joined_at'
    save_on_top = True

    fieldsets = (
        ('Identity', {
            'fields': ('uuid',),
            'description': 'Unique identifier for this circusale membership.'
        }),
        ('Assignment', {
            'fields': ('user', 'circusale'),
            'description': 'User and circusale association.'
        }),
        ('Role & Permissions', {
            'fields': ('role', 'is_primary'),
            'description': 'Role determines permissions within the circusale. Primary flag indicates the user\'s main circusale.'
        }),
        ('Timestamps', {
            'fields': ('joined_at',),
            'classes': ('collapse',),
            'description': 'When the user was added to this circusale.'
        }),
    )

    def tenant_display(self, obj):
        """Display the tenant name from the related circusale."""
        return obj.circusale.tenant.name
    tenant_display.short_description = 'Tenant'
    tenant_display.admin_order_field = 'circusale__tenant__name'

    def role_badge(self, obj):
        """Display role with styled colored badge."""
        colors = {
            'manager': '#6f42c1',     # Purple
            'supervisor': '#007bff',  # Blue
            'member': '#20c997',      # Teal
            'viewer': '#6c757d',      # Gray
        }
        bg_color = colors.get(obj.role, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: #ffffff; padding: 4px 10px; '
            'border-radius: 4px; font-size: 11px; font-weight: 600; '
            'text-transform: uppercase; letter-spacing: 0.5px;">{}</span>',
            bg_color, obj.get_role_display()
        )
    role_badge.short_description = 'Role'
    role_badge.admin_order_field = 'role'

    def is_primary_badge(self, obj):
        """Display primary circusale status with styled badge."""
        if obj.is_primary:
            return format_html(
                '<span style="background-color: #ffc107; color: #212529; padding: 4px 8px; '
                'border-radius: 4px; font-size: 10px; font-weight: 700; '
                'text-transform: uppercase;">PRIMARY</span>'
            )
        return format_html('<span style="color: #adb5bd;">-</span>')
    is_primary_badge.short_description = 'Primary'
    is_primary_badge.admin_order_field = 'is_primary'
