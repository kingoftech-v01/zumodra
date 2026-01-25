from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from .models import CustomUser, PlatformLaunch, UserIdentity, MarketplaceProfile, TenantInvitation


@admin.register(PlatformLaunch)
class PlatformLaunchAdmin(admin.ModelAdmin):
    """
    Admin interface for Platform Launch Configuration.

    Features:
    - Singleton pattern (only one record)
    - Cannot delete the configuration
    - Shows days until launch
    - Manual launch override
    """
    list_display = [
        'launch_status_display',
        'launch_date',
        'days_until_launch',
        'is_launched',
        'waitlist_enabled',
        'updated_at',
    ]

    fieldsets = [
        ('Launch Configuration', {
            'fields': ['launch_date', 'is_launched', 'waitlist_enabled'],
            'description': 'Configure platform launch date and waitlist system'
        }),
        ('Waitlist Message', {
            'fields': ['waitlist_message'],
            'description': 'Customize the message shown to waitlisted users'
        }),
        ('Metadata', {
            'fields': ['created_at', 'updated_at'],
            'classes': ['collapse'],
        }),
    ]

    readonly_fields = ['created_at', 'updated_at']

    def has_add_permission(self, request):
        """Only one instance allowed (singleton)."""
        return not PlatformLaunch.objects.exists()

    def has_delete_permission(self, request, obj=None):
        """Cannot delete the configuration."""
        return False

    def launch_status_display(self, obj):
        """Display current launch status with color coding."""
        if obj.is_platform_launched:
            return '🟢 LAUNCHED'
        elif obj.launch_date:
            return f'🟡 Scheduled for {obj.launch_date.strftime("%Y-%m-%d")}'
        else:
            return '🔴 No launch date set'
    launch_status_display.short_description = 'Status'


@admin.register(CustomUser)
class CustomUserAdmin(BaseUserAdmin):
    """
    Enhanced CustomUser admin with waitlist management.
    """
    list_display = [
        'email',
        'first_name',
        'last_name',
        'is_waitlisted_display',
        'waitlist_position',
        'mfa_enabled',
        'is_staff',
        'is_active',
        'created_at',
    ]

    list_filter = [
        'is_waitlisted',
        'is_staff',
        'is_superuser',
        'is_active',
        'mfa_enabled',
        'created_at',
    ]

    search_fields = ['email', 'first_name', 'last_name']

    ordering = ['-created_at']

    fieldsets = [
        (None, {
            'fields': ['email', 'password']
        }),
        ('Personal Info', {
            'fields': ['first_name', 'last_name']
        }),
        ('Waitlist', {
            'fields': ['is_waitlisted', 'waitlist_joined_at', 'waitlist_position'],
            'description': 'Waitlist system fields - automatically managed'
        }),
        ('MFA', {
            'fields': ['mfa_enabled', 'mfa_grace_period_end']
        }),
        ('Permissions', {
            'fields': ['is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions']
        }),
        ('Privacy', {
            'fields': ['anonymous_mode']
        }),
        ('Timestamps', {
            'fields': ['created_at', 'updated_at', 'last_login'],
            'classes': ['collapse']
        }),
    ]

    readonly_fields = ['created_at', 'updated_at', 'last_login', 'waitlist_joined_at']

    def is_waitlisted_display(self, obj):
        """Display waitlist status with icon."""
        if obj.is_waitlisted:
            return '⏳ Waitlisted'
        return '✅ Active'
    is_waitlisted_display.short_description = 'Access Status'

    actions = ['grant_access', 'add_to_waitlist']

    def grant_access(self, request, queryset):
        """Grant immediate platform access to selected users."""
        count = queryset.filter(is_waitlisted=True).update(is_waitlisted=False)
        self.message_user(request, f'Granted access to {count} users')
    grant_access.short_description = 'Grant platform access'

    def add_to_waitlist(self, request, queryset):
        """Add selected users back to waitlist."""
        count = queryset.filter(is_waitlisted=False).update(is_waitlisted=True)
        self.message_user(request, f'Added {count} users to waitlist')
    add_to_waitlist.short_description = 'Add to waitlist'


# Register other models
admin.site.register(UserIdentity)
admin.site.register(MarketplaceProfile)
admin.site.register(TenantInvitation)