"""
API Serializers for PublicProfile and ProfileFieldSync
"""

from rest_framework import serializers
from custom_account_u.models import PublicProfile, ProfileFieldSync


class PublicProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for PublicProfile.
    Used for viewing and updating user's public marketplace profile.
    """
    completion_percentage = serializers.ReadOnlyField()
    verification_badges = serializers.ReadOnlyField()
    user_email = serializers.EmailField(source='user.email', read_only=True)
    user_full_name = serializers.CharField(source='user.get_full_name', read_only=True)

    class Meta:
        model = PublicProfile
        fields = [
            'uuid',
            'user_email',
            'user_full_name',
            # Identity
            'display_name',
            'professional_title',
            'avatar',
            'bio',
            # Contact
            'public_email',
            'phone',
            # Location
            'city',
            'state',
            'country',
            'timezone',
            # Professional Links
            'linkedin_url',
            'github_url',
            'portfolio_url',
            'personal_website',
            # CV/Resume
            'cv_file',
            'cv_last_updated',
            # Skills & Certifications
            'skills',
            'languages',
            'certifications',
            # Marketplace
            'available_for_work',
            'hourly_rate_min',
            'hourly_rate_max',
            'currency',
            # Privacy
            'profile_visibility',
            # Computed
            'completion_percentage',
            'verification_badges',
            # Timestamps
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'uuid',
            'user_email',
            'user_full_name',
            'completion_percentage',
            'verification_badges',
            'created_at',
            'updated_at',
        ]

    def validate_hourly_rate_min(self, value):
        """Validate minimum hourly rate."""
        if value is not None and value < 0:
            raise serializers.ValidationError("Minimum hourly rate cannot be negative.")
        return value

    def validate_hourly_rate_max(self, value):
        """Validate maximum hourly rate."""
        if value is not None and value < 0:
            raise serializers.ValidationError("Maximum hourly rate cannot be negative.")
        return value

    def validate(self, data):
        """Cross-field validation."""
        hourly_min = data.get('hourly_rate_min')
        hourly_max = data.get('hourly_rate_max')

        if hourly_min and hourly_max and hourly_min > hourly_max:
            raise serializers.ValidationError({
                'hourly_rate_min': 'Minimum rate cannot be greater than maximum rate.'
            })

        return data


class PublicProfileReadSerializer(PublicProfileSerializer):
    """
    Read-only serializer for viewing others' public profiles.
    Respects profile_visibility settings.
    """
    class Meta(PublicProfileSerializer.Meta):
        read_only_fields = PublicProfileSerializer.Meta.fields  # All fields read-only


class ProfileFieldSyncSerializer(serializers.ModelSerializer):
    """
    Serializer for ProfileFieldSync settings.
    Used for managing per-tenant privacy controls.
    """
    tenant_name = serializers.SerializerMethodField()
    enabled_fields = serializers.ReadOnlyField(source='get_enabled_fields')
    user_email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = ProfileFieldSync
        fields = [
            'uuid',
            'user_email',
            'tenant_uuid',
            'tenant_name',
            # Sync toggles
            'sync_display_name',
            'sync_avatar',
            'sync_bio',
            'sync_public_email',
            'sync_phone',
            'sync_city',
            'sync_state',
            'sync_country',
            'sync_linkedin',
            'sync_github',
            'sync_portfolio',
            'sync_skills',
            'sync_languages',
            # Auto-sync
            'auto_sync',
            # Computed
            'enabled_fields',
            # Timestamps
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'uuid',
            'user_email',
            'tenant_uuid',
            'tenant_name',
            'enabled_fields',
            'created_at',
            'updated_at',
        ]

    def get_tenant_name(self, obj):
        """Get tenant name from UUID."""
        # Try to get tenant name from context if available
        tenant = self.context.get('tenant')
        if tenant:
            return tenant.name

        # Otherwise try to fetch from database
        try:
            from tenants.models import Tenant
            tenant = Tenant.objects.get(uuid=obj.tenant_uuid)
            return tenant.name
        except Exception:
            return None


class ProfileFieldSyncUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating ProfileFieldSync settings.
    Allows updating only the sync toggle fields.
    """
    class Meta:
        model = ProfileFieldSync
        fields = [
            'sync_display_name',
            'sync_avatar',
            'sync_bio',
            'sync_public_email',
            'sync_phone',
            'sync_city',
            'sync_state',
            'sync_country',
            'sync_linkedin',
            'sync_github',
            'sync_portfolio',
            'sync_skills',
            'sync_languages',
            'auto_sync',
        ]

    def validate_auto_sync(self, value):
        """Warn if auto-sync is enabled (not recommended)."""
        if value:
            # Allow it but could log a warning
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(
                f"User {self.context['request'].user.email} enabled auto_sync "
                f"for tenant {self.instance.tenant_uuid if self.instance else 'unknown'}"
            )
        return value
