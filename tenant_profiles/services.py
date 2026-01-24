"""
Profile Synchronization Service

Handles synchronization of PublicProfile data to TenantProfile with
user-controlled field-level privacy settings.
"""

import logging
from django.utils import timezone
from django.db import transaction
from custom_account_u.models import PublicProfile, ProfileFieldSync
from tenant_profiles.models import TenantProfile

logger = logging.getLogger(__name__)


class ProfileSyncService:
    """
    Service for syncing PublicProfile data to TenantProfile.

    Privacy-first design:
    - Only syncs fields enabled in ProfileFieldSync settings
    - Email and phone OFF by default
    - Manual sync only (no auto-sync)
    - One-way sync: PUBLIC → TENANT only
    """

    # Field mapping: PublicProfile field → TenantProfile field
    FIELD_MAPPING = {
        'display_name': 'full_name',
        'avatar': 'avatar_url',  # Special: ImageField → URL
        'bio': 'bio',
        'public_email': 'email',
        'phone': 'phone',
        'city': 'city',
        'state': 'state',
        'country': 'country',
        'linkedin_url': 'linkedin_url',
        'github_url': 'github_url',
        'portfolio_url': 'portfolio_url',
        'skills': 'skills_json',
        'languages': 'languages_json',
    }

    @classmethod
    def sync_on_invitation_acceptance(cls, user, tenant):
        """
        Initial one-time sync when user accepts tenant invitation.

        Creates ProfileFieldSync with privacy-friendly defaults and
        performs initial sync to TenantProfile.

        Args:
            user: CustomUser instance
            tenant: Tenant instance

        Returns:
            dict: {
                'success': bool,
                'synced_fields': list,
                'tenant_profile_created': bool,
                'error': str (if success=False)
            }
        """
        try:
            # Get or create PublicProfile
            try:
                public_profile = user.public_profile
            except PublicProfile.DoesNotExist:
                logger.warning(
                    f"User {user.email} has no PublicProfile. Creating one."
                )
                public_profile = PublicProfile.objects.create(
                    user=user,
                    display_name=f"{user.first_name} {user.last_name}".strip() or user.email
                )

            # Create ProfileFieldSync with privacy defaults
            sync_settings, sync_created = ProfileFieldSync.get_or_create_defaults(
                user=user,
                tenant_uuid=tenant.uuid
            )

            # Create or get TenantProfile
            tenant_profile, profile_created = TenantProfile.objects.get_or_create(
                user=user,
                tenant=tenant,
                defaults={
                    'job_title': 'Employee',  # Default job title
                }
            )

            # Perform sync
            synced_fields = cls._perform_sync(
                public_profile=public_profile,
                tenant_profile=tenant_profile,
                sync_settings=sync_settings
            )

            # Update sync metadata
            tenant_profile.last_synced_at = timezone.now()
            tenant_profile.synced_fields = synced_fields
            tenant_profile.save(update_fields=['last_synced_at', 'synced_fields', 'updated_at'])

            logger.info(
                f"Profile sync on invitation: {user.email} → {tenant.name}, "
                f"synced {len(synced_fields)} fields: {synced_fields}"
            )

            return {
                'success': True,
                'synced_fields': synced_fields,
                'tenant_profile_created': profile_created,
                'sync_settings_created': sync_created,
            }

        except Exception as e:
            logger.error(
                f"Profile sync failed on invitation: {user.email} → {tenant.name}: {e}",
                exc_info=True
            )
            return {
                'success': False,
                'error': str(e),
                'synced_fields': [],
                'tenant_profile_created': False,
            }

    @classmethod
    def sync_manual_trigger(cls, user, tenant, field_overrides=None):
        """
        User-triggered manual sync.

        Syncs PublicProfile data to TenantProfile based on ProfileFieldSync settings.
        Optionally allows one-time field overrides.

        Args:
            user: CustomUser instance
            tenant: Tenant instance
            field_overrides: dict, optional one-time sync overrides
                Example: {'sync_phone': True} to sync phone just this once

        Returns:
            dict: {
                'success': bool,
                'synced_fields': list,
                'sync_timestamp': str,
                'error': str (if success=False)
            }
        """
        try:
            # Validate PublicProfile exists
            try:
                public_profile = user.public_profile
            except PublicProfile.DoesNotExist:
                return {
                    'success': False,
                    'error': 'no_public_profile',
                    'synced_fields': [],
                }

            # Get ProfileFieldSync settings
            sync_settings, _ = ProfileFieldSync.get_or_create_defaults(
                user=user,
                tenant_uuid=tenant.uuid
            )

            # Apply field overrides (temporary, don't save)
            if field_overrides:
                for field, value in field_overrides.items():
                    if hasattr(sync_settings, field):
                        setattr(sync_settings, field, value)

            # Get or create TenantProfile
            tenant_profile, created = TenantProfile.objects.get_or_create(
                user=user,
                tenant=tenant,
                defaults={
                    'job_title': 'Employee',
                }
            )

            # Perform sync
            synced_fields = cls._perform_sync(
                public_profile=public_profile,
                tenant_profile=tenant_profile,
                sync_settings=sync_settings
            )

            # Update sync metadata
            sync_timestamp = timezone.now()
            tenant_profile.last_synced_at = sync_timestamp
            tenant_profile.synced_fields = synced_fields
            tenant_profile.save(update_fields=['last_synced_at', 'synced_fields', 'updated_at'])

            logger.info(
                f"Manual profile sync: {user.email} → {tenant.name}, "
                f"synced {len(synced_fields)} fields: {synced_fields}"
            )

            return {
                'success': True,
                'synced_fields': synced_fields,
                'sync_timestamp': sync_timestamp.isoformat(),
            }

        except Exception as e:
            logger.error(
                f"Manual profile sync failed: {user.email} → {tenant.name}: {e}",
                exc_info=True
            )
            return {
                'success': False,
                'error': str(e),
                'synced_fields': [],
            }

    @classmethod
    def _perform_sync(cls, public_profile, tenant_profile, sync_settings):
        """
        Internal method to perform actual field synchronization.

        Copies enabled fields from PublicProfile to TenantProfile
        based on sync_settings.

        Args:
            public_profile: PublicProfile instance
            tenant_profile: TenantProfile instance
            sync_settings: ProfileFieldSync instance (may have temporary overrides)

        Returns:
            list: Names of fields that were synced
        """
        synced_fields = []

        for public_field, tenant_field in cls.FIELD_MAPPING.items():
            # Check if this field is enabled for sync
            sync_enabled = getattr(sync_settings, f'sync_{public_field}', False)

            if sync_enabled:
                # Get value from PublicProfile
                public_value = getattr(public_profile, public_field, None)

                # Special handling for avatar (ImageField → URL)
                if public_field == 'avatar' and public_value:
                    try:
                        public_value = public_value.url
                    except ValueError:
                        # File doesn't exist
                        public_value = ''
                    except Exception as e:
                        logger.warning(
                            f"Failed to get avatar URL for {public_profile.user.email}: {e}"
                        )
                        public_value = ''

                # Convert None to empty string/list for consistency
                if public_value is None:
                    if tenant_field.endswith('_json'):
                        public_value = []
                    else:
                        public_value = ''

                # Set value in TenantProfile
                setattr(tenant_profile, tenant_field, public_value)
                synced_fields.append(public_field)

        # Save TenantProfile with synced fields
        if synced_fields:
            # Get list of tenant field names for update_fields
            tenant_fields = [cls.FIELD_MAPPING[f] for f in synced_fields]
            tenant_fields.append('updated_at')  # Always update timestamp
            tenant_profile.save(update_fields=tenant_fields)

        return synced_fields

    @classmethod
    def validate_sync_privacy(cls, user, tenant, requested_fields):
        """
        Validate requested fields against sync settings.

        Used for checking if specific fields can be synced based on
        the user's privacy settings for this tenant.

        Args:
            user: CustomUser instance
            tenant: Tenant instance
            requested_fields: list of field names to validate

        Returns:
            dict: {
                'valid': bool,
                'allowed_fields': list,
                'denied_fields': list
            }
        """
        try:
            sync_settings, _ = ProfileFieldSync.get_or_create_defaults(
                user=user,
                tenant_uuid=tenant.uuid
            )

            enabled_fields = sync_settings.get_enabled_fields()
            allowed = [f for f in requested_fields if f in enabled_fields]
            denied = [f for f in requested_fields if f not in enabled_fields]

            return {
                'valid': len(denied) == 0,
                'allowed_fields': allowed,
                'denied_fields': denied,
            }

        except Exception as e:
            logger.error(f"Privacy validation failed: {e}", exc_info=True)
            return {
                'valid': False,
                'allowed_fields': [],
                'denied_fields': requested_fields,
            }

    @classmethod
    def get_syncable_fields(cls):
        """
        Get list of all syncable fields with descriptions.

        Returns:
            list: [
                {
                    'field': str,
                    'label': str,
                    'default_enabled': bool,
                    'sensitive': bool
                },
                ...
            ]
        """
        fields_info = [
            {'field': 'display_name', 'label': 'Display Name', 'default_enabled': True, 'sensitive': False},
            {'field': 'avatar', 'label': 'Avatar Picture', 'default_enabled': True, 'sensitive': False},
            {'field': 'bio', 'label': 'Professional Bio', 'default_enabled': True, 'sensitive': False},
            {'field': 'public_email', 'label': 'Public Email', 'default_enabled': False, 'sensitive': True},
            {'field': 'phone', 'label': 'Phone Number', 'default_enabled': False, 'sensitive': True},
            {'field': 'city', 'label': 'City', 'default_enabled': True, 'sensitive': False},
            {'field': 'state', 'label': 'State/Province', 'default_enabled': True, 'sensitive': False},
            {'field': 'country', 'label': 'Country', 'default_enabled': True, 'sensitive': False},
            {'field': 'linkedin', 'label': 'LinkedIn URL', 'default_enabled': True, 'sensitive': False},
            {'field': 'github', 'label': 'GitHub URL', 'default_enabled': True, 'sensitive': False},
            {'field': 'portfolio', 'label': 'Portfolio URL', 'default_enabled': True, 'sensitive': False},
            {'field': 'skills', 'label': 'Skills', 'default_enabled': True, 'sensitive': False},
            {'field': 'languages', 'label': 'Languages', 'default_enabled': True, 'sensitive': False},
        ]
        return fields_info

    @classmethod
    def get_sync_status(cls, user, tenant):
        """
        Get current sync status for user in tenant.

        Args:
            user: CustomUser instance
            tenant: Tenant instance

        Returns:
            dict: {
                'status': str ('never_synced', 'synced', 'out_of_sync', 'no_public_profile'),
                'last_synced_at': datetime or None,
                'synced_fields': list,
                'enabled_fields': list,
            }
        """
        try:
            # Check PublicProfile exists
            try:
                public_profile = user.public_profile
            except PublicProfile.DoesNotExist:
                return {
                    'status': 'no_public_profile',
                    'last_synced_at': None,
                    'synced_fields': [],
                    'enabled_fields': [],
                }

            # Get TenantProfile
            try:
                tenant_profile = TenantProfile.objects.get(user=user, tenant=tenant)
            except TenantProfile.DoesNotExist:
                return {
                    'status': 'never_synced',
                    'last_synced_at': None,
                    'synced_fields': [],
                    'enabled_fields': [],
                }

            # Get sync settings
            sync_settings, _ = ProfileFieldSync.get_or_create_defaults(
                user=user,
                tenant_uuid=tenant.uuid
            )
            enabled_fields = sync_settings.get_enabled_fields()

            # Determine status
            if not tenant_profile.last_synced_at:
                status = 'never_synced'
            elif public_profile.updated_at > tenant_profile.last_synced_at:
                status = 'out_of_sync'
            else:
                status = 'synced'

            return {
                'status': status,
                'last_synced_at': tenant_profile.last_synced_at,
                'synced_fields': tenant_profile.synced_fields,
                'enabled_fields': enabled_fields,
            }

        except Exception as e:
            logger.error(f"Get sync status failed: {e}", exc_info=True)
            return {
                'status': 'error',
                'last_synced_at': None,
                'synced_fields': [],
                'enabled_fields': [],
                'error': str(e),
            }
