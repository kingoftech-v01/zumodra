"""
Tenants Signals - Automatic tenant setup and cleanup.
"""

from django.db.models.signals import post_save, pre_delete, post_migrate
from django.dispatch import receiver
from django.utils import timezone
from datetime import timedelta
import secrets

from django_tenants.signals import post_schema_sync
from django_tenants.utils import schema_context, get_tenant_model

from .models import Tenant, TenantSettings, TenantUsage, TenantInvitation


@receiver(post_save, sender=Tenant)
def create_tenant_settings(sender, instance, created, **kwargs):
    """
    Automatically create TenantSettings and TenantUsage when a new Tenant is created.
    """
    if created:
        # Create default settings
        TenantSettings.objects.get_or_create(
            tenant=instance,
            defaults={
                'default_pipeline_stages': [
                    'New',
                    'Screening',
                    'Phone Interview',
                    'Technical Interview',
                    'Final Interview',
                    'Offer',
                    'Hired',
                    'Rejected'
                ]
            }
        )

        # Create usage tracking
        TenantUsage.objects.get_or_create(
            tenant=instance,
            defaults={
                'month_reset_at': timezone.now()
            }
        )

        # Set trial end date if on trial (14 days by default)
        if instance.on_trial and not instance.trial_ends_at:
            instance.trial_ends_at = timezone.now() + timedelta(days=14)
            instance.save(update_fields=['trial_ends_at'])


@receiver(post_save, sender=Tenant)
def auto_geocode_tenant(sender, instance, created, **kwargs):
    """
    Automatically geocode tenant address when created or address fields change.
    Implements TODO-CAREERS-001 from careers/TODO.md.

    Geocoding is done asynchronously via Celery to avoid blocking tenant creation.
    """
    # Skip if tenant has no address info
    if not instance.city or not instance.country:
        return

    # Skip if already geocoded (unless address changed)
    if instance.location and not created:
        # Check if address fields changed
        if not kwargs.get('update_fields'):
            return

        address_fields = {'city', 'state', 'country', 'address_line1'}
        updated_fields = set(kwargs.get('update_fields', []))

        # Only geocode if address fields were updated
        if not address_fields.intersection(updated_fields):
            return

    # Queue geocoding task (async via Celery)
    # Import here to avoid circular imports
    from tenants.tasks import geocode_tenant_task

    # Delay task by 2 seconds to allow transaction to commit
    geocode_tenant_task.apply_async(
        args=[instance.pk],
        countdown=2
    )


@receiver(pre_delete, sender=Tenant)
def cleanup_tenant(sender, instance, **kwargs):
    """
    Cleanup related resources before tenant deletion.
    Note: Schema deletion handled by django-tenants if auto_drop_schema=True
    """
    # Revoke all pending invitations
    TenantInvitation.objects.filter(
        tenant=instance,
        status='pending'
    ).update(status='revoked')


def generate_invitation_token():
    """Generate a secure token for tenant invitations."""
    return secrets.token_urlsafe(32)


@receiver(post_save, sender=TenantInvitation)
def set_invitation_token(sender, instance, created, **kwargs):
    """
    Generate secure token for new invitations.
    """
    if created and not instance.token:
        instance.token = generate_invitation_token()
        # Set expiration to 7 days from now
        if not instance.expires_at:
            instance.expires_at = timezone.now() + timedelta(days=7)
        instance.save(update_fields=['token', 'expires_at'])


@receiver(post_schema_sync, sender=get_tenant_model())
def create_tenant_site_and_run_migrations(sender, tenant, **kwargs):
    """
    After tenant schema is created/synced:
    1. Run migrations to ensure all tables exist (FAIL HARD if migrations fail)
    2. Create Site object for the tenant

    This is required for django-allauth to function properly in tenant schemas.

    CRITICAL: This uses STRICT error handling. If migrations fail, the entire
    tenant creation fails with a clear error message. NO SILENT FAILURES.
    """
    import logging
    from django.contrib.sites.models import Site
    from django.core.management import call_command
    from django.core.management.base import CommandError

    logger = logging.getLogger(__name__)

    # Step 1: Run migrations for this tenant schema (FAIL HARD ON ERROR)
    try:
        logger.info(f"🔄 Running migrations for tenant: {tenant.schema_name}")
        call_command(
            'migrate_schemas',
            schema_name=tenant.schema_name,
            verbosity=1,
            interactive=False
        )
        logger.info(f"✅ Migrations completed successfully for tenant: {tenant.schema_name}")
    except CommandError as e:
        error_msg = (
            f"❌ CRITICAL MIGRATION FAILURE for tenant '{tenant.schema_name}':\n"
            f"   Migration command failed: {str(e)}\n"
            f"   Tenant creation ABORTED. The tenant schema exists but is INCOMPLETE.\n"
            f"   Required action: Delete tenant '{tenant.schema_name}' and recreate.\n"
            f"   OR run: python manage.py migrate_schemas --schema={tenant.schema_name}"
        )
        logger.critical(error_msg)
        # FAIL HARD - Raise exception to block tenant creation
        raise RuntimeError(error_msg) from e
    except Exception as e:
        error_msg = (
            f"❌ UNEXPECTED ERROR during migration for tenant '{tenant.schema_name}':\n"
            f"   Error: {type(e).__name__}: {str(e)}\n"
            f"   Tenant creation ABORTED. System state is INCONSISTENT.\n"
            f"   Required action: Investigate error, delete incomplete tenant, retry."
        )
        logger.critical(error_msg)
        # FAIL HARD - Don't allow partial tenant state
        raise RuntimeError(error_msg) from e

    # Step 2: Create Site object within tenant schema
    try:
        # Use tenant's schema context to create the Site in the correct schema
        with schema_context(tenant.schema_name):
            # Get the tenant's primary domain
            primary_domain = tenant.get_primary_domain()

            # Use primary domain if exists, otherwise construct from schema name
            if primary_domain:
                domain_name = primary_domain.domain
            else:
                # Use environment-based domain construction
                from core.domain import get_primary_domain
                base_domain = get_primary_domain()
                domain_name = f"{tenant.schema_name}.{base_domain}"

            # Create or update the Site for this tenant
            site, created = Site.objects.update_or_create(
                pk=1,  # Use pk=1 to match SITE_ID setting
                defaults={
                    'domain': domain_name,
                    'name': tenant.name or tenant.schema_name.title()
                }
            )

            if created:
                logger.info(f"✅ Created Site for tenant {tenant.schema_name}: {domain_name}")
            else:
                logger.info(f"✅ Updated Site for tenant {tenant.schema_name}: {domain_name}")
    except Exception as e:
        error_msg = (
            f"❌ CRITICAL ERROR creating Site object for tenant '{tenant.schema_name}':\n"
            f"   Error: {type(e).__name__}: {str(e)}\n"
            f"   Migrations succeeded but Site creation failed.\n"
            f"   Required action: Check django.contrib.sites configuration."
        )
        logger.critical(error_msg)
        # FAIL HARD
        raise RuntimeError(error_msg) from e
