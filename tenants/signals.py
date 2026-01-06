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
def create_tenant_site(sender, tenant, **kwargs):
    """
    Create a Site object for the tenant after its schema is created/synced.
    This is required for django-allauth to function properly in tenant schemas.
    """
    from django.contrib.sites.models import Site

    # Use tenant's schema context to create the Site in the correct schema
    with schema_context(tenant.schema_name):
        # Get the tenant's primary domain
        primary_domain = tenant.get_primary_domain()
        domain_name = primary_domain.domain if primary_domain else f"{tenant.schema_name}.zumodra.rhematek-solutions.com"

        # Create or update the Site for this tenant
        site, created = Site.objects.update_or_create(
            pk=1,  # Use pk=1 to match SITE_ID setting
            defaults={
                'domain': domain_name,
                'name': tenant.name or tenant.schema_name.title()
            }
        )
        if created:
            print(f"Created Site for tenant {tenant.schema_name}: {domain_name}")
