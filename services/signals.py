"""
Service Marketplace Synchronization Signals

Automatically syncs tenant services to public catalog when is_public=True.
Uses Django signals (post_save/post_delete) to maintain consistency between
tenant schemas and the public catalog.

Architecture:
- Service.post_save → sync to PublicServiceCatalog (if is_public=True)
- Service.post_delete → remove from PublicServiceCatalog
- ServiceProvider.post_save → remove all services if marketplace_enabled=False
"""

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.db import connection
from django.utils import timezone
import logging

from .models import Service, ServiceProvider
from tenants.models import PublicServiceCatalog

logger = logging.getLogger(__name__)


@receiver(post_save, sender=Service)
def sync_service_to_public_catalog(sender, instance, created, **kwargs):
    """
    Sync service to public catalog when is_public=True.
    Remove from catalog when is_public=False or is_active=False.

    This signal ensures that the PublicServiceCatalog (in public schema) stays
    in sync with Service models (in tenant schemas). It's triggered every time
    a Service is saved.

    Synchronization Rules:
    1. Service must have is_public=True AND is_active=True
    2. Provider must have marketplace_enabled=True
    3. Tenant schema must be valid (not 'public')
    4. Service data is denormalized (name, price, category, etc.)

    Args:
        sender: Service model class
        instance: Service instance being saved
        created: Boolean indicating if this is a new record
        **kwargs: Additional signal arguments
    """

    # Validate schema (prevent SSRF attacks)
    if connection.schema_name == 'public':
        logger.error("Cannot sync service from public schema - invalid operation")
        return

    # Validate tenant exists
    from tenants.models import Tenant
    try:
        tenant = Tenant.objects.get(schema_name=connection.schema_name)
        if instance.tenant_id != tenant.id:
            logger.error(
                f"Tenant mismatch: service.tenant_id={instance.tenant_id}, "
                f"connection.tenant={tenant.id}"
            )
            return
    except Tenant.DoesNotExist:
        logger.error(f"Invalid tenant schema: {connection.schema_name}")
        return

    # Skip if service is not public or not active
    if not instance.is_public or not instance.is_active:
        # Remove from catalog if exists
        deleted_count, _ = PublicServiceCatalog.objects.filter(
            tenant_schema_name=connection.schema_name,
            service_uuid=instance.uuid
        ).delete()

        if deleted_count > 0:
            logger.info(
                f"Removed service {instance.uuid} from catalog "
                f"(is_public={instance.is_public}, is_active={instance.is_active})"
            )

        # Update service sync status
        Service.objects.filter(pk=instance.pk).update(
            published_to_catalog=False,
            catalog_synced_at=None
        )
        return

    # Provider must have marketplace enabled
    if not instance.provider.marketplace_enabled:
        logger.warning(
            f"Cannot publish service {instance.uuid} - "
            f"provider {instance.provider.uuid} marketplace not enabled"
        )
        return

    # Prepare denormalized catalog data
    try:
        catalog_data = {
            'uuid': instance.uuid,
            'tenant_id': instance.tenant_id,
            'service_uuid': instance.uuid,
            'tenant_schema_name': connection.schema_name,
            'name': instance.name,
            'slug': instance.slug,
            'description': instance.description or '',
            'short_description': instance.short_description or '',
            'category_name': instance.category.name if instance.category else '',
            'category_slug': instance.category.slug if instance.category else '',
            'provider_name': instance.provider.display_name or '',
            'provider_uuid': instance.provider.uuid,
            'service_type': instance.service_type,
            'price': instance.price,
            'price_min': instance.price_min,
            'price_max': instance.price_max,
            'currency': instance.currency,
            'thumbnail_url': instance.thumbnail.url if instance.thumbnail else '',
            'rating_avg': instance.provider.rating_avg,
            'review_count': instance.provider.total_reviews,
            'order_count': instance.order_count,
            'is_active': instance.is_active,
            'is_featured': instance.is_featured,
            'synced_at': timezone.now(),
        }

        # Update or create catalog entry
        catalog_entry, created_entry = PublicServiceCatalog.objects.update_or_create(
            tenant_schema_name=connection.schema_name,
            service_uuid=instance.uuid,
            defaults=catalog_data
        )

        # Update service sync status
        Service.objects.filter(pk=instance.pk).update(
            published_to_catalog=True,
            catalog_synced_at=timezone.now()
        )

        action = 'Created' if created_entry else 'Updated'
        logger.info(
            f"{action} catalog entry for service {instance.uuid} "
            f"from {connection.schema_name}"
        )

    except Exception as e:
        logger.error(
            f"Failed to sync service {instance.uuid} to catalog: {e}",
            exc_info=True
        )


@receiver(post_delete, sender=Service)
def remove_service_from_catalog(sender, instance, **kwargs):
    """
    Remove service from public catalog when deleted from tenant schema.

    Args:
        sender: Service model class
        instance: Service instance being deleted
        **kwargs: Additional signal arguments
    """
    try:
        deleted_count, _ = PublicServiceCatalog.objects.filter(
            tenant_schema_name=connection.schema_name,
            service_uuid=instance.uuid
        ).delete()

        if deleted_count > 0:
            logger.info(
                f"Removed service {instance.uuid} from public catalog "
                f"(tenant deleted service from {connection.schema_name})"
            )
    except Exception as e:
        logger.error(
            f"Failed to remove service {instance.uuid} from catalog: {e}",
            exc_info=True
        )


@receiver(post_save, sender=ServiceProvider)
def handle_provider_marketplace_change(sender, instance, **kwargs):
    """
    Remove all provider's services from catalog when marketplace_enabled=False.

    When a provider disables marketplace access, all their public services
    must be removed from the public catalog. This ensures that providers can
    opt out of the public marketplace at any time.

    Args:
        sender: ServiceProvider model class
        instance: ServiceProvider instance being saved
        **kwargs: Additional signal arguments
    """
    if not instance.marketplace_enabled:
        try:
            # Get all public services from this provider
            public_services = instance.services.filter(is_public=True)

            removed_count = 0
            for service in public_services:
                deleted, _ = PublicServiceCatalog.objects.filter(
                    tenant_schema_name=connection.schema_name,
                    service_uuid=service.uuid
                ).delete()

                if deleted:
                    removed_count += 1

                # Update service sync status
                Service.objects.filter(pk=service.pk).update(
                    published_to_catalog=False,
                    catalog_synced_at=None
                )

            if removed_count > 0:
                logger.info(
                    f"Removed {removed_count} services from catalog "
                    f"(provider {instance.uuid} marketplace disabled in {connection.schema_name})"
                )

        except Exception as e:
            logger.error(
                f"Failed to remove provider {instance.uuid} services from catalog: {e}",
                exc_info=True
            )
