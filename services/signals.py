"""
Services Signals

Django signal handlers for services models.

Handles:
- Service sync to PublicService catalog when is_public=True
- Service removal from catalog when deleted or is_public=False
- Related model changes (images, pricing tiers) trigger parent service re-sync
"""

from django.db.models.signals import post_save, post_delete, pre_delete
from django.dispatch import receiver
from django.core.cache import cache
from django.db import connection
from django_tenants.utils import get_public_schema_name
import logging

logger = logging.getLogger(__name__)


# ==================== SERVICE PUBLIC CATALOG SYNC ====================


@receiver(post_save, sender='services.Service')
def sync_service_to_public_catalog_on_save(sender, instance, created, raw, **kwargs):
    """
    Sync Service to PublicService catalog when is_public=True.

    Triggers:
        - Service created with is_public=True → queue sync task
        - Service updated and is_public=True → queue re-sync task
        - Service updated and is_public=False → queue removal task

    Security:
        - Skip if in public schema (prevent circular signals)
        - Skip if raw=True (fixtures/migrations)
        - Only sync if is_public=True AND is_active=True
        - Provider must have marketplace_enabled=True
    """
    # Prevent circular signals: skip if already in public schema
    if connection.schema_name == get_public_schema_name():
        logger.debug(f"Skipping service sync signal: already in public schema")
        return

    # Skip during fixture loading or migrations
    if raw:
        logger.debug(f"Skipping service sync signal: raw=True (fixture/migration)")
        return

    # Import here to avoid circular imports
    from tenants.models import Tenant
    from .tasks import sync_service_to_public_catalog_task, remove_service_from_public_catalog_task

    try:
        # Get current tenant
        tenant = Tenant.objects.get(schema_name=connection.schema_name)

        # Determine action based on is_public flag
        if instance.is_public and instance.is_active:
            # Check provider conditions
            if hasattr(instance, 'provider') and instance.provider:
                if instance.provider.marketplace_enabled and instance.provider.is_active:
                    # Queue sync task
                    sync_service_to_public_catalog_task.delay(
                        str(instance.uuid),
                        tenant.schema_name,
                        tenant.id
                    )
                    logger.info(
                        f"Queued sync task for service {instance.uuid} "
                        f"from tenant {tenant.schema_name}"
                    )
                else:
                    logger.debug(
                        f"Service {instance.uuid} provider not eligible for marketplace "
                        f"(marketplace_enabled={instance.provider.marketplace_enabled}, "
                        f"is_active={instance.provider.is_active})"
                    )
            else:
                logger.warning(
                    f"Service {instance.uuid} has no provider, cannot sync to catalog"
                )
        else:
            # Service is not public or not active, remove from catalog if exists
            remove_service_from_public_catalog_task.delay(
                str(instance.uuid),
                tenant.schema_name
            )
            logger.info(
                f"Queued removal task for service {instance.uuid} "
                f"from tenant {tenant.schema_name} "
                f"(is_public={instance.is_public}, is_active={instance.is_active})"
            )

    except Tenant.DoesNotExist:
        logger.error(
            f"Tenant not found for schema {connection.schema_name} "
            f"when syncing service {instance.uuid}"
        )
    except Exception as e:
        logger.error(
            f"Error in service sync signal for {instance.uuid}: {e}",
            exc_info=True
        )


@receiver(pre_delete, sender='services.Service')
def remove_service_from_public_catalog_on_delete(sender, instance, **kwargs):
    """
    Remove Service from PublicService catalog when deleted.

    Triggers:
        - Service deleted → queue removal task

    Security:
        - Skip if in public schema (prevent circular signals)
        - Removal is idempotent (safe even if not in catalog)
    """
    # Prevent circular signals: skip if already in public schema
    if connection.schema_name == get_public_schema_name():
        logger.debug(f"Skipping service deletion signal: already in public schema")
        return

    # Import here to avoid circular imports
    from .tasks import remove_service_from_public_catalog_task

    try:
        # Queue removal task (idempotent, safe even if not in catalog)
        remove_service_from_public_catalog_task.delay(
            str(instance.uuid),
            connection.schema_name
        )
        logger.info(
            f"Queued removal task for deleted service {instance.uuid} "
            f"from tenant {connection.schema_name}"
        )
    except Exception as e:
        logger.error(
            f"Error in service deletion signal for {instance.uuid}: {e}",
            exc_info=True
        )


# ==================== RELATED MODEL CHANGES → RE-SYNC PARENT SERVICE ====================


@receiver(post_save, sender='services.ServiceImage')
def resync_service_on_image_change(sender, instance, created, raw, **kwargs):
    """
    Re-sync parent service when ServiceImage is added/updated.

    Triggers:
        - ServiceImage created → re-sync parent service
        - ServiceImage updated → re-sync parent service

    This ensures the public catalog reflects the latest images.
    """
    # Skip if in public schema or during fixture loading
    if connection.schema_name == get_public_schema_name() or raw:
        return

    if not hasattr(instance, 'service') or not instance.service:
        logger.debug(f"ServiceImage {instance.id} has no parent service, skipping re-sync")
        return

    # Import here to avoid circular imports
    from tenants.models import Tenant
    from .tasks import sync_service_to_public_catalog_task

    try:
        service = instance.service

        # Only re-sync if service is public
        if service.is_public and service.is_active:
            tenant = Tenant.objects.get(schema_name=connection.schema_name)

            sync_service_to_public_catalog_task.delay(
                str(service.uuid),
                tenant.schema_name,
                tenant.id
            )
            logger.info(
                f"Queued re-sync task for service {service.uuid} "
                f"after image {'created' if created else 'updated'}"
            )

    except Tenant.DoesNotExist:
        logger.error(
            f"Tenant not found for schema {connection.schema_name} "
            f"when re-syncing service after image change"
        )
    except Exception as e:
        logger.error(
            f"Error re-syncing service after image change: {e}",
            exc_info=True
        )


@receiver(post_save, sender='services.ServicePricingTier')
def resync_service_on_pricing_tier_change(sender, instance, created, raw, **kwargs):
    """
    Re-sync parent service when ServicePricingTier is added/updated.

    Triggers:
        - ServicePricingTier created → re-sync parent service
        - ServicePricingTier updated → re-sync parent service

    This ensures the public catalog reflects the latest pricing tiers.
    """
    # Skip if in public schema or during fixture loading
    if connection.schema_name == get_public_schema_name() or raw:
        return

    if not hasattr(instance, 'service') or not instance.service:
        logger.debug(f"ServicePricingTier {instance.id} has no parent service, skipping re-sync")
        return

    # Import here to avoid circular imports
    from tenants.models import Tenant
    from .tasks import sync_service_to_public_catalog_task

    try:
        service = instance.service

        # Only re-sync if service is public
        if service.is_public and service.is_active:
            tenant = Tenant.objects.get(schema_name=connection.schema_name)

            sync_service_to_public_catalog_task.delay(
                str(service.uuid),
                tenant.schema_name,
                tenant.id
            )
            logger.info(
                f"Queued re-sync task for service {service.uuid} "
                f"after pricing tier {'created' if created else 'updated'}"
            )

    except Tenant.DoesNotExist:
        logger.error(
            f"Tenant not found for schema {connection.schema_name} "
            f"when re-syncing service after pricing tier change"
        )
    except Exception as e:
        logger.error(
            f"Error re-syncing service after pricing tier change: {e}",
            exc_info=True
        )
