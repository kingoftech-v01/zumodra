"""
Services Public Catalog Celery Tasks.

Handles syncing ServiceProvider instances from tenant schemas to public catalog.

Tasks:
    - sync_provider_to_public: Sync a provider to public catalog
    - remove_provider_from_public: Remove a provider from public catalog
    - bulk_sync_all_public_providers: Initial sync of all public providers
"""

import logging
from typing import Dict, Any, Optional

from celery import shared_task
from django.db import connection
from django.utils import timezone
from django_tenants.utils import get_tenant_model

logger = logging.getLogger(__name__)


def sanitize_html(html_content: str) -> str:
    """Sanitize HTML content to prevent XSS attacks."""
    try:
        import nh3
        return nh3.clean(
            html_content,
            tags={'p', 'br', 'strong', 'em', 'b', 'i', 'u', 'ul', 'ol', 'li'},
            attributes={'a': {'href'}},
            link_rel='nofollow noopener noreferrer'
        )
    except ImportError:
        import re
        return re.sub(r'<[^>]+>', '', html_content)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def sync_provider_to_public(self, provider_id: str, tenant_schema_name: str) -> Dict[str, Any]:
    """
    Sync a service provider from tenant schema to public catalog.

    Args:
        provider_id: UUID of ServiceProvider in tenant schema
        tenant_schema_name: Schema name of source tenant

    Returns:
        Dict with status and details
    """
    from services.models import ServiceProvider
    from services_public.models import PublicServiceCatalog
    from tenants.context import public_schema_context

    try:
        # Step 1: Switch to tenant schema and fetch provider
        Tenant = get_tenant_model()
        tenant = Tenant.objects.get(schema_name=tenant_schema_name)
        connection.set_tenant(tenant)

        provider = ServiceProvider.objects.get(id=provider_id)

        # Step 2: Extract data for public catalog
        catalog_data = {
            'provider_uuid': provider.uuid,
            'tenant_id': tenant.id,
            'tenant_schema_name': tenant_schema_name,
            'provider_name': provider.display_name or provider.user.get_full_name() or provider.user.email.split('@')[0],
            'provider_avatar_url': provider.user.profile.avatar.url if hasattr(provider.user, 'profile') and provider.user.profile.avatar else '',
            'bio': sanitize_html(provider.bio) if provider.bio else '',
            'tagline': provider.tagline if hasattr(provider, 'tagline') else '',
            'provider_type': provider.provider_type if hasattr(provider, 'provider_type') else 'individual',
            'location_city': provider.city if hasattr(provider, 'city') else '',
            'location_state': provider.state if hasattr(provider, 'state') else '',
            'location_country': provider.country if hasattr(provider, 'country') else '',
            'location': provider.location if hasattr(provider, 'location') else None,
            'can_work_remotely': provider.can_work_remotely if hasattr(provider, 'can_work_remotely') else True,
            'can_work_onsite': provider.can_work_onsite if hasattr(provider, 'can_work_onsite') else False,
            'hourly_rate': provider.hourly_rate if hasattr(provider, 'hourly_rate') else None,
            'minimum_budget': provider.minimum_budget if hasattr(provider, 'minimum_budget') else None,
            'currency': provider.currency if hasattr(provider, 'currency') else 'USD',
            'category_names': [cat.name for cat in provider.categories.all()] if hasattr(provider, 'categories') else [],
            'category_slugs': [cat.slug for cat in provider.categories.all()] if hasattr(provider, 'categories') else [],
            'skills_data': _get_skills_data(provider),
            'rating_avg': _get_rating_avg(provider),
            'total_reviews': _get_total_reviews(provider),
            'completed_jobs_count': _get_completed_jobs_count(provider),
            'response_rate': provider.response_rate if hasattr(provider, 'response_rate') else None,
            'avg_response_time_hours': provider.avg_response_time_hours if hasattr(provider, 'avg_response_time_hours') else None,
            'availability_status': provider.availability_status if hasattr(provider, 'availability_status') else 'available',
            'is_verified': provider.user.is_verified if hasattr(provider.user, 'is_verified') else False,
            'is_featured': provider.is_featured if hasattr(provider, 'is_featured') else False,
            'is_accepting_work': provider.is_accepting_work if hasattr(provider, 'is_accepting_work') else True,
            'published_at': provider.created_at if hasattr(provider, 'created_at') else timezone.now(),
            'booking_url': f"https://{tenant.domain_url}/services/{provider.uuid}/book/",
        }

        # Step 3: Switch to public schema and update catalog
        with public_schema_context():
            PublicServiceCatalog.objects.update_or_create(
                provider_uuid=provider.uuid,
                defaults=catalog_data
            )

        logger.info(f"Synced provider {provider.uuid} to public catalog from {tenant_schema_name}")
        return {'status': 'success', 'provider_uuid': str(provider.uuid)}

    except ServiceProvider.DoesNotExist:
        logger.error(f"Provider {provider_id} not found in {tenant_schema_name}")
        return {'status': 'error', 'reason': 'provider_not_found'}
    except Tenant.DoesNotExist:
        logger.error(f"Tenant {tenant_schema_name} not found")
        return {'status': 'error', 'reason': 'tenant_not_found'}
    except Exception as e:
        logger.error(f"Failed to sync provider {provider_id}: {e}", exc_info=True)
        raise self.retry(exc=e)


@shared_task(bind=True)
def remove_provider_from_public(self, provider_id: str, tenant_schema_name: str) -> Dict[str, Any]:
    """
    Remove provider from public catalog.

    Args:
        provider_id: UUID of ServiceProvider in tenant schema
        tenant_schema_name: Schema name of source tenant

    Returns:
        Dict with status and deleted count
    """
    from services.models import ServiceProvider
    from services_public.models import PublicServiceCatalog
    from tenants.context import public_schema_context

    try:
        # Switch to tenant to get UUID
        Tenant = get_tenant_model()
        tenant = Tenant.objects.get(schema_name=tenant_schema_name)
        connection.set_tenant(tenant)

        try:
            provider = ServiceProvider.objects.get(id=provider_id)
            provider_uuid = provider.uuid
        except ServiceProvider.DoesNotExist:
            # Provider already deleted, try to remove by provider_id (if it's a UUID)
            provider_uuid = provider_id

        # Remove from public catalog
        with public_schema_context():
            deleted_count, _ = PublicServiceCatalog.objects.filter(
                provider_uuid=provider_uuid
            ).delete()

        logger.info(f"Removed provider {provider_uuid} from public catalog ({deleted_count} entries)")
        return {'status': 'success', 'deleted_count': deleted_count}

    except Exception as e:
        logger.error(f"Failed to remove provider {provider_id}: {e}", exc_info=True)
        return {'status': 'error', 'reason': str(e)}


@shared_task(bind=True)
def bulk_sync_all_public_providers(self) -> Dict[str, Any]:
    """
    Bulk sync all public providers from all tenants to public catalog.

    This is for initial sync or recovery. Run manually via:
        python manage.py shell
        >>> from services_public.tasks import bulk_sync_all_public_providers
        >>> bulk_sync_all_public_providers.delay()

    Returns:
        Dict with sync stats
    """
    from services.models import ServiceProvider
    from tenants.context import public_schema_context

    Tenant = get_tenant_model()
    synced_count = 0
    error_count = 0

    # Iterate through all tenants
    for tenant in Tenant.objects.exclude(schema_name='public'):
        try:
            connection.set_tenant(tenant)

            # Find all public providers
            public_providers = ServiceProvider.objects.filter(
                marketplace_enabled=True,
                is_active=True
            )

            for provider in public_providers:
                try:
                    # Trigger sync task for each provider
                    sync_provider_to_public.delay(str(provider.id), tenant.schema_name)
                    synced_count += 1
                except Exception as e:
                    logger.error(f"Failed to sync provider {provider.id} from {tenant.schema_name}: {e}")
                    error_count += 1

        except Exception as e:
            logger.error(f"Failed to process tenant {tenant.schema_name}: {e}")
            error_count += 1

    logger.info(f"Bulk sync complete: {synced_count} providers synced, {error_count} errors")
    return {
        'status': 'success',
        'synced_count': synced_count,
        'error_count': error_count
    }


# ===== Helper Functions =====

def _get_skills_data(provider) -> list:
    """Extract skills data from provider."""
    skills_data = []
    try:
        if hasattr(provider, 'skills') and provider.skills:
            if hasattr(provider.skills, 'all'):
                for skill in provider.skills.all():
                    skill_dict = {'name': skill.name}
                    if hasattr(skill, 'level'):
                        skill_dict['level'] = skill.level
                    if hasattr(skill, 'years_experience'):
                        skill_dict['years_experience'] = skill.years_experience
                    skills_data.append(skill_dict)
    except Exception as e:
        logger.debug(f"Could not get skills data: {e}")
    return skills_data


def _get_rating_avg(provider) -> Optional[float]:
    """Get average rating from reviews."""
    try:
        if hasattr(provider, 'rating_avg') and provider.rating_avg:
            return float(provider.rating_avg)

        if hasattr(provider, 'reviews'):
            from django.db.models import Avg
            result = provider.reviews.aggregate(avg=Avg('rating'))
            return float(result['avg']) if result['avg'] else None
    except Exception:
        pass
    return None


def _get_total_reviews(provider) -> int:
    """Get total number of reviews."""
    try:
        if hasattr(provider, 'total_reviews'):
            return int(provider.total_reviews)

        if hasattr(provider, 'reviews'):
            return provider.reviews.count()
    except Exception:
        pass
    return 0


def _get_completed_jobs_count(provider) -> int:
    """Get number of completed jobs."""
    try:
        if hasattr(provider, 'completed_jobs_count'):
            return int(provider.completed_jobs_count)

        if hasattr(provider, 'contracts'):
            return provider.contracts.filter(status='completed').count()
    except Exception:
        pass
    return 0
