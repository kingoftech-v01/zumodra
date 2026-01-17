"""
ATS Public Catalog Celery Tasks.

Handles syncing JobPosting instances from tenant schemas to public catalog.

Tasks:
    - sync_job_to_public: Sync a job to public catalog
    - remove_job_from_public: Remove a job from public catalog
    - bulk_sync_all_public_jobs: Initial sync of all public jobs
"""

import logging
from typing import Dict, Any, Optional

from celery import shared_task
from django.db import connection
from django.utils import timezone
from django_tenants.utils import get_tenant_model

logger = logging.getLogger(__name__)


def sanitize_html(html_content: str) -> str:
    """
    Sanitize HTML content to prevent XSS attacks.

    Uses nh3 (Rust-based sanitizer) for security.
    Allows safe tags only for job descriptions.
    """
    try:
        import nh3
        return nh3.clean(
            html_content,
            tags={'p', 'br', 'strong', 'em', 'b', 'i', 'u', 'ul', 'ol', 'li', 'h2', 'h3'},
            attributes={'a': {'href'}},
            link_rel='nofollow noopener noreferrer'
        )
    except ImportError:
        # Fallback: strip all HTML if nh3 not available
        import re
        return re.sub(r'<[^>]+>', '', html_content)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def sync_job_to_public(self, job_id: str, tenant_schema_name: str) -> Dict[str, Any]:
    """
    Sync a job from tenant schema to public catalog.

    Args:
        job_id: UUID of JobPosting in tenant schema
        tenant_schema_name: Schema name of source tenant

    Returns:
        Dict with status and details
    """
    from ats.models import JobPosting
    from ats_public.models import PublicJobCatalog
    from tenants.context import public_schema_context

    try:
        # Step 1: Switch to tenant schema and fetch job
        Tenant = get_tenant_model()
        tenant = Tenant.objects.get(schema_name=tenant_schema_name)
        connection.set_tenant(tenant)

        job = JobPosting.objects.get(id=job_id)

        # Step 2: Extract data for public catalog
        catalog_data = {
            'jobposting_uuid': job.uuid,
            'tenant_id': tenant.id,
            'tenant_schema_name': tenant_schema_name,
            'company_name': tenant.name,
            'company_logo_url': tenant.logo.url if tenant.logo else '',
            'title': job.title,
            'description_html': sanitize_html(job.description) if job.description else '',
            'employment_type': job.job_type or '',
            'location_city': job.location_city or '',
            'location_state': job.location_state or '',
            'location_country': job.location_country or '',
            'is_remote': job.remote_policy in ['remote', 'hybrid'] if hasattr(job, 'remote_policy') else False,
            'salary_min': job.salary_min,
            'salary_max': job.salary_max,
            'salary_currency': job.salary_currency or 'CAD',
            'category_names': [job.category.name] if job.category else [],
            'category_slugs': [job.category.slug] if job.category else [],
            'required_skills': job.required_skills if hasattr(job, 'required_skills') else [],
            'published_at': job.published_at if job.published_at else job.created_at,
            'application_url': f"https://{tenant.domain_url}/careers/jobs/{job.uuid}/apply/",
        }

        # Step 3: Switch to public schema and update catalog
        with public_schema_context():
            PublicJobCatalog.objects.update_or_create(
                jobposting_uuid=job.uuid,
                defaults=catalog_data
            )

        logger.info(f"Synced job {job.uuid} to public catalog from {tenant_schema_name}")
        return {'status': 'success', 'job_uuid': str(job.uuid)}

    except JobPosting.DoesNotExist:
        logger.error(f"Job {job_id} not found in {tenant_schema_name}")
        return {'status': 'error', 'reason': 'job_not_found'}
    except Tenant.DoesNotExist:
        logger.error(f"Tenant {tenant_schema_name} not found")
        return {'status': 'error', 'reason': 'tenant_not_found'}
    except Exception as e:
        logger.error(f"Failed to sync job {job_id}: {e}", exc_info=True)
        raise self.retry(exc=e)


@shared_task(bind=True)
def remove_job_from_public(self, job_id: str, tenant_schema_name: str) -> Dict[str, Any]:
    """
    Remove job from public catalog.

    Args:
        job_id: UUID of JobPosting in tenant schema
        tenant_schema_name: Schema name of source tenant

    Returns:
        Dict with status and deleted count
    """
    from ats.models import JobPosting
    from ats_public.models import PublicJobCatalog
    from tenants.context import public_schema_context

    try:
        # Switch to tenant to get UUID
        Tenant = get_tenant_model()
        tenant = Tenant.objects.get(schema_name=tenant_schema_name)
        connection.set_tenant(tenant)

        try:
            job = JobPosting.objects.get(id=job_id)
            job_uuid = job.uuid
        except JobPosting.DoesNotExist:
            # Job already deleted, try to remove by job_id (if it's a UUID)
            job_uuid = job_id

        # Remove from public catalog
        with public_schema_context():
            deleted_count, _ = PublicJobCatalog.objects.filter(
                jobposting_uuid=job_uuid
            ).delete()

        logger.info(f"Removed job {job_uuid} from public catalog ({deleted_count} entries)")
        return {'status': 'success', 'deleted_count': deleted_count}

    except Exception as e:
        logger.error(f"Failed to remove job {job_id}: {e}", exc_info=True)
        return {'status': 'error', 'reason': str(e)}


@shared_task(bind=True)
def bulk_sync_all_public_jobs(self) -> Dict[str, Any]:
    """
    Bulk sync all published jobs from all tenants to public catalog.

    This is for initial sync or recovery. Run manually via:
        python manage.py shell
        >>> from ats_public.tasks import bulk_sync_all_public_jobs
        >>> bulk_sync_all_public_jobs.delay()

    Returns:
        Dict with sync stats
    """
    from ats.models import JobPosting
    from tenants.context import public_schema_context

    Tenant = get_tenant_model()
    synced_count = 0
    error_count = 0

    # Iterate through all tenants
    for tenant in Tenant.objects.exclude(schema_name='public'):
        try:
            connection.set_tenant(tenant)

            # Find all published jobs
            public_jobs = JobPosting.objects.filter(
                published_on_career_page=True,
                is_internal_only=False
            )

            for job in public_jobs:
                try:
                    # Trigger sync task for each job
                    sync_job_to_public.delay(str(job.id), tenant.schema_name)
                    synced_count += 1
                except Exception as e:
                    logger.error(f"Failed to sync job {job.id} from {tenant.schema_name}: {e}")
                    error_count += 1

        except Exception as e:
            logger.error(f"Failed to process tenant {tenant.schema_name}: {e}")
            error_count += 1

    logger.info(f"Bulk sync complete: {synced_count} jobs synced, {error_count} errors")
    return {
        'status': 'success',
        'synced_count': synced_count,
        'error_count': error_count
    }
