"""
Job Catalog Sync Service

Synchronizes JobPosting data from tenant schemas to PublicJobCatalog (public schema).
"""

import logging
from django.db import connection
from django_tenants.utils import get_tenant_model

logger = logging.getLogger(__name__)


class JobCatalogSyncService:
    """
    Sync service for JobPosting → PublicJobCatalog.

    Handles denormalization of tenant job data to public catalog for
    cross-tenant browsing without schema context.
    """

    @classmethod
    def sync_job(cls, job_posting):
        """
        Sync a single JobPosting to PublicJobCatalog.

        Args:
            job_posting: JobPosting instance from tenant schema

        Returns:
            PublicJobCatalog instance (created or updated)
        """
        from tenants.models import PublicJobCatalog

        try:
            # Get current tenant
            tenant = get_tenant_model().objects.get(schema_name=connection.schema_name)

            # Prepare denormalized data
            data = {
                'tenant_schema_name': tenant.schema_name,
                'tenant': tenant,
                'title': job_posting.title,
                'description': job_posting.description,
                'location': job_posting.location or '',
                'job_type': job_posting.job_type or 'full_time',
                'is_remote': job_posting.remote_work_allowed if hasattr(job_posting, 'remote_work_allowed') else False,
                'salary_min': job_posting.salary_min,
                'salary_max': job_posting.salary_max,
                'salary_currency': job_posting.salary_currency if hasattr(job_posting, 'salary_currency') else 'USD',
                'show_salary': job_posting.show_salary if hasattr(job_posting, 'show_salary') else True,
                'company_name': tenant.name,
                'is_active': job_posting.status == 'open',
                'published_at': job_posting.created_at,
                'expires_at': job_posting.expires_at if hasattr(job_posting, 'expires_at') else None,
            }

            # Add category information if available
            if hasattr(job_posting, 'category') and job_posting.category:
                data['category_name'] = job_posting.category.name
                data['category_slug'] = job_posting.category.slug

            # Check if job has public_listing relationship
            if hasattr(job_posting, 'public_listing'):
                listing = job_posting.public_listing
                data['is_featured'] = listing.is_featured if hasattr(listing, 'is_featured') else False

            # Update or create in public catalog
            catalog_entry, created = PublicJobCatalog.objects.update_or_create(
                job_id=job_posting.id,
                defaults=data
            )

            action = "created" if created else "updated"
            logger.info(
                f"PublicJobCatalog {action}: {job_posting.title} "
                f"(job_id={job_posting.id}, tenant={tenant.schema_name})"
            )

            return catalog_entry

        except Exception as e:
            logger.error(
                f"Failed to sync job {job_posting.id} to PublicJobCatalog: {e}",
                exc_info=True
            )
            raise

    @classmethod
    def remove_job(cls, job_id):
        """
        Remove a job from PublicJobCatalog.

        Args:
            job_id: UUID of the job to remove

        Returns:
            int: Number of entries deleted
        """
        from tenants.models import PublicJobCatalog

        try:
            deleted_count, _ = PublicJobCatalog.objects.filter(job_id=job_id).delete()

            if deleted_count > 0:
                logger.info(f"Removed job {job_id} from PublicJobCatalog")
            else:
                logger.warning(f"Job {job_id} not found in PublicJobCatalog")

            return deleted_count

        except Exception as e:
            logger.error(
                f"Failed to remove job {job_id} from PublicJobCatalog: {e}",
                exc_info=True
            )
            raise

    @classmethod
    def sync_all_jobs_for_tenant(cls, tenant_schema_name):
        """
        Sync all active jobs for a specific tenant.

        Args:
            tenant_schema_name: Schema name of the tenant

        Returns:
            dict: Statistics (synced, failed, removed)
        """
        from ats.models import JobPosting
        from django_tenants.utils import schema_context

        stats = {'synced': 0, 'failed': 0, 'removed': 0}

        try:
            with schema_context(tenant_schema_name):
                # Get all jobs that should be in public catalog
                active_jobs = JobPosting.objects.filter(
                    status='open',
                    published_on_career_page=True
                )

                for job in active_jobs:
                    try:
                        cls.sync_job(job)
                        stats['synced'] += 1
                    except Exception as e:
                        logger.error(f"Failed to sync job {job.id}: {e}")
                        stats['failed'] += 1

                # Get IDs of jobs that should be in catalog
                active_job_ids = set(active_jobs.values_list('id', flat=True))

                # Remove jobs that are no longer active/published
                from tenants.models import PublicJobCatalog
                catalog_entries = PublicJobCatalog.objects.filter(
                    tenant_schema_name=tenant_schema_name
                )

                for entry in catalog_entries:
                    if entry.job_id not in active_job_ids:
                        entry.delete()
                        stats['removed'] += 1

            logger.info(
                f"Sync complete for tenant {tenant_schema_name}: "
                f"{stats['synced']} synced, {stats['failed']} failed, {stats['removed']} removed"
            )

        except Exception as e:
            logger.error(
                f"Failed to sync jobs for tenant {tenant_schema_name}: {e}",
                exc_info=True
            )
            raise

        return stats
