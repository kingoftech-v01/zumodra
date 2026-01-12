"""
Job sync service for PublicJobCatalog.

Handles bidirectional synchronization between JobPosting (tenant schemas)
and PublicJobCatalog (public schema) for the careers page.
"""

import logging
from typing import Optional

from core.sync.base import PublicSyncService

logger = logging.getLogger(__name__)


class JobPublicSyncService(PublicSyncService):
    """
    Sync service for JobPosting → PublicJobCatalog.

    Sync Conditions:
        - published_on_career_page = True
        - is_internal_only = False
        - status = 'open'

    Field Mapping:
        - Denormalizes 26 safe fields from JobPosting
        - Conditionally includes salary (only if show_salary=True)
        - Excludes sensitive fields (hiring manager, internal notes, etc.)
        - Sanitizes HTML in description fields

    Usage:
        sync_service = JobPublicSyncService()

        # Check if job should sync
        if sync_service.should_sync(job):
            # Sync to public catalog
            catalog_entry = sync_service.sync_to_public(job)

        # Remove from catalog
        sync_service.remove_from_public(job)
    """

    def __init__(self):
        """Initialize with model and mapping configuration."""
        # Import here to avoid circular imports
        from tenants.models import PublicJobCatalog
        from ats.models import JobPosting

        self.public_model = PublicJobCatalog
        self.tenant_model = JobPosting

        # Field mapping: public_field -> source (field name or callable)
        self.field_mapping = {
            # Identity
            'uuid': 'uuid',
            'job_uuid': 'uuid',

            # Basic Job Info
            'title': 'title',
            'slug': 'slug',
            'reference_code': 'reference_code',

            # Category (denormalized)
            'category_name': lambda job: job.category.name if job.category else '',
            'category_slug': lambda job: job.category.slug if job.category else '',

            # Classification
            'job_type': 'job_type',
            'experience_level': 'experience_level',
            'remote_policy': 'remote_policy',

            # Location
            'location_city': 'location_city',
            'location_state': 'location_state',
            'location_country': 'location_country',
            'location_coordinates': 'location_coordinates',

            # Descriptions (will be HTML sanitized)
            'description': 'description',
            'responsibilities': 'responsibilities',
            'requirements': 'requirements',
            'nice_to_have': 'nice_to_have',
            'benefits': 'benefits',

            # Compensation (conditional on show_salary)
            'salary_min': lambda job: job.salary_min if job.show_salary else None,
            'salary_max': lambda job: job.salary_max if job.show_salary else None,
            'salary_currency': 'salary_currency',
            'salary_period': 'salary_period',
            'show_salary': 'show_salary',

            # Skills (ArrayField in JobPosting, JSONField in catalog)
            'required_skills': lambda job: list(job.required_skills) if job.required_skills else [],
            'preferred_skills': lambda job: list(job.preferred_skills) if job.preferred_skills else [],

            # Hiring Details
            'positions_count': 'positions_count',
            'team': 'team',

            # Company Info (from tenant)
            'company_name': lambda job: job.tenant.name if job.tenant else '',
            'company_logo_url': lambda job: job.tenant.logo.url if (job.tenant and job.tenant.logo) else '',

            # Visibility
            'is_featured': 'is_featured',

            # Deadlines
            'application_deadline': 'application_deadline',
            'published_at': lambda job: job.published_at or job.created_at,

            # SEO
            'meta_title': 'meta_title',
            'meta_description': 'meta_description',
        }

        # Sync conditions - ALL must be True for sync to happen
        self.sync_conditions = [
            lambda job: getattr(job, 'published_on_career_page', False) == True,
            lambda job: getattr(job, 'is_internal_only', True) == False,
            lambda job: getattr(job, 'status', None) == 'open',
        ]

        # Call parent init for validation
        super().__init__()

    def sync_to_public(self, instance, created: bool = False):
        """
        Override to add custom post-sync actions.

        Updates JobPosting with sync status metadata after successful sync.
        """
        catalog_entry = super().sync_to_public(instance, created)

        if catalog_entry:
            # Update source JobPosting with sync metadata
            # Use update() instead of save() to avoid triggering signals again
            try:
                from ats.models import JobPosting
                from django.utils import timezone

                JobPosting.objects.filter(pk=instance.pk).update(
                    # Assuming these fields exist (will be added in migration)
                    # published_to_catalog=True,
                    # catalog_synced_at=timezone.now(),
                )
                logger.debug(f"Updated sync metadata for job {instance.uuid}")

            except Exception as e:
                # Non-critical - sync was successful even if metadata update failed
                logger.warning(
                    f"Failed to update sync metadata for job {instance.uuid}: {e}"
                )

        return catalog_entry

    def remove_from_public(self, instance) -> int:
        """
        Override to add custom post-removal actions.

        Updates JobPosting sync status after successful removal.
        """
        deleted_count = super().remove_from_public(instance)

        if deleted_count > 0:
            # Update source JobPosting
            try:
                from ats.models import JobPosting

                JobPosting.objects.filter(pk=instance.pk).update(
                    # published_to_catalog=False,
                    # catalog_synced_at=None,
                )
                logger.debug(f"Cleared sync metadata for job {instance.uuid}")

            except Exception as e:
                logger.warning(
                    f"Failed to clear sync metadata for job {instance.uuid}: {e}"
                )

        return deleted_count
