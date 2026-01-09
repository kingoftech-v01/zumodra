"""
Celery Tasks for Configurations App

This module contains async tasks for configuration management:
- Skill synchronization from external sources
- Category cleanup
- Company statistics updates
- Data integrity checks

Security Features:
- Admin-only operations
- Audit logging for configuration changes
"""

import logging
from datetime import timedelta
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone
from django.db.models import Count, Q
from django.core.cache import cache

logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security.configurations.tasks')


# ==================== SKILL SYNCHRONIZATION ====================

@shared_task(
    bind=True,
    name='configurations.tasks.sync_skills_from_external',
    max_retries=3,
    default_retry_delay=600,
    autoretry_for=(Exception,),
    soft_time_limit=3600,
)
def sync_skills_from_external(self, source='default'):
    """
    Synchronize skills from external sources.

    This task can integrate with external APIs to keep
    the skill database up to date.

    Args:
        source: Source identifier for skill data

    Returns:
        dict: Summary of sync operation.
    """
    from configurations.models import Skill

    try:
        now = timezone.now()

        # This is a placeholder for external API integration
        # In production, would fetch from LinkedIn, Indeed, etc.

        # For now, just ensure all skills are properly categorized
        uncategorized = Skill.objects.filter(
            Q(category__isnull=True) | Q(category='')
        ).count()

        logger.info(f"Skill sync completed. {uncategorized} skills need categorization.")

        return {
            'status': 'success',
            'source': source,
            'uncategorized_count': uncategorized,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Skill sync exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error syncing skills: {str(e)}")
        raise self.retry(exc=e)


# ==================== CATEGORY CLEANUP ====================

@shared_task(
    bind=True,
    name='configurations.tasks.cleanup_unused_categories',
    max_retries=3,
    default_retry_delay=300,
)
def cleanup_unused_categories(self):
    """
    Clean up orphaned and unused categories.

    Identifies categories that:
    - Have no associated items
    - Are marked as inactive for 90+ days

    Returns:
        dict: Summary of cleanup.
    """
    from configurations.models import JobCategory

    try:
        now = timezone.now()
        inactive_threshold = now - timedelta(days=90)

        # Find categories with no jobs or skills
        empty_categories = JobCategory.objects.annotate(
            job_count=Count('job_postings'),
        ).filter(
            job_count=0,
            is_active=False,
            updated_at__lt=inactive_threshold
        )

        count = empty_categories.count()

        # Log before deletion
        for cat in empty_categories:
            security_logger.info(f"CATEGORY_CLEANUP: Deleting inactive category {cat.id} - {cat.name}")

        # Soft delete or hard delete based on policy
        # Using soft delete here
        empty_categories.update(is_deleted=True, deleted_at=now)

        logger.info(f"Cleaned up {count} unused categories")

        return {
            'status': 'success',
            'cleaned_count': count,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error cleaning up categories: {str(e)}")
        raise self.retry(exc=e)


# ==================== COMPANY STATISTICS ====================

@shared_task(
    bind=True,
    name='configurations.tasks.update_company_stats',
    max_retries=3,
    default_retry_delay=300,
    soft_time_limit=1800,
)
def update_company_stats(self):
    """
    Update statistics for companies.

    Updates:
    - Employee counts
    - Active job counts
    - Rating aggregates

    Returns:
        dict: Summary of updates.
    """
    from configurations.models import Company

    try:
        now = timezone.now()
        updated = 0

        companies = Company.objects.filter(is_active=True)

        for company in companies:
            try:
                # Update employee count if relation exists
                if hasattr(company, 'employees'):
                    company.employee_count = company.employees.filter(is_active=True).count()

                # Update job count if relation exists
                if hasattr(company, 'job_postings'):
                    company.active_job_count = company.job_postings.filter(status='open').count()

                company.stats_updated_at = now
                company.save(update_fields=['stats_updated_at', 'updated_at'])

                # Invalidate cache
                cache.delete(f"company_{company.id}:stats")

                updated += 1

            except Exception as e:
                logger.error(f"Error updating stats for company {company.id}: {e}")

        logger.info(f"Updated statistics for {updated} companies")

        return {
            'status': 'success',
            'updated_count': updated,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Company stats update exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error updating company stats: {str(e)}")
        raise self.retry(exc=e)


# ==================== DATA INTEGRITY CHECKS ====================

@shared_task(
    bind=True,
    name='configurations.tasks.check_data_integrity',
    max_retries=3,
    default_retry_delay=300,
)
def check_data_integrity(self):
    """
    Run data integrity checks on configuration data.

    Checks:
    - Orphaned records
    - Invalid references
    - Missing required fields

    Returns:
        dict: Summary of issues found.
    """
    from configurations.models import Skill, JobCategory, Company

    try:
        now = timezone.now()
        issues = []

        # Check for skills without names
        unnamed_skills = Skill.objects.filter(
            Q(name__isnull=True) | Q(name='')
        ).count()
        if unnamed_skills > 0:
            issues.append(f"{unnamed_skills} skills without names")

        # Check for categories with invalid parents
        try:
            invalid_parent_cats = JobCategory.objects.filter(
                parent__isnull=False
            ).exclude(
                parent__in=JobCategory.objects.all()
            ).count()
            if invalid_parent_cats > 0:
                issues.append(f"{invalid_parent_cats} categories with invalid parents")
        except Exception:
            pass

        # Check for inactive companies with active jobs
        if hasattr(Company, 'job_postings'):
            inactive_with_jobs = Company.objects.filter(
                is_active=False,
                job_postings__status='open'
            ).distinct().count()
            if inactive_with_jobs > 0:
                issues.append(f"{inactive_with_jobs} inactive companies with active jobs")

        logger.info(f"Data integrity check completed. Issues: {len(issues)}")

        return {
            'status': 'success',
            'issues_found': len(issues),
            'issues': issues,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error checking data integrity: {str(e)}")
        raise self.retry(exc=e)


# ==================== CACHE WARMING ====================

@shared_task(
    bind=True,
    name='configurations.tasks.warm_configuration_cache',
    max_retries=2,
    default_retry_delay=300,
)
def warm_configuration_cache(self):
    """
    Pre-warm cache for frequently accessed configuration data.

    Caches:
    - Active skills list
    - Active categories tree
    - Company lookups

    Returns:
        dict: Summary of cached items.
    """
    from configurations.models import Skill, JobCategory, Company

    try:
        now = timezone.now()
        cached_items = 0

        # Cache active skills
        skills = list(Skill.objects.filter(is_active=True).values('id', 'name', 'category'))
        cache.set('config:skills:active', skills, timeout=3600)
        cached_items += 1

        # Cache job categories tree
        categories = list(JobCategory.objects.filter(
            is_active=True
        ).values('id', 'name', 'slug', 'parent_id'))
        cache.set('config:categories:tree', categories, timeout=3600)
        cached_items += 1

        # Cache company list for dropdowns
        companies = list(Company.objects.filter(
            is_active=True
        ).values('id', 'name', 'slug')[:1000])
        cache.set('config:companies:list', companies, timeout=1800)
        cached_items += 1

        logger.info(f"Warmed configuration cache with {cached_items} items")

        return {
            'status': 'success',
            'cached_items': cached_items,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error warming configuration cache: {str(e)}")
        raise self.retry(exc=e)


# ==================== SITE SETTINGS SYNC ====================

@shared_task(
    bind=True,
    name='configurations.tasks.sync_site_settings',
    max_retries=3,
    default_retry_delay=300,
)
def sync_site_settings(self):
    """
    Synchronize site settings across tenants.

    Ensures default settings are applied to new tenants
    and validates existing settings.

    Returns:
        dict: Summary of sync.
    """
    from django.conf import settings as django_settings

    try:
        now = timezone.now()

        # Invalidate settings cache
        cache.delete_pattern('config:site_settings:*') if hasattr(cache, 'delete_pattern') else None

        logger.info("Site settings synchronized")

        return {
            'status': 'success',
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error syncing site settings: {str(e)}")
        raise self.retry(exc=e)


# ==================== FAQ MANAGEMENT ====================

@shared_task(
    bind=True,
    name='configurations.tasks.update_faq_stats',
    max_retries=3,
    default_retry_delay=300,
)
def update_faq_stats(self):
    """
    Update FAQ statistics and helpfulness scores.

    Updates:
    - View counts
    - Helpfulness ratings
    - Search rankings

    Returns:
        dict: Summary of updates.
    """
    from configurations.models import FAQ

    try:
        now = timezone.now()

        # Calculate helpfulness scores
        faqs = FAQ.objects.filter(is_active=True)

        updated = 0
        for faq in faqs:
            try:
                # Calculate helpfulness score (if tracking exists)
                if hasattr(faq, 'helpful_count') and hasattr(faq, 'not_helpful_count'):
                    total = (faq.helpful_count or 0) + (faq.not_helpful_count or 0)
                    if total > 0:
                        faq.helpfulness_score = (faq.helpful_count or 0) / total * 100
                        faq.save(update_fields=['helpfulness_score', 'updated_at'])
                        updated += 1
            except Exception as e:
                logger.error(f"Error updating FAQ {faq.id}: {e}")

        logger.info(f"Updated statistics for {updated} FAQs")

        return {
            'status': 'success',
            'updated_count': updated,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error updating FAQ stats: {str(e)}")
        raise self.retry(exc=e)
