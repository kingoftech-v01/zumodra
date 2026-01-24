"""
Projects Celery Tasks - Async operations.

This module defines Celery tasks for:
- Syncing projects to public catalog
- Updating provider stats
- Sending notifications
- Periodic cleanup

All tasks are async and retried on failure.
"""

from celery import shared_task
from django.utils import timezone
from django.db import transaction


@shared_task(bind=True, max_retries=3)
def sync_project_to_public_catalog(self, project_id):
    """
    Sync published project to public catalog.

    Creates or updates PublicProjectCatalog entry with denormalized data.

    Args:
        project_id: ID of Project instance to sync

    Retries: 3 times with exponential backoff
    """
    from .models import Project
    from projects_public.models import PublicProjectCatalog

    try:
        # Get project from tenant schema
        project = Project.objects.select_related('category', 'tenant').get(id=project_id)

        # Only sync if published and open
        if not project.is_published or project.status != Project.Status.OPEN:
            # If exists in catalog but shouldn't, remove it
            PublicProjectCatalog.objects.filter(
                tenant_id=project.tenant.id,
                tenant_project_id=project.id
            ).delete()
            return

        # Build denormalized data
        catalog_data = {
            'tenant_project_id': project.id,
            'tenant_id': project.tenant.id,
            'tenant_schema': project.tenant.schema_name,

            # Project info
            'title': project.title,
            'description': project.description,
            'short_description': project.short_description or project.description[:500],

            # Classification
            'category_name': project.category.name,
            'category_slug': project.category.slug,
            'required_skills': project.required_skills,
            'experience_level': project.experience_level,

            # Timeline
            'start_date': project.start_date,
            'end_date': project.end_date,
            'estimated_duration_weeks': project.estimated_duration_weeks,
            'deadline': project.deadline,

            # Budget
            'budget_type': project.budget_type,
            'budget_min': project.budget_min,
            'budget_max': project.budget_max,
            'budget_currency': project.budget_currency,

            # Location
            'location_type': project.location_type,
            'location_city': project.location_city,
            'location_country': project.location_country,

            # Company info
            'company_name': project.tenant.name,
            'company_logo_url': project.tenant.logo.url if project.tenant.logo else '',
            'company_domain': project.tenant.get_primary_domain().domain if project.tenant.get_primary_domain() else '',

            # Application
            'max_proposals': project.max_proposals,
            'proposal_count': project.proposal_count,
            'proposal_deadline': project.proposal_deadline,

            # Status
            'is_open': project.status == Project.Status.OPEN,
            'is_featured': False,  # Can be set manually in admin

            # Publication
            'published_at': project.published_at or timezone.now(),

            # SEO metadata
            'meta_title': f"{project.title} - {project.tenant.name}",
            'meta_description': project.short_description or project.description[:300],
        }

        # Create or update catalog entry
        catalog_entry, created = PublicProjectCatalog.objects.update_or_create(
            tenant_id=project.tenant.id,
            tenant_project_id=project.id,
            defaults=catalog_data
        )

        # Mark project as synced
        project.published_to_catalog = True
        project.save(update_fields=['published_to_catalog'])

        action = 'created' if created else 'updated'
        return f"Project {project.id} {action} in public catalog"

    except Project.DoesNotExist:
        return f"Project {project_id} not found"
    except Exception as exc:
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task
def remove_project_from_catalog(project_id):
    """
    Remove project from public catalog.

    Args:
        project_id: ID of Project instance to remove
    """
    from .models import Project
    from projects_public.models import PublicProjectCatalog

    try:
        project = Project.objects.get(id=project_id)

        # Remove from catalog
        deleted_count, _ = PublicProjectCatalog.objects.filter(
            tenant_id=project.tenant.id,
            tenant_project_id=project.id
        ).delete()

        # Update project
        project.published_to_catalog = False
        project.save(update_fields=['published_to_catalog'])

        return f"Removed {deleted_count} catalog entries for project {project_id}"

    except Project.DoesNotExist:
        # Project deleted, just remove from catalog by ID
        deleted_count, _ = PublicProjectCatalog.objects.filter(
            tenant_project_id=project_id
        ).delete()
        return f"Removed {deleted_count} orphaned catalog entries"


@shared_task
def update_provider_stats(provider_id):
    """
    Recalculate provider statistics after review submission.

    Updates:
    - Average rating
    - Total reviews
    - Completed projects count

    Args:
        provider_id: ID of ProjectProvider instance
    """
    from .models import ProjectProvider, ProjectReview, Project
    from django.db.models import Avg, Count, Q

    try:
        provider = ProjectProvider.objects.get(id=provider_id)

        # Get all reviews where this provider was reviewed
        provider_reviews = ProjectReview.objects.filter(
            project__assigned_provider=provider,
            reviewer_type=ProjectReview.ReviewerType.CLIENT
        )

        # Calculate average rating
        avg_rating = provider_reviews.aggregate(avg=Avg('rating'))['avg']

        # Count reviews and completed projects
        total_reviews = provider_reviews.count()
        completed_projects = Project.objects.filter(
            assigned_provider=provider,
            status=Project.Status.COMPLETED
        ).count()

        # Update provider
        provider.average_rating = avg_rating
        provider.total_reviews = total_reviews
        provider.completed_projects = completed_projects
        provider.save(update_fields=[
            'average_rating',
            'total_reviews',
            'completed_projects'
        ])

        return f"Updated stats for provider {provider_id}: {total_reviews} reviews, {avg_rating:.2f} avg rating"

    except ProjectProvider.DoesNotExist:
        return f"Provider {provider_id} not found"


@shared_task
def update_project_category_counts():
    """
    Update project counts for all categories.

    Periodic task (run daily via Celery Beat).
    """
    from .models import ProjectCategory, Project

    for category in ProjectCategory.objects.all():
        # Count published projects in this category
        count = Project.objects.filter(
            category=category,
            is_published=True,
            status=Project.Status.OPEN
        ).count()

        category.project_count = count
        category.save(update_fields=['project_count'])

    return f"Updated counts for {ProjectCategory.objects.count()} categories"


@shared_task
def close_expired_projects():
    """
    Close projects past their proposal deadline.

    Periodic task (run hourly via Celery Beat).
    """
    from .models import Project

    now = timezone.now()

    # Find projects with expired proposal deadlines
    expired_projects = Project.objects.filter(
        status=Project.Status.OPEN,
        proposal_deadline__lt=now,
        is_published=True
    )

    updated_count = 0
    for project in expired_projects:
        project.status = Project.Status.DRAFT
        project.is_published = False
        project.save(update_fields=['status', 'is_published'])
        updated_count += 1

        # This will trigger signal to remove from public catalog

    return f"Closed {updated_count} expired projects"


@shared_task
def generate_public_project_stats():
    """
    Generate daily statistics snapshot for public project catalog.

    Periodic task (run daily via Celery Beat).
    """
    from projects_public.models import PublicProjectCatalog, PublicProjectStats
    from django.db.models import Avg, Count

    today = timezone.now().date()

    # Aggregate stats
    total_projects = PublicProjectCatalog.objects.count()
    open_projects = PublicProjectCatalog.objects.filter(is_open=True).count()
    total_companies = PublicProjectCatalog.objects.values('tenant_id').distinct().count()

    # By category
    by_category = dict(
        PublicProjectCatalog.objects.filter(is_open=True)
        .values('category_name')
        .annotate(count=Count('id'))
        .values_list('category_name', 'count')
    )

    # By country
    by_country = dict(
        PublicProjectCatalog.objects.filter(is_open=True)
        .exclude(location_country='')
        .values('location_country')
        .annotate(count=Count('id'))
        .values_list('location_country', 'count')
    )

    # Budget ranges
    by_budget_range = {
        '0-1000': PublicProjectCatalog.objects.filter(
            is_open=True,
            budget_max__lte=1000
        ).count(),
        '1000-5000': PublicProjectCatalog.objects.filter(
            is_open=True,
            budget_max__gt=1000,
            budget_max__lte=5000
        ).count(),
        '5000-10000': PublicProjectCatalog.objects.filter(
            is_open=True,
            budget_max__gt=5000,
            budget_max__lte=10000
        ).count(),
        '10000+': PublicProjectCatalog.objects.filter(
            is_open=True,
            budget_max__gt=10000
        ).count(),
    }

    # Averages
    avg_stats = PublicProjectCatalog.objects.filter(is_open=True).aggregate(
        avg_budget=Avg('budget_max'),
        avg_duration=Avg('estimated_duration_weeks'),
        avg_proposals=Avg('proposal_count')
    )

    # Create or update stats
    stats, created = PublicProjectStats.objects.update_or_create(
        snapshot_date=today,
        defaults={
            'total_projects': total_projects,
            'open_projects': open_projects,
            'total_companies': total_companies,
            'by_category': by_category,
            'by_country': by_country,
            'by_budget_range': by_budget_range,
            'avg_budget': avg_stats['avg_budget'],
            'avg_duration_weeks': avg_stats['avg_duration'],
            'avg_proposals_per_project': avg_stats['avg_proposals'],
        }
    )

    action = 'created' if created else 'updated'
    return f"Stats {action} for {today}: {open_projects} open projects"
