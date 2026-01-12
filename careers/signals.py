"""
Django signals to trigger WebSocket broadcasts for career page updates.
"""

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import JobListing
from tenants.models import Tenant
from .consumers import (
    broadcast_job_created,
    broadcast_job_updated,
    broadcast_job_deleted,
    broadcast_company_created,
    broadcast_company_updated,
)


@receiver(post_save, sender=JobListing)
def job_listing_saved(sender, instance, created, **kwargs):
    """Broadcast job creation/update via WebSocket."""
    # Only broadcast published jobs
    if not hasattr(instance, 'job') or not instance.job:
        return

    job = instance.job

    # Don't broadcast unpublished or internal-only jobs
    if job.status != 'open':
        return

    # Prepare job data for broadcast
    job_data = {
        'id': instance.pk,
        'title': job.title,
        'company': job.tenant.name if hasattr(job, 'tenant') and job.tenant else 'Company',
        'location_city': getattr(job, 'location_city', ''),
        'location_country': getattr(job, 'location_country', ''),
        'location_coordinates': None,
        'job_type': getattr(job, 'job_type', ''),
        'remote_policy': getattr(job, 'remote_policy', ''),
        'salary_min': getattr(job, 'salary_min', None),
        'salary_max': getattr(job, 'salary_max', None),
        'is_featured': getattr(instance, 'is_featured', False),
        'published_at': instance.published_at.isoformat() if hasattr(instance, 'published_at') and instance.published_at else None,
        'url': f"/careers/job/{getattr(instance, 'custom_slug', instance.pk)}/",
    }

    # Add coordinates if available
    if hasattr(job, 'location_coordinates') and job.location_coordinates:
        job_data['location_coordinates'] = {
            'lat': job.location_coordinates.y,
            'lng': job.location_coordinates.x,
        }

    # Add salary range formatting
    if job_data['salary_min'] and job_data['salary_max']:
        job_data['salary_range'] = f"${job_data['salary_min']:,}-${job_data['salary_max']:,}"
    elif job_data['salary_min']:
        job_data['salary_range'] = f"${job_data['salary_min']:,}+"
    else:
        job_data['salary_range'] = None

    # Broadcast
    if created:
        broadcast_job_created(job_data)
    else:
        broadcast_job_updated(job_data)


@receiver(post_delete, sender=JobListing)
def job_listing_deleted(sender, instance, **kwargs):
    """Broadcast job deletion via WebSocket."""
    broadcast_job_deleted(instance.pk)


@receiver(post_save, sender=Tenant)
def tenant_saved(sender, instance, created, **kwargs):
    """Broadcast company creation/update via WebSocket."""
    # Only broadcast active tenants of type COMPANY
    if instance.status != 'active':
        return

    if hasattr(instance, 'tenant_type') and instance.tenant_type == 'freelancer':
        return  # Don't broadcast freelancers on company browse pages

    # Prepare company data for broadcast
    company_data = {
        'id': instance.pk,
        'name': instance.name,
        'slug': instance.slug,
        'city': getattr(instance, 'city', ''),
        'country': getattr(instance, 'country', ''),
        'location_coordinates': None,
        'logo': instance.logo.url if hasattr(instance, 'logo') and instance.logo else None,
        'description': getattr(instance, 'description', ''),
        'open_jobs_count': 0,  # This would need to be calculated
    }

    # Add coordinates if available
    if hasattr(instance, 'location_coordinates') and instance.location_coordinates:
        company_data['location_coordinates'] = {
            'lat': instance.location_coordinates.y,
            'lng': instance.location_coordinates.x,
        }

    # Try to get open jobs count
    try:
        from ats.models import JobPosting
        company_data['open_jobs_count'] = JobPosting.objects.filter(
            tenant=instance,
            status='open'
        ).count()
    except Exception:
        pass

    # Broadcast
    if created:
        broadcast_company_created(company_data)
    else:
        broadcast_company_updated(company_data)


@receiver(post_save, sender='services.Service')
def service_saved(sender, instance, created, **kwargs):
    """Broadcast project/service creation/update via WebSocket."""
    # Only broadcast public/active services
    if not instance.is_active:
        return

    # Import broadcast functions
    from .consumers import broadcast_project_created, broadcast_project_updated

    # Prepare project data for broadcast
    project_data = {
        'id': instance.pk,
        'title': instance.name,
        'description': instance.short_description or instance.description[:200] if instance.description else '',
        'location': 'Remote',  # Services are typically remote
        'location_coordinates': None,
        'budget': float(instance.price) if instance.price else 0,
        'budget_type': instance.service_type,
        'proposals': 0,  # This would need to be calculated if needed
        'created_at': instance.created_at.strftime('%Y-%m-%d') if hasattr(instance, 'created_at') else None,
    }

    # Add provider location if available
    if hasattr(instance, 'provider') and instance.provider:
        provider = instance.provider
        if hasattr(provider, 'city') and provider.city:
            project_data['location'] = f"{provider.city}, {provider.country}" if provider.country else provider.city

        # Add coordinates from provider
        if hasattr(provider, 'location') and provider.location:
            project_data['location_coordinates'] = {
                'lat': provider.location.y,
                'lng': provider.location.x,
            }
        elif hasattr(provider, 'location_lat') and provider.location_lat:
            project_data['location_coordinates'] = {
                'lat': provider.location_lat,
                'lng': provider.location_lng,
            }

    # Broadcast
    if created:
        broadcast_project_created(project_data)
    else:
        broadcast_project_updated(project_data)
