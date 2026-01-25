"""
Jobs Public Catalog Celery Tasks.

Handles syncing JobPosting instances from tenant schemas to public catalog.

Tasks:
    - sync_job_to_public: Sync a job to public catalog
    - remove_job_from_public: Remove a job from public catalog
    - bulk_sync_all_public_jobs: Initial sync of all public jobs

Helper Functions:
    - parse_html_to_list: Convert HTML lists to Python lists
    - geocode_location: Geocode city/state/country to lat/lng
    - get_job_images: Extract job image URLs
"""

import logging
import re
from typing import Dict, Any, Optional, Tuple, List

from celery import shared_task
from django.core.cache import cache
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


def parse_html_to_list(html_text: str) -> List[str]:
    """
    Parse HTML text (with <ul>/<li> or line breaks) into a clean list of strings.

    Handles both structured HTML lists and simple text with line breaks.
    Removes HTML tags and empty entries.

    Args:
        html_text: HTML content to parse (e.g., "<ul><li>Item 1</li><li>Item 2</li></ul>")

    Returns:
        List of clean text strings (e.g., ["Item 1", "Item 2"])

    Example:
        >>> parse_html_to_list("<ul><li>Python</li><li>Django</li></ul>")
        ['Python', 'Django']
    """
    if not html_text:
        return []

    # Extract <li> items if present
    li_pattern = re.compile(r'<li[^>]*>(.*?)</li>', re.DOTALL | re.IGNORECASE)
    matches = li_pattern.findall(html_text)

    if matches:
        # Clean HTML tags from each item
        return [re.sub(r'<[^>]+>', '', item).strip() for item in matches if item.strip()]

    # Fallback: split by line breaks
    lines = html_text.replace('<br>', '\n').replace('<br/>', '\n').replace('<br />', '\n')
    lines = re.sub(r'<[^>]+>', '', lines)  # Strip remaining HTML
    return [line.strip() for line in lines.split('\n') if line.strip()]


def geocode_location(city: str, state: str, country: str) -> Tuple[Optional[float], Optional[float]]:
    """
    Geocode location to (latitude, longitude) coordinates.

    Uses GeoPy with Nominatim geocoder (OpenStreetMap).
    Implements caching to avoid repeated API calls for same location.

    Args:
        city: City name (e.g., "San Francisco")
        state: State/province (e.g., "California")
        country: Country (e.g., "United States")

    Returns:
        Tuple of (latitude, longitude) or (None, None) if geocoding fails

    Example:
        >>> geocode_location("Montreal", "Quebec", "Canada")
        (45.5017, -73.5673)
    """
    if not city and not country:
        return None, None

    try:
        from geopy.geocoders import Nominatim
        from geopy.exc import GeocoderTimedOut, GeocoderServiceError

        # Build location string
        location_parts = [p for p in [city, state, country] if p]
        location_string = ", ".join(location_parts)

        # Check cache first (cache for 30 days)
        cache_key = f"geocode:{location_string}"
        cached_result = cache.get(cache_key)
        if cached_result:
            return cached_result

        # Geocode with timeout
        geolocator = Nominatim(user_agent="zumodra_jobs_public", timeout=5)
        location = geolocator.geocode(location_string)

        if location:
            result = (location.latitude, location.longitude)
            cache.set(cache_key, result, 30 * 24 * 60 * 60)  # 30 days
            return result

        return None, None

    except (GeocoderTimedOut, GeocoderServiceError) as e:
        logger.warning(f"Geocoding failed for {location_string}: {e}")
        return None, None
    except Exception as e:
        logger.error(f"Unexpected geocoding error: {e}", exc_info=True)
        return None, None


def get_job_images(job) -> List[str]:
    """
    Get job image gallery URLs from JobImage instances.

    Returns list of publicly accessible image URLs ordered by display order.

    Args:
        job: JobPosting instance

    Returns:
        List of image URLs (e.g., ["/media/jobs/images/2025/01/photo1.jpg", ...])

    Example:
        >>> get_job_images(job_posting)
        ['/media/jobs/images/2025/01/office.jpg', '/media/jobs/images/2025/01/team.jpg']
    """
    images = []
    try:
        if hasattr(job, 'images'):
            images = [img.image.url for img in job.images.all().order_by('order') if img.image]
    except Exception as e:
        logger.warning(f"Failed to get job images: {e}")
    return images


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
    from jobs.models import JobPosting
    from jobs_public.models import PublicJobCatalog
    from tenants.context import public_schema_context

    try:
        # Step 1: Switch to tenant schema and fetch job
        Tenant = get_tenant_model()
        tenant = Tenant.objects.get(schema_name=tenant_schema_name)
        connection.set_tenant(tenant)

        job = JobPosting.objects.get(id=job_id)

        # Step 2: Extract data for public catalog
        catalog_data = {
            # Identity
            'jobposting_uuid': job.uuid,
            'tenant_id': tenant.id,
            'tenant_schema_name': tenant_schema_name,

            # Company Info (basic)
            'company_name': tenant.name,
            'company_logo_url': tenant.logo.url if tenant.logo else '',

            # Job Details
            'title': job.title,
            'description_html': sanitize_html(job.description) if job.description else '',
            'employment_type': job.job_type or '',

            # Location
            'location_city': job.location_city or '',
            'location_state': job.location_state or '',
            'location_country': job.location_country or '',
            'is_remote': job.remote_policy in ['remote', 'hybrid'] if hasattr(job, 'remote_policy') else False,

            # Salary
            'salary_min': job.salary_min,
            'salary_max': job.salary_max,
            'salary_currency': job.salary_currency or 'CAD',
            'salary_period': getattr(job, 'salary_period', 'yearly'),
            'show_salary': getattr(job, 'show_salary', False),

            # Job Overview (NEW)
            'experience_level': getattr(job, 'experience_level', ''),
            'hours_per_week': getattr(job, 'hours_per_week', None),
            'years_of_experience': getattr(job, 'years_of_experience', None),
            'english_level': getattr(job, 'english_level', ''),

            # Rich Content (parse HTML to lists) (NEW)
            'responsibilities_list': parse_html_to_list(job.responsibilities) if hasattr(job, 'responsibilities') and job.responsibilities else [],
            'requirements_list': parse_html_to_list(job.requirements) if hasattr(job, 'requirements') and job.requirements else [],
            'qualifications_list': parse_html_to_list(job.nice_to_have) if hasattr(job, 'nice_to_have') and job.nice_to_have else [],
            'benefits_list': parse_html_to_list(job.benefits) if hasattr(job, 'benefits') and job.benefits else [],

            # Media (NEW)
            'video_url': getattr(job, 'video_url', ''),
            'image_gallery': get_job_images(job),

            # Geocoding (will be computed below) (NEW)
            'latitude': None,
            'longitude': None,

            # Metadata (NEW)
            'expiration_date': getattr(job, 'application_deadline', None) if hasattr(job, 'application_deadline') else None,
            'is_active': job.status == 'open' if hasattr(job, 'status') else True,
            'is_expired': False,  # Will be computed below
            'is_featured': getattr(job, 'is_featured', False),
            'view_count': 0,  # Will be tracked separately
            'application_count': 0,  # Will be tracked separately

            # Categories & Skills
            'category_names': [job.category.name] if hasattr(job, 'category') and job.category else [],
            'category_slugs': [job.category.slug] if hasattr(job, 'category') and job.category else [],
            'required_skills': job.required_skills if hasattr(job, 'required_skills') else [],

            # Company Information (denormalized from Tenant) (NEW)
            'company_rating': getattr(tenant, 'rating', None),
            'company_established_date': getattr(tenant, 'established_date', None),
            'company_industry': getattr(tenant, 'industry', ''),
            'company_size': getattr(tenant, 'company_size', ''),
            'company_website': getattr(tenant, 'website', ''),
            'company_linkedin': getattr(tenant, 'linkedin_url', ''),
            'company_twitter': getattr(tenant, 'twitter_url', ''),
            'company_facebook': getattr(tenant, 'facebook_url', ''),
            'company_instagram': getattr(tenant, 'instagram_url', ''),
            'company_pinterest': getattr(tenant, 'pinterest_url', ''),

            # Application URL
            'published_at': job.published_at if hasattr(job, 'published_at') and job.published_at else job.created_at,
            'application_url': f"https://{tenant.domain_url}/careers/jobs/{job.uuid}/apply/",
        }

        # Geocode location if coordinates not in source job
        if hasattr(job, 'location_coordinates') and job.location_coordinates:
            # Use existing coordinates from PostGIS PointField
            catalog_data['latitude'] = job.location_coordinates.y
            catalog_data['longitude'] = job.location_coordinates.x
        else:
            # Geocode from address
            lat, lng = geocode_location(
                catalog_data['location_city'],
                catalog_data['location_state'],
                catalog_data['location_country']
            )
            catalog_data['latitude'] = lat
            catalog_data['longitude'] = lng

        # Compute is_expired based on expiration_date
        if catalog_data['expiration_date']:
            catalog_data['is_expired'] = timezone.now() > catalog_data['expiration_date']

        # Step 3: Switch to public schema and update catalog
        with public_schema_context():
            catalog_entry, created = PublicJobCatalog.objects.update_or_create(
                jobposting_uuid=job.uuid,
                defaults=catalog_data
            )

        action = 'created' if created else 'updated'
        logger.info(f"Synced job {job.uuid} to public catalog from {tenant_schema_name} ({action})")

        # Broadcast to WebSocket clients for real-time map updates
        try:
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync

            channel_layer = get_channel_layer()

            # Serialize job data for WebSocket
            job_data = {
                'id': str(catalog_entry.id),
                'uuid': str(catalog_entry.jobposting_uuid),
                'title': catalog_entry.title,
                'company_name': catalog_entry.company_name,
                'location': {
                    'lat': catalog_entry.latitude,
                    'lng': catalog_entry.longitude,
                    'display': catalog_entry.location_display,
                },
                'employment_type': catalog_entry.employment_type,
                'salary_display': catalog_entry.salary_display,
                'is_remote': catalog_entry.is_remote,
                'detail_url': f'/jobs/{catalog_entry.jobposting_uuid}/',
            }

            # Broadcast to all connected clients
            event_type = 'job_created' if created else 'job_updated'
            async_to_sync(channel_layer.group_send)(
                'public_jobs_updates',
                {
                    'type': event_type,
                    'job': job_data
                }
            )

            logger.info(f"Broadcasted {event_type} for job {job.uuid} via WebSocket")

        except Exception as e:
            logger.error(f"Failed to broadcast WebSocket event for job {job.uuid}: {e}", exc_info=True)

        return {
            'status': 'success',
            'job_uuid': str(job.uuid),
            'action': action,
            'catalog_id': str(catalog_entry.id)
        }

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
    from jobs.models import JobPosting
    from jobs_public.models import PublicJobCatalog
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

        # Broadcast removal to WebSocket clients
        if deleted_count > 0:
            try:
                from channels.layers import get_channel_layer
                from asgiref.sync import async_to_sync

                channel_layer = get_channel_layer()
                async_to_sync(channel_layer.group_send)(
                    'public_jobs_updates',
                    {
                        'type': 'job_removed',
                        'job_uuid': str(job_uuid)
                    }
                )

                logger.info(f"Broadcasted job_removed for {job_uuid} via WebSocket")

            except Exception as e:
                logger.error(f"Failed to broadcast removal for job {job_uuid}: {e}", exc_info=True)

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
        >>> from jobs_public.tasks import bulk_sync_all_public_jobs
        >>> bulk_sync_all_public_jobs.delay()

    Returns:
        Dict with sync stats
    """
    from jobs.models import JobPosting
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
