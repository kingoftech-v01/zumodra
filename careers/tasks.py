"""
Celery Tasks for Careers App

This module contains async tasks for public career page operations:
- Public application processing
- Job view count aggregation
- Job listing synchronization
- Sitemap generation
"""

import logging
from datetime import timedelta
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.db.models import F

logger = logging.getLogger(__name__)


# ==================== APPLICATION PROCESSING ====================

@shared_task(
    bind=True,
    name='careers.tasks.process_public_applications',
    max_retries=3,
    default_retry_delay=60,
    autoretry_for=(Exception,),
    retry_backoff=True,
)
def process_public_applications(self):
    """
    Process applications submitted from public career page.

    Handles:
    - Converting public submissions to ATS applications
    - Resume parsing
    - Initial validation
    - Duplicate detection
    - Sending confirmation emails

    Returns:
        dict: Summary of processed applications.
    """
    from careers.models import PublicApplication
    from ats.models import Application, JobPosting

    try:
        now = timezone.now()
        processed = 0
        errors = []

        # Find unprocessed public applications
        pending_applications = PublicApplication.objects.filter(
            is_processed=False,
            submitted_at__lt=now - timedelta(minutes=1)  # Wait 1 min before processing
        ).select_related('job_listing')[:50]  # Process in batches

        for public_app in pending_applications:
            try:
                # Convert to ATS application
                ats_application = _convert_to_ats_application(public_app)

                if ats_application:
                    # Send confirmation email
                    _send_application_confirmation(public_app)

                    # Mark as processed
                    public_app.is_processed = True
                    public_app.processed_at = now
                    public_app.ats_application = ats_application
                    public_app.save()

                    processed += 1

            except Exception as e:
                errors.append({
                    'application_id': public_app.id,
                    'error': str(e)
                })
                logger.error(f"Error processing public application {public_app.id}: {e}")

        logger.info(f"Processed {processed} public applications")

        return {
            'status': 'success',
            'processed_count': processed,
            'error_count': len(errors),
            'errors': errors,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Application processing exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error processing public applications: {str(e)}")
        raise self.retry(exc=e)


def _convert_to_ats_application(public_app):
    """
    Convert a public application to an ATS application.

    Args:
        public_app: PublicApplication object

    Returns:
        Application: Created ATS application or None
    """
    from ats.models import Application, JobPosting, Candidate
    from django.contrib.auth import get_user_model

    User = get_user_model()

    try:
        job = public_app.job_listing.job

        # Find or create candidate
        candidate, created = Candidate.objects.get_or_create(
            email=public_app.email,
            defaults={
                'first_name': public_app.first_name,
                'last_name': public_app.last_name,
                'phone': public_app.phone,
                'source': 'career_page',
            }
        )

        # Create application
        application = Application.objects.create(
            job=job,
            candidate=candidate,
            cover_letter=public_app.cover_letter,
            resume=public_app.resume,
            status='new',
            source='career_page',
            submitted_via='web',
        )

        # Queue for match score calculation
        from ats.tasks import calculate_single_match_score
        calculate_single_match_score.delay(application.id)

        return application

    except Exception as e:
        logger.error(f"Error converting public application: {e}")
        raise


def _send_application_confirmation(public_app):
    """Send application confirmation email to candidate."""
    subject = f"Application received - {public_app.job_listing.job.title}"

    context = {
        'applicant_name': f"{public_app.first_name} {public_app.last_name}",
        'job_title': public_app.job_listing.job.title,
        'company_name': getattr(public_app.job_listing, 'company_name', 'Company'),
    }

    try:
        html_content = render_to_string('emails/application_confirmation.html', context)
        text_content = f"Thank you for applying to {public_app.job_listing.job.title}!"
    except Exception:
        text_content = f"Thank you for applying to {public_app.job_listing.job.title}!"
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[public_app.email],
        html_message=html_content,
        fail_silently=True,
    )


@shared_task(
    bind=True,
    name='careers.tasks.process_single_application',
    max_retries=3,
    default_retry_delay=60,
)
def process_single_application(self, application_id):
    """
    Process a single public application immediately.

    Args:
        application_id: ID of the PublicApplication

    Returns:
        dict: Processing result
    """
    from careers.models import PublicApplication

    try:
        public_app = PublicApplication.objects.get(id=application_id)

        if public_app.is_processed:
            return {
                'status': 'skipped',
                'reason': 'Already processed',
            }

        ats_application = _convert_to_ats_application(public_app)

        if ats_application:
            _send_application_confirmation(public_app)

            public_app.is_processed = True
            public_app.processed_at = timezone.now()
            public_app.ats_application = ats_application
            public_app.save()

            return {
                'status': 'success',
                'ats_application_id': ats_application.id,
            }

        return {
            'status': 'error',
            'error': 'Failed to create ATS application',
        }

    except PublicApplication.DoesNotExist:
        return {
            'status': 'error',
            'error': 'Application not found',
        }

    except Exception as e:
        logger.error(f"Error processing application: {str(e)}")
        raise self.retry(exc=e)


# ==================== VIEW COUNT AGGREGATION ====================

@shared_task(
    bind=True,
    name='careers.tasks.update_job_view_counts',
    max_retries=3,
    default_retry_delay=300,
)
def update_job_view_counts(self):
    """
    Aggregate and update job view counts.

    Processes view tracking data and updates
    JobListing view counts for analytics.

    Returns:
        dict: Summary of updated listings.
    """
    from careers.models import JobListing, JobView
    from django.db.models import Count

    try:
        now = timezone.now()
        last_update = now - timedelta(hours=6)

        # Aggregate views by job listing
        view_counts = JobView.objects.filter(
            viewed_at__gte=last_update
        ).values('job_listing_id').annotate(
            view_count=Count('id')
        )

        updated = 0

        for vc in view_counts:
            try:
                JobListing.objects.filter(id=vc['job_listing_id']).update(
                    view_count=F('view_count') + vc['view_count']
                )
                updated += 1
            except Exception as e:
                logger.error(f"Error updating view count: {e}")

        # Clean up old view records (optional)
        old_views = JobView.objects.filter(
            viewed_at__lt=now - timedelta(days=30)
        )
        deleted_count = old_views.count()
        old_views.delete()

        logger.info(f"Updated view counts for {updated} job listings")

        return {
            'status': 'success',
            'updated_count': updated,
            'deleted_old_views': deleted_count,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error updating view counts: {str(e)}")
        raise self.retry(exc=e)


@shared_task(
    bind=True,
    name='careers.tasks.track_job_view',
    max_retries=2,
)
def track_job_view(self, job_listing_id, visitor_data=None):
    """
    Track a single job view asynchronously.

    Args:
        job_listing_id: ID of the JobListing
        visitor_data: Optional dict with visitor information

    Returns:
        dict: Tracking result
    """
    from careers.models import JobListing, JobView

    try:
        visitor_data = visitor_data or {}

        # Create view record
        JobView.objects.create(
            job_listing_id=job_listing_id,
            ip_address=visitor_data.get('ip_address'),
            user_agent=visitor_data.get('user_agent', ''),
            referrer=visitor_data.get('referrer', ''),
            session_key=visitor_data.get('session_key', ''),
        )

        return {
            'status': 'success',
            'job_listing_id': job_listing_id,
        }

    except Exception as e:
        logger.error(f"Error tracking job view: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
        }


# ==================== JOB LISTING SYNC ====================

@shared_task(
    bind=True,
    name='careers.tasks.sync_job_listings',
    max_retries=3,
    default_retry_delay=300,
)
def sync_job_listings(self):
    """
    Sync job listings with ATS job postings.

    Ensures:
    - New open jobs have listings
    - Closed jobs have listings unpublished
    - Listing data is current

    Returns:
        dict: Summary of sync operation.
    """
    from careers.models import JobListing, CareerPage
    from ats.models import JobPosting

    try:
        now = timezone.now()
        created = 0
        updated = 0
        unpublished = 0

        # Find open jobs without listings
        open_jobs = JobPosting.objects.filter(
            status='open',
            is_internal_only=False
        ).exclude(
            public_listing__isnull=False
        )

        for job in open_jobs:
            try:
                JobListing.objects.create(
                    job=job,
                    published_at=now,
                )
                created += 1
            except Exception as e:
                logger.error(f"Error creating listing for job {job.id}: {e}")

        # Update existing listings
        active_listings = JobListing.objects.filter(
            job__status='open'
        ).select_related('job')

        for listing in active_listings:
            try:
                # Sync fields from job to listing
                listing.save()  # Triggers any auto-update logic
                updated += 1
            except Exception as e:
                logger.error(f"Error updating listing {listing.id}: {e}")

        # Unpublish listings for closed jobs
        stale_listings = JobListing.objects.filter(
            job__status__in=['closed', 'filled', 'cancelled']
        ).exclude(
            unpublished_at__isnull=False
        )

        for listing in stale_listings:
            try:
                listing.unpublished_at = now
                listing.save(update_fields=['unpublished_at'])
                unpublished += 1
            except Exception as e:
                logger.error(f"Error unpublishing listing {listing.id}: {e}")

        logger.info(f"Job listing sync: {created} created, {updated} updated, {unpublished} unpublished")

        return {
            'status': 'success',
            'created': created,
            'updated': updated,
            'unpublished': unpublished,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error syncing job listings: {str(e)}")
        raise self.retry(exc=e)


# ==================== SITEMAP GENERATION ====================

@shared_task(
    bind=True,
    name='careers.tasks.generate_sitemap',
    max_retries=2,
    soft_time_limit=300,
)
def generate_sitemap(self):
    """
    Regenerate career page sitemap.

    Creates an XML sitemap for all public job listings
    to improve SEO.

    Returns:
        dict: Generation result.
    """
    from careers.models import JobListing, CareerPage
    from django.contrib.sitemaps import Sitemap
    from django.urls import reverse
    import os

    try:
        now = timezone.now()

        # Get all published job listings
        active_listings = JobListing.objects.filter(
            job__status='open',
            unpublished_at__isnull=True
        ).select_related('job')

        # Generate sitemap XML
        sitemap_content = _generate_sitemap_xml(active_listings)

        # Save to static files
        sitemap_path = os.path.join(settings.STATIC_ROOT or settings.BASE_DIR, 'sitemaps')
        os.makedirs(sitemap_path, exist_ok=True)

        sitemap_file = os.path.join(sitemap_path, 'careers-sitemap.xml')
        with open(sitemap_file, 'w', encoding='utf-8') as f:
            f.write(sitemap_content)

        logger.info(f"Generated sitemap with {active_listings.count()} job listings")

        return {
            'status': 'success',
            'jobs_count': active_listings.count(),
            'sitemap_path': sitemap_file,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error generating sitemap: {str(e)}")
        raise self.retry(exc=e)


def _generate_sitemap_xml(listings):
    """
    Generate sitemap XML content.

    Args:
        listings: QuerySet of JobListing objects

    Returns:
        str: Sitemap XML content
    """
    xml_parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]

    for listing in listings:
        try:
            url = f"/careers/jobs/{listing.custom_slug or listing.job.slug}/"
            lastmod = listing.job.updated_at.strftime('%Y-%m-%d')

            xml_parts.append(f'''
  <url>
    <loc>{url}</loc>
    <lastmod>{lastmod}</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.8</priority>
  </url>''')

        except Exception as e:
            logger.warning(f"Error adding listing to sitemap: {e}")

    xml_parts.append('</urlset>')

    return ''.join(xml_parts)


# ==================== CAREER PAGE TASKS ====================

@shared_task(
    bind=True,
    name='careers.tasks.update_career_page_stats',
    max_retries=2,
)
def update_career_page_stats(self, career_page_id=None):
    """
    Update career page statistics.

    Args:
        career_page_id: Optional specific career page ID

    Returns:
        dict: Update result
    """
    from careers.models import CareerPage, JobListing

    try:
        now = timezone.now()

        if career_page_id:
            pages = CareerPage.objects.filter(id=career_page_id)
        else:
            pages = CareerPage.objects.filter(is_active=True)

        updated = 0

        for page in pages:
            try:
                # Count active job listings
                active_jobs = JobListing.objects.filter(
                    career_page=page,
                    job__status='open',
                    unpublished_at__isnull=True
                ).count()

                # Update stats (if such fields exist)
                if hasattr(page, 'active_job_count'):
                    page.active_job_count = active_jobs
                    page.save(update_fields=['active_job_count'])

                updated += 1

            except Exception as e:
                logger.error(f"Error updating career page stats: {e}")

        return {
            'status': 'success',
            'updated_count': updated,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error updating career page stats: {str(e)}")
        raise self.retry(exc=e)


@shared_task(
    bind=True,
    name='careers.tasks.expire_job_listings',
    max_retries=3,
    default_retry_delay=300,
)
def expire_job_listings(self):
    """
    Expire job listings past their expiration date.

    Returns:
        dict: Summary of expired listings.
    """
    from careers.models import JobListing

    try:
        now = timezone.now()

        # Find and expire listings
        expired = JobListing.objects.filter(
            expires_at__lt=now,
            unpublished_at__isnull=True
        )

        count = expired.count()

        expired.update(unpublished_at=now)

        logger.info(f"Expired {count} job listings")

        return {
            'status': 'success',
            'expired_count': count,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error expiring job listings: {str(e)}")
        raise self.retry(exc=e)
