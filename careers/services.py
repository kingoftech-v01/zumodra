"""
Careers Services - Business logic for public career portal.

This module provides service classes for:
- CareerSiteService: Career site management and domain routing
- PublicApplicationService: Process public applications to ATS
- JobAlertService: Job alert subscriptions and notifications
"""

import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from uuid import UUID

from django.db import transaction
from django.db.models import Q, QuerySet
from django.utils import timezone
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings

logger = logging.getLogger(__name__)


@dataclass
class ServiceResult:
    """Standard service result wrapper."""
    success: bool
    data: Any = None
    error: Optional[str] = None
    errors: Optional[Dict[str, List[str]]] = None

    @classmethod
    def ok(cls, data=None):
        return cls(success=True, data=data)

    @classmethod
    def fail(cls, error: str, errors: Dict = None):
        return cls(success=False, error=error, errors=errors)


@dataclass
class ValidationResult:
    """Validation result wrapper."""
    is_valid: bool
    errors: Dict[str, List[str]] = None

    @classmethod
    def valid(cls):
        return cls(is_valid=True, errors={})

    @classmethod
    def invalid(cls, errors: Dict[str, List[str]]):
        return cls(is_valid=False, errors=errors)


# =============================================================================
# CAREER SITE SERVICE
# =============================================================================

class CareerSiteService:
    """
    Career site management service.

    Handles domain routing, site configuration, and job listing queries.
    """

    @staticmethod
    def get_site_by_domain(domain: str) -> Optional['CareerSite']:
        """
        Get career site by domain (subdomain or custom domain).

        Args:
            domain: The domain to look up (e.g., 'acme' or 'careers.acme.com')

        Returns:
            CareerSite instance or None
        """
        from careers.models import CareerSite

        # First try custom domain (exact match)
        site = CareerSite.objects.filter(
            custom_domain__iexact=domain,
            is_active=True
        ).first()

        if site:
            return site

        # Try subdomain match
        site = CareerSite.objects.filter(
            subdomain__iexact=domain,
            is_active=True
        ).first()

        return site

    @staticmethod
    def get_site_by_subdomain(subdomain: str) -> Optional['CareerSite']:
        """Get career site by subdomain only."""
        from careers.models import CareerSite

        return CareerSite.objects.filter(
            subdomain__iexact=subdomain,
            is_active=True
        ).first()

    @staticmethod
    def get_site_by_tenant(tenant) -> Optional['CareerSite']:
        """Get the primary career site for a tenant."""
        from careers.models import CareerSite

        return CareerSite.objects.filter(
            tenant=tenant,
            is_active=True
        ).first()

    @staticmethod
    def get_active_jobs(
        site: 'CareerSite',
        filters: Dict[str, Any] = None
    ) -> QuerySet:
        """
        Get active job listings for a career site.

        Args:
            site: CareerSite instance
            filters: Optional filters (department, location, type, search, etc.)

        Returns:
            QuerySet of JobListing objects
        """
        from careers.models import JobListing

        filters = filters or {}

        queryset = JobListing.objects.filter(
            career_site=site,
            job__status='open',
            published_at__isnull=False
        ).exclude(
            expires_at__lt=timezone.now()
        ).select_related('job', 'job__category')

        # Apply filters
        if filters.get('department'):
            queryset = queryset.filter(
                job__category__slug=filters['department']
            )

        if filters.get('location'):
            location = filters['location']
            queryset = queryset.filter(
                Q(job__location_city__icontains=location) |
                Q(job__location_state__icontains=location) |
                Q(job__location_country__icontains=location)
            )

        if filters.get('job_type'):
            queryset = queryset.filter(job__job_type=filters['job_type'])

        if filters.get('remote'):
            queryset = queryset.filter(
                job__remote_policy__in=['remote', 'hybrid', 'flexible']
            )

        if filters.get('search'):
            search_term = filters['search']
            queryset = queryset.filter(
                Q(job__title__icontains=search_term) |
                Q(job__description__icontains=search_term) |
                Q(job__requirements__icontains=search_term)
            )

        if filters.get('featured_only'):
            queryset = queryset.filter(is_featured=True)

        return queryset.order_by('-is_featured', '-feature_priority', '-published_at')

    @staticmethod
    def get_job_detail(site: 'CareerSite', job_slug: str) -> Optional['JobListing']:
        """
        Get job listing detail by slug.

        Args:
            site: CareerSite instance
            job_slug: Job slug (custom_slug or job.slug)

        Returns:
            JobListing instance or None
        """
        from careers.models import JobListing

        listing = JobListing.objects.filter(
            Q(custom_slug=job_slug) | Q(job__slug=job_slug),
            career_site=site,
            job__status='open',
            published_at__isnull=False
        ).exclude(
            expires_at__lt=timezone.now()
        ).select_related('job', 'job__category').first()

        return listing

    @staticmethod
    def validate_application(
        site: 'CareerSite',
        job: 'JobListing',
        data: Dict[str, Any]
    ) -> ValidationResult:
        """
        Validate application data before submission.

        Args:
            site: CareerSite instance
            job: JobListing instance (can be None for general applications)
            data: Application data dictionary

        Returns:
            ValidationResult with any errors
        """
        errors = {}

        # Required fields
        required_fields = ['first_name', 'last_name', 'email', 'resume']
        for field in required_fields:
            if not data.get(field):
                errors[field] = [f'{field.replace("_", " ").title()} is required.']

        # Cover letter requirement
        if site.require_cover_letter and not data.get('cover_letter'):
            errors['cover_letter'] = ['Cover letter is required for this position.']

        # GDPR consent
        if not data.get('consent_to_store') or not data.get('consent_to_process'):
            errors['consent'] = ['You must consent to data processing to apply.']

        # Email validation
        email = data.get('email', '')
        if email and '@' not in email:
            errors['email'] = ['Please provide a valid email address.']

        # Resume validation
        resume = data.get('resume')
        if resume:
            allowed_extensions = ['pdf', 'doc', 'docx']
            ext = resume.name.split('.')[-1].lower() if hasattr(resume, 'name') else ''
            if ext not in allowed_extensions:
                errors['resume'] = ['Resume must be PDF, DOC, or DOCX format.']

            # Size check (10MB)
            if hasattr(resume, 'size') and resume.size > 10 * 1024 * 1024:
                errors['resume'] = ['Resume must be under 10MB.']

        # Honeypot check (spam protection)
        if data.get('honeypot_field'):
            errors['_spam'] = ['Spam detected.']

        if errors:
            return ValidationResult.invalid(errors)

        return ValidationResult.valid()

    @staticmethod
    def get_departments(site: 'CareerSite') -> List[Dict]:
        """Get list of departments with active jobs."""
        from careers.models import JobListing
        from jobs.models import JobCategory

        # Get categories that have active jobs on this site
        active_category_ids = JobListing.objects.filter(
            career_site=site,
            job__status='open',
            published_at__isnull=False
        ).exclude(
            expires_at__lt=timezone.now()
        ).values_list('job__category_id', flat=True).distinct()

        categories = JobCategory.objects.filter(
            id__in=active_category_ids,
            is_active=True
        ).values('id', 'name', 'slug')

        return list(categories)

    @staticmethod
    def get_locations(site: 'CareerSite') -> List[str]:
        """Get list of unique locations with active jobs."""
        from careers.models import JobListing

        locations = JobListing.objects.filter(
            career_site=site,
            job__status='open',
            published_at__isnull=False
        ).exclude(
            expires_at__lt=timezone.now()
        ).values_list('job__location_city', flat=True).distinct()

        return [loc for loc in locations if loc]


# =============================================================================
# PUBLIC APPLICATION SERVICE
# =============================================================================

class PublicApplicationService:
    """
    Service for processing public job applications.

    Handles submission, validation, spam detection, and ATS conversion.
    """

    @staticmethod
    @transaction.atomic
    def submit_application(
        site: 'CareerSite',
        job: Optional['JobListing'],
        data: Dict[str, Any],
        files: Dict[str, Any],
        request_meta: Dict[str, Any] = None
    ) -> ServiceResult:
        """
        Submit a new public application.

        Args:
            site: CareerSite instance
            job: JobListing instance (None for general applications)
            data: Form data
            files: Uploaded files (resume, cover_letter_file)
            request_meta: Request metadata (IP, user_agent, etc.)

        Returns:
            ServiceResult with created PublicApplication
        """
        from careers.models import PublicApplication

        request_meta = request_meta or {}

        try:
            # Create application record
            application = PublicApplication(
                job_listing=job,
                first_name=data['first_name'],
                last_name=data['last_name'],
                email=data['email'],
                phone=data.get('phone', ''),
                city=data.get('city', ''),
                country=data.get('country', ''),
                resume=files.get('resume'),
                cover_letter=data.get('cover_letter', ''),
                cover_letter_file=files.get('cover_letter_file'),
                custom_answers=data.get('custom_answers', {}),
                linkedin_url=data.get('linkedin_url', ''),
                portfolio_url=data.get('portfolio_url', ''),
                github_url=data.get('github_url', ''),
                website_url=data.get('website_url', ''),
                # GDPR consent
                consent_to_store=data.get('consent_to_store', False),
                consent_to_process=data.get('consent_to_process', False),
                privacy_consent=data.get('privacy_consent', False),
                marketing_consent=data.get('marketing_consent', False),
                consent_timestamp=timezone.now(),
                consent_ip=request_meta.get('ip_address'),
                # Source tracking
                source=data.get('source', 'direct'),
                referrer_code=data.get('referrer_code', ''),
                utm_source=data.get('utm_source', ''),
                utm_medium=data.get('utm_medium', ''),
                utm_campaign=data.get('utm_campaign', ''),
                utm_term=data.get('utm_term', ''),
                utm_content=data.get('utm_content', ''),
                referrer=request_meta.get('referrer', ''),
                user_agent=request_meta.get('user_agent', ''),
                ip_address=request_meta.get('ip_address'),
                # Spam protection
                honeypot_field=data.get('honeypot_field', ''),
                submission_time_ms=data.get('submission_time_ms', 0),
            )

            application.save()

            # Queue for async processing
            from careers.tasks import process_single_application
            process_single_application.delay(application.id)

            # Send confirmation email
            PublicApplicationService._send_confirmation_email(application, site)

            logger.info(f"Public application submitted: {application.uuid}")

            return ServiceResult.ok(data={
                'application_id': str(application.uuid),
                'email': application.email,
            })

        except Exception as e:
            logger.error(f"Error submitting application: {str(e)}")
            return ServiceResult.fail(f"Failed to submit application: {str(e)}")

    @staticmethod
    def process_application(application_id: int) -> ServiceResult:
        """
        Process a public application into ATS.

        Args:
            application_id: PublicApplication ID

        Returns:
            ServiceResult with processing status
        """
        from careers.models import PublicApplication

        try:
            application = PublicApplication.objects.get(id=application_id)

            if application.status != PublicApplication.ApplicationStatus.PENDING:
                return ServiceResult.fail(
                    f"Application already processed with status: {application.status}"
                )

            success = application.process_to_ats()

            if success:
                return ServiceResult.ok(data={
                    'status': application.status,
                    'candidate_id': application.ats_candidate_id,
                    'application_id': application.ats_application_id,
                })
            else:
                return ServiceResult.fail(
                    f"Processing failed: {application.processing_error}"
                )

        except PublicApplication.DoesNotExist:
            return ServiceResult.fail("Application not found")
        except Exception as e:
            logger.error(f"Error processing application: {str(e)}")
            return ServiceResult.fail(str(e))

    @staticmethod
    def check_duplicate(email: str, job: 'JobListing') -> bool:
        """
        Check if applicant has already applied to this job.

        Args:
            email: Applicant email
            job: JobListing instance

        Returns:
            True if duplicate exists
        """
        from careers.models import PublicApplication

        return PublicApplication.objects.filter(
            email__iexact=email,
            job_listing=job,
            status__in=['pending', 'processed']
        ).exists()

    @staticmethod
    def _send_confirmation_email(application: 'PublicApplication', site: 'CareerSite'):
        """Send application confirmation email."""
        try:
            job_title = application.job_listing.job.title if application.job_listing else 'General Application'

            context = {
                'applicant_name': f"{application.first_name} {application.last_name}",
                'job_title': job_title,
                'company_name': site.tenant.name if hasattr(site, 'tenant') else 'Company',
                'site': site,
            }

            # Use custom confirmation email if configured
            if site.application_confirmation_email:
                html_content = site.application_confirmation_email
            else:
                try:
                    html_content = render_to_string(
                        'careers/emails/application_confirmation.html',
                        context
                    )
                except Exception:
                    html_content = f"""
                    <p>Dear {application.first_name},</p>
                    <p>Thank you for applying to {job_title}.</p>
                    <p>We have received your application and will review it shortly.</p>
                    <p>Best regards,<br>The Hiring Team</p>
                    """

            send_mail(
                subject=f"Application Received - {job_title}",
                message=f"Thank you for applying to {job_title}.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[application.email],
                html_message=html_content,
                fail_silently=True,
            )

        except Exception as e:
            logger.error(f"Failed to send confirmation email: {str(e)}")


# =============================================================================
# JOB ALERT SERVICE
# =============================================================================

class JobAlertService:
    """
    Service for managing job alert subscriptions.

    Handles subscription, confirmation, unsubscription, and alert delivery.
    """

    @staticmethod
    @transaction.atomic
    def subscribe(
        email: str,
        site: 'CareerSite',
        preferences: Dict[str, Any],
        request_meta: Dict[str, Any] = None
    ) -> ServiceResult:
        """
        Subscribe to job alerts.

        Args:
            email: Subscriber email
            site: CareerSite instance
            preferences: Alert preferences (departments, locations, etc.)
            request_meta: Request metadata

        Returns:
            ServiceResult with subscription info
        """
        from careers.models import JobAlert

        request_meta = request_meta or {}

        try:
            # Check for existing subscription
            existing = JobAlert.objects.filter(
                email__iexact=email,
                career_site=site,
                tenant=site.tenant
            ).first()

            if existing:
                if existing.is_active:
                    return ServiceResult.fail(
                        "You are already subscribed to job alerts."
                    )
                else:
                    # Reactivate and update preferences
                    existing.departments = preferences.get('departments', [])
                    existing.job_types = preferences.get('job_types', [])
                    existing.locations = preferences.get('locations', [])
                    existing.keywords = preferences.get('keywords', [])
                    existing.remote_only = preferences.get('remote_only', False)
                    existing.frequency = preferences.get('frequency', 'daily')
                    existing.is_active = False
                    existing.confirmation_token = JobAlert._meta.get_field(
                        'confirmation_token'
                    ).default()
                    existing.consent_given = True
                    existing.consent_timestamp = timezone.now()
                    existing.consent_ip = request_meta.get('ip_address')
                    existing.save()
                    alert = existing
            else:
                alert = JobAlert.objects.create(
                    tenant=site.tenant,
                    email=email,
                    name=preferences.get('name', ''),
                    career_site=site,
                    departments=preferences.get('departments', []),
                    job_types=preferences.get('job_types', []),
                    locations=preferences.get('locations', []),
                    keywords=preferences.get('keywords', []),
                    remote_only=preferences.get('remote_only', False),
                    frequency=preferences.get('frequency', 'daily'),
                    consent_given=True,
                    consent_timestamp=timezone.now(),
                    consent_ip=request_meta.get('ip_address'),
                )

            # Send confirmation email
            JobAlertService._send_confirmation_email(alert, site)

            logger.info(f"Job alert subscription created: {alert.uuid}")

            return ServiceResult.ok(data={
                'alert_id': str(alert.uuid),
                'email': alert.email,
                'message': 'Please check your email to confirm your subscription.',
            })

        except Exception as e:
            logger.error(f"Error creating job alert: {str(e)}")
            return ServiceResult.fail(str(e))

    @staticmethod
    def confirm_subscription(token: UUID) -> ServiceResult:
        """
        Confirm job alert subscription.

        Args:
            token: Confirmation token

        Returns:
            ServiceResult with confirmation status
        """
        from careers.models import JobAlert

        try:
            alert = JobAlert.objects.get(confirmation_token=token)

            if alert.is_active:
                return ServiceResult.ok(data={
                    'message': 'Your subscription is already confirmed.'
                })

            alert.confirm()

            logger.info(f"Job alert confirmed: {alert.uuid}")

            return ServiceResult.ok(data={
                'message': 'Your subscription has been confirmed!',
                'email': alert.email,
            })

        except JobAlert.DoesNotExist:
            return ServiceResult.fail("Invalid confirmation token.")
        except Exception as e:
            logger.error(f"Error confirming subscription: {str(e)}")
            return ServiceResult.fail(str(e))

    @staticmethod
    def unsubscribe(token: UUID) -> ServiceResult:
        """
        Unsubscribe from job alerts.

        Args:
            token: Unsubscribe token

        Returns:
            ServiceResult with unsubscribe status
        """
        from careers.models import JobAlert

        try:
            alert = JobAlert.objects.get(unsubscribe_token=token)
            alert.unsubscribe()

            logger.info(f"Job alert unsubscribed: {alert.uuid}")

            return ServiceResult.ok(data={
                'message': 'You have been unsubscribed from job alerts.',
                'email': alert.email,
            })

        except JobAlert.DoesNotExist:
            return ServiceResult.fail("Invalid unsubscribe token.")
        except Exception as e:
            logger.error(f"Error unsubscribing: {str(e)}")
            return ServiceResult.fail(str(e))

    @staticmethod
    def send_alerts(frequency: str = 'daily') -> int:
        """
        Send job alerts to subscribers.

        Args:
            frequency: Alert frequency ('immediate', 'daily', 'weekly')

        Returns:
            Number of alerts sent
        """
        from careers.models import JobAlert, JobListing
        from jobs.models import JobPosting

        sent_count = 0

        # Get active alerts with this frequency
        alerts = JobAlert.objects.filter(
            is_active=True,
            frequency=frequency
        ).select_related('career_site', 'tenant')

        for alert in alerts:
            try:
                # Get new jobs since last alert
                since_date = alert.last_sent_at or alert.created_at

                matching_jobs = JobAlertService.get_matching_jobs(alert, since_date)

                if matching_jobs:
                    # Send alert email
                    JobAlertService._send_alert_email(alert, matching_jobs)

                    # Update tracking
                    alert.last_sent_at = timezone.now()
                    alert.alerts_sent_count += 1
                    alert.save(update_fields=['last_sent_at', 'alerts_sent_count'])

                    sent_count += 1

            except Exception as e:
                logger.error(f"Error sending alert {alert.id}: {str(e)}")

        logger.info(f"Sent {sent_count} job alerts for frequency: {frequency}")
        return sent_count

    @staticmethod
    def get_matching_jobs(
        alert: 'JobAlert',
        since_date=None
    ) -> List['JobListing']:
        """
        Get jobs matching alert criteria.

        Args:
            alert: JobAlert instance
            since_date: Only get jobs published after this date

        Returns:
            List of matching JobListing objects
        """
        from careers.models import JobListing
        from jobs.models import JobPosting

        queryset = JobListing.objects.filter(
            career_site=alert.career_site,
            job__status='open',
            published_at__isnull=False
        ).exclude(
            expires_at__lt=timezone.now()
        ).select_related('job', 'job__category')

        if since_date:
            queryset = queryset.filter(published_at__gt=since_date)

        matching = []
        for listing in queryset:
            if alert.matches_job(listing.job):
                matching.append(listing)

        return matching

    @staticmethod
    def _send_confirmation_email(alert: 'JobAlert', site: 'CareerSite'):
        """Send subscription confirmation email."""
        try:
            confirm_url = f"{site.full_url}/alerts/confirm/{alert.confirmation_token}/"

            context = {
                'email': alert.email,
                'confirm_url': confirm_url,
                'site': site,
            }

            try:
                html_content = render_to_string(
                    'careers/emails/alert_confirmation.html',
                    context
                )
            except Exception:
                html_content = f"""
                <p>Please confirm your job alert subscription.</p>
                <p><a href="{confirm_url}">Click here to confirm</a></p>
                """

            send_mail(
                subject="Confirm your job alert subscription",
                message=f"Please confirm your subscription: {confirm_url}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[alert.email],
                html_message=html_content,
                fail_silently=True,
            )

        except Exception as e:
            logger.error(f"Failed to send confirmation email: {str(e)}")

    @staticmethod
    def _send_alert_email(alert: 'JobAlert', jobs: List['JobListing']):
        """Send job alert email with matching jobs."""
        try:
            site = alert.career_site
            unsubscribe_url = f"{site.full_url}/alerts/unsubscribe/{alert.unsubscribe_token}/"

            context = {
                'jobs': jobs,
                'unsubscribe_url': unsubscribe_url,
                'site': site,
            }

            try:
                html_content = render_to_string(
                    'careers/emails/job_alert.html',
                    context
                )
            except Exception:
                job_list = "\n".join([
                    f"- {job.job.title} ({job.job.location_city})"
                    for job in jobs
                ])
                html_content = f"""
                <p>New jobs matching your preferences:</p>
                <pre>{job_list}</pre>
                <p><a href="{unsubscribe_url}">Unsubscribe</a></p>
                """

            send_mail(
                subject=f"New jobs matching your preferences ({len(jobs)} jobs)",
                message=f"New jobs available. Visit our careers page to apply.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[alert.email],
                html_message=html_content,
                fail_silently=True,
            )

        except Exception as e:
            logger.error(f"Failed to send alert email: {str(e)}")
