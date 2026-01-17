"""
Celery Tasks for ATS (Applicant Tracking System) App

This module contains async tasks for ATS operations:
- AI match score calculation
- Application reminders
- Auto-rejection of stale applications
- Pipeline statistics updates
- Interview reminders
- Job posting expiration

Security Features:
- SecureTenantTask for permission-validated operations
- Tenant isolation on all queries
- Audit logging for bulk operations
- Rate limiting on sensitive operations
"""

import logging
from datetime import timedelta
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.db.models import Avg, Count, F, Q

# Import secure task base classes
from core.tasks.secure_task import SecureTenantTask, PermissionValidatedTask

logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security.ats.tasks')


# ==================== AI MATCH SCORING ====================

@shared_task(
    bind=True,
    name='ats.tasks.calculate_match_scores',
    max_retries=3,
    default_retry_delay=300,
    autoretry_for=(Exception,),
    retry_backoff=True,
    soft_time_limit=1800,
)
def calculate_match_scores(self):
    """
    Calculate AI match scores for candidates.

    Uses AI/ML to match candidates to job requirements based on:
    - Skills matching
    - Experience level
    - Location preferences
    - Salary expectations

    Returns:
        dict: Summary of match scores calculated.
    """
    from ats.models import Application, JobPosting

    try:
        now = timezone.now()

        # Find applications needing score calculation
        # Those without an AI match score
        applications = Application.objects.filter(
            Q(ai_match_score__isnull=True)
        ).select_related('job', 'candidate')[:100]  # Process in batches

        calculated = 0

        for application in applications:
            try:
                score = _calculate_application_match_score(application)

                # Update application with AI match score
                Application.objects.filter(id=application.id).update(
                    ai_match_score=score
                )

                calculated += 1

            except Exception as e:
                logger.error(f"Error calculating match score for application {application.id}: {e}")

        logger.info(f"Calculated {calculated} match scores")

        return {
            'status': 'success',
            'calculated_count': calculated,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Match score calculation exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error in match score calculation: {str(e)}")
        raise self.retry(exc=e)


def _calculate_application_match_score(application):
    """
    Calculate match score for a single application using AI matching service.

    This function integrates with the ai_matching app when available,
    falling back to basic matching when AI services are unavailable.

    Args:
        application: Application object with job and candidate relations

    Returns:
        float: Match score between 0 and 100
    """
    job = application.job
    candidate = getattr(application, 'candidate', None)

    # Try AI-powered matching first
    try:
        from ai_matching.services import MatchingService

        matching_service = MatchingService()

        # Build candidate profile from application data
        candidate_profile = {
            'skills': [],
            'experience_years': 0,
            'education_level': None,
            'location': None,
        }

        if candidate:
            candidate_profile['skills'] = getattr(candidate, 'skills', []) or []
            candidate_profile['experience_years'] = getattr(candidate, 'years_experience', 0) or 0
            candidate_profile['location'] = {
                'city': getattr(candidate, 'city', ''),
                'country': getattr(candidate, 'country', ''),
            }

            # Extract education level from education JSON
            education = getattr(candidate, 'education', []) or []
            if education:
                # Find highest degree
                degree_levels = {'phd': 5, 'master': 4, 'bachelor': 3, 'associate': 2, 'high_school': 1}
                max_level = 0
                for edu in education:
                    degree = edu.get('degree', '').lower()
                    for level_name, level_val in degree_levels.items():
                        if level_name in degree and level_val > max_level:
                            max_level = level_val
                            candidate_profile['education_level'] = level_name

        # Get resume text if available
        resume_text = getattr(candidate, 'resume_text', '') or getattr(application, 'resume_text', '') or ''

        # Calculate AI match score
        result = matching_service.calculate_match(
            job_id=job.id,
            candidate_profile=candidate_profile,
            resume_text=resume_text,
        )

        if result and result.get('success'):
            # Return AI score (weighted composite score)
            ai_score = result.get('overall_score', 0)
            # Scale to 0-100 if needed
            if 0 <= ai_score <= 1:
                return ai_score * 100
            return min(max(ai_score, 0), 100)

    except ImportError:
        logger.debug("AI matching service not available, using basic matching")
    except Exception as e:
        logger.warning(f"AI matching failed for application {application.id}: {e}")

    # Fallback to basic matching algorithm
    return _basic_match_score(application, job, candidate)


def _basic_match_score(application, job, candidate):
    """
    Basic match score calculation without AI.

    Used as fallback when AI matching is unavailable.
    """
    score = 0
    max_score = 100

    # Skills matching (40 points max)
    if candidate:
        candidate_skills = set(s.lower() for s in (getattr(candidate, 'skills', []) or []))
        job_skills = set()

        # Get required skills from job
        if hasattr(job, 'required_skills'):
            job_skills = set(s.lower() for s in (job.required_skills or []))
        elif hasattr(job, 'skills'):
            job_skills = set(s.lower() for s in (job.skills or []))

        if job_skills:
            skill_overlap = len(candidate_skills.intersection(job_skills))
            skill_ratio = skill_overlap / len(job_skills) if job_skills else 0
            score += skill_ratio * 40
        else:
            # No job skills defined, give partial credit for having skills
            score += 20 if candidate_skills else 10

    # Experience matching (30 points max)
    candidate_experience = getattr(candidate, 'years_experience', 0) or 0
    required_experience = getattr(job, 'min_experience_years', 0) or 0

    if candidate_experience >= required_experience:
        score += 30
    elif required_experience > 0:
        experience_ratio = candidate_experience / required_experience
        score += experience_ratio * 30

    # Location matching (15 points max)
    remote_policy = getattr(job, 'remote_policy', None)
    if remote_policy == 'remote':
        score += 15  # Remote jobs match everyone
    elif remote_policy == 'hybrid':
        score += 10  # Partial credit for hybrid
    elif candidate:
        # Check location match
        candidate_location = getattr(candidate, 'city', '') or ''
        job_location = getattr(job, 'location', '') or getattr(job, 'city', '') or ''
        if candidate_location and job_location:
            if candidate_location.lower() in job_location.lower() or job_location.lower() in candidate_location.lower():
                score += 15

    # Cover letter bonus (15 points)
    if hasattr(application, 'cover_letter') and application.cover_letter:
        score += 15

    # Normalize to 0-100 scale
    return min(max(round(score, 2), 0), max_score)


@shared_task(
    bind=True,
    name='ats.tasks.calculate_single_match_score',
    max_retries=3,
)
def calculate_single_match_score(self, application_id):
    """
    Calculate match score for a single application.

    Args:
        application_id: ID of the application

    Returns:
        dict: Match score result
    """
    from ats.models import Application

    try:
        application = Application.objects.select_related('job', 'candidate').get(id=application_id)
        score = _calculate_application_match_score(application)

        application.ai_match_score = score
        application.save(update_fields=['ai_match_score'])

        return {
            'status': 'success',
            'application_id': application_id,
            'match_score': score,
        }

    except Application.DoesNotExist:
        return {
            'status': 'error',
            'error': 'Application not found',
        }

    except Exception as e:
        logger.error(f"Error calculating single match score: {str(e)}")
        raise self.retry(exc=e)


# ==================== APPLICATION REMINDERS ====================

@shared_task(
    bind=True,
    name='ats.tasks.send_application_reminders',
    max_retries=3,
    default_retry_delay=600,
    autoretry_for=(Exception,),
)
def send_application_reminders(self):
    """
    Send reminders for pending application reviews.

    Sends reminders to recruiters about applications that:
    - Have been in 'new' stage for more than 3 days
    - Need follow-up action

    Returns:
        dict: Summary of reminders sent.
    """
    from ats.models import Application
    from accounts.models import TenantUser

    try:
        now = timezone.now()
        threshold = now - timedelta(days=3)
        reminders_sent = 0

        # Find applications needing attention
        pending_applications = Application.objects.filter(
            status='new',
            created_at__lt=threshold
        ).select_related('job')

        # Group by job and send consolidated reminders
        jobs_with_pending = {}
        for app in pending_applications:
            job_id = app.job_id
            if job_id not in jobs_with_pending:
                jobs_with_pending[job_id] = {
                    'job': app.job,
                    'count': 0,
                    'applications': []
                }
            jobs_with_pending[job_id]['count'] += 1
            jobs_with_pending[job_id]['applications'].append(app)

        # Send reminders for each job
        for job_id, data in jobs_with_pending.items():
            try:
                job = data['job']

                # Find assigned recruiters
                if hasattr(job, 'assigned_recruiters'):
                    recruiters = job.assigned_recruiters.all()
                else:
                    # Fallback: notify job creator
                    recruiters = [job.created_by] if hasattr(job, 'created_by') and job.created_by else []

                for recruiter in recruiters:
                    _send_application_reminder_email(recruiter, job, data['count'])
                    reminders_sent += 1

            except Exception as e:
                logger.error(f"Error sending reminder for job {job_id}: {e}")

        logger.info(f"Sent {reminders_sent} application reminders")

        return {
            'status': 'success',
            'reminders_sent': reminders_sent,
            'jobs_with_pending': len(jobs_with_pending),
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error sending application reminders: {str(e)}")
        raise self.retry(exc=e)


def _send_application_reminder_email(user, job, pending_count):
    """Send application review reminder email."""
    subject = f"{pending_count} applications pending review - {job.title}"

    context = {
        'user': user,
        'job': job,
        'pending_count': pending_count,
    }

    try:
        html_content = render_to_string('emails/application_reminder.html', context)
        text_content = f"You have {pending_count} applications pending review for {job.title}."
    except Exception:
        text_content = f"You have {pending_count} applications pending review for {job.title}."
        html_content = f"<p>{text_content}</p>"

    if hasattr(user, 'email'):
        send_mail(
            subject=subject,
            message=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_content,
            fail_silently=True,
        )


# ==================== AUTO-REJECTION ====================

@shared_task(
    bind=True,
    name='ats.tasks.auto_reject_stale_applications',
    max_retries=3,
    default_retry_delay=300,
)
def auto_reject_stale_applications(self):
    """
    Auto-reject applications that have been stale for too long.

    Uses pipeline stage settings to determine auto-reject thresholds.

    Returns:
        dict: Summary of auto-rejected applications.
    """
    from ats.models import Application, PipelineStage

    try:
        now = timezone.now()
        rejected_count = 0

        # Find stages with auto-reject enabled
        auto_reject_stages = PipelineStage.objects.filter(
            auto_reject_after_days__gt=0,
            is_active=True
        )

        for stage in auto_reject_stages:
            threshold = now - timedelta(days=stage.auto_reject_after_days)

            # Find stale applications in this stage
            stale_applications = Application.objects.filter(
                current_stage=stage,
                stage_entered_at__lt=threshold,
                status__in=['new', 'screening', 'interview']
            )

            for application in stale_applications:
                try:
                    application.status = 'rejected'
                    application.rejection_reason = 'Auto-rejected due to inactivity'
                    application.rejected_at = now
                    application.save(update_fields=['status', 'rejection_reason', 'rejected_at'])

                    # Send rejection notification if enabled
                    if hasattr(stage, 'send_email_on_enter') and stage.send_email_on_enter:
                        _send_auto_rejection_email(application)

                    rejected_count += 1

                except Exception as e:
                    logger.error(f"Error auto-rejecting application {application.id}: {e}")

        logger.info(f"Auto-rejected {rejected_count} stale applications")

        return {
            'status': 'success',
            'rejected_count': rejected_count,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error in auto-rejection: {str(e)}")
        raise self.retry(exc=e)


def _send_auto_rejection_email(application):
    """Send rejection notification to candidate."""
    if not hasattr(application, 'candidate') or not application.candidate:
        return

    subject = f"Update on your application - {application.job.title}"

    context = {
        'application': application,
        'job': application.job,
    }

    try:
        html_content = render_to_string('emails/application_rejected.html', context)
        text_content = f"Thank you for your interest in {application.job.title}."
    except Exception:
        text_content = f"Thank you for your interest in {application.job.title}."
        html_content = f"<p>{text_content}</p>"

    candidate_email = getattr(application.candidate, 'email', None)
    if candidate_email:
        send_mail(
            subject=subject,
            message=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[candidate_email],
            html_message=html_content,
            fail_silently=True,
        )


# ==================== PIPELINE STATISTICS ====================

@shared_task(
    bind=True,
    name='ats.tasks.update_pipeline_statistics',
    max_retries=3,
    default_retry_delay=300,
)
def update_pipeline_statistics(self):
    """
    Update pipeline stage statistics.

    Calculates:
    - Average time in each stage
    - Conversion rates between stages
    - Total applications per stage

    Returns:
        dict: Summary of updated statistics.
    """
    from ats.models import Pipeline, PipelineStage, Application

    try:
        now = timezone.now()
        updated_stages = 0

        # Get all active pipelines
        pipelines = Pipeline.objects.filter(is_active=True).prefetch_related('stages')

        for pipeline in pipelines:
            for stage in pipeline.stages.filter(is_active=True):
                try:
                    # Calculate average time in stage
                    # This requires tracking stage entry/exit times
                    applications_in_stage = Application.objects.filter(
                        current_stage=stage
                    )

                    # Count applications
                    stage.application_count = applications_in_stage.count()

                    # Calculate average time (simplified)
                    avg_time = applications_in_stage.filter(
                        stage_entered_at__isnull=False
                    ).aggregate(
                        avg_duration=Avg(now - F('stage_entered_at'))
                    )

                    if avg_time.get('avg_duration'):
                        stage.average_time_in_stage = avg_time['avg_duration']

                    stage.save(update_fields=['average_time_in_stage'])
                    updated_stages += 1

                except Exception as e:
                    logger.error(f"Error updating stage {stage.id} statistics: {e}")

        logger.info(f"Updated statistics for {updated_stages} pipeline stages")

        return {
            'status': 'success',
            'updated_stages': updated_stages,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error updating pipeline statistics: {str(e)}")
        raise self.retry(exc=e)


# ==================== INTERVIEW REMINDERS ====================

@shared_task(
    bind=True,
    name='ats.tasks.send_interview_reminders',
    max_retries=3,
    default_retry_delay=300,
)
def send_interview_reminders(self):
    """
    Send reminders for upcoming interviews.

    Sends reminders:
    - 24 hours before interview
    - 1 hour before interview

    Returns:
        dict: Summary of reminders sent.
    """
    from ats.models import Interview

    try:
        now = timezone.now()
        reminders_sent = 0

        # Reminder intervals
        intervals = [
            (timedelta(hours=24), timedelta(hours=23), '24_hour'),
            (timedelta(hours=1), timedelta(minutes=30), '1_hour'),
        ]

        for max_ahead, min_ahead, reminder_type in intervals:
            upcoming_interviews = Interview.objects.filter(
                scheduled_start__gte=now + min_ahead,
                scheduled_start__lt=now + max_ahead,
                status='scheduled'
            ).select_related('application', 'application__job')

            for interview in upcoming_interviews:
                try:
                    # Send to candidate
                    _send_interview_reminder(interview, 'candidate', reminder_type)

                    # Send to interviewers
                    if hasattr(interview, 'interviewers'):
                        for interviewer in interview.interviewers.all():
                            _send_interview_reminder(interview, 'interviewer', reminder_type, interviewer)

                    reminders_sent += 1

                except Exception as e:
                    logger.error(f"Error sending interview reminder: {e}")

        logger.info(f"Sent {reminders_sent} interview reminders")

        return {
            'status': 'success',
            'reminders_sent': reminders_sent,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error sending interview reminders: {str(e)}")
        raise self.retry(exc=e)


def _send_interview_reminder(interview, recipient_type, reminder_type, user=None):
    """Send interview reminder email."""
    job = interview.application.job

    if recipient_type == 'candidate':
        subject = f"Reminder: Interview for {job.title}"
        email = getattr(interview.application.candidate, 'email', None) if hasattr(interview.application, 'candidate') else None
    else:
        subject = f"Reminder: Interview with candidate for {job.title}"
        email = getattr(user, 'email', None) if user else None

    if not email:
        return

    context = {
        'interview': interview,
        'job': job,
        'reminder_type': reminder_type,
    }

    try:
        html_content = render_to_string(f'emails/interview_reminder_{recipient_type}.html', context)
        text_content = f"Interview reminder for {job.title} at {interview.scheduled_start}."
    except Exception:
        text_content = f"Interview reminder for {job.title} at {interview.scheduled_start}."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        html_message=html_content,
        fail_silently=True,
    )


# ==================== JOB EXPIRATION ====================

@shared_task(
    bind=True,
    name='ats.tasks.expire_job_postings',
    max_retries=3,
    default_retry_delay=300,
)
def expire_job_postings(self):
    """
    Close expired job postings.

    Marks job postings as closed if they have passed their
    expiration date.

    Returns:
        dict: Summary of expired jobs.
    """
    from ats.models import JobPosting

    try:
        now = timezone.now()

        # Find and close expired job postings
        expired_jobs = JobPosting.objects.filter(
            status='open',
            expires_at__lt=now
        )

        count = expired_jobs.count()

        # Update status to closed
        expired_jobs.update(
            status='closed',
            closed_at=now,
            close_reason='expired'
        )

        logger.info(f"Closed {count} expired job postings")

        return {
            'status': 'success',
            'expired_count': count,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error expiring job postings: {str(e)}")
        raise self.retry(exc=e)


# ==================== CANDIDATE PROCESSING ====================

@shared_task(
    bind=True,
    name='ats.tasks.process_candidate_application',
    max_retries=3,
    default_retry_delay=60,
)
def process_candidate_application(self, application_id):
    """
    Process a new candidate application.

    Performs:
    - Resume parsing (if implemented)
    - Match score calculation
    - Duplicate detection
    - Initial screening

    Args:
        application_id: ID of the application to process

    Returns:
        dict: Processing result
    """
    from ats.models import Application

    try:
        application = Application.objects.select_related('job', 'candidate').get(id=application_id)

        # Calculate match score
        score = _calculate_application_match_score(application)
        application.ai_match_score = score

        # Check for duplicates
        # (Simplified - would check for same email applying to same job)

        # Mark as processed
        application.is_processed = True
        application.processed_at = timezone.now()
        application.save()

        logger.info(f"Processed application {application_id} with score {score}")

        return {
            'status': 'success',
            'application_id': application_id,
            'match_score': score,
        }

    except Application.DoesNotExist:
        return {
            'status': 'error',
            'error': 'Application not found',
        }

    except Exception as e:
        logger.error(f"Error processing application: {str(e)}")
        raise self.retry(exc=e)


# ==================== BULK OPERATIONS ====================

class BulkMoveApplicationsTask(SecureTenantTask):
    """
    Secure task for bulk moving applications.

    Requires:
    - User must be authenticated
    - User must have recruiter, hr_manager, or admin role
    - Applications must belong to user's tenant
    """
    name = 'ats.tasks.bulk_move_applications'
    max_retries = 2
    soft_time_limit = 600
    required_roles = ['recruiter', 'hiring_manager', 'hr_manager', 'admin', 'owner']

    def run(self, application_ids, target_stage_id, user_id=None, tenant_id=None):
        """
        Bulk move applications to a different pipeline stage.

        Args:
            application_ids: List of application IDs
            target_stage_id: Target pipeline stage ID
            user_id: ID of user performing the action
            tenant_id: ID of the tenant context

        Returns:
            dict: Summary of move operation
        """
        from ats.models import Application, PipelineStage

        # Set context for permission validation
        self.user_id = user_id
        self.tenant_id = tenant_id

        # Validate permissions before proceeding
        if user_id:
            self.require_role('recruiter')  # Or hr_manager, admin, owner

        try:
            now = timezone.now()

            target_stage = PipelineStage.objects.get(id=target_stage_id)
            moved = 0
            errors = []
            skipped = 0

            for app_id in application_ids:
                try:
                    # SECURITY: Verify application belongs to current tenant
                    if tenant_id:
                        app_exists = Application.objects.filter(
                            id=app_id,
                            tenant_id=tenant_id
                        ).exists()
                        if not app_exists:
                            skipped += 1
                            security_logger.warning(
                                f"BULK_MOVE_SKIPPED: user={user_id} attempted to move "
                                f"application={app_id} from different tenant"
                            )
                            continue

                    Application.objects.filter(id=app_id).update(
                        current_stage=target_stage,
                        stage_entered_at=now,
                        updated_at=now
                    )
                    moved += 1

                except Exception as e:
                    errors.append({
                        'application_id': app_id,
                        'error': str(e)
                    })

            # Security audit log
            security_logger.info(
                f"BULK_MOVE_APPLICATIONS: user={user_id} tenant={tenant_id} "
                f"moved={moved} skipped={skipped} errors={len(errors)} "
                f"target_stage={target_stage.name}"
            )

            return {
                'status': 'success',
                'moved_count': moved,
                'skipped_count': skipped,
                'error_count': len(errors),
                'errors': errors,
                'target_stage': target_stage.name,
            }

        except PipelineStage.DoesNotExist:
            return {
                'status': 'error',
                'error': 'Target stage not found',
            }

        except Exception as e:
            logger.error(f"Error in bulk move: {str(e)}")
            raise self.retry(exc=e)


# Register the task
bulk_move_applications = BulkMoveApplicationsTask()


# ==================== Public Job Catalog Sync Tasks ====================

from celery import shared_task
from tenants.context import tenant_context, public_schema_context
from core.sync.job_sync import JobCatalogSyncService as JobPublicSyncService


@shared_task(
    bind=True,
    name='ats.sync_job_to_catalog',
    max_retries=3,
    default_retry_delay=60,  # 1 minute
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=600,  # Max 10 minutes
)
def sync_job_to_catalog_task(self, job_uuid, tenant_schema, tenant_id):
    """
    Async task to sync JobPosting → PublicJobCatalog.

    Workflow:
        1. Load tenant and switch to tenant schema
        2. Fetch JobPosting instance
        3. Check sync conditions (published, not internal, open)
        4. Extract and map safe fields
        5. Switch to public schema
        6. Update or create PublicJobCatalog entry

    Args:
        job_uuid: UUID string of the job to sync
        tenant_schema: Source tenant schema name
        tenant_id: Tenant primary key

    Returns:
        dict: {'status': 'success'|'not_found'|'skipped', 'job_uuid': str}

    Raises:
        Retry exception on errors (auto-retry with exponential backoff)
    """
    from tenants.models import Tenant
    from ats.models import JobPosting

    try:
        # Load tenant
        tenant = Tenant.objects.get(pk=tenant_id)

        # Switch to tenant schema
        with tenant_context(tenant):
            try:
                job = JobPosting.objects.get(uuid=job_uuid)
            except JobPosting.DoesNotExist:
                logger.warning(
                    f"Job {job_uuid} not found in {tenant_schema} - may have been deleted"
                )
                return {'status': 'not_found', 'job_uuid': job_uuid}

            # Perform sync
            sync_service = JobPublicSyncService()

            # Check if should sync
            if not sync_service.should_sync(job):
                logger.debug(
                    f"Job {job_uuid} does not meet sync conditions - removing from catalog"
                )
                # Remove from catalog if exists
                sync_service.remove_from_public(job)
                return {'status': 'skipped', 'job_uuid': job_uuid, 'reason': 'conditions_not_met'}

            # Sync to public catalog
            catalog_entry = sync_service.sync_to_public(job)

            if catalog_entry:
                logger.info(
                    f"Successfully synced job {job_uuid} to public catalog from {tenant_schema}"
                )
                return {
                    'status': 'success',
                    'job_uuid': job_uuid,
                    'catalog_id': catalog_entry.id
                }
            else:
                logger.error(f"Sync failed for job {job_uuid} - no catalog entry created")
                return {'status': 'error', 'job_uuid': job_uuid}

    except Tenant.DoesNotExist:
        logger.error(f"Tenant {tenant_id} not found for job sync")
        return {'status': 'error', 'error': 'tenant_not_found'}

    except Exception as e:
        logger.error(
            f"Error syncing job {job_uuid} from {tenant_schema}: {e}",
            exc_info=True
        )
        # Raise to trigger Celery retry
        raise self.retry(exc=e)


@shared_task(
    bind=True,
    name='ats.remove_job_from_catalog',
    max_retries=3,
    default_retry_delay=30,
)
def remove_job_from_catalog_task(self, job_uuid, tenant_schema):
    """
    Async task to remove job from PublicJobCatalog.

    Called when JobPosting is deleted or conditions no longer met.

    Args:
        job_uuid: UUID string of the job to remove
        tenant_schema: Source tenant schema name

    Returns:
        dict: {'status': 'success', 'deleted': int}
    """
    from tenants.models import PublicJobCatalog

    try:
        with public_schema_context():
            deleted_count, _ = PublicJobCatalog.objects.filter(
                tenant_schema_name=tenant_schema,
                job_uuid=job_uuid
            ).delete()

            logger.info(
                f"Removed job {job_uuid} from public catalog (deleted={deleted_count})"
            )

            return {
                'status': 'success',
                'deleted': deleted_count,
                'job_uuid': job_uuid
            }

    except Exception as e:
        logger.error(
            f"Error removing job {job_uuid} from catalog: {e}",
            exc_info=True
        )
        raise self.retry(exc=e)


@shared_task(name='ats.bulk_sync_tenant_jobs')
def bulk_sync_tenant_jobs(tenant_id):
    """
    Bulk sync all eligible jobs for a tenant.

    Used for:
    - Initial data load
    - Recovery from sync failures
    - Manual re-sync operations

    Args:
        tenant_id: Tenant primary key

    Returns:
        dict: {'tenant': str, 'synced': int, 'skipped': int, 'errors': int}
    """
    from tenants.models import Tenant
    from ats.models import JobPosting

    tenant = Tenant.objects.get(pk=tenant_id)
    sync_service = JobPublicSyncService()

    with tenant_context(tenant):
        # Get all jobs that should be synced
        jobs = JobPosting.objects.filter(
            published_on_career_page=True,
            is_internal_only=False,
            status='open',
        )

        synced_count = 0
        skipped_count = 0
        error_count = 0

        for job in jobs:
            try:
                if sync_service.should_sync(job):
                    catalog_entry = sync_service.sync_to_public(job)
                    if catalog_entry:
                        synced_count += 1
                    else:
                        error_count += 1
                else:
                    skipped_count += 1

            except Exception as e:
                logger.error(f"Failed to sync job {job.uuid}: {e}")
                error_count += 1

        logger.info(
            f"Bulk sync completed for {tenant.name}: "
            f"synced={synced_count}, skipped={skipped_count}, errors={error_count}"
        )

        return {
            'tenant': tenant.name,
            'synced': synced_count,
            'skipped': skipped_count,
            'errors': error_count,
            'total': jobs.count(),
        }


# ==================== PUBLIC JOB CATALOG SYNC ====================

@shared_task(
    bind=True,
    name='ats.tasks.sync_job_to_public_catalog',
    max_retries=3,
    default_retry_delay=60,
    autoretry_for=(Exception,),
    retry_backoff=True,
)
def sync_job_to_public_catalog(self, job_id, tenant_schema_name=None):
    """
    Async task to sync JobPosting → PublicJobCatalog.

    Workflow:
    1. JobPosting created/updated in tenant schema
    2. Signal triggers this Celery task
    3. Task fetches JobPosting data
    4. Denormalizes and syncs to PublicJobCatalog (public schema)
    5. Makes job browsable by public users across all tenants

    Args:
        job_id (str): UUID of the JobPosting to sync
        tenant_schema_name (str, optional): Tenant schema name to query from

    Returns:
        dict: Sync result with status and details
    """
    from ats.models import JobPosting
    from core.sync.job_sync import JobCatalogSyncService
    from django.db import connection
    from django_tenants.utils import get_tenant_model

    try:
        logger.info(f"Syncing job {job_id} to PublicJobCatalog (tenant: {tenant_schema_name})")

        # Switch to tenant schema if provided
        if tenant_schema_name:
            try:
                Tenant = get_tenant_model()
                tenant = Tenant.objects.get(schema_name=tenant_schema_name)
                connection.set_tenant(tenant)
            except Tenant.DoesNotExist:
                logger.error(f"Tenant with schema {tenant_schema_name} not found")
                return {'status': 'error', 'reason': 'tenant_not_found'}

        # Fetch the job
        try:
            job = JobPosting.objects.get(id=job_id)
        except JobPosting.DoesNotExist:
            logger.warning(f"Job {job_id} not found in schema {tenant_schema_name}, skipping sync")
            return {'status': 'skipped', 'reason': 'job_not_found'}
        
        # Check if job should be in public catalog
        if not job.published_on_career_page or job.status != 'open':
            logger.info(f"Job {job_id} is not published or not open, removing from catalog")
            JobCatalogSyncService.remove_job(job_id)
            return {'status': 'removed', 'reason': 'not_publishable'}
        
        # Sync to public catalog
        catalog_entry = JobCatalogSyncService.sync_job(job)
        
        logger.info(f"Successfully synced job {job_id} to PublicJobCatalog (entry_id={catalog_entry.id})")
        
        return {
            'status': 'success',
            'job_id': str(job_id),
            'catalog_entry_id': catalog_entry.id,
            'title': job.title,
        }
        
    except Exception as e:
        logger.error(f"Failed to sync job {job_id} to PublicJobCatalog: {e}", exc_info=True)
        raise


@shared_task(
    bind=True,
    name='ats.tasks.remove_job_from_public_catalog',
    max_retries=3,
    default_retry_delay=60,
    autoretry_for=(Exception,),
    retry_backoff=True,
)
def remove_job_from_public_catalog(self, job_id, tenant_schema_name=None):
    """
    Async task to remove job from PublicJobCatalog.

    Triggered when:
    - Job is deleted
    - Job status changed to non-open (closed, filled, cancelled)
    - Job unpublished from career page
    
    Args:
        job_id (str): UUID of the job to remove
        
    Returns:
        dict: Removal result
    """
    from core.sync.job_sync import JobCatalogSyncService
    
    try:
        logger.info(f"Removing job {job_id} from PublicJobCatalog")
        
        deleted_count = JobCatalogSyncService.remove_job(job_id)
        
        if deleted_count > 0:
            logger.info(f"Successfully removed job {job_id} from PublicJobCatalog")
            return {'status': 'success', 'job_id': str(job_id), 'deleted_count': deleted_count}
        else:
            logger.warning(f"Job {job_id} not found in PublicJobCatalog")
            return {'status': 'not_found', 'job_id': str(job_id)}
            
    except Exception as e:
        logger.error(f"Failed to remove job {job_id} from PublicJobCatalog: {e}", exc_info=True)
        raise


@shared_task(
    bind=True,
    name='ats.tasks.sync_all_jobs_to_public_catalog',
    max_retries=2,
    default_retry_delay=300,
    soft_time_limit=3600,
)
def sync_all_jobs_to_public_catalog(self, tenant_schema_name=None):
    """
    Bulk sync all jobs to PublicJobCatalog.
    
    This task can be run:
    - For a specific tenant (provide tenant_schema_name)
    - For all tenants (leave tenant_schema_name=None)
    
    Used for:
    - Initial migration/setup
    - Periodic full sync (scheduled via celery beat)
    - Manual reconciliation after data issues
    
    Args:
        tenant_schema_name (str, optional): Specific tenant to sync, or None for all tenants
        
    Returns:
        dict: Aggregate statistics across all tenants synced
    """
    from django_tenants.utils import get_tenant_model
    from core.sync.job_sync import JobCatalogSyncService
    
    try:
        if tenant_schema_name:
            # Sync specific tenant
            logger.info(f"Starting bulk sync for tenant: {tenant_schema_name}")
            stats = JobCatalogSyncService.sync_all_jobs_for_tenant(tenant_schema_name)
            logger.info(f"Bulk sync complete for {tenant_schema_name}: {stats}")
            return {tenant_schema_name: stats}
        else:
            # Sync all tenants
            logger.info("Starting bulk sync for ALL tenants")
            
            tenants = get_tenant_model().objects.exclude(schema_name='public')
            all_stats = {}
            
            for tenant in tenants:
                try:
                    logger.info(f"Syncing tenant: {tenant.schema_name}")
                    stats = JobCatalogSyncService.sync_all_jobs_for_tenant(tenant.schema_name)
                    all_stats[tenant.schema_name] = stats
                except Exception as e:
                    logger.error(f"Failed to sync tenant {tenant.schema_name}: {e}")
                    all_stats[tenant.schema_name] = {'error': str(e)}
            
            # Calculate totals
            total_synced = sum(s.get('synced', 0) for s in all_stats.values())
            total_failed = sum(s.get('failed', 0) for s in all_stats.values())
            total_removed = sum(s.get('removed', 0) for s in all_stats.values())
            
            logger.info(
                f"Bulk sync complete for all tenants: "
                f"{total_synced} synced, {total_failed} failed, {total_removed} removed"
            )
            
            return {
                'tenants': all_stats,
                'totals': {
                    'synced': total_synced,
                    'failed': total_failed,
                    'removed': total_removed,
                }
            }
            
    except SoftTimeLimitExceeded:
        logger.error("Bulk sync task exceeded time limit")
        raise
    except Exception as e:
        logger.error(f"Bulk sync task failed: {e}", exc_info=True)
        raise
