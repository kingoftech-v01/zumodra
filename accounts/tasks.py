"""
Celery Tasks for Accounts App

This module contains async tasks for account management:
- Token cleanup
- KYC verification reminders
- Login history cleanup
- Consent expiration
- Employment/Education verification workflows
- Trust score calculation
- Review content analysis
"""

import logging
from datetime import timedelta
from typing import Dict, Any, Optional
from decimal import Decimal

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.urls import reverse

logger = logging.getLogger(__name__)


# ==================== TOKEN CLEANUP ====================

@shared_task(
    bind=True,
    name='accounts.tasks.cleanup_expired_tokens',
    max_retries=3,
    default_retry_delay=300,
    autoretry_for=(Exception,),
    retry_backoff=True,
)
def cleanup_expired_tokens(self):
    """
    Remove expired authentication tokens.

    Cleans up:
    - Expired JWT refresh tokens (if using blacklist)
    - Expired password reset tokens
    - Expired email verification tokens

    Returns:
        dict: Summary of cleanup operation.
    """
    try:
        now = timezone.now()
        deleted_counts = {}

        # Clean up blacklisted tokens (rest_framework_simplejwt)
        try:
            from rest_framework_simplejwt.token_blacklist.models import (
                BlacklistedToken,
                OutstandingToken,
            )

            # Delete blacklisted tokens older than refresh token lifetime
            old_tokens = OutstandingToken.objects.filter(
                expires_at__lt=now - timedelta(days=7)
            )
            deleted_counts['jwt_tokens'] = old_tokens.count()
            old_tokens.delete()

        except ImportError:
            deleted_counts['jwt_tokens'] = 0

        # Clean up allauth email confirmations
        try:
            from allauth.account.models import EmailConfirmation

            expired_confirmations = EmailConfirmation.objects.filter(
                sent__lt=now - timedelta(days=7)
            )
            deleted_counts['email_confirmations'] = expired_confirmations.count()
            expired_confirmations.delete()

        except ImportError:
            deleted_counts['email_confirmations'] = 0

        logger.info(f"Cleaned up expired tokens: {deleted_counts}")

        return {
            'status': 'success',
            'deleted_counts': deleted_counts,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Token cleanup task exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error cleaning up tokens: {str(e)}")
        raise self.retry(exc=e)


# ==================== KYC VERIFICATION ====================

@shared_task(
    bind=True,
    name='accounts.tasks.kyc_verification_reminder',
    max_retries=3,
    default_retry_delay=600,
    autoretry_for=(Exception,),
)
def kyc_verification_reminder(self):
    """
    Send reminders to users with incomplete KYC verification.

    Sends reminders to users who:
    - Started but didn't complete verification
    - Have verification pending for too long
    - Have expiring documents

    Returns:
        dict: Summary of reminders sent.
    """
    from accounts.models import KYCVerification, UserProfile
    from django.contrib.auth import get_user_model

    User = get_user_model()

    try:
        now = timezone.now()
        reminders_sent = 0

        # Remind users with pending verifications older than 3 days
        pending_verifications = KYCVerification.objects.filter(
            status='pending',
            created_at__lt=now - timedelta(days=3)
        ).select_related('user')

        for verification in pending_verifications:
            try:
                _send_kyc_reminder(
                    verification.user,
                    verification,
                    'pending'
                )
                reminders_sent += 1
            except Exception as e:
                logger.error(f"Error sending KYC reminder to {verification.user.email}: {e}")

        # Remind users with verifications expiring soon (within 30 days)
        expiring_verifications = KYCVerification.objects.filter(
            status='verified',
            expires_at__isnull=False,
            expires_at__lte=now + timedelta(days=30),
            expires_at__gt=now
        ).select_related('user')

        for verification in expiring_verifications:
            try:
                _send_kyc_reminder(
                    verification.user,
                    verification,
                    'expiring'
                )
                reminders_sent += 1
            except Exception as e:
                logger.error(f"Error sending KYC expiry reminder: {e}")

        logger.info(f"Sent {reminders_sent} KYC verification reminders")

        return {
            'status': 'success',
            'reminders_sent': reminders_sent,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error sending KYC reminders: {str(e)}")
        raise self.retry(exc=e)


def _send_kyc_reminder(user, verification, reminder_type):
    """Send KYC verification reminder email."""
    if reminder_type == 'pending':
        subject = "Complete your identity verification"
        template_suffix = 'pending'
    else:
        subject = "Your verification is expiring soon"
        template_suffix = 'expiring'

    context = {
        'user': user,
        'verification': verification,
        'verification_type': verification.get_verification_type_display(),
    }

    try:
        html_content = render_to_string(
            f'emails/kyc_reminder_{template_suffix}.html', context
        )
        text_content = render_to_string(
            f'emails/kyc_reminder_{template_suffix}.txt', context
        )
    except Exception:
        text_content = f"Please complete your identity verification."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_content,
        fail_silently=False,
    )


@shared_task(
    bind=True,
    name='accounts.tasks.expire_kyc_verifications',
    max_retries=3,
    default_retry_delay=300,
)
def expire_kyc_verifications(self):
    """
    Mark expired KYC verifications.

    Updates verification status for documents that have passed
    their expiration date.

    Returns:
        dict: Summary of expired verifications.
    """
    from accounts.models import KYCVerification

    try:
        now = timezone.now()

        # Find and expire verified entries past their expiration date
        expired = KYCVerification.objects.filter(
            status='verified',
            expires_at__lt=now
        )

        count = expired.count()

        # Update status to expired
        expired.update(status='expired')

        logger.info(f"Expired {count} KYC verifications")

        return {
            'status': 'success',
            'expired_count': count,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error expiring KYC verifications: {str(e)}")
        raise self.retry(exc=e)


# ==================== LOGIN HISTORY CLEANUP ====================

@shared_task(
    bind=True,
    name='accounts.tasks.cleanup_old_login_history',
    max_retries=3,
    default_retry_delay=300,
)
def cleanup_old_login_history(self, days=180):
    """
    Clean up old login history records.

    Args:
        days: Number of days to keep login history. Defaults to 180.

    Returns:
        dict: Summary of cleanup operation.
    """
    from accounts.models import LoginHistory

    try:
        now = timezone.now()
        cutoff_date = now - timedelta(days=days)

        # Delete old login history
        old_records = LoginHistory.objects.filter(timestamp__lt=cutoff_date)
        count = old_records.count()
        old_records.delete()

        logger.info(f"Cleaned up {count} login history records older than {days} days")

        return {
            'status': 'success',
            'deleted_count': count,
            'cutoff_date': cutoff_date.isoformat(),
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error cleaning up login history: {str(e)}")
        raise self.retry(exc=e)


# ==================== CONSENT MANAGEMENT ====================

@shared_task(
    bind=True,
    name='accounts.tasks.expire_consents',
    max_retries=3,
    default_retry_delay=300,
)
def expire_consents(self):
    """
    Mark expired progressive consents.

    Updates consent status for entries that have passed
    their expiration date.

    Returns:
        dict: Summary of expired consents.
    """
    from accounts.models import ProgressiveConsent

    try:
        now = timezone.now()

        # Find and expire granted consents past their expiration date
        expired = ProgressiveConsent.objects.filter(
            status='granted',
            expires_at__lt=now
        )

        count = expired.count()

        # Update status to expired
        expired.update(status='expired')

        logger.info(f"Expired {count} consents")

        return {
            'status': 'success',
            'expired_count': count,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error expiring consents: {str(e)}")
        raise self.retry(exc=e)


# ==================== DATA ACCESS CLEANUP ====================

@shared_task(
    bind=True,
    name='accounts.tasks.cleanup_old_access_logs',
    max_retries=3,
    default_retry_delay=300,
)
def cleanup_old_access_logs(self, days=365):
    """
    Clean up old data access logs.

    Args:
        days: Number of days to keep access logs. Defaults to 365.

    Returns:
        dict: Summary of cleanup operation.
    """
    from accounts.models import DataAccessLog

    try:
        now = timezone.now()
        cutoff_date = now - timedelta(days=days)

        # Delete old access logs
        old_records = DataAccessLog.objects.filter(accessed_at__lt=cutoff_date)
        count = old_records.count()
        old_records.delete()

        logger.info(f"Cleaned up {count} data access logs older than {days} days")

        return {
            'status': 'success',
            'deleted_count': count,
            'cutoff_date': cutoff_date.isoformat(),
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error cleaning up access logs: {str(e)}")
        raise self.retry(exc=e)


# ==================== USER PROFILE TASKS ====================

@shared_task(
    bind=True,
    name='accounts.tasks.send_profile_completion_reminder',
    max_retries=3,
    default_retry_delay=600,
)
def send_profile_completion_reminder(self, user_id):
    """
    Send profile completion reminder to a specific user.

    Args:
        user_id: ID of the user to send reminder to.

    Returns:
        dict: Reminder status.
    """
    from accounts.models import UserProfile
    from django.contrib.auth import get_user_model

    User = get_user_model()

    try:
        user = User.objects.get(id=user_id)

        if not hasattr(user, 'profile'):
            UserProfile.objects.create(user=user)
            user.refresh_from_db()

        profile = user.profile

        if profile.is_complete:
            return {
                'status': 'skipped',
                'reason': 'Profile already complete',
            }

        completion = profile.completion_percentage

        subject = f"Complete your profile ({completion}% done)"

        context = {
            'user': user,
            'profile': profile,
            'completion': completion,
        }

        try:
            html_content = render_to_string('emails/profile_completion_reminder.html', context)
            text_content = f"Your profile is {completion}% complete. Finish it now!"
        except Exception:
            text_content = f"Your profile is {completion}% complete. Finish it now!"
            html_content = f"<p>{text_content}</p>"

        send_mail(
            subject=subject,
            message=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_content,
            fail_silently=False,
        )

        return {
            'status': 'success',
            'completion': completion,
        }

    except User.DoesNotExist:
        return {
            'status': 'error',
            'error': 'User not found',
        }

    except Exception as e:
        logger.error(f"Error sending profile reminder: {str(e)}")
        raise self.retry(exc=e)


@shared_task(
    bind=True,
    name='accounts.tasks.send_incomplete_profile_reminders',
    max_retries=3,
    default_retry_delay=600,
)
def send_incomplete_profile_reminders(self):
    """
    Send profile completion reminders to users with incomplete profiles.

    Targets users who:
    - Created account more than 3 days ago
    - Have profile completion < 50%
    - Haven't received a reminder in the last 7 days

    Returns:
        dict: Summary of reminders sent.
    """
    from accounts.models import UserProfile
    from django.contrib.auth import get_user_model

    User = get_user_model()

    try:
        now = timezone.now()
        reminders_sent = 0

        # Find users with incomplete profiles
        # Created more than 3 days ago
        users = User.objects.filter(
            date_joined__lt=now - timedelta(days=3),
            is_active=True,
        ).prefetch_related('profile')

        for user in users:
            if not hasattr(user, 'profile'):
                continue

            profile = user.profile

            if profile.completion_percentage < 50:
                # Queue individual reminder task
                send_profile_completion_reminder.delay(user.id)
                reminders_sent += 1

        logger.info(f"Queued {reminders_sent} profile completion reminders")

        return {
            'status': 'success',
            'reminders_queued': reminders_sent,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error sending profile reminders: {str(e)}")
        raise self.retry(exc=e)


# ==================== SECURITY TASKS ====================

@shared_task(
    bind=True,
    name='accounts.tasks.detect_suspicious_activity',
    max_retries=2,
)
def detect_suspicious_activity(self):
    """
    Detect suspicious login activity patterns.

    Analyzes:
    - Multiple failed logins
    - Logins from new locations
    - Unusual login times

    Returns:
        dict: Summary of suspicious activities detected.
    """
    from accounts.models import LoginHistory
    from django.db.models import Count

    try:
        now = timezone.now()
        last_hour = now - timedelta(hours=1)

        suspicious_users = []

        # Find users with multiple failed logins in the last hour
        failed_logins = LoginHistory.objects.filter(
            result='failed',
            timestamp__gte=last_hour
        ).values('user_id').annotate(
            fail_count=Count('id')
        ).filter(fail_count__gte=5)

        for record in failed_logins:
            suspicious_users.append({
                'user_id': record['user_id'],
                'reason': 'Multiple failed logins',
                'fail_count': record['fail_count'],
            })

        logger.info(f"Detected {len(suspicious_users)} users with suspicious activity")

        return {
            'status': 'success',
            'suspicious_count': len(suspicious_users),
            'suspicious_users': suspicious_users,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error detecting suspicious activity: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
        }


# ==================== EMPLOYMENT/EDUCATION VERIFICATION TASKS ====================

@shared_task(
    bind=True,
    name='accounts.tasks.send_employment_verification_email',
    max_retries=3,
    default_retry_delay=300,
    autoretry_for=(Exception,),
    retry_backoff=True,
    queue='emails',
)
def send_employment_verification_email(self, verification_id: int) -> Dict[str, Any]:
    """
    Send employment verification email to HR contact.

    Generates a unique verification link with token and sends an email
    to the HR contact requesting verification of employment details.

    Args:
        verification_id: ID of the EmploymentVerification record.

    Returns:
        dict: Status of the email send operation.
    """
    from accounts.models import EmploymentVerification

    try:
        verification = EmploymentVerification.objects.select_related('user').get(
            id=verification_id
        )

        if not verification.hr_contact_email:
            logger.warning(f"No HR contact email for verification {verification_id}")
            return {
                'status': 'error',
                'error': 'No HR contact email provided',
                'verification_id': verification_id,
            }

        # Generate verification URL from centralized config
        base_url = getattr(settings, 'FRONTEND_URL', None) or getattr(settings, 'SITE_URL', '')
        verification_url = f"{base_url}/verify/employment/{verification.verification_token}/"

        # Prepare email context
        context = {
            'user_name': verification.user.get_full_name() or verification.user.email,
            'company_name': verification.company_name,
            'job_title': verification.job_title,
            'start_date': verification.start_date.strftime('%B %d, %Y'),
            'end_date': verification.end_date.strftime('%B %d, %Y') if verification.end_date else 'Present',
            'is_current': verification.is_current,
            'verification_url': verification_url,
            'hr_contact_name': verification.hr_contact_name or 'HR Department',
            'expires_at': verification.token_expires_at.strftime('%B %d, %Y') if verification.token_expires_at else None,
        }

        subject = f"Employment Verification Request for {context['user_name']}"

        # Render email templates
        try:
            html_content = render_to_string('emails/employment_verification_request.html', context)
            text_content = render_to_string('emails/employment_verification_request.txt', context)
        except Exception:
            # Fallback to simple email content
            text_content = f"""
Employment Verification Request

Dear {context['hr_contact_name']},

We have received a request to verify the employment of {context['user_name']}
who claims to have worked at {context['company_name']} as a {context['job_title']}
from {context['start_date']} to {context['end_date']}.

Please click the link below to verify this employment:
{verification_url}

This verification link will expire on {context['expires_at']}.

Thank you for your assistance.

Best regards,
Zumodra Verification Team
            """
            html_content = text_content.replace('\n', '<br>')

        # Send email
        send_mail(
            subject=subject,
            message=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[verification.hr_contact_email],
            html_message=html_content,
            fail_silently=False,
        )

        # Update verification status
        verification.status = EmploymentVerification.VerificationStatus.PENDING
        verification.request_sent_at = timezone.now()
        verification.save(update_fields=['status', 'request_sent_at', 'updated_at'])

        logger.info(f"Employment verification email sent for {verification_id} to {verification.hr_contact_email}")

        return {
            'status': 'success',
            'verification_id': verification_id,
            'recipient': verification.hr_contact_email,
            'sent_at': timezone.now().isoformat(),
        }

    except EmploymentVerification.DoesNotExist:
        logger.error(f"EmploymentVerification {verification_id} not found")
        return {
            'status': 'error',
            'error': 'Verification not found',
            'verification_id': verification_id,
        }

    except Exception as e:
        logger.error(f"Error sending employment verification email: {str(e)}")
        raise self.retry(exc=e)


@shared_task(
    bind=True,
    name='accounts.tasks.send_education_verification_email',
    max_retries=3,
    default_retry_delay=300,
    autoretry_for=(Exception,),
    retry_backoff=True,
    queue='emails',
)
def send_education_verification_email(self, verification_id: int) -> Dict[str, Any]:
    """
    Send education verification email to institution registrar.

    Generates a unique verification link with token and sends an email
    to the registrar requesting verification of education details.

    Args:
        verification_id: ID of the EducationVerification record.

    Returns:
        dict: Status of the email send operation.
    """
    from accounts.models import EducationVerification

    try:
        verification = EducationVerification.objects.select_related('user').get(
            id=verification_id
        )

        if not verification.registrar_email:
            logger.warning(f"No registrar email for education verification {verification_id}")
            return {
                'status': 'error',
                'error': 'No registrar email provided',
                'verification_id': verification_id,
            }

        # Generate verification URL from centralized config
        base_url = getattr(settings, 'FRONTEND_URL', None) or getattr(settings, 'SITE_URL', '')
        verification_url = f"{base_url}/verify/education/{verification.verification_token}/"

        # Prepare email context
        context = {
            'user_name': verification.user.get_full_name() or verification.user.email,
            'institution_name': verification.institution_name,
            'degree_type': verification.get_degree_type_display(),
            'field_of_study': verification.field_of_study,
            'start_date': verification.start_date.strftime('%B %Y'),
            'end_date': verification.end_date.strftime('%B %Y') if verification.end_date else 'Present',
            'graduated': verification.graduated,
            'student_id': verification.student_id,
            'verification_url': verification_url,
            'expires_at': verification.token_expires_at.strftime('%B %d, %Y') if verification.token_expires_at else None,
        }

        subject = f"Education Verification Request for {context['user_name']}"

        try:
            html_content = render_to_string('emails/education_verification_request.html', context)
            text_content = render_to_string('emails/education_verification_request.txt', context)
        except Exception:
            text_content = f"""
Education Verification Request

Dear Registrar,

We have received a request to verify the education of {context['user_name']}
who claims to have attended {context['institution_name']} for a {context['degree_type']}
in {context['field_of_study']} from {context['start_date']} to {context['end_date']}.

Student ID: {context['student_id'] or 'Not provided'}

Please click the link below to verify this education:
{verification_url}

This verification link will expire on {context['expires_at']}.

Thank you for your assistance.

Best regards,
Zumodra Verification Team
            """
            html_content = text_content.replace('\n', '<br>')

        send_mail(
            subject=subject,
            message=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[verification.registrar_email],
            html_message=html_content,
            fail_silently=False,
        )

        # Update verification status
        verification.status = EducationVerification.VerificationStatus.PENDING
        verification.request_sent_at = timezone.now()
        verification.verification_method = EducationVerification.VerificationMethod.EMAIL
        verification.save(update_fields=['status', 'request_sent_at', 'verification_method', 'updated_at'])

        logger.info(f"Education verification email sent for {verification_id} to {verification.registrar_email}")

        return {
            'status': 'success',
            'verification_id': verification_id,
            'recipient': verification.registrar_email,
            'sent_at': timezone.now().isoformat(),
        }

    except EducationVerification.DoesNotExist:
        logger.error(f"EducationVerification {verification_id} not found")
        return {
            'status': 'error',
            'error': 'Verification not found',
            'verification_id': verification_id,
        }

    except Exception as e:
        logger.error(f"Error sending education verification email: {str(e)}")
        raise self.retry(exc=e)


@shared_task(
    bind=True,
    name='accounts.tasks.send_verification_reminder',
    max_retries=2,
    default_retry_delay=600,
    queue='emails',
)
def send_verification_reminder(self, verification_id: int, verification_type: str = 'employment') -> Dict[str, Any]:
    """
    Send reminder email for pending verification after 7 days.

    Checks if the verification is still pending and sends a reminder
    to the HR contact or registrar.

    Args:
        verification_id: ID of the verification record.
        verification_type: Type of verification ('employment' or 'education').

    Returns:
        dict: Status of the reminder operation.
    """
    from accounts.models import EmploymentVerification, EducationVerification

    try:
        now = timezone.now()

        if verification_type == 'employment':
            verification = EmploymentVerification.objects.select_related('user').get(id=verification_id)
            ModelClass = EmploymentVerification
            contact_email = verification.hr_contact_email
            contact_name = verification.hr_contact_name or 'HR Department'
            entity_name = verification.company_name
        else:
            verification = EducationVerification.objects.select_related('user').get(id=verification_id)
            ModelClass = EducationVerification
            contact_email = verification.registrar_email
            contact_name = 'Registrar'
            entity_name = verification.institution_name

        # Check if still pending
        if verification.status != ModelClass.VerificationStatus.PENDING:
            logger.info(f"Verification {verification_id} is no longer pending, skipping reminder")
            return {
                'status': 'skipped',
                'reason': f'Verification status is {verification.status}',
                'verification_id': verification_id,
            }

        # Check if at least 7 days have passed since request
        if verification.request_sent_at:
            days_since_request = (now - verification.request_sent_at).days
            if days_since_request < 7:
                return {
                    'status': 'skipped',
                    'reason': f'Only {days_since_request} days since initial request',
                    'verification_id': verification_id,
                }

        # Check if reminder was recently sent (within last 7 days)
        if verification.reminder_sent_at:
            days_since_reminder = (now - verification.reminder_sent_at).days
            if days_since_reminder < 7:
                return {
                    'status': 'skipped',
                    'reason': f'Reminder sent {days_since_reminder} days ago',
                    'verification_id': verification_id,
                }

        if not contact_email:
            return {
                'status': 'error',
                'error': 'No contact email provided',
                'verification_id': verification_id,
            }

        # Generate verification URL from centralized config
        base_url = getattr(settings, 'FRONTEND_URL', None) or getattr(settings, 'SITE_URL', '')
        verification_url = f"{base_url}/verify/{verification_type}/{verification.verification_token}/"

        context = {
            'user_name': verification.user.get_full_name() or verification.user.email,
            'entity_name': entity_name,
            'contact_name': contact_name,
            'verification_url': verification_url,
            'days_pending': days_since_request if verification.request_sent_at else 7,
            'verification_type': verification_type,
        }

        subject = f"Reminder: Verification Request Pending for {context['user_name']}"

        try:
            html_content = render_to_string('emails/verification_reminder.html', context)
            text_content = render_to_string('emails/verification_reminder.txt', context)
        except Exception:
            text_content = f"""
Reminder: Verification Request Pending

Dear {context['contact_name']},

This is a friendly reminder that a {verification_type} verification request
for {context['user_name']} at {context['entity_name']} has been pending for
{context['days_pending']} days.

Please click the link below to complete the verification:
{verification_url}

Your prompt attention to this matter is appreciated.

Best regards,
Zumodra Verification Team
            """
            html_content = text_content.replace('\n', '<br>')

        send_mail(
            subject=subject,
            message=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[contact_email],
            html_message=html_content,
            fail_silently=False,
        )

        # Update reminder timestamp
        verification.reminder_sent_at = now
        verification.save(update_fields=['reminder_sent_at', 'updated_at'])

        logger.info(f"Verification reminder sent for {verification_type} {verification_id}")

        return {
            'status': 'success',
            'verification_id': verification_id,
            'verification_type': verification_type,
            'recipient': contact_email,
            'sent_at': now.isoformat(),
        }

    except (EmploymentVerification.DoesNotExist, EducationVerification.DoesNotExist):
        logger.error(f"{verification_type.capitalize()}Verification {verification_id} not found")
        return {
            'status': 'error',
            'error': 'Verification not found',
            'verification_id': verification_id,
        }

    except Exception as e:
        logger.error(f"Error sending verification reminder: {str(e)}")
        raise self.retry(exc=e)


@shared_task(
    bind=True,
    name='accounts.tasks.send_pending_verification_reminders',
    max_retries=2,
    queue='emails',
)
def send_pending_verification_reminders(self) -> Dict[str, Any]:
    """
    Periodic task to send reminders for all pending verifications.

    Finds all verifications that have been pending for 7+ days
    and queues reminder emails.

    Returns:
        dict: Summary of reminders queued.
    """
    from accounts.models import EmploymentVerification, EducationVerification

    try:
        now = timezone.now()
        seven_days_ago = now - timedelta(days=7)
        reminders_queued = {'employment': 0, 'education': 0}

        # Find pending employment verifications older than 7 days
        pending_employment = EmploymentVerification.objects.filter(
            status=EmploymentVerification.VerificationStatus.PENDING,
            request_sent_at__lt=seven_days_ago,
            hr_contact_email__isnull=False,
        ).exclude(
            hr_contact_email=''
        ).filter(
            # Either never reminded or reminded 7+ days ago
            models_Q_reminder_sent_at_null=True
        ) | EmploymentVerification.objects.filter(
            status=EmploymentVerification.VerificationStatus.PENDING,
            request_sent_at__lt=seven_days_ago,
            hr_contact_email__isnull=False,
            reminder_sent_at__lt=seven_days_ago,
        ).exclude(hr_contact_email='')

        # Use a simpler query approach
        pending_employment = EmploymentVerification.objects.filter(
            status=EmploymentVerification.VerificationStatus.PENDING,
            request_sent_at__lt=seven_days_ago,
        ).exclude(hr_contact_email='').exclude(hr_contact_email__isnull=True)

        for verification in pending_employment:
            # Check if reminder needed
            if not verification.reminder_sent_at or verification.reminder_sent_at < seven_days_ago:
                send_verification_reminder.delay(verification.id, 'employment')
                reminders_queued['employment'] += 1

        # Find pending education verifications
        pending_education = EducationVerification.objects.filter(
            status=EducationVerification.VerificationStatus.PENDING,
            request_sent_at__lt=seven_days_ago,
        ).exclude(registrar_email='').exclude(registrar_email__isnull=True)

        for verification in pending_education:
            if not verification.reminder_sent_at or verification.reminder_sent_at < seven_days_ago:
                send_verification_reminder.delay(verification.id, 'education')
                reminders_queued['education'] += 1

        total_queued = reminders_queued['employment'] + reminders_queued['education']
        logger.info(f"Queued {total_queued} verification reminders")

        return {
            'status': 'success',
            'reminders_queued': reminders_queued,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error queuing verification reminders: {str(e)}")
        raise self.retry(exc=e)


# ==================== TRUST SCORE TASKS ====================

@shared_task(
    bind=True,
    name='accounts.tasks.recalculate_trust_score',
    max_retries=3,
    default_retry_delay=60,
    autoretry_for=(Exception,),
    queue='hr',
)
def recalculate_trust_score(self, user_id: int) -> Dict[str, Any]:
    """
    Recalculate the trust score for a user.

    Gets or creates the TrustScore object and calls all update methods
    to recalculate identity, career, review, dispute, and activity scores.

    Args:
        user_id: ID of the user whose trust score to recalculate.

    Returns:
        dict: Updated trust score details.
    """
    from accounts.models import TrustScore, EmploymentVerification, EducationVerification
    from django.contrib.auth import get_user_model

    User = get_user_model()

    try:
        user = User.objects.get(id=user_id)

        # Get or create TrustScore
        trust_score, created = TrustScore.objects.get_or_create(
            user=user,
            defaults={
                'entity_type': TrustScore.EntityType.CANDIDATE,
            }
        )

        if created:
            logger.info(f"Created new TrustScore for user {user_id}")

        # Update employment and education counts
        verified_employment = EmploymentVerification.objects.filter(
            user=user,
            status=EmploymentVerification.VerificationStatus.VERIFIED
        ).count()

        total_employment = EmploymentVerification.objects.filter(user=user).count()

        verified_education = EducationVerification.objects.filter(
            user=user,
            status=EducationVerification.VerificationStatus.VERIFIED
        ).count()

        total_education = EducationVerification.objects.filter(user=user).count()

        trust_score.verified_employment_count = verified_employment
        trust_score.total_employment_count = total_employment
        trust_score.verified_education_count = verified_education
        trust_score.total_education_count = total_education
        trust_score.save()

        # Update all component scores
        trust_score.update_identity_score()
        trust_score.update_career_score()
        trust_score.update_review_score()
        trust_score.update_dispute_score()

        # Calculate activity score based on platform activity
        _update_activity_score(trust_score)

        # Calculate overall score
        trust_score.calculate_overall_score()

        logger.info(
            f"Trust score recalculated for user {user_id}: "
            f"level={trust_score.trust_level}, score={trust_score.overall_score}"
        )

        return {
            'status': 'success',
            'user_id': user_id,
            'trust_level': trust_score.trust_level,
            'overall_score': float(trust_score.overall_score),
            'identity_score': float(trust_score.identity_score),
            'career_score': float(trust_score.career_score),
            'review_score': float(trust_score.review_score),
            'dispute_score': float(trust_score.dispute_score),
            'activity_score': float(trust_score.activity_score),
            'is_id_verified': trust_score.is_id_verified,
            'is_career_verified': trust_score.is_career_verified,
            'created': created,
            'timestamp': timezone.now().isoformat(),
        }

    except User.DoesNotExist:
        logger.error(f"User {user_id} not found")
        return {
            'status': 'error',
            'error': 'User not found',
            'user_id': user_id,
        }

    except Exception as e:
        logger.error(f"Error recalculating trust score for user {user_id}: {str(e)}")
        raise self.retry(exc=e)


def _update_activity_score(trust_score) -> None:
    """
    Update activity score based on platform activity metrics.

    Activity score considers:
    - Profile completion
    - Completed jobs/contracts
    - Response rate
    - Platform tenure
    """
    score = Decimal('0.00')

    # Profile completion (up to 20 points)
    if hasattr(trust_score.user, 'profile'):
        completion = trust_score.user.profile.completion_percentage
        score += Decimal(str(min(completion / 5, 20)))

    # Completed jobs (up to 30 points)
    if trust_score.completed_jobs > 0:
        jobs_score = min(trust_score.completed_jobs * 3, 30)
        score += Decimal(str(jobs_score))

    # On-time deliveries (up to 20 points)
    if trust_score.completed_jobs > 0:
        on_time_rate = trust_score.on_time_deliveries / trust_score.completed_jobs
        score += Decimal(str(on_time_rate * 20))

    # Platform tenure (up to 30 points)
    if trust_score.created_at:
        days_on_platform = (timezone.now() - trust_score.created_at).days
        tenure_score = min(days_on_platform / 30, 30)  # 1 point per month, max 30
        score += Decimal(str(tenure_score))

    trust_score.activity_score = min(score, Decimal('100.00'))
    trust_score.save(update_fields=['activity_score', 'updated_at'])


@shared_task(
    bind=True,
    name='accounts.tasks.recalculate_all_trust_scores',
    max_retries=1,
    soft_time_limit=3600,  # 1 hour
    queue='hr',
)
def recalculate_all_trust_scores(self, batch_size: int = 100) -> Dict[str, Any]:
    """
    Recalculate trust scores for all users.

    This is a maintenance task that should be run periodically
    to ensure all trust scores are up to date.

    Args:
        batch_size: Number of users to process per batch.

    Returns:
        dict: Summary of the recalculation.
    """
    from accounts.models import TrustScore
    from django.contrib.auth import get_user_model

    User = get_user_model()

    try:
        now = timezone.now()
        recalculated = 0
        errors = 0

        # Get all users with trust scores
        users_with_scores = TrustScore.objects.values_list('user_id', flat=True)

        # Process in batches
        for user_id in users_with_scores:
            try:
                recalculate_trust_score.delay(user_id)
                recalculated += 1
            except Exception as e:
                logger.error(f"Failed to queue trust score recalculation for user {user_id}: {e}")
                errors += 1

        logger.info(f"Queued trust score recalculation for {recalculated} users")

        return {
            'status': 'success',
            'recalculated': recalculated,
            'errors': errors,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error recalculating all trust scores: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
        }


# ==================== REVIEW ANALYSIS TASKS ====================

# Policy violation patterns for basic content analysis
POLICY_VIOLATION_PATTERNS = {
    'profanity': [
        # Common profane terms (simplified for example)
        r'\b(damn|hell|crap)\b',
    ],
    'discrimination': [
        r'\b(racist|sexist|discriminat)',
        r'\b(hate|hatred)\s+(group|people|race|religion)',
    ],
    'harassment': [
        r'\b(threat|threaten|kill|hurt|harm)\b',
        r'\b(stalk|harass|bully)\b',
    ],
    'personal_info': [
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone numbers
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        r'\b\d{3}[-]?\d{2}[-]?\d{4}\b',  # SSN pattern
    ],
    'spam': [
        r'(http[s]?://[^\s]+){3,}',  # Multiple URLs
        r'(.)\1{10,}',  # Repeated characters
    ],
}


@shared_task(
    bind=True,
    name='accounts.tasks.analyze_review_content',
    max_retries=3,
    default_retry_delay=60,
    queue='hr',
)
def analyze_review_content(self, review_id: int) -> Dict[str, Any]:
    """
    Analyze review content for policy violations.

    Performs basic content analysis to detect:
    - Profanity and inappropriate language
    - Discriminatory content
    - Personal information exposure
    - Spam patterns
    - Sentiment analysis for negative reviews

    Args:
        review_id: ID of the Review to analyze.

    Returns:
        dict: Analysis results.
    """
    import re
    from accounts.models import Review

    try:
        review = Review.objects.select_related('reviewer', 'reviewee').get(id=review_id)

        analysis = {
            'violations_found': [],
            'severity': 'none',
            'sentiment': 'neutral',
            'flagged': False,
            'confidence': 0.0,
            'recommendations': [],
        }

        content_to_analyze = f"{review.title} {review.content} {review.pros} {review.cons}".lower()

        # Check for policy violations
        total_violations = 0
        for violation_type, patterns in POLICY_VIOLATION_PATTERNS.items():
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, content_to_analyze, re.IGNORECASE)
                    if matches:
                        analysis['violations_found'].append({
                            'type': violation_type,
                            'count': len(matches),
                        })
                        total_violations += len(matches)
                except re.error:
                    pass

        # Determine severity based on violations
        if total_violations == 0:
            analysis['severity'] = 'none'
            analysis['confidence'] = 0.9
        elif total_violations <= 2:
            analysis['severity'] = 'low'
            analysis['confidence'] = 0.7
            analysis['recommendations'].append('Manual review recommended')
        elif total_violations <= 5:
            analysis['severity'] = 'medium'
            analysis['confidence'] = 0.8
            analysis['flagged'] = True
            analysis['recommendations'].append('Requires immediate review')
        else:
            analysis['severity'] = 'high'
            analysis['confidence'] = 0.85
            analysis['flagged'] = True
            analysis['recommendations'].append('Auto-hide recommended pending review')

        # Basic sentiment analysis based on rating and keywords
        if review.overall_rating <= 2:
            analysis['sentiment'] = 'negative'
            negative_keywords = ['terrible', 'awful', 'horrible', 'worst', 'never', 'avoid', 'scam', 'fraud']
            negative_count = sum(1 for word in negative_keywords if word in content_to_analyze)
            if negative_count >= 3:
                analysis['sentiment'] = 'very_negative'
                if not analysis['flagged']:
                    analysis['recommendations'].append('Negative review may require mediation')
        elif review.overall_rating >= 4:
            analysis['sentiment'] = 'positive'
        else:
            analysis['sentiment'] = 'neutral'

        # Check for potential fake review patterns
        word_count = len(content_to_analyze.split())
        if word_count < 10 and review.overall_rating in [1, 5]:
            analysis['recommendations'].append('Short extreme review - verify authenticity')

        # Update review with analysis
        review.ai_analysis = analysis
        review.ai_flagged = analysis['flagged']
        review.ai_confidence_score = Decimal(str(analysis['confidence']))

        # If negative and flagged, mark for verification
        if review.is_negative and analysis['flagged']:
            review.requires_verification = True
            review.status = Review.ReviewStatus.UNDER_REVIEW

        review.save(update_fields=[
            'ai_analysis', 'ai_flagged', 'ai_confidence_score',
            'requires_verification', 'status', 'updated_at'
        ])

        logger.info(
            f"Review {review_id} analyzed: severity={analysis['severity']}, "
            f"flagged={analysis['flagged']}"
        )

        return {
            'status': 'success',
            'review_id': review_id,
            'analysis': analysis,
            'timestamp': timezone.now().isoformat(),
        }

    except Review.DoesNotExist:
        logger.error(f"Review {review_id} not found")
        return {
            'status': 'error',
            'error': 'Review not found',
            'review_id': review_id,
        }

    except Exception as e:
        logger.error(f"Error analyzing review {review_id}: {str(e)}")
        raise self.retry(exc=e)


@shared_task(
    bind=True,
    name='accounts.tasks.analyze_pending_reviews',
    max_retries=1,
    queue='hr',
)
def analyze_pending_reviews(self, limit: int = 50) -> Dict[str, Any]:
    """
    Analyze all pending reviews that haven't been analyzed yet.

    Args:
        limit: Maximum number of reviews to process.

    Returns:
        dict: Summary of reviews analyzed.
    """
    from accounts.models import Review

    try:
        now = timezone.now()
        analyzed = 0
        errors = 0

        # Find pending reviews without AI analysis
        pending_reviews = Review.objects.filter(
            status=Review.ReviewStatus.PENDING,
            ai_analysis={},
        )[:limit]

        for review in pending_reviews:
            try:
                analyze_review_content.delay(review.id)
                analyzed += 1
            except Exception as e:
                logger.error(f"Failed to queue review analysis for {review.id}: {e}")
                errors += 1

        logger.info(f"Queued analysis for {analyzed} pending reviews")

        return {
            'status': 'success',
            'analyzed': analyzed,
            'errors': errors,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error analyzing pending reviews: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
        }


# ==================== VERIFICATION EXPIRY TASKS ====================

@shared_task(
    bind=True,
    name='accounts.tasks.expire_old_verifications',
    max_retries=3,
    default_retry_delay=300,
    queue='hr',
)
def expire_old_verifications(self) -> Dict[str, Any]:
    """
    Find and expire verifications that are past their expiry date.

    Checks both employment and education verifications and updates
    status to EXPIRED for any that have passed their expires_at date.

    Returns:
        dict: Summary of expired verifications.
    """
    from accounts.models import EmploymentVerification, EducationVerification

    try:
        now = timezone.now()
        expired_counts = {'employment': 0, 'education': 0}

        # Expire employment verifications
        expired_employment = EmploymentVerification.objects.filter(
            status=EmploymentVerification.VerificationStatus.VERIFIED,
            expires_at__lt=now
        )
        expired_counts['employment'] = expired_employment.count()
        expired_employment.update(
            status=EmploymentVerification.VerificationStatus.EXPIRED
        )

        # Expire education verifications
        expired_education = EducationVerification.objects.filter(
            status=EducationVerification.VerificationStatus.VERIFIED,
            expires_at__lt=now
        )
        expired_counts['education'] = expired_education.count()
        expired_education.update(
            status=EducationVerification.VerificationStatus.EXPIRED
        )

        # Also expire pending verifications with expired tokens
        stale_employment = EmploymentVerification.objects.filter(
            status=EmploymentVerification.VerificationStatus.PENDING,
            token_expires_at__lt=now
        )
        stale_emp_count = stale_employment.count()
        stale_employment.update(
            status=EmploymentVerification.VerificationStatus.EXPIRED
        )

        stale_education = EducationVerification.objects.filter(
            status=EducationVerification.VerificationStatus.PENDING,
            token_expires_at__lt=now
        )
        stale_edu_count = stale_education.count()
        stale_education.update(
            status=EducationVerification.VerificationStatus.EXPIRED
        )

        total_expired = (
            expired_counts['employment'] + expired_counts['education'] +
            stale_emp_count + stale_edu_count
        )

        logger.info(
            f"Expired verifications: employment={expired_counts['employment']}, "
            f"education={expired_counts['education']}, "
            f"stale_tokens={stale_emp_count + stale_edu_count}"
        )

        # Queue trust score recalculation for affected users
        affected_user_ids = set()

        # Get users from expired employment verifications
        affected_user_ids.update(
            EmploymentVerification.objects.filter(
                status=EmploymentVerification.VerificationStatus.EXPIRED,
                updated_at__gte=now - timedelta(minutes=5)
            ).values_list('user_id', flat=True)
        )

        # Get users from expired education verifications
        affected_user_ids.update(
            EducationVerification.objects.filter(
                status=EducationVerification.VerificationStatus.EXPIRED,
                updated_at__gte=now - timedelta(minutes=5)
            ).values_list('user_id', flat=True)
        )

        # Queue trust score recalculation
        for user_id in affected_user_ids:
            recalculate_trust_score.delay(user_id)

        return {
            'status': 'success',
            'expired': expired_counts,
            'stale_tokens': {
                'employment': stale_emp_count,
                'education': stale_edu_count,
            },
            'total_expired': total_expired,
            'trust_scores_queued': len(affected_user_ids),
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error expiring old verifications: {str(e)}")
        raise self.retry(exc=e)


@shared_task(
    bind=True,
    name='accounts.tasks.send_expiring_verification_warnings',
    max_retries=2,
    queue='emails',
)
def send_expiring_verification_warnings(self, days_before: int = 30) -> Dict[str, Any]:
    """
    Send warnings to users whose verifications are about to expire.

    Args:
        days_before: Number of days before expiry to send warning.

    Returns:
        dict: Summary of warnings sent.
    """
    from accounts.models import EmploymentVerification, EducationVerification
    from django.contrib.auth import get_user_model

    User = get_user_model()

    try:
        now = timezone.now()
        expiry_window = now + timedelta(days=days_before)
        warnings_sent = 0

        # Find verifications expiring soon
        expiring_employment = EmploymentVerification.objects.filter(
            status=EmploymentVerification.VerificationStatus.VERIFIED,
            expires_at__gt=now,
            expires_at__lte=expiry_window
        ).select_related('user')

        expiring_education = EducationVerification.objects.filter(
            status=EducationVerification.VerificationStatus.VERIFIED,
            expires_at__gt=now,
            expires_at__lte=expiry_window
        ).select_related('user')

        # Group by user
        users_to_notify = {}

        for verification in expiring_employment:
            if verification.user_id not in users_to_notify:
                users_to_notify[verification.user_id] = {
                    'user': verification.user,
                    'employment': [],
                    'education': [],
                }
            users_to_notify[verification.user_id]['employment'].append(verification)

        for verification in expiring_education:
            if verification.user_id not in users_to_notify:
                users_to_notify[verification.user_id] = {
                    'user': verification.user,
                    'employment': [],
                    'education': [],
                }
            users_to_notify[verification.user_id]['education'].append(verification)

        # Send warnings
        for user_id, data in users_to_notify.items():
            try:
                user = data['user']
                context = {
                    'user': user,
                    'employment_verifications': data['employment'],
                    'education_verifications': data['education'],
                    'days_before': days_before,
                }

                subject = "Your verifications are expiring soon"

                try:
                    html_content = render_to_string('emails/verification_expiring.html', context)
                    text_content = render_to_string('emails/verification_expiring.txt', context)
                except Exception:
                    emp_count = len(data['employment'])
                    edu_count = len(data['education'])
                    text_content = f"""
Your Verifications Are Expiring Soon

Dear {user.get_full_name() or user.email},

Some of your verified credentials are expiring within the next {days_before} days:

Employment Verifications: {emp_count}
Education Verifications: {edu_count}

Please log in to your Zumodra account to request re-verification.

Best regards,
Zumodra Team
                    """
                    html_content = text_content.replace('\n', '<br>')

                send_mail(
                    subject=subject,
                    message=text_content,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    html_message=html_content,
                    fail_silently=False,
                )
                warnings_sent += 1

            except Exception as e:
                logger.error(f"Failed to send expiry warning to user {user_id}: {e}")

        logger.info(f"Sent {warnings_sent} verification expiry warnings")

        return {
            'status': 'success',
            'warnings_sent': warnings_sent,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error sending expiring verification warnings: {str(e)}")
        raise self.retry(exc=e)


# ==================== KYC PROVIDER TASKS ====================

@shared_task(
    bind=True,
    name='accounts.tasks.process_kyc_verification',
    max_retries=3,
    default_retry_delay=300,
    autoretry_for=(Exception,),
    retry_backoff=True,
    queue='verification',
)
def process_kyc_verification(self, verification_id: int) -> Dict[str, Any]:
    """
    Process KYC verification with external provider (STUB).

    This task simulates communication with a KYC provider (e.g., Onfido, Jumio).
    In production, this would:
    1. Submit documents to the provider
    2. Poll for verification results
    3. Update the verification status

    For now, this is a stub that simulates the verification process.

    Args:
        verification_id: ID of the KYCVerification record.

    Returns:
        dict: Status of the verification process.
    """
    from accounts.models import KYCVerification

    try:
        verification = KYCVerification.objects.select_related('user').get(
            id=verification_id
        )

        # Update status to in_progress
        verification.status = KYCVerification.VerificationStatus.IN_PROGRESS
        verification.save(update_fields=['status', 'updated_at'])

        # ========================================
        # STUB: Simulated provider response
        # ========================================
        # In production, this would call the actual provider API:
        #
        # from zumodra.integrations.kyc_providers import get_provider
        # provider = get_provider(verification.provider or 'default')
        # result = provider.submit_verification(
        #     document_type=verification.document_type,
        #     document_country=verification.document_country,
        #     user_id=str(verification.user.uuid),
        # )
        #
        # For now, we simulate a successful verification with a delay
        # ========================================

        import random

        # Simulate processing time (in production, this would be polling)
        # For the stub, we'll just mark as verified with 90% success rate
        success_rate = 0.9
        is_successful = random.random() < success_rate

        if is_successful:
            # Simulate successful verification
            verification.status = KYCVerification.VerificationStatus.VERIFIED
            verification.verified_at = timezone.now()
            verification.confidence_score = Decimal(str(random.uniform(85.0, 99.0)))
            verification.provider = verification.provider or 'stub_provider'
            verification.provider_reference_id = f"STUB_{verification.uuid}"
            verification.provider_response = {
                'status': 'verified',
                'confidence': float(verification.confidence_score),
                'checks_passed': [
                    'document_authenticity',
                    'face_match',
                    'data_consistency',
                ],
                'timestamp': timezone.now().isoformat(),
                'note': 'STUB - Replace with actual provider response in production',
            }
            verification.verified_data = {
                'document_type': verification.document_type,
                'document_country': verification.document_country,
                'verification_level': verification.level,
            }
            # Set expiry (1 year from verification)
            verification.expires_at = timezone.now() + timedelta(days=365)

            logger.info(
                f"KYC verification {verification_id} APPROVED (stub) "
                f"for user {verification.user.email}"
            )

            # Queue trust score recalculation
            recalculate_trust_score.delay(verification.user_id)

        else:
            # Simulate rejection (10% of cases for testing)
            verification.status = KYCVerification.VerificationStatus.REJECTED
            verification.rejection_reason = (
                "STUB REJECTION: Document could not be verified. "
                "This is a test rejection. In production, the actual "
                "provider reason would be shown here."
            )
            verification.provider_response = {
                'status': 'rejected',
                'reason': 'document_unverifiable',
                'timestamp': timezone.now().isoformat(),
                'note': 'STUB - Replace with actual provider response in production',
            }

            logger.info(
                f"KYC verification {verification_id} REJECTED (stub) "
                f"for user {verification.user.email}"
            )

        verification.save()

        # Send notification to user
        _send_kyc_status_notification(verification)

        return {
            'status': 'success',
            'verification_id': verification_id,
            'verification_status': verification.status,
            'provider': verification.provider,
            'is_stub': True,
            'timestamp': timezone.now().isoformat(),
        }

    except KYCVerification.DoesNotExist:
        logger.error(f"KYCVerification {verification_id} not found")
        return {
            'status': 'error',
            'error': 'Verification not found',
            'verification_id': verification_id,
        }

    except Exception as e:
        logger.error(f"Error processing KYC verification {verification_id}: {str(e)}")
        raise self.retry(exc=e)


def _send_kyc_status_notification(verification) -> None:
    """
    Send notification to user about KYC verification status update.
    """
    from accounts.models import KYCVerification

    user = verification.user

    if verification.status == KYCVerification.VerificationStatus.VERIFIED:
        subject = "Your identity has been verified!"
        template_suffix = 'approved'
    elif verification.status == KYCVerification.VerificationStatus.REJECTED:
        subject = "Identity verification could not be completed"
        template_suffix = 'rejected'
    else:
        subject = "Identity verification status update"
        template_suffix = 'update'

    context = {
        'user': user,
        'verification': verification,
        'status': verification.get_status_display(),
        'verification_type': verification.get_verification_type_display(),
        'rejection_reason': verification.rejection_reason if verification.status == KYCVerification.VerificationStatus.REJECTED else None,
    }

    try:
        html_content = render_to_string(f'emails/kyc_{template_suffix}.html', context)
        text_content = render_to_string(f'emails/kyc_{template_suffix}.txt', context)
    except Exception:
        # Fallback email content
        if verification.status == KYCVerification.VerificationStatus.VERIFIED:
            text_content = f"""
Dear {user.get_full_name() or user.email},

Congratulations! Your identity verification has been completed successfully.

Your {verification.get_verification_type_display()} verification is now active.

Thank you for helping keep our platform secure.

Best regards,
Zumodra Team
            """
        else:
            text_content = f"""
Dear {user.get_full_name() or user.email},

Unfortunately, we were unable to verify your identity at this time.

Reason: {verification.rejection_reason or 'Please contact support for more information.'}

You can try submitting your verification again with clearer documents.

Best regards,
Zumodra Team
            """
        html_content = text_content.replace('\n', '<br>')

    try:
        send_mail(
            subject=subject,
            message=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_content,
            fail_silently=False,
        )
    except Exception as e:
        logger.error(f"Failed to send KYC status notification to {user.email}: {e}")


@shared_task(
    bind=True,
    name='accounts.tasks.submit_kyc_to_provider',
    max_retries=3,
    default_retry_delay=60,
    queue='verification',
)
def submit_kyc_to_provider(
    self,
    verification_id: int,
    document_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Submit KYC verification to external provider.

    This is the entry point for initiating KYC verification.
    It validates the request and queues the processing task.

    Args:
        verification_id: ID of the KYCVerification record.
        document_data: Optional additional document data.

    Returns:
        dict: Submission status.
    """
    from accounts.models import KYCVerification

    try:
        verification = KYCVerification.objects.select_related('user').get(
            id=verification_id
        )

        # Validate verification is in correct state
        if verification.status not in [
            KYCVerification.VerificationStatus.PENDING,
            KYCVerification.VerificationStatus.REQUIRES_UPDATE,
        ]:
            return {
                'status': 'error',
                'error': f'Verification cannot be submitted in {verification.status} state',
                'verification_id': verification_id,
            }

        # Mark submission timestamp
        verification.submitted_at = timezone.now()
        verification.save(update_fields=['submitted_at', 'updated_at'])

        # Queue the processing task
        process_kyc_verification.delay(verification_id)

        logger.info(f"KYC verification {verification_id} submitted for processing")

        return {
            'status': 'success',
            'verification_id': verification_id,
            'message': 'Verification submitted for processing',
            'submitted_at': verification.submitted_at.isoformat(),
        }

    except KYCVerification.DoesNotExist:
        logger.error(f"KYCVerification {verification_id} not found")
        return {
            'status': 'error',
            'error': 'Verification not found',
            'verification_id': verification_id,
        }

    except Exception as e:
        logger.error(f"Error submitting KYC verification {verification_id}: {str(e)}")
        raise self.retry(exc=e)
