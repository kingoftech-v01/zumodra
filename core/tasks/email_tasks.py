"""
Email Delivery Tasks for Zumodra

This module provides Celery tasks for email operations:
- send_email_task: Single email with retry
- send_bulk_email_task: Batch email sending with throttling
- send_transactional_email_task: High-priority transactional emails

All tasks implement:
- Automatic retry with exponential backoff
- Rate limiting to prevent provider throttling
- Tenant awareness for multi-tenant context
- Detailed logging and metrics
"""

import logging
from typing import List, Dict, Optional, Any
from datetime import datetime

from celery import shared_task, group, chain
from celery.exceptions import SoftTimeLimitExceeded, MaxRetriesExceededError
from django.conf import settings
from django.core.mail import send_mail, send_mass_mail, EmailMessage, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

logger = logging.getLogger(__name__)


# =============================================================================
# SINGLE EMAIL TASK
# =============================================================================

@shared_task(
    bind=True,
    name='core.tasks.email_tasks.send_email_task',
    max_retries=3,
    default_retry_delay=60,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
    rate_limit='100/m',
    queue='emails',
    soft_time_limit=120,
    time_limit=180,
)
def send_email_task(
    self,
    to_email: str,
    subject: str,
    template_name: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
    plain_message: Optional[str] = None,
    html_message: Optional[str] = None,
    from_email: Optional[str] = None,
    reply_to: Optional[List[str]] = None,
    cc: Optional[List[str]] = None,
    bcc: Optional[List[str]] = None,
    attachments: Optional[List[Dict[str, Any]]] = None,
    headers: Optional[Dict[str, str]] = None,
    tenant_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Send a single email with retry capability.

    Args:
        to_email: Recipient email address
        subject: Email subject line
        template_name: Django template name for HTML content
        context: Template context dictionary
        plain_message: Plain text message (alternative to template)
        html_message: HTML message (alternative to template)
        from_email: Sender email (defaults to settings.DEFAULT_FROM_EMAIL)
        reply_to: Reply-to email addresses
        cc: CC email addresses
        bcc: BCC email addresses
        attachments: List of attachment dicts with 'filename', 'content', 'mimetype'
        headers: Additional email headers
        tenant_id: Tenant ID for multi-tenant context

    Returns:
        dict: Result with status and metadata
    """
    try:
        logger.info(f"Sending email to {to_email}: {subject}")

        # Prepare sender
        sender = from_email or settings.DEFAULT_FROM_EMAIL

        # Prepare content
        if template_name:
            html_content = render_to_string(template_name, context or {})
            text_content = strip_tags(html_content)
        else:
            html_content = html_message
            text_content = plain_message or (strip_tags(html_message) if html_message else '')

        if not text_content and not html_content:
            raise ValueError("Either template_name, plain_message, or html_message is required")

        # Create email message
        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=sender,
            to=[to_email],
            cc=cc,
            bcc=bcc,
            reply_to=reply_to,
            headers=headers or {},
        )

        # Attach HTML version if available
        if html_content:
            email.attach_alternative(html_content, 'text/html')

        # Add attachments
        if attachments:
            for attachment in attachments:
                email.attach(
                    filename=attachment.get('filename', 'attachment'),
                    content=attachment.get('content', b''),
                    mimetype=attachment.get('mimetype', 'application/octet-stream'),
                )

        # Send email
        email.send(fail_silently=False)

        logger.info(f"Successfully sent email to {to_email}")

        return {
            'status': 'success',
            'to_email': to_email,
            'subject': subject,
            'task_id': self.request.id,
            'timestamp': datetime.utcnow().isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning(f"Email task to {to_email} exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")

        # Check if we should retry
        if self.request.retries < self.max_retries:
            raise self.retry(exc=e)
        else:
            # Max retries exceeded, log and return failure
            logger.error(f"Email to {to_email} failed after {self.max_retries} retries")
            return {
                'status': 'failed',
                'to_email': to_email,
                'subject': subject,
                'error': str(e),
                'task_id': self.request.id,
                'timestamp': datetime.utcnow().isoformat(),
            }


# =============================================================================
# BULK EMAIL TASK
# =============================================================================

@shared_task(
    bind=True,
    name='core.tasks.email_tasks.send_bulk_email_task',
    max_retries=3,
    default_retry_delay=120,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=900,
    retry_jitter=True,
    rate_limit='20/m',
    queue='emails',
    soft_time_limit=1800,
    time_limit=2100,
)
def send_bulk_email_task(
    self,
    recipients: List[str],
    subject: str,
    template_name: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
    plain_message: Optional[str] = None,
    html_message: Optional[str] = None,
    from_email: Optional[str] = None,
    batch_size: int = 50,
    delay_between_batches: float = 1.0,
    personalize: bool = False,
    personalization_data: Optional[Dict[str, Dict[str, Any]]] = None,
    tenant_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Send bulk emails with batching and throttling.

    Args:
        recipients: List of recipient email addresses
        subject: Email subject line
        template_name: Django template name for HTML content
        context: Base template context (merged with personalization)
        plain_message: Plain text message
        html_message: HTML message
        from_email: Sender email
        batch_size: Number of emails per batch
        delay_between_batches: Seconds to wait between batches
        personalize: Whether to personalize each email
        personalization_data: Dict mapping email to personalization context
        tenant_id: Tenant ID for multi-tenant context

    Returns:
        dict: Result with counts and metadata
    """
    import time

    try:
        logger.info(f"Starting bulk email to {len(recipients)} recipients: {subject}")

        sender = from_email or settings.DEFAULT_FROM_EMAIL
        total_sent = 0
        total_failed = 0
        failed_emails = []

        # Split recipients into batches
        batches = [
            recipients[i:i + batch_size]
            for i in range(0, len(recipients), batch_size)
        ]

        for batch_index, batch in enumerate(batches):
            logger.info(
                f"Processing batch {batch_index + 1}/{len(batches)} "
                f"({len(batch)} emails)"
            )

            batch_results = _send_email_batch(
                batch=batch,
                subject=subject,
                template_name=template_name,
                context=context,
                plain_message=plain_message,
                html_message=html_message,
                sender=sender,
                personalize=personalize,
                personalization_data=personalization_data,
            )

            total_sent += batch_results['sent']
            total_failed += batch_results['failed']
            failed_emails.extend(batch_results['failed_emails'])

            # Delay between batches to avoid rate limiting
            if batch_index < len(batches) - 1:
                time.sleep(delay_between_batches)

        logger.info(
            f"Bulk email completed: {total_sent} sent, {total_failed} failed"
        )

        return {
            'status': 'completed',
            'total_recipients': len(recipients),
            'total_sent': total_sent,
            'total_failed': total_failed,
            'failed_emails': failed_emails[:100],  # Limit for response size
            'batch_count': len(batches),
            'task_id': self.request.id,
            'timestamp': datetime.utcnow().isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Bulk email task exceeded soft time limit")
        return {
            'status': 'timeout',
            'total_recipients': len(recipients),
            'total_sent': total_sent,
            'total_failed': total_failed,
            'task_id': self.request.id,
            'timestamp': datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Bulk email failed: {e}")
        raise self.retry(exc=e)


def _send_email_batch(
    batch: List[str],
    subject: str,
    template_name: Optional[str],
    context: Optional[Dict],
    plain_message: Optional[str],
    html_message: Optional[str],
    sender: str,
    personalize: bool,
    personalization_data: Optional[Dict],
) -> Dict[str, Any]:
    """
    Send a batch of emails.

    Returns:
        dict: Batch results with sent/failed counts
    """
    sent = 0
    failed = 0
    failed_emails = []

    for recipient in batch:
        try:
            # Prepare context for this recipient
            if personalize and personalization_data:
                recipient_context = {
                    **(context or {}),
                    **personalization_data.get(recipient, {}),
                }
            else:
                recipient_context = context or {}

            # Render template if provided
            if template_name:
                html_content = render_to_string(template_name, recipient_context)
                text_content = strip_tags(html_content)
            else:
                html_content = html_message
                text_content = plain_message or (strip_tags(html_message) if html_message else '')

            # Send email
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=sender,
                to=[recipient],
            )

            if html_content:
                email.attach_alternative(html_content, 'text/html')

            email.send(fail_silently=False)
            sent += 1

        except Exception as e:
            failed += 1
            failed_emails.append({'email': recipient, 'error': str(e)})
            logger.warning(f"Failed to send to {recipient}: {e}")

    return {
        'sent': sent,
        'failed': failed,
        'failed_emails': failed_emails,
    }


# =============================================================================
# TRANSACTIONAL EMAIL TASK (HIGH PRIORITY)
# =============================================================================

@shared_task(
    bind=True,
    name='core.tasks.email_tasks.send_transactional_email_task',
    max_retries=5,
    default_retry_delay=30,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=300,
    retry_jitter=True,
    rate_limit='200/m',
    queue='emails_transactional',
    priority=9,
    soft_time_limit=60,
    time_limit=90,
)
def send_transactional_email_task(
    self,
    to_email: str,
    email_type: str,
    context: Dict[str, Any],
    language: str = 'en',
    tenant_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Send high-priority transactional email.

    Transactional emails are critical communications like:
    - Password resets
    - Email verification
    - Order confirmations
    - Payment receipts
    - Account notifications

    Args:
        to_email: Recipient email address
        email_type: Type of transactional email (e.g., 'password_reset')
        context: Template context dictionary
        language: Language code for localization
        tenant_id: Tenant ID for multi-tenant context

    Returns:
        dict: Result with status and metadata
    """
    try:
        logger.info(f"Sending transactional email ({email_type}) to {to_email}")

        # Get email configuration based on type
        email_config = _get_transactional_email_config(email_type, language)

        if not email_config:
            raise ValueError(f"Unknown transactional email type: {email_type}")

        # Render templates
        html_content = render_to_string(
            email_config['html_template'],
            context
        )
        text_content = render_to_string(
            email_config['text_template'],
            context
        ) if email_config.get('text_template') else strip_tags(html_content)

        # Create and send email
        email = EmailMultiAlternatives(
            subject=email_config['subject'].format(**context),
            body=text_content,
            from_email=email_config.get('from_email', settings.DEFAULT_FROM_EMAIL),
            to=[to_email],
            headers={
                'X-Priority': '1',
                'X-Transaction-Type': email_type,
            },
        )

        email.attach_alternative(html_content, 'text/html')
        email.send(fail_silently=False)

        logger.info(f"Transactional email ({email_type}) sent to {to_email}")

        return {
            'status': 'success',
            'email_type': email_type,
            'to_email': to_email,
            'task_id': self.request.id,
            'timestamp': datetime.utcnow().isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning(
            f"Transactional email ({email_type}) to {to_email} exceeded time limit"
        )
        raise

    except Exception as e:
        logger.error(
            f"Failed to send transactional email ({email_type}) to {to_email}: {e}"
        )
        raise self.retry(exc=e)


def _get_transactional_email_config(
    email_type: str,
    language: str = 'en'
) -> Optional[Dict[str, Any]]:
    """
    Get configuration for a transactional email type.

    Args:
        email_type: Type of email
        language: Language code

    Returns:
        dict: Email configuration or None if not found
    """
    # Email type configurations
    EMAIL_CONFIGS = {
        'password_reset': {
            'subject': 'Reset Your Password - {site_name}',
            'html_template': 'emails/transactional/password_reset.html',
            'text_template': 'emails/transactional/password_reset.txt',
        },
        'email_verification': {
            'subject': 'Verify Your Email Address - {site_name}',
            'html_template': 'emails/transactional/email_verification.html',
            'text_template': 'emails/transactional/email_verification.txt',
        },
        'welcome': {
            'subject': 'Welcome to {site_name}!',
            'html_template': 'emails/transactional/welcome.html',
            'text_template': 'emails/transactional/welcome.txt',
        },
        'order_confirmation': {
            'subject': 'Order Confirmation - {order_number}',
            'html_template': 'emails/transactional/order_confirmation.html',
            'text_template': 'emails/transactional/order_confirmation.txt',
        },
        'payment_receipt': {
            'subject': 'Payment Receipt - {amount}',
            'html_template': 'emails/transactional/payment_receipt.html',
            'text_template': 'emails/transactional/payment_receipt.txt',
        },
        'payment_failed': {
            'subject': 'Payment Failed - Action Required',
            'html_template': 'emails/transactional/payment_failed.html',
            'text_template': 'emails/transactional/payment_failed.txt',
        },
        'account_locked': {
            'subject': 'Account Security Alert',
            'html_template': 'emails/transactional/account_locked.html',
            'text_template': 'emails/transactional/account_locked.txt',
        },
        'two_factor_code': {
            'subject': 'Your Verification Code',
            'html_template': 'emails/transactional/two_factor_code.html',
            'text_template': 'emails/transactional/two_factor_code.txt',
        },
        'application_received': {
            'subject': 'Application Received - {job_title}',
            'html_template': 'emails/transactional/application_received.html',
            'text_template': 'emails/transactional/application_received.txt',
        },
        'application_status': {
            'subject': 'Application Status Update - {job_title}',
            'html_template': 'emails/transactional/application_status.html',
            'text_template': 'emails/transactional/application_status.txt',
        },
        'interview_scheduled': {
            'subject': 'Interview Scheduled - {job_title}',
            'html_template': 'emails/transactional/interview_scheduled.html',
            'text_template': 'emails/transactional/interview_scheduled.txt',
        },
        'offer_letter': {
            'subject': 'Offer Letter - {company_name}',
            'html_template': 'emails/transactional/offer_letter.html',
            'text_template': 'emails/transactional/offer_letter.txt',
        },
    }

    config = EMAIL_CONFIGS.get(email_type)

    if config and language != 'en':
        # Try to get localized templates
        localized_html = f"emails/transactional/{language}/{email_type}.html"
        localized_text = f"emails/transactional/{language}/{email_type}.txt"

        # Check if localized template exists
        from django.template.loader import get_template
        try:
            get_template(localized_html)
            config = {
                **config,
                'html_template': localized_html,
                'text_template': localized_text,
            }
        except Exception:
            # Fall back to default language
            pass

    return config


# =============================================================================
# HELPER TASKS
# =============================================================================

@shared_task(
    bind=True,
    name='core.tasks.email_tasks.schedule_email_task',
    max_retries=1,
)
def schedule_email_task(
    self,
    to_email: str,
    subject: str,
    template_name: str,
    context: Dict[str, Any],
    send_at: str,
    tenant_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Schedule an email to be sent at a specific time.

    Args:
        to_email: Recipient email
        subject: Email subject
        template_name: Template name
        context: Template context
        send_at: ISO datetime string for scheduled send time
        tenant_id: Tenant ID

    Returns:
        dict: Scheduled task info
    """
    from datetime import datetime
    from celery import current_app

    try:
        # Parse scheduled time
        send_time = datetime.fromisoformat(send_at.replace('Z', '+00:00'))
        now = datetime.utcnow()

        if send_time <= now:
            # Send immediately if time has passed
            result = send_email_task.delay(
                to_email=to_email,
                subject=subject,
                template_name=template_name,
                context=context,
                tenant_id=tenant_id,
            )
            return {
                'status': 'sent_immediately',
                'task_id': result.id,
            }

        # Calculate ETA
        eta = send_time

        # Schedule the task
        result = send_email_task.apply_async(
            kwargs={
                'to_email': to_email,
                'subject': subject,
                'template_name': template_name,
                'context': context,
                'tenant_id': tenant_id,
            },
            eta=eta,
        )

        return {
            'status': 'scheduled',
            'task_id': result.id,
            'scheduled_for': send_at,
        }

    except Exception as e:
        logger.error(f"Failed to schedule email: {e}")
        raise


@shared_task(
    bind=True,
    name='core.tasks.email_tasks.send_email_with_attachment_task',
    max_retries=3,
    rate_limit='50/m',
)
def send_email_with_attachment_task(
    self,
    to_email: str,
    subject: str,
    body: str,
    attachment_path: str,
    attachment_name: Optional[str] = None,
    from_email: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Send email with a file attachment.

    Args:
        to_email: Recipient email
        subject: Email subject
        body: Email body text
        attachment_path: Path to attachment file
        attachment_name: Name for attachment (defaults to filename)
        from_email: Sender email

    Returns:
        dict: Send result
    """
    import os
    import mimetypes

    try:
        sender = from_email or settings.DEFAULT_FROM_EMAIL

        # Read attachment
        with open(attachment_path, 'rb') as f:
            attachment_content = f.read()

        # Get filename and mimetype
        filename = attachment_name or os.path.basename(attachment_path)
        mimetype, _ = mimetypes.guess_type(attachment_path)
        mimetype = mimetype or 'application/octet-stream'

        # Create email
        email = EmailMessage(
            subject=subject,
            body=body,
            from_email=sender,
            to=[to_email],
        )

        email.attach(filename, attachment_content, mimetype)
        email.send(fail_silently=False)

        return {
            'status': 'success',
            'to_email': to_email,
            'attachment': filename,
            'task_id': self.request.id,
        }

    except Exception as e:
        logger.error(f"Failed to send email with attachment: {e}")
        raise self.retry(exc=e)
