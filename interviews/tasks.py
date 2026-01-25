# tasks.py
# Path: interviews/tasks.py

"""
Author: Adams Pierre David
Since: 3.1.0
"""
from django.core.mail import EmailMessage
from django.utils.translation import gettext as _

from interviews.email_sender import notify_admin, send_email
from interviews.logger_config import get_logger
from interviews.models import Appointment

logger = get_logger(__name__)


def send_email_reminder(to_email, first_name, reschedule_link, appointment_id):
    """
    Send a reminder email to the client about the upcoming appointment.
    """

    # Fetch the appointment using appointment_id
    logger.info(f"Sending reminder to {to_email} for appointment {appointment_id}")
    appointment = Appointment.objects.get(id=appointment_id)
    recipient_type = 'client'
    email_context = {
        'first_name': first_name,
        'appointment': appointment,
        'reschedule_link': reschedule_link,
        'recipient_type': recipient_type,
    }
    send_email(
            recipient_list=[to_email], subject=_("Reminder: Upcoming Appointment"),
            template_url='email_sender/reminder_email.html', context=email_context
    )
    # Notify the admin
    logger.info(f"Sending admin reminder also")
    email_context['recipient_type'] = 'admin'
    notify_admin(
            subject=_("Admin Reminder: Upcoming Appointment"),
            template_url='email_sender/reminder_email.html', context=email_context
    )


def send_email_task(recipient_list, subject, message, html_message, from_email, attachments=None):
    try:
        email = EmailMessage(
                subject=subject,
                body=message if not html_message else html_message,
                from_email=from_email,
                to=recipient_list
        )

        if html_message:
            email.content_subtype = "html"

        if attachments:
            for attachment in attachments:
                email.attach(*attachment)

        email.send(fail_silently=False)
    except Exception as e:
        logger.error(f"Error sending email from task: {e}")


def notify_admin_task(subject, message, html_message):
    """
    Task function to send an admin email asynchronously.
    """
    try:
        from django.core.mail import mail_admins
        logger.info(f"Sending admin email with subject: {subject}")
        mail_admins(subject=subject, message=message, html_message=html_message, fail_silently=False)
    except Exception as e:
        logger.error(f"Error sending admin email from task: {e}")


# ==================== CANCELLATION & REFUND TASKS ====================
# Implements TODO-APPT-001 from appointment/TODO.md

from celery import shared_task
from decimal import Decimal


@shared_task(
    bind=True,
    name='appointment.tasks.process_appointment_cancellation',
    max_retries=3,
    default_retry_delay=300,  # 5 minutes
    autoretry_for=(Exception,),
    retry_backoff=True,
)
def process_appointment_cancellation(self, appointment_id, user_id, reason=''):
    """
    Process appointment cancellation including refund calculation and notifications.

    This task handles:
    - Calculating refund amount based on cancellation policy
    - Updating appointment status
    - Processing refund via finance app (if applicable)
    - Sending notifications to customer and staff

    Args:
        appointment_id: ID of appointment to cancel
        user_id: ID of user who initiated cancellation
        reason: Optional cancellation reason

    Returns:
        dict: Cancellation result with refund info

    Raises:
        Appointment.DoesNotExist: If appointment not found
    """
    from django.utils import timezone
    from django.contrib.auth import get_user_model
    from interviews.models import Appointment

    User = get_user_model()

    try:
        appointment = Appointment.objects.select_related(
            'client',
            'appointment_request__service',
            'appointment_request__staff_member'
        ).get(pk=appointment_id)

        user = User.objects.get(pk=user_id)

        logger.info(f"Processing cancellation for appointment {appointment_id} by user {user_id}")

        # Check if can be cancelled
        can_cancel, cancel_reason = appointment.can_be_cancelled()
        if not can_cancel:
            logger.warning(f"Cannot cancel appointment {appointment_id}: {cancel_reason}")
            return {
                'status': 'error',
                'error': cancel_reason,
                'appointment_id': appointment_id,
            }

        # Calculate refund amount
        refund_amount = appointment.calculate_refund_amount()

        # Update appointment status
        appointment.status = 'cancelled'
        appointment.cancelled_at = timezone.now()
        appointment.cancelled_by = user
        appointment.cancellation_reason = reason
        appointment.refund_amount = refund_amount

        # Set refund status
        if refund_amount > 0:
            appointment.refund_status = 'pending'
        else:
            appointment.refund_status = 'none'

        appointment.save(update_fields=[
            'status',
            'cancelled_at',
            'cancelled_by',
            'cancellation_reason',
            'refund_amount',
            'refund_status'
        ])

        logger.info(
            f"Appointment {appointment_id} cancelled successfully. "
            f"Refund amount: {refund_amount}"
        )

        # Process refund if applicable
        refund_result = {}
        if refund_amount > 0:
            refund_result = _process_refund(appointment)

        # Send notifications
        _send_cancellation_notifications(appointment)

        return {
            'status': 'success',
            'appointment_id': appointment_id,
            'refund_amount': float(refund_amount),
            'refund_status': appointment.refund_status,
            'refund_result': refund_result,
        }

    except Appointment.DoesNotExist:
        error_msg = f"Appointment {appointment_id} not found"
        logger.error(error_msg)
        return {
            'status': 'error',
            'error': error_msg,
            'appointment_id': appointment_id,
        }

    except User.DoesNotExist:
        error_msg = f"User {user_id} not found"
        logger.error(error_msg)
        return {
            'status': 'error',
            'error': error_msg,
            'appointment_id': appointment_id,
        }

    except Exception as e:
        logger.error(f"Error processing cancellation for appointment {appointment_id}: {e}")
        raise self.retry(exc=e)


def _process_refund(appointment):
    """
    Process refund through finance app.

    Args:
        appointment: Appointment instance

    Returns:
        dict: Refund processing result
    """
    from django.utils import timezone

    try:
        # Check if finance app is available
        try:
            from finance.services import process_refund
        except ImportError:
            logger.warning("Finance app not available for refund processing")
            # Mark as pending for manual processing
            appointment.refund_status = 'pending'
            appointment.save(update_fields=['refund_status'])
            return {
                'status': 'manual_review',
                'message': 'Refund requires manual processing',
            }

        # Process refund via finance app
        result = process_refund(
            appointment_id=appointment.id,
            amount=appointment.refund_amount,
            reason=f"Appointment cancellation: {appointment.cancellation_reason[:100]}"
        )

        if result.get('status') == 'success':
            appointment.refund_status = 'processed'
            appointment.refund_processed_at = timezone.now()
            appointment.save(update_fields=['refund_status', 'refund_processed_at'])
            logger.info(f"Refund processed successfully for appointment {appointment.id}")
        else:
            appointment.refund_status = 'failed'
            appointment.save(update_fields=['refund_status'])
            logger.error(f"Refund failed for appointment {appointment.id}: {result.get('error')}")

        return result

    except Exception as e:
        logger.error(f"Error processing refund for appointment {appointment.id}: {e}")
        appointment.refund_status = 'failed'
        appointment.save(update_fields=['refund_status'])
        return {
            'status': 'error',
            'error': str(e),
        }


def _send_cancellation_notifications(appointment):
    """
    Send cancellation notifications to customer and staff.

    Args:
        appointment: Appointment instance
    """
    try:
        # Send notification to customer
        email_context = {
            'appointment': appointment,
            'client_name': appointment.get_client_name(),
            'service_name': appointment.get_service_name(),
            'appointment_date': appointment.get_appointment_date(),
            'refund_amount': appointment.refund_amount,
            'refund_status': appointment.get_refund_status_display(),
        }

        send_email(
            recipient_list=[appointment.client.email],
            subject=_("Appointment Cancellation Confirmation"),
            template_url='email_sender/cancellation_confirmation.html',
            context=email_context
        )

        logger.info(f"Cancellation confirmation sent to {appointment.client.email}")

        # Send notification to staff member
        if appointment.appointment_request.staff_member:
            staff_member = appointment.appointment_request.staff_member
            if staff_member.user and staff_member.user.email:
                staff_context = {
                    'appointment': appointment,
                    'staff_name': staff_member.get_staff_member_name(),
                    'client_name': appointment.get_client_name(),
                    'service_name': appointment.get_service_name(),
                    'appointment_date': appointment.get_appointment_date(),
                    'cancellation_reason': appointment.cancellation_reason,
                }

                send_email(
                    recipient_list=[staff_member.user.email],
                    subject=_("Appointment Cancelled by Customer"),
                    template_url='email_sender/staff_cancellation_notice.html',
                    context=staff_context
                )

                logger.info(f"Staff cancellation notice sent to {staff_member.user.email}")

    except Exception as e:
        logger.error(f"Error sending cancellation notifications for appointment {appointment.id}: {e}")
        # Don't fail the cancellation if notifications fail
