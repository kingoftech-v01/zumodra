"""
Celery Tasks for HR Core App

This module contains async tasks for HR operations:
- Time-off accrual processing
- Onboarding reminders
- Probation period management
- Time-off approval reminders
- Employee anniversaries
- Document expiration handling
"""

import logging
from datetime import timedelta
from decimal import Decimal
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.db.models import Q

logger = logging.getLogger(__name__)


# ==================== TIME-OFF ACCRUALS ====================

@shared_task(
    bind=True,
    name='hr_core.tasks.process_time_off_accruals',
    max_retries=3,
    default_retry_delay=300,
    autoretry_for=(Exception,),
    retry_backoff=True,
    soft_time_limit=1800,
)
def process_time_off_accruals(self):
    """
    Process monthly time-off accruals for all employees.

    Calculates and adds accrued PTO/sick leave based on:
    - Employment type
    - Years of service
    - Accrual policy

    Returns:
        dict: Summary of accruals processed.
    """
    from hr_core.models import Employee, TimeOffType, TimeOffBalance

    try:
        now = timezone.now()
        processed_count = 0
        errors = []

        # Get active employees
        employees = Employee.objects.filter(
            status__in=['active', 'probation']
        ).select_related('user')

        # Get accrual rates for each time-off type
        time_off_types = TimeOffType.objects.filter(
            is_active=True,
            accrual_rate__gt=0
        )

        for employee in employees:
            for time_off_type in time_off_types:
                try:
                    # Calculate accrual amount
                    accrual_amount = _calculate_accrual(employee, time_off_type)

                    if accrual_amount > 0:
                        # Get or create balance record
                        balance, created = TimeOffBalance.objects.get_or_create(
                            employee=employee,
                            time_off_type=time_off_type,
                            defaults={'balance': Decimal('0.00')}
                        )

                        # Add accrual
                        balance.balance += accrual_amount
                        balance.last_accrual_date = now.date()
                        balance.save()

                        processed_count += 1

                except Exception as e:
                    errors.append({
                        'employee': employee.employee_id,
                        'time_off_type': time_off_type.code,
                        'error': str(e)
                    })

        logger.info(f"Processed {processed_count} time-off accruals")

        return {
            'status': 'success',
            'processed_count': processed_count,
            'error_count': len(errors),
            'errors': errors,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Accrual processing exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error processing accruals: {str(e)}")
        raise self.retry(exc=e)


def _calculate_accrual(employee, time_off_type):
    """
    Calculate accrual amount for an employee and time-off type.

    Args:
        employee: Employee object
        time_off_type: TimeOffType object

    Returns:
        Decimal: Accrual amount in hours/days
    """
    # Base accrual rate
    base_rate = getattr(time_off_type, 'accrual_rate', Decimal('0.00'))

    # Adjust for years of service
    years_of_service = employee.years_of_service

    # Example tiered accrual:
    # 0-2 years: base rate
    # 3-5 years: base + 25%
    # 6+ years: base + 50%
    if years_of_service >= 6:
        multiplier = Decimal('1.50')
    elif years_of_service >= 3:
        multiplier = Decimal('1.25')
    else:
        multiplier = Decimal('1.00')

    # Adjust for employment type
    if employee.employment_type == 'part_time':
        multiplier *= Decimal('0.50')
    elif employee.employment_type in ['contract', 'temporary']:
        return Decimal('0.00')  # No accrual for contractors

    return base_rate * multiplier


# ==================== ONBOARDING REMINDERS ====================

@shared_task(
    bind=True,
    name='hr_core.tasks.send_onboarding_reminders',
    max_retries=3,
    default_retry_delay=600,
    autoretry_for=(Exception,),
)
def send_onboarding_reminders(self):
    """
    Send reminders for pending onboarding tasks.

    Reminds:
    - New hires about incomplete onboarding tasks
    - HR about employees starting soon
    - Managers about team member onboarding

    Returns:
        dict: Summary of reminders sent.
    """
    from hr_core.models import Employee, OnboardingTask, OnboardingChecklist

    try:
        now = timezone.now()
        reminders_sent = 0

        # Find employees with pending onboarding
        pending_employees = Employee.objects.filter(
            status='pending',
            start_date__isnull=False,
            start_date__lte=now.date() + timedelta(days=7)
        ).select_related('user')

        for employee in pending_employees:
            try:
                # Get incomplete tasks
                incomplete_tasks = OnboardingTask.objects.filter(
                    employee=employee,
                    is_completed=False
                )

                if incomplete_tasks.exists():
                    # Send reminder to employee
                    _send_onboarding_reminder(employee, incomplete_tasks)
                    reminders_sent += 1

                    # Notify manager if employee starts within 3 days
                    days_until_start = (employee.start_date - now.date()).days
                    if days_until_start <= 3 and employee.manager:
                        _notify_manager_of_new_hire(employee)

            except Exception as e:
                logger.error(f"Error sending onboarding reminder for {employee.employee_id}: {e}")

        # Send HR notifications for employees starting tomorrow
        starting_tomorrow = Employee.objects.filter(
            status='pending',
            start_date=now.date() + timedelta(days=1)
        )

        for employee in starting_tomorrow:
            try:
                _notify_hr_of_start(employee)
                reminders_sent += 1
            except Exception as e:
                logger.error(f"Error notifying HR of start: {e}")

        logger.info(f"Sent {reminders_sent} onboarding reminders")

        return {
            'status': 'success',
            'reminders_sent': reminders_sent,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error sending onboarding reminders: {str(e)}")
        raise self.retry(exc=e)


def _send_onboarding_reminder(employee, tasks):
    """Send onboarding task reminder to employee."""
    subject = "Complete your onboarding tasks"

    context = {
        'employee': employee,
        'tasks': tasks,
        'task_count': tasks.count(),
    }

    try:
        html_content = render_to_string('emails/onboarding_reminder.html', context)
        text_content = f"You have {tasks.count()} onboarding tasks to complete."
    except Exception:
        text_content = f"You have {tasks.count()} onboarding tasks to complete."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[employee.user.email],
        html_message=html_content,
        fail_silently=True,
    )


def _notify_manager_of_new_hire(employee):
    """Notify manager about new team member starting."""
    if not employee.manager:
        return

    subject = f"New team member starting: {employee.full_name}"

    context = {
        'manager': employee.manager,
        'employee': employee,
        'start_date': employee.start_date,
    }

    try:
        html_content = render_to_string('emails/new_hire_notification.html', context)
        text_content = f"{employee.full_name} is starting on {employee.start_date}."
    except Exception:
        text_content = f"{employee.full_name} is starting on {employee.start_date}."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[employee.manager.user.email],
        html_message=html_content,
        fail_silently=True,
    )


def _notify_hr_of_start(employee):
    """Notify HR about employee starting tomorrow."""
    # This would typically send to HR team email or specific HR managers
    subject = f"Employee starting tomorrow: {employee.full_name}"

    context = {'employee': employee}

    try:
        text_content = f"{employee.full_name} ({employee.job_title}) starts tomorrow."
        html_content = f"<p>{text_content}</p>"
    except Exception:
        text_content = f"Employee {employee.employee_id} starts tomorrow."
        html_content = f"<p>{text_content}</p>"

    # Send to default HR email (configurable)
    hr_email = getattr(settings, 'HR_NOTIFICATION_EMAIL', settings.DEFAULT_FROM_EMAIL)

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[hr_email],
        html_message=html_content,
        fail_silently=True,
    )


# ==================== PROBATION MANAGEMENT ====================

@shared_task(
    bind=True,
    name='hr_core.tasks.process_probation_ends',
    max_retries=3,
    default_retry_delay=300,
)
def process_probation_ends(self):
    """
    Process employees ending their probation period.

    Sends notifications for:
    - Employees whose probation ends today
    - Employees whose probation ends within 7 days

    Returns:
        dict: Summary of notifications sent.
    """
    from hr_core.models import Employee

    try:
        now = timezone.now()
        today = now.date()
        notifications_sent = 0

        # Find employees with probation ending soon
        upcoming_probation_ends = Employee.objects.filter(
            status='probation',
            probation_end_date__isnull=False,
            probation_end_date__gte=today,
            probation_end_date__lte=today + timedelta(days=7)
        ).select_related('user', 'manager')

        for employee in upcoming_probation_ends:
            try:
                days_remaining = (employee.probation_end_date - today).days

                # Notify manager
                if employee.manager:
                    _send_probation_end_notification(employee, days_remaining)
                    notifications_sent += 1

                # If probation ends today, update status
                if days_remaining == 0:
                    employee.status = 'active'
                    employee.save(update_fields=['status'])

                    # Send congratulations to employee
                    _send_probation_complete_notification(employee)
                    notifications_sent += 1

            except Exception as e:
                logger.error(f"Error processing probation end for {employee.employee_id}: {e}")

        logger.info(f"Sent {notifications_sent} probation notifications")

        return {
            'status': 'success',
            'notifications_sent': notifications_sent,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error processing probation ends: {str(e)}")
        raise self.retry(exc=e)


def _send_probation_end_notification(employee, days_remaining):
    """Send probation end notification to manager."""
    if days_remaining == 0:
        subject = f"Probation ending today: {employee.full_name}"
    else:
        subject = f"Probation ending in {days_remaining} days: {employee.full_name}"

    context = {
        'employee': employee,
        'days_remaining': days_remaining,
        'probation_end_date': employee.probation_end_date,
    }

    try:
        html_content = render_to_string('emails/probation_end_notification.html', context)
        text_content = f"{employee.full_name}'s probation ends in {days_remaining} days."
    except Exception:
        text_content = f"{employee.full_name}'s probation ends in {days_remaining} days."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[employee.manager.user.email],
        html_message=html_content,
        fail_silently=True,
    )


def _send_probation_complete_notification(employee):
    """Send probation completion notification to employee."""
    subject = "Congratulations! Your probation period is complete"

    context = {'employee': employee}

    try:
        html_content = render_to_string('emails/probation_complete.html', context)
        text_content = "Congratulations! Your probation period is now complete."
    except Exception:
        text_content = "Congratulations! Your probation period is now complete."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[employee.user.email],
        html_message=html_content,
        fail_silently=True,
    )


# ==================== TIME-OFF APPROVAL REMINDERS ====================

@shared_task(
    bind=True,
    name='hr_core.tasks.send_time_off_reminders',
    max_retries=3,
    default_retry_delay=600,
)
def send_time_off_reminders(self):
    """
    Send reminders for pending time-off approvals.

    Reminds managers about:
    - Time-off requests pending for more than 2 days
    - Upcoming time-off that needs coverage planning

    Returns:
        dict: Summary of reminders sent.
    """
    from hr_core.models import TimeOffRequest

    try:
        now = timezone.now()
        reminders_sent = 0

        # Find pending requests older than 2 days
        pending_requests = TimeOffRequest.objects.filter(
            status='pending',
            created_at__lt=now - timedelta(days=2)
        ).select_related('employee', 'employee__manager')

        # Group by approver
        approvers = {}
        for request in pending_requests:
            approver = request.employee.manager
            if approver:
                if approver.id not in approvers:
                    approvers[approver.id] = {
                        'manager': approver,
                        'requests': []
                    }
                approvers[approver.id]['requests'].append(request)

        # Send consolidated reminders
        for approver_data in approvers.values():
            try:
                _send_time_off_approval_reminder(
                    approver_data['manager'],
                    approver_data['requests']
                )
                reminders_sent += 1
            except Exception as e:
                logger.error(f"Error sending time-off reminder: {e}")

        logger.info(f"Sent {reminders_sent} time-off approval reminders")

        return {
            'status': 'success',
            'reminders_sent': reminders_sent,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error sending time-off reminders: {str(e)}")
        raise self.retry(exc=e)


def _send_time_off_approval_reminder(manager, requests):
    """Send time-off approval reminder to manager."""
    subject = f"You have {len(requests)} pending time-off requests"

    context = {
        'manager': manager,
        'requests': requests,
        'request_count': len(requests),
    }

    try:
        html_content = render_to_string('emails/time_off_approval_reminder.html', context)
        text_content = f"You have {len(requests)} time-off requests awaiting approval."
    except Exception:
        text_content = f"You have {len(requests)} time-off requests awaiting approval."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[manager.user.email],
        html_message=html_content,
        fail_silently=True,
    )


# ==================== EMPLOYEE ANNIVERSARIES ====================

@shared_task(
    bind=True,
    name='hr_core.tasks.update_employee_anniversaries',
    max_retries=3,
    default_retry_delay=300,
)
def update_employee_anniversaries(self):
    """
    Send work anniversary notifications.

    Sends notifications for:
    - Employees celebrating work anniversaries today
    - Upcoming milestone anniversaries (5, 10, 15, 20+ years)

    Returns:
        dict: Summary of notifications sent.
    """
    from hr_core.models import Employee

    try:
        now = timezone.now()
        today = now.date()
        notifications_sent = 0

        # Find employees with anniversaries today
        # Match month and day of hire date
        employees_with_anniversary = Employee.objects.filter(
            status='active',
            start_date__isnull=False,
            start_date__month=today.month,
            start_date__day=today.day
        ).exclude(
            start_date__year=today.year  # Exclude people who just started
        ).select_related('user', 'manager')

        for employee in employees_with_anniversary:
            try:
                years = today.year - employee.start_date.year

                # Send anniversary notification
                _send_anniversary_notification(employee, years)
                notifications_sent += 1

                # Notify manager of milestone anniversaries
                if years in [5, 10, 15, 20, 25, 30] and employee.manager:
                    _notify_manager_of_anniversary(employee, years)
                    notifications_sent += 1

            except Exception as e:
                logger.error(f"Error processing anniversary for {employee.employee_id}: {e}")

        logger.info(f"Sent {notifications_sent} anniversary notifications")

        return {
            'status': 'success',
            'notifications_sent': notifications_sent,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error processing anniversaries: {str(e)}")
        raise self.retry(exc=e)


def _send_anniversary_notification(employee, years):
    """Send work anniversary notification to employee."""
    subject = f"Happy {years}-year work anniversary!"

    context = {
        'employee': employee,
        'years': years,
    }

    try:
        html_content = render_to_string('emails/work_anniversary.html', context)
        text_content = f"Congratulations on your {years}-year work anniversary!"
    except Exception:
        text_content = f"Congratulations on your {years}-year work anniversary!"
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[employee.user.email],
        html_message=html_content,
        fail_silently=True,
    )


def _notify_manager_of_anniversary(employee, years):
    """Notify manager of employee's milestone anniversary."""
    subject = f"Milestone Anniversary: {employee.full_name} - {years} years"

    context = {
        'employee': employee,
        'years': years,
    }

    try:
        text_content = f"{employee.full_name} is celebrating their {years}-year anniversary today!"
        html_content = f"<p>{text_content}</p>"
    except Exception:
        text_content = f"Employee milestone anniversary: {years} years."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[employee.manager.user.email],
        html_message=html_content,
        fail_silently=True,
    )


# ==================== DOCUMENT EXPIRATION ====================

@shared_task(
    bind=True,
    name='hr_core.tasks.expire_pending_documents',
    max_retries=3,
    default_retry_delay=300,
)
def expire_pending_documents(self):
    """
    Expire documents awaiting signature past their deadline.

    Marks documents as expired if they have been pending
    signature for too long.

    Returns:
        dict: Summary of expired documents.
    """
    from hr_core.models import Document

    try:
        now = timezone.now()

        # Find documents pending signature for more than 7 days
        expired_docs = Document.objects.filter(
            status='pending_signature',
            sent_for_signature_at__lt=now - timedelta(days=7)
        )

        count = expired_docs.count()

        # Update status
        expired_docs.update(
            status='expired',
            expired_at=now
        )

        logger.info(f"Expired {count} pending documents")

        return {
            'status': 'success',
            'expired_count': count,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error expiring documents: {str(e)}")
        raise self.retry(exc=e)


@shared_task(
    bind=True,
    name='hr_core.tasks.send_document_signature_reminders',
    max_retries=3,
    default_retry_delay=600,
)
def send_document_signature_reminders(self):
    """
    Send reminders for documents awaiting signature.

    Returns:
        dict: Summary of reminders sent.
    """
    from hr_core.models import Document

    try:
        now = timezone.now()
        reminders_sent = 0

        # Find documents pending for more than 2 days
        pending_docs = Document.objects.filter(
            status='pending_signature',
            sent_for_signature_at__lt=now - timedelta(days=2)
        ).select_related('employee')

        for doc in pending_docs:
            try:
                _send_document_reminder(doc)
                reminders_sent += 1
            except Exception as e:
                logger.error(f"Error sending document reminder: {e}")

        logger.info(f"Sent {reminders_sent} document signature reminders")

        return {
            'status': 'success',
            'reminders_sent': reminders_sent,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error sending document reminders: {str(e)}")
        raise self.retry(exc=e)


def _send_document_reminder(document):
    """Send document signature reminder."""
    subject = f"Reminder: Please sign {document.title}"

    context = {
        'document': document,
        'employee': document.employee,
    }

    try:
        text_content = f"Please sign the document: {document.title}"
        html_content = f"<p>{text_content}</p>"
    except Exception:
        text_content = "Please sign your pending document."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[document.employee.user.email],
        html_message=html_content,
        fail_silently=True,
    )
