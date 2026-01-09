"""
HR Core Signals - Automatic HR workflows.
"""

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
import uuid

from .models import (
    Employee, EmployeeOnboarding, OnboardingTaskProgress,
    TimeOffRequest, Offboarding
)


@receiver(pre_save, sender=Employee)
def generate_employee_id(sender, instance, **kwargs):
    """Generate unique employee ID."""
    if not instance.employee_id:
        # Format: EMP-YYYYMM-XXXX
        date_part = timezone.now().strftime('%Y%m')
        random_part = uuid.uuid4().hex[:4].upper()
        instance.employee_id = f"EMP-{date_part}-{random_part}"


@receiver(post_save, sender=Employee)
def create_onboarding(sender, instance, created, **kwargs):
    """Create onboarding record for new employees."""
    if created and instance.status == Employee.EmploymentStatus.PENDING:
        # Auto-create onboarding if start date is set
        if instance.start_date:
            from .models import OnboardingChecklist
            # Find applicable checklist
            checklist = OnboardingChecklist.objects.filter(
                is_active=True,
                department=instance.department
            ).first() or OnboardingChecklist.objects.filter(
                is_active=True,
                department__isnull=True
            ).first()

            if checklist:
                onboarding = EmployeeOnboarding.objects.create(
                    employee=instance,
                    checklist=checklist,
                    start_date=instance.start_date,
                )

                # Create task progress entries
                for task in checklist.tasks.all():
                    due_date = None
                    if task.due_days:
                        due_date = instance.start_date + timezone.timedelta(days=task.due_days)

                    OnboardingTaskProgress.objects.create(
                        onboarding=onboarding,
                        task=task,
                        due_date=due_date,
                    )


@receiver(post_save, sender=TimeOffRequest)
def notify_time_off_request(sender, instance, created, **kwargs):
    """
    Send notification when time off request is created or status changes.

    Notifications are sent:
    - To manager when a new request is created (pending approval)
    - To employee when request is approved/rejected
    - To HR for compliance tracking
    """
    import logging
    logger = logging.getLogger(__name__)

    try:
        from notifications.models import Notification
        from django.conf import settings

        employee = instance.employee
        requester_user = employee.user if hasattr(employee, 'user') else None

        if created:
            # New request - notify manager
            manager = employee.manager
            if manager and hasattr(manager, 'user') and manager.user:
                Notification.objects.create(
                    user=manager.user,
                    notification_type='time_off_request',
                    title='New Time Off Request',
                    message=f'{employee.full_name} has submitted a time off request '
                            f'for {instance.start_date} to {instance.end_date} '
                            f'({instance.total_days} days - {instance.time_off_type.name})',
                    action_url=f'/hr/time-off/requests/{instance.id}/',
                    context_data={
                        'request_id': instance.id,
                        'employee_id': employee.id,
                        'employee_name': employee.full_name,
                        'start_date': str(instance.start_date),
                        'end_date': str(instance.end_date),
                        'days': float(instance.total_days),
                        'type': instance.time_off_type.name,
                    }
                )
                logger.info(f"Time off request notification sent to manager {manager.full_name}")

        else:
            # Status changed - check if approved/rejected
            old_status = getattr(instance, '_original_status', None)
            current_status = instance.status

            if old_status != current_status:
                # Status changed - notify the employee
                if requester_user:
                    if current_status == TimeOffRequest.RequestStatus.APPROVED:
                        Notification.objects.create(
                            user=requester_user,
                            notification_type='time_off_approved',
                            title='Time Off Request Approved',
                            message=f'Your time off request for {instance.start_date} to '
                                    f'{instance.end_date} has been approved.',
                            action_url=f'/hr/my-time-off/',
                            context_data={
                                'request_id': instance.id,
                                'start_date': str(instance.start_date),
                                'end_date': str(instance.end_date),
                            }
                        )
                        logger.info(f"Time off approval notification sent to {employee.full_name}")

                    elif current_status == TimeOffRequest.RequestStatus.REJECTED:
                        Notification.objects.create(
                            user=requester_user,
                            notification_type='time_off_rejected',
                            title='Time Off Request Rejected',
                            message=f'Your time off request for {instance.start_date} to '
                                    f'{instance.end_date} has been rejected. '
                                    f'Reason: {instance.rejection_reason or "Not specified"}',
                            action_url=f'/hr/my-time-off/',
                            context_data={
                                'request_id': instance.id,
                                'start_date': str(instance.start_date),
                                'end_date': str(instance.end_date),
                                'rejection_reason': instance.rejection_reason or '',
                            }
                        )
                        logger.info(f"Time off rejection notification sent to {employee.full_name}")

                    elif current_status == TimeOffRequest.RequestStatus.CANCELLED:
                        # Notify manager if employee cancelled
                        manager = employee.manager
                        if manager and hasattr(manager, 'user') and manager.user:
                            Notification.objects.create(
                                user=manager.user,
                                notification_type='time_off_cancelled',
                                title='Time Off Request Cancelled',
                                message=f'{employee.full_name} has cancelled their time off request '
                                        f'for {instance.start_date} to {instance.end_date}.',
                                action_url=f'/hr/time-off/requests/',
                            )

    except ImportError:
        # Notifications app not available
        logger.debug("Notifications app not available, skipping time off notification")
    except Exception as e:
        logger.error(f"Error sending time off notification: {e}")


@receiver(pre_save, sender=TimeOffRequest)
def store_original_status(sender, instance, **kwargs):
    """Store original status for comparison in post_save."""
    if instance.pk:
        try:
            original = TimeOffRequest.objects.get(pk=instance.pk)
            instance._original_status = original.status
        except TimeOffRequest.DoesNotExist:
            instance._original_status = None
    else:
        instance._original_status = None


@receiver(post_save, sender=Offboarding)
def update_employee_status(sender, instance, created, **kwargs):
    """Update employee status when offboarding is created."""
    if created:
        employee = instance.employee
        employee.status = Employee.EmploymentStatus.NOTICE_PERIOD
        employee.last_working_day = instance.last_working_day
        employee.save(update_fields=['status', 'last_working_day'])
