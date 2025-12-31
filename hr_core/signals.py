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
    """Send notification when time off request is created or status changes."""
    if created:
        # TODO: Send notification to manager
        pass


@receiver(post_save, sender=Offboarding)
def update_employee_status(sender, instance, created, **kwargs):
    """Update employee status when offboarding is created."""
    if created:
        employee = instance.employee
        employee.status = Employee.EmploymentStatus.NOTICE_PERIOD
        employee.last_working_day = instance.last_working_day
        employee.save(update_fields=['status', 'last_working_day'])
