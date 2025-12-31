"""
Management command to send onboarding task reminders.
Notifies relevant parties about pending onboarding tasks.
"""

from datetime import timedelta
from django.core.management.base import BaseCommand, CommandError
from django.core.mail import send_mail
from django.conf import settings
from django.db import connection
from django.utils import timezone
from tenants.models import Tenant
from hr_core.models import (
    Employee, EmployeeOnboarding, OnboardingTaskProgress, OnboardingTask
)


class Command(BaseCommand):
    help = 'Send reminders for pending onboarding tasks'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant',
            type=str,
            help='Specific tenant slug (processes all active tenants if not specified)'
        )
        parser.add_argument(
            '--employee-id',
            type=str,
            help='Specific employee ID'
        )
        parser.add_argument(
            '--due-days',
            type=int,
            default=3,
            help='Send reminders for tasks due within N days (default: 3)'
        )
        parser.add_argument(
            '--overdue',
            action='store_true',
            help='Include overdue tasks in reminders'
        )
        parser.add_argument(
            '--reminder-type',
            type=str,
            default='all',
            choices=['all', 'employee', 'hr', 'manager'],
            help='Who to send reminders to (default: all)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be sent without sending emails'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed progress'
        )

    def handle(self, *args, **options):
        tenant_slug = options.get('tenant')
        employee_id = options.get('employee_id')
        due_days = options.get('due_days', 3)
        include_overdue = options.get('overdue', False)
        reminder_type = options.get('reminder_type', 'all')
        dry_run = options.get('dry_run', False)
        verbose = options.get('verbose', False)

        if dry_run:
            self.stdout.write(self.style.WARNING("=== DRY RUN MODE ===\n"))

        self.stdout.write(f"Sending reminders for tasks due within {due_days} days")
        if include_overdue:
            self.stdout.write("Including overdue tasks")

        # Determine tenants to process
        if tenant_slug:
            try:
                tenants = [Tenant.objects.get(slug=tenant_slug)]
            except Tenant.DoesNotExist:
                raise CommandError(f"Tenant not found: {tenant_slug}")
        else:
            tenants = Tenant.objects.filter(status=Tenant.TenantStatus.ACTIVE)

        total_stats = {
            'tenants': 0,
            'onboardings': 0,
            'tasks': 0,
            'emails_sent': 0,
            'errors': 0,
        }

        for tenant in tenants:
            self.stdout.write(f"\nProcessing tenant: {tenant.name}")
            total_stats['tenants'] += 1

            connection.set_schema(tenant.schema_name)

            try:
                stats = self._process_tenant(
                    tenant, employee_id, due_days, include_overdue,
                    reminder_type, dry_run, verbose
                )

                total_stats['onboardings'] += stats['onboardings']
                total_stats['tasks'] += stats['tasks']
                total_stats['emails_sent'] += stats['emails_sent']
                total_stats['errors'] += stats['errors']

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  Error: {e}"))
                total_stats['errors'] += 1
            finally:
                connection.set_schema_to_public()

        # Print summary
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(self.style.SUCCESS("Reminder Summary:"))
        self.stdout.write(f"  Tenants processed: {total_stats['tenants']}")
        self.stdout.write(f"  Onboardings checked: {total_stats['onboardings']}")
        self.stdout.write(f"  Pending tasks found: {total_stats['tasks']}")
        self.stdout.write(f"  Emails sent: {total_stats['emails_sent']}")
        self.stdout.write(f"  Errors: {total_stats['errors']}")

    def _process_tenant(self, tenant, employee_id, due_days, include_overdue,
                        reminder_type, dry_run, verbose):
        """Process reminders for a tenant."""
        stats = {
            'onboardings': 0,
            'tasks': 0,
            'emails_sent': 0,
            'errors': 0,
        }

        # Get active onboardings
        onboardings = EmployeeOnboarding.objects.filter(
            completed_at__isnull=True,
            employee__status__in=[
                Employee.EmploymentStatus.PENDING,
                Employee.EmploymentStatus.PROBATION,
                Employee.EmploymentStatus.ACTIVE,
            ]
        )

        if employee_id:
            onboardings = onboardings.filter(employee__employee_id=employee_id)

        today = timezone.now().date()
        due_cutoff = today + timedelta(days=due_days)

        for onboarding in onboardings:
            stats['onboardings'] += 1

            # Get pending tasks
            pending_tasks = OnboardingTaskProgress.objects.filter(
                onboarding=onboarding,
                is_completed=False
            ).select_related('task')

            # Filter by due date
            tasks_to_remind = []
            for task_progress in pending_tasks:
                task_due = task_progress.due_date

                if not task_due:
                    # Calculate due date from start date + due_days
                    if onboarding.start_date and task_progress.task.due_days:
                        task_due = onboarding.start_date + timedelta(
                            days=task_progress.task.due_days
                        )

                if task_due:
                    if task_due <= due_cutoff:
                        is_overdue = task_due < today
                        if is_overdue and not include_overdue:
                            continue
                        tasks_to_remind.append({
                            'task': task_progress.task,
                            'due_date': task_due,
                            'is_overdue': is_overdue,
                        })

            if not tasks_to_remind:
                continue

            stats['tasks'] += len(tasks_to_remind)

            if verbose:
                self.stdout.write(
                    f"  {onboarding.employee.full_name}: {len(tasks_to_remind)} pending tasks"
                )

            # Send reminders based on type
            emails_sent = self._send_reminders(
                tenant, onboarding, tasks_to_remind, reminder_type, dry_run, verbose
            )
            stats['emails_sent'] += emails_sent

        return stats

    def _send_reminders(self, tenant, onboarding, tasks, reminder_type, dry_run, verbose):
        """Send reminder emails for pending tasks."""
        emails_sent = 0
        employee = onboarding.employee

        # Group tasks by assigned role
        hr_tasks = [t for t in tasks if t['task'].assigned_to_role.lower() == 'hr']
        manager_tasks = [t for t in tasks if t['task'].assigned_to_role.lower() == 'manager']
        employee_tasks = [t for t in tasks if t['task'].assigned_to_role.lower() in ['', 'employee']]

        # Send to employee
        if reminder_type in ['all', 'employee'] and employee_tasks:
            if self._send_email(
                recipient=employee.user.email,
                subject=f"Onboarding Tasks Reminder - {len(employee_tasks)} pending",
                employee_name=employee.full_name,
                tasks=employee_tasks,
                tenant_name=tenant.name,
                dry_run=dry_run,
                verbose=verbose
            ):
                emails_sent += 1

        # Send to HR
        if reminder_type in ['all', 'hr'] and hr_tasks:
            # Find HR users (simplified - in practice, query TenantUser with HR role)
            hr_email = tenant.owner_email  # Fallback to owner
            if self._send_email(
                recipient=hr_email,
                subject=f"HR Action Required: {employee.full_name} Onboarding - {len(hr_tasks)} tasks",
                employee_name=employee.full_name,
                tasks=hr_tasks,
                tenant_name=tenant.name,
                dry_run=dry_run,
                verbose=verbose
            ):
                emails_sent += 1

        # Send to manager
        if reminder_type in ['all', 'manager'] and manager_tasks and employee.manager:
            if self._send_email(
                recipient=employee.manager.user.email,
                subject=f"Manager Action Required: {employee.full_name} Onboarding - {len(manager_tasks)} tasks",
                employee_name=employee.full_name,
                tasks=manager_tasks,
                tenant_name=tenant.name,
                dry_run=dry_run,
                verbose=verbose
            ):
                emails_sent += 1

        return emails_sent

    def _send_email(self, recipient, subject, employee_name, tasks, tenant_name,
                    dry_run, verbose):
        """Send a reminder email."""
        # Build task list
        task_lines = []
        for t in tasks:
            status = "OVERDUE" if t['is_overdue'] else f"Due: {t['due_date']}"
            task_lines.append(f"  - {t['task'].title} ({status})")

        task_list = "\n".join(task_lines)

        body = f"""
Hello,

This is a reminder about pending onboarding tasks for {employee_name} at {tenant_name}.

Pending Tasks:
{task_list}

Please complete these tasks as soon as possible.

Best regards,
Zumodra HR System
        """.strip()

        if verbose:
            self.stdout.write(f"    Sending to: {recipient}")

        if dry_run:
            if verbose:
                self.stdout.write(f"    [DRY RUN] Subject: {subject}")
            return True

        try:
            send_mail(
                subject=subject,
                message=body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[recipient],
                fail_silently=False,
            )
            return True
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"    Failed to send email: {e}"))
            return False
