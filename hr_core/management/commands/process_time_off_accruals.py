"""
Management command to process time-off accruals for employees.
Should be run on a regular schedule (e.g., per pay period or monthly).
"""

from decimal import Decimal
from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django.utils import timezone
from tenants.models import Tenant
from hr_core.models import Employee, TimeOffType


class Command(BaseCommand):
    help = 'Process time-off accruals for employees based on accrual policies'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant',
            type=str,
            help='Specific tenant slug (processes all active tenants if not specified)'
        )
        parser.add_argument(
            '--employee-id',
            type=str,
            help='Specific employee ID to process'
        )
        parser.add_argument(
            '--time-off-type',
            type=str,
            help='Specific time-off type code (e.g., PTO, SICK)'
        )
        parser.add_argument(
            '--period',
            type=str,
            default='bi_weekly',
            choices=['weekly', 'bi_weekly', 'semi_monthly', 'monthly'],
            help='Accrual period (default: bi_weekly)'
        )
        parser.add_argument(
            '--accrual-date',
            type=str,
            help='Override accrual date (YYYY-MM-DD format)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be accrued without making changes'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed progress'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force accrual even if already processed for this period'
        )

    def handle(self, *args, **options):
        tenant_slug = options.get('tenant')
        employee_id = options.get('employee_id')
        time_off_type_code = options.get('time_off_type')
        period = options.get('period', 'bi_weekly')
        accrual_date_str = options.get('accrual_date')
        dry_run = options.get('dry_run', False)
        verbose = options.get('verbose', False)
        force = options.get('force', False)

        if dry_run:
            self.stdout.write(self.style.WARNING("=== DRY RUN MODE ===\n"))

        # Parse accrual date
        if accrual_date_str:
            try:
                accrual_date = timezone.datetime.strptime(accrual_date_str, '%Y-%m-%d').date()
            except ValueError:
                raise CommandError("Invalid date format. Use YYYY-MM-DD")
        else:
            accrual_date = timezone.now().date()

        self.stdout.write(f"Accrual date: {accrual_date}")
        self.stdout.write(f"Period: {period}")

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
            'employees': 0,
            'accruals': 0,
            'total_days': Decimal('0'),
            'capped': 0,
            'errors': 0,
        }

        for tenant in tenants:
            self.stdout.write(f"\nProcessing tenant: {tenant.name}")
            total_stats['tenants'] += 1

            connection.set_schema(tenant.schema_name)

            try:
                stats = self._process_tenant(
                    employee_id, time_off_type_code, period, accrual_date,
                    dry_run, verbose, force
                )

                total_stats['employees'] += stats['employees']
                total_stats['accruals'] += stats['accruals']
                total_stats['total_days'] += stats['total_days']
                total_stats['capped'] += stats['capped']
                total_stats['errors'] += stats['errors']

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  Error: {e}"))
                total_stats['errors'] += 1
            finally:
                connection.set_schema_to_public()

        # Print summary
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(self.style.SUCCESS("Accrual Summary:"))
        self.stdout.write(f"  Tenants processed: {total_stats['tenants']}")
        self.stdout.write(f"  Employees processed: {total_stats['employees']}")
        self.stdout.write(f"  Accruals applied: {total_stats['accruals']}")
        self.stdout.write(f"  Total days accrued: {total_stats['total_days']:.2f}")
        self.stdout.write(f"  Capped at max balance: {total_stats['capped']}")
        self.stdout.write(f"  Errors: {total_stats['errors']}")

    def _process_tenant(self, employee_id, time_off_type_code, period,
                        accrual_date, dry_run, verbose, force):
        """Process accruals for a tenant."""
        stats = {
            'employees': 0,
            'accruals': 0,
            'total_days': Decimal('0'),
            'capped': 0,
            'errors': 0,
        }

        # Get time-off types with accruals
        time_off_types = TimeOffType.objects.filter(is_active=True, is_accrued=True)
        if time_off_type_code:
            time_off_types = time_off_types.filter(code=time_off_type_code)

        if not time_off_types.exists():
            self.stdout.write("  No accrual-based time-off types found")
            return stats

        # Get eligible employees
        employees = Employee.objects.filter(
            status__in=[
                Employee.EmploymentStatus.ACTIVE,
                Employee.EmploymentStatus.PROBATION,
            ]
        )
        if employee_id:
            employees = employees.filter(employee_id=employee_id)

        for employee in employees:
            stats['employees'] += 1

            for time_off_type in time_off_types:
                try:
                    result = self._process_employee_accrual(
                        employee, time_off_type, period, accrual_date,
                        dry_run, verbose, force
                    )

                    if result['accrued']:
                        stats['accruals'] += 1
                        stats['total_days'] += result['amount']
                        if result['capped']:
                            stats['capped'] += 1

                except Exception as e:
                    stats['errors'] += 1
                    if verbose:
                        self.stdout.write(
                            self.style.ERROR(
                                f"    Error for {employee.employee_id}: {e}"
                            )
                        )

        return stats

    def _process_employee_accrual(self, employee, time_off_type, period,
                                   accrual_date, dry_run, verbose, force):
        """Process accrual for a single employee and time-off type."""
        result = {
            'accrued': False,
            'amount': Decimal('0'),
            'capped': False,
        }

        # Check if employee is eligible based on tenure
        if employee.start_date and employee.start_date > accrual_date:
            return result  # Not yet started

        # Get current balance
        if time_off_type.code.upper() == 'PTO':
            current_balance = employee.pto_balance
        elif time_off_type.code.upper() == 'SICK':
            current_balance = employee.sick_leave_balance
        else:
            current_balance = Decimal('0')

        # Calculate accrual amount based on period
        accrual_rate = time_off_type.accrual_rate
        if period == 'weekly':
            accrual_amount = accrual_rate * Decimal('2')  # Assuming bi-weekly rate
        elif period == 'bi_weekly':
            accrual_amount = accrual_rate
        elif period == 'semi_monthly':
            accrual_amount = accrual_rate * Decimal('1.083')  # ~26/24
        elif period == 'monthly':
            accrual_amount = accrual_rate * Decimal('2.167')  # ~26/12
        else:
            accrual_amount = accrual_rate

        # Check max balance cap
        new_balance = current_balance + accrual_amount
        if time_off_type.max_balance and new_balance > time_off_type.max_balance:
            accrual_amount = max(Decimal('0'), time_off_type.max_balance - current_balance)
            result['capped'] = True
            new_balance = time_off_type.max_balance

        if accrual_amount <= 0:
            if verbose:
                self.stdout.write(
                    f"    {employee.employee_id}: {time_off_type.code} - "
                    f"No accrual (at max balance: {current_balance})"
                )
            return result

        result['accrued'] = True
        result['amount'] = accrual_amount

        if verbose:
            cap_note = " (capped)" if result['capped'] else ""
            self.stdout.write(
                f"    {employee.employee_id}: {time_off_type.code} - "
                f"+{accrual_amount:.2f} days (new balance: {new_balance:.2f}){cap_note}"
            )

        if not dry_run:
            # Update the appropriate balance field
            if time_off_type.code.upper() == 'PTO':
                employee.pto_balance = new_balance
                employee.save(update_fields=['pto_balance'])
            elif time_off_type.code.upper() == 'SICK':
                employee.sick_leave_balance = new_balance
                employee.save(update_fields=['sick_leave_balance'])

        return result
