"""
Management command to generate employee IDs for employees without one.
Supports various ID formats and patterns.
"""

import re
from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django.utils import timezone
from tenants.models import Tenant
from hr_core.models import Employee


class Command(BaseCommand):
    help = 'Generate employee IDs for employees without one'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant',
            type=str,
            help='Specific tenant slug (processes all active tenants if not specified)'
        )
        parser.add_argument(
            '--format',
            type=str,
            default='EMP-{NNNN}',
            help='ID format pattern. Placeholders: {NNNN}=seq number, {YYYY}=year, '
                 '{MM}=month, {DD}=day, {DEPT}=department code (default: EMP-{NNNN})'
        )
        parser.add_argument(
            '--start-number',
            type=int,
            default=1,
            help='Starting sequence number (default: 1)'
        )
        parser.add_argument(
            '--padding',
            type=int,
            default=4,
            help='Zero-padding for sequence numbers (default: 4)'
        )
        parser.add_argument(
            '--prefix',
            type=str,
            default='',
            help='Additional prefix for all IDs'
        )
        parser.add_argument(
            '--suffix',
            type=str,
            default='',
            help='Additional suffix for all IDs'
        )
        parser.add_argument(
            '--regenerate',
            action='store_true',
            help='Regenerate IDs for all employees (WARNING: may break references)'
        )
        parser.add_argument(
            '--status',
            type=str,
            nargs='+',
            choices=[s[0] for s in Employee.EmploymentStatus.choices],
            help='Only process employees with these statuses'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be generated without making changes'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed progress'
        )

    def handle(self, *args, **options):
        tenant_slug = options.get('tenant')
        id_format = options.get('format', 'EMP-{NNNN}')
        start_number = options.get('start_number', 1)
        padding = options.get('padding', 4)
        prefix = options.get('prefix', '')
        suffix = options.get('suffix', '')
        regenerate = options.get('regenerate', False)
        statuses = options.get('status')
        dry_run = options.get('dry_run', False)
        verbose = options.get('verbose', False)

        if dry_run:
            self.stdout.write(self.style.WARNING("=== DRY RUN MODE ===\n"))

        if regenerate:
            self.stdout.write(self.style.WARNING(
                "WARNING: Regenerating IDs may break external references!"
            ))

        self.stdout.write(f"ID Format: {prefix}{id_format}{suffix}")

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
            'generated': 0,
            'skipped': 0,
            'errors': 0,
        }

        for tenant in tenants:
            self.stdout.write(f"\nProcessing tenant: {tenant.name}")
            total_stats['tenants'] += 1

            connection.set_schema(tenant.schema_name)

            try:
                stats = self._process_tenant(
                    id_format, start_number, padding, prefix, suffix,
                    regenerate, statuses, dry_run, verbose
                )

                total_stats['generated'] += stats['generated']
                total_stats['skipped'] += stats['skipped']
                total_stats['errors'] += stats['errors']

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  Error: {e}"))
                total_stats['errors'] += 1
            finally:
                connection.set_schema_to_public()

        # Print summary
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(self.style.SUCCESS("Generation Summary:"))
        self.stdout.write(f"  Tenants processed: {total_stats['tenants']}")
        self.stdout.write(f"  IDs generated: {total_stats['generated']}")
        self.stdout.write(f"  Skipped (already have ID): {total_stats['skipped']}")
        self.stdout.write(f"  Errors: {total_stats['errors']}")

    def _process_tenant(self, id_format, start_number, padding, prefix, suffix,
                        regenerate, statuses, dry_run, verbose):
        """Generate employee IDs for a tenant."""
        stats = {
            'generated': 0,
            'skipped': 0,
            'errors': 0,
        }

        # Build queryset
        employees = Employee.objects.all()

        if statuses:
            employees = employees.filter(status__in=statuses)

        if not regenerate:
            # Only employees without IDs or with placeholder IDs
            employees = employees.filter(employee_id='') | \
                       employees.filter(employee_id__startswith='TEMP-')

        # Get current max sequence number
        existing_ids = Employee.objects.exclude(employee_id='').values_list(
            'employee_id', flat=True
        )
        current_max = self._find_max_sequence(existing_ids, id_format)
        sequence = max(start_number, current_max + 1)

        employees = employees.order_by('hire_date', 'pk')

        for employee in employees:
            try:
                if employee.employee_id and not regenerate:
                    stats['skipped'] += 1
                    continue

                # Generate new ID
                new_id = self._generate_id(
                    employee, id_format, sequence, padding, prefix, suffix
                )

                # Check for uniqueness
                if Employee.objects.filter(employee_id=new_id).exclude(pk=employee.pk).exists():
                    # Increment sequence and try again
                    sequence += 1
                    new_id = self._generate_id(
                        employee, id_format, sequence, padding, prefix, suffix
                    )

                if verbose:
                    old_id = employee.employee_id or "(none)"
                    self.stdout.write(f"    {employee.full_name}: {old_id} -> {new_id}")

                if not dry_run:
                    employee.employee_id = new_id
                    employee.save(update_fields=['employee_id'])

                stats['generated'] += 1
                sequence += 1

            except Exception as e:
                stats['errors'] += 1
                if verbose:
                    self.stdout.write(
                        self.style.ERROR(f"    Error for {employee.full_name}: {e}")
                    )

        return stats

    def _generate_id(self, employee, id_format, sequence, padding, prefix, suffix):
        """Generate an employee ID from the format pattern."""
        today = timezone.now().date()

        # Replace placeholders
        result = id_format

        # Sequence number with padding
        seq_pattern = r'\{N+\}'
        match = re.search(seq_pattern, result)
        if match:
            n_count = match.group().count('N')
            result = re.sub(seq_pattern, str(sequence).zfill(max(padding, n_count)), result)

        # Date components
        result = result.replace('{YYYY}', str(today.year))
        result = result.replace('{YY}', str(today.year)[-2:])
        result = result.replace('{MM}', str(today.month).zfill(2))
        result = result.replace('{DD}', str(today.day).zfill(2))

        # Employee hire date
        if employee.hire_date:
            result = result.replace('{HIRE_YYYY}', str(employee.hire_date.year))
            result = result.replace('{HIRE_YY}', str(employee.hire_date.year)[-2:])

        # Department code
        if employee.department:
            dept_code = employee.department.name[:3].upper()
            result = result.replace('{DEPT}', dept_code)
        else:
            result = result.replace('{DEPT}', 'GEN')

        # Initials
        initials = (employee.first_name[:1] + employee.last_name[:1]).upper()
        result = result.replace('{INIT}', initials)

        return f"{prefix}{result}{suffix}"

    def _find_max_sequence(self, existing_ids, id_format):
        """Find the maximum sequence number in existing IDs."""
        max_seq = 0

        # Extract numeric portions from IDs
        for emp_id in existing_ids:
            # Find all numeric sequences in the ID
            numbers = re.findall(r'\d+', emp_id)
            for num in numbers:
                try:
                    val = int(num)
                    if val > max_seq and val < 1000000:  # Reasonable limit
                        max_seq = val
                except ValueError:
                    pass

        return max_seq
