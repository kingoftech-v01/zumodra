"""
Management command to bulk import employees from CSV file.
"""

import csv
from datetime import datetime
from decimal import Decimal
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.db import connection, transaction
from django.utils import timezone
from tenants.models import Tenant
from hr_core.models import Employee

User = get_user_model()


class Command(BaseCommand):
    help = 'Bulk import employees from a CSV file'

    def add_arguments(self, parser):
        parser.add_argument(
            'csv_file',
            type=str,
            help='Path to the CSV file'
        )
        parser.add_argument(
            'tenant_slug',
            type=str,
            help='Target tenant slug'
        )
        parser.add_argument(
            '--delimiter',
            type=str,
            default=',',
            help='CSV delimiter (default: comma)'
        )
        parser.add_argument(
            '--encoding',
            type=str,
            default='utf-8',
            help='File encoding (default: utf-8)'
        )
        parser.add_argument(
            '--create-users',
            action='store_true',
            help='Create user accounts for employees if they do not exist'
        )
        parser.add_argument(
            '--default-password',
            type=str,
            default='ChangeMe123!',
            help='Default password for new user accounts'
        )
        parser.add_argument(
            '--status',
            type=str,
            default='pending',
            choices=[s[0] for s in Employee.EmploymentStatus.choices],
            help='Default employment status (default: pending)'
        )
        parser.add_argument(
            '--update-existing',
            action='store_true',
            help='Update existing employees based on email'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Validate without importing'
        )
        parser.add_argument(
            '--batch-size',
            type=int,
            default=50,
            help='Number of records to process in each batch (default: 50)'
        )

    def handle(self, *args, **options):
        csv_file = options['csv_file']
        tenant_slug = options['tenant_slug']
        delimiter = options.get('delimiter', ',')
        encoding = options.get('encoding', 'utf-8')
        create_users = options.get('create_users', False)
        default_password = options.get('default_password', 'ChangeMe123!')
        default_status = options.get('status', 'pending')
        update_existing = options.get('update_existing', False)
        dry_run = options.get('dry_run', False)
        batch_size = options.get('batch_size', 50)

        # Find tenant
        try:
            tenant = Tenant.objects.get(slug=tenant_slug)
        except Tenant.DoesNotExist:
            raise CommandError(f"Tenant not found: {tenant_slug}")

        self.stdout.write(f"Importing employees to tenant: {tenant.name}")

        if dry_run:
            self.stdout.write(self.style.WARNING("=== DRY RUN MODE ===\n"))

        # Switch to tenant schema
        connection.set_schema(tenant.schema_name)

        try:
            # Read and validate CSV
            employees_data = self._read_csv(csv_file, delimiter, encoding)
            self.stdout.write(f"Found {len(employees_data)} employee records in CSV")

            # Validate data
            errors = self._validate_employees(employees_data)
            if errors:
                self.stdout.write(self.style.ERROR("Validation errors:"))
                for error in errors[:10]:
                    self.stdout.write(f"  - {error}")
                if len(errors) > 10:
                    self.stdout.write(f"  ... and {len(errors) - 10} more errors")
                raise CommandError("Fix validation errors before importing")

            # Import employees
            stats = self._import_employees(
                employees_data, create_users, default_password, default_status,
                update_existing, dry_run, batch_size
            )

            # Print summary
            self.stdout.write("\n" + "=" * 50)
            self.stdout.write(self.style.SUCCESS("Import Summary:"))
            self.stdout.write(f"  Total records: {stats['total']}")
            self.stdout.write(f"  Users created: {stats['users_created']}")
            self.stdout.write(f"  Employees created: {stats['created']}")
            self.stdout.write(f"  Employees updated: {stats['updated']}")
            self.stdout.write(f"  Skipped: {stats['skipped']}")
            self.stdout.write(f"  Errors: {stats['errors']}")

        finally:
            connection.set_schema_to_public()

    def _read_csv(self, filepath, delimiter, encoding):
        """Read and parse CSV file."""
        employees = []

        try:
            with open(filepath, 'r', encoding=encoding) as f:
                reader = csv.DictReader(f, delimiter=delimiter)
                for row in reader:
                    employees.append(row)
        except FileNotFoundError:
            raise CommandError(f"File not found: {filepath}")
        except csv.Error as e:
            raise CommandError(f"CSV parsing error: {e}")

        return employees

    def _validate_employees(self, employees_data):
        """Validate employee data before import."""
        errors = []
        required_fields = ['email', 'first_name', 'last_name', 'job_title', 'hire_date']
        seen_emails = set()

        for i, employee in enumerate(employees_data, start=1):
            row_num = i + 1

            # Check required fields
            for field in required_fields:
                if not employee.get(field):
                    errors.append(f"Row {row_num}: Missing required field '{field}'")

            # Validate email
            email = employee.get('email', '').strip().lower()
            if email:
                if '@' not in email:
                    errors.append(f"Row {row_num}: Invalid email format")
                if email in seen_emails:
                    errors.append(f"Row {row_num}: Duplicate email in file")
                seen_emails.add(email)

            # Validate dates
            for date_field in ['hire_date', 'start_date', 'probation_end_date']:
                if employee.get(date_field):
                    try:
                        self._parse_date(employee[date_field])
                    except ValueError:
                        errors.append(
                            f"Row {row_num}: Invalid date format for {date_field}"
                        )

            # Validate salary
            if employee.get('base_salary'):
                try:
                    Decimal(employee['base_salary'])
                except:
                    errors.append(f"Row {row_num}: Invalid salary value")

        return errors

    def _parse_date(self, date_str):
        """Parse date from various formats."""
        formats = ['%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y', '%Y/%m/%d']
        for fmt in formats:
            try:
                return datetime.strptime(date_str.strip(), fmt).date()
            except ValueError:
                continue
        raise ValueError(f"Could not parse date: {date_str}")

    def _import_employees(self, employees_data, create_users, default_password,
                          default_status, update_existing, dry_run, batch_size):
        """Import employees from validated data."""
        stats = {
            'total': len(employees_data),
            'users_created': 0,
            'created': 0,
            'updated': 0,
            'skipped': 0,
            'errors': 0,
        }

        for i, emp_data in enumerate(employees_data):
            try:
                result = self._import_single_employee(
                    emp_data, create_users, default_password, default_status,
                    update_existing, dry_run
                )
                stats[result['action']] += 1
                if result.get('user_created'):
                    stats['users_created'] += 1

                if (i + 1) % batch_size == 0:
                    self.stdout.write(f"  Processed {i + 1}/{len(employees_data)} records...")

            except Exception as e:
                stats['errors'] += 1
                self.stdout.write(self.style.ERROR(f"  Error importing row {i + 1}: {e}"))

        return stats

    def _import_single_employee(self, data, create_users, default_password,
                                 default_status, update_existing, dry_run):
        """Import a single employee."""
        result = {'action': 'skipped', 'user_created': False}
        email = data['email'].strip().lower()

        # Find or create user
        user = User.objects.filter(email=email).first()

        if not user:
            if not create_users:
                self.stdout.write(
                    self.style.WARNING(f"    No user found for {email} (use --create-users)")
                )
                return result

            if dry_run:
                result['user_created'] = True
            else:
                user = User.objects.create_user(
                    email=email,
                    password=default_password,
                    first_name=data['first_name'].strip(),
                    last_name=data['last_name'].strip(),
                )
                result['user_created'] = True

        # Check for existing employee
        existing = Employee.objects.filter(user=user).first() if user else None

        if existing:
            if not update_existing:
                return result  # skipped

            if dry_run:
                result['action'] = 'updated'
                return result

            # Update existing employee
            self._update_employee(existing, data)
            existing.save()
            result['action'] = 'updated'
            return result

        if dry_run:
            result['action'] = 'created'
            return result

        # Generate employee ID
        emp_count = Employee.objects.count()
        employee_id = data.get('employee_id') or f"EMP-{str(emp_count + 1).zfill(4)}"

        # Create new employee
        employee = Employee(
            user=user,
            employee_id=employee_id,
            job_title=data['job_title'].strip(),
            hire_date=self._parse_date(data['hire_date']),
            status=default_status,
            employment_type=data.get('employment_type', 'full_time').lower(),
            team=data.get('team', '').strip(),
            work_location=data.get('work_location', '').strip(),
        )

        # Optional dates
        if data.get('start_date'):
            employee.start_date = self._parse_date(data['start_date'])
        if data.get('probation_end_date'):
            employee.probation_end_date = self._parse_date(data['probation_end_date'])

        # Salary
        if data.get('base_salary'):
            employee.base_salary = Decimal(data['base_salary'])
        if data.get('salary_currency'):
            employee.salary_currency = data['salary_currency'].upper()
        if data.get('pay_frequency'):
            employee.pay_frequency = data['pay_frequency'].lower()

        # Emergency contact
        if data.get('emergency_contact_name'):
            employee.emergency_contact_name = data['emergency_contact_name'].strip()
        if data.get('emergency_contact_phone'):
            employee.emergency_contact_phone = data['emergency_contact_phone'].strip()
        if data.get('emergency_contact_relationship'):
            employee.emergency_contact_relationship = data['emergency_contact_relationship'].strip()

        employee.save()
        result['action'] = 'created'
        return result

    def _update_employee(self, employee, data):
        """Update an existing employee with new data."""
        if data.get('job_title'):
            employee.job_title = data['job_title'].strip()
        if data.get('team'):
            employee.team = data['team'].strip()
        if data.get('work_location'):
            employee.work_location = data['work_location'].strip()
        if data.get('base_salary'):
            employee.base_salary = Decimal(data['base_salary'])
        if data.get('employment_type'):
            employee.employment_type = data['employment_type'].lower()
