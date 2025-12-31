"""
Management command to bulk import job postings from CSV file.
"""

import csv
import uuid
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from django.utils import timezone
from django.utils.text import slugify
from tenants.models import Tenant
from ats.models import JobPosting, JobCategory, Pipeline


class Command(BaseCommand):
    help = 'Bulk import job postings from a CSV file'

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
            '--skip-header',
            action='store_true',
            default=True,
            help='Skip first row as header (default: True)'
        )
        parser.add_argument(
            '--status',
            type=str,
            default='draft',
            choices=['draft', 'open', 'on_hold'],
            help='Default status for imported jobs (default: draft)'
        )
        parser.add_argument(
            '--update-existing',
            action='store_true',
            help='Update existing jobs based on reference_code'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Validate without importing'
        )
        parser.add_argument(
            '--batch-size',
            type=int,
            default=100,
            help='Number of records to process in each batch (default: 100)'
        )

    def handle(self, *args, **options):
        csv_file = options['csv_file']
        tenant_slug = options['tenant_slug']
        delimiter = options.get('delimiter', ',')
        encoding = options.get('encoding', 'utf-8')
        skip_header = options.get('skip_header', True)
        default_status = options.get('status', 'draft')
        update_existing = options.get('update_existing', False)
        dry_run = options.get('dry_run', False)
        batch_size = options.get('batch_size', 100)

        # Find tenant
        try:
            tenant = Tenant.objects.get(slug=tenant_slug)
        except Tenant.DoesNotExist:
            raise CommandError(f"Tenant not found: {tenant_slug}")

        self.stdout.write(f"Importing jobs to tenant: {tenant.name}")

        if dry_run:
            self.stdout.write(self.style.WARNING("=== DRY RUN MODE ===\n"))

        # Switch to tenant schema
        connection.set_schema(tenant.schema_name)

        try:
            # Read and validate CSV
            jobs_data = self._read_csv(csv_file, delimiter, encoding, skip_header)
            self.stdout.write(f"Found {len(jobs_data)} job records in CSV")

            # Validate data
            errors = self._validate_jobs(jobs_data)
            if errors:
                self.stdout.write(self.style.ERROR("Validation errors:"))
                for error in errors[:10]:  # Show first 10 errors
                    self.stdout.write(f"  - {error}")
                if len(errors) > 10:
                    self.stdout.write(f"  ... and {len(errors) - 10} more errors")
                raise CommandError("Fix validation errors before importing")

            # Import jobs
            stats = self._import_jobs(
                jobs_data, default_status, update_existing, dry_run, batch_size
            )

            # Print summary
            self.stdout.write("\n" + "=" * 50)
            self.stdout.write(self.style.SUCCESS("Import Summary:"))
            self.stdout.write(f"  Total records: {stats['total']}")
            self.stdout.write(f"  Created: {stats['created']}")
            self.stdout.write(f"  Updated: {stats['updated']}")
            self.stdout.write(f"  Skipped: {stats['skipped']}")
            self.stdout.write(f"  Errors: {stats['errors']}")

        finally:
            connection.set_schema_to_public()

    def _read_csv(self, filepath, delimiter, encoding, skip_header):
        """Read and parse CSV file."""
        jobs = []

        try:
            with open(filepath, 'r', encoding=encoding) as f:
                reader = csv.DictReader(f, delimiter=delimiter)
                for row in reader:
                    jobs.append(row)
        except FileNotFoundError:
            raise CommandError(f"File not found: {filepath}")
        except csv.Error as e:
            raise CommandError(f"CSV parsing error: {e}")

        return jobs

    def _validate_jobs(self, jobs_data):
        """Validate job data before import."""
        errors = []
        required_fields = ['title']

        for i, job in enumerate(jobs_data, start=1):
            row_num = i + 1  # Account for header

            # Check required fields
            for field in required_fields:
                if not job.get(field):
                    errors.append(f"Row {row_num}: Missing required field '{field}'")

            # Validate job type
            job_type = job.get('job_type', '').lower()
            valid_types = [t[0] for t in JobPosting.JobType.choices]
            if job_type and job_type not in valid_types:
                errors.append(f"Row {row_num}: Invalid job_type '{job_type}'")

            # Validate experience level
            exp_level = job.get('experience_level', '').lower()
            valid_levels = [l[0] for l in JobPosting.ExperienceLevel.choices]
            if exp_level and exp_level not in valid_levels:
                errors.append(f"Row {row_num}: Invalid experience_level '{exp_level}'")

            # Validate salary fields
            try:
                if job.get('salary_min'):
                    float(job['salary_min'])
                if job.get('salary_max'):
                    float(job['salary_max'])
            except ValueError:
                errors.append(f"Row {row_num}: Invalid salary value")

        return errors

    def _import_jobs(self, jobs_data, default_status, update_existing, dry_run, batch_size):
        """Import jobs from validated data."""
        stats = {
            'total': len(jobs_data),
            'created': 0,
            'updated': 0,
            'skipped': 0,
            'errors': 0,
        }

        # Get default pipeline
        default_pipeline = Pipeline.objects.filter(is_default=True).first()

        for i, job_data in enumerate(jobs_data):
            try:
                result = self._import_single_job(
                    job_data, default_status, default_pipeline, update_existing, dry_run
                )
                stats[result] += 1

                if (i + 1) % batch_size == 0:
                    self.stdout.write(f"  Processed {i + 1}/{len(jobs_data)} records...")

            except Exception as e:
                stats['errors'] += 1
                self.stdout.write(self.style.ERROR(f"  Error importing row {i + 1}: {e}"))

        return stats

    def _import_single_job(self, data, default_status, default_pipeline, update_existing, dry_run):
        """Import a single job posting."""
        # Generate reference code if not provided
        reference_code = data.get('reference_code') or f"JOB-{uuid.uuid4().hex[:8].upper()}"

        # Check if exists
        existing = JobPosting.objects.filter(reference_code=reference_code).first()

        if existing:
            if not update_existing:
                return 'skipped'
            if dry_run:
                return 'updated'

            # Update existing
            self._update_job(existing, data)
            existing.save()
            return 'updated'

        if dry_run:
            return 'created'

        # Create new job
        job = JobPosting(
            title=data['title'],
            reference_code=reference_code,
            slug=slugify(data['title'])[:220],
            description=data.get('description', ''),
            responsibilities=data.get('responsibilities', ''),
            requirements=data.get('requirements', ''),
            benefits=data.get('benefits', ''),
            job_type=data.get('job_type', JobPosting.JobType.FULL_TIME).lower(),
            experience_level=data.get('experience_level', JobPosting.ExperienceLevel.MID).lower(),
            remote_policy=data.get('remote_policy', JobPosting.RemotePolicy.ON_SITE).lower(),
            location_city=data.get('location_city', ''),
            location_state=data.get('location_state', ''),
            location_country=data.get('location_country', 'Canada'),
            status=default_status,
            pipeline=default_pipeline,
        )

        # Salary
        if data.get('salary_min'):
            job.salary_min = float(data['salary_min'])
        if data.get('salary_max'):
            job.salary_max = float(data['salary_max'])
        if data.get('salary_currency'):
            job.salary_currency = data['salary_currency']

        # Skills (comma-separated)
        if data.get('required_skills'):
            job.required_skills = [s.strip() for s in data['required_skills'].split(',')]

        # Category
        if data.get('category'):
            category, _ = JobCategory.objects.get_or_create(
                name=data['category'],
                defaults={'slug': slugify(data['category'])}
            )
            job.category = category

        job.save()
        return 'created'

    def _update_job(self, job, data):
        """Update an existing job with new data."""
        if data.get('title'):
            job.title = data['title']
        if data.get('description'):
            job.description = data['description']
        if data.get('requirements'):
            job.requirements = data['requirements']
        if data.get('benefits'):
            job.benefits = data['benefits']
        if data.get('job_type'):
            job.job_type = data['job_type'].lower()
        if data.get('experience_level'):
            job.experience_level = data['experience_level'].lower()
        if data.get('salary_min'):
            job.salary_min = float(data['salary_min'])
        if data.get('salary_max'):
            job.salary_max = float(data['salary_max'])
