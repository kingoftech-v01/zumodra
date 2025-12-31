"""
Management command to bulk import candidates from CSV file.
"""

import csv
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from django.utils import timezone
from tenants.models import Tenant
from ats.models import Candidate


class Command(BaseCommand):
    help = 'Bulk import candidates from a CSV file'

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
            '--source',
            type=str,
            default='imported',
            choices=[s[0] for s in Candidate.Source.choices],
            help='Source for imported candidates (default: imported)'
        )
        parser.add_argument(
            '--source-detail',
            type=str,
            default='',
            help='Source detail (e.g., campaign name, recruiter name)'
        )
        parser.add_argument(
            '--update-existing',
            action='store_true',
            help='Update existing candidates based on email'
        )
        parser.add_argument(
            '--skip-duplicates',
            action='store_true',
            help='Skip duplicate emails without error'
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
        parser.add_argument(
            '--tags',
            type=str,
            help='Comma-separated tags to add to all imported candidates'
        )

    def handle(self, *args, **options):
        csv_file = options['csv_file']
        tenant_slug = options['tenant_slug']
        delimiter = options.get('delimiter', ',')
        encoding = options.get('encoding', 'utf-8')
        source = options.get('source', 'imported')
        source_detail = options.get('source_detail', '')
        update_existing = options.get('update_existing', False)
        skip_duplicates = options.get('skip_duplicates', False)
        dry_run = options.get('dry_run', False)
        batch_size = options.get('batch_size', 100)
        tags = options.get('tags', '')

        # Parse tags
        import_tags = [t.strip() for t in tags.split(',')] if tags else []

        # Find tenant
        try:
            tenant = Tenant.objects.get(slug=tenant_slug)
        except Tenant.DoesNotExist:
            raise CommandError(f"Tenant not found: {tenant_slug}")

        self.stdout.write(f"Importing candidates to tenant: {tenant.name}")

        if dry_run:
            self.stdout.write(self.style.WARNING("=== DRY RUN MODE ===\n"))

        # Switch to tenant schema
        connection.set_schema(tenant.schema_name)

        try:
            # Read and validate CSV
            candidates_data = self._read_csv(csv_file, delimiter, encoding)
            self.stdout.write(f"Found {len(candidates_data)} candidate records in CSV")

            # Validate data
            errors = self._validate_candidates(candidates_data)
            if errors:
                self.stdout.write(self.style.ERROR("Validation errors:"))
                for error in errors[:10]:
                    self.stdout.write(f"  - {error}")
                if len(errors) > 10:
                    self.stdout.write(f"  ... and {len(errors) - 10} more errors")
                raise CommandError("Fix validation errors before importing")

            # Import candidates
            stats = self._import_candidates(
                candidates_data, source, source_detail, import_tags,
                update_existing, skip_duplicates, dry_run, batch_size
            )

            # Print summary
            self.stdout.write("\n" + "=" * 50)
            self.stdout.write(self.style.SUCCESS("Import Summary:"))
            self.stdout.write(f"  Total records: {stats['total']}")
            self.stdout.write(f"  Created: {stats['created']}")
            self.stdout.write(f"  Updated: {stats['updated']}")
            self.stdout.write(f"  Skipped (duplicates): {stats['skipped']}")
            self.stdout.write(f"  Errors: {stats['errors']}")

        finally:
            connection.set_schema_to_public()

    def _read_csv(self, filepath, delimiter, encoding):
        """Read and parse CSV file."""
        candidates = []

        try:
            with open(filepath, 'r', encoding=encoding) as f:
                reader = csv.DictReader(f, delimiter=delimiter)
                for row in reader:
                    candidates.append(row)
        except FileNotFoundError:
            raise CommandError(f"File not found: {filepath}")
        except csv.Error as e:
            raise CommandError(f"CSV parsing error: {e}")

        return candidates

    def _validate_candidates(self, candidates_data):
        """Validate candidate data before import."""
        errors = []
        required_fields = ['email', 'first_name', 'last_name']
        seen_emails = set()

        for i, candidate in enumerate(candidates_data, start=1):
            row_num = i + 1  # Account for header

            # Check required fields
            for field in required_fields:
                if not candidate.get(field):
                    errors.append(f"Row {row_num}: Missing required field '{field}'")

            # Validate email format
            email = candidate.get('email', '').strip().lower()
            if email:
                if '@' not in email or '.' not in email:
                    errors.append(f"Row {row_num}: Invalid email format '{email}'")

                # Check for duplicates in file
                if email in seen_emails:
                    errors.append(f"Row {row_num}: Duplicate email in file '{email}'")
                seen_emails.add(email)

            # Validate years of experience
            if candidate.get('years_experience'):
                try:
                    years = int(candidate['years_experience'])
                    if years < 0 or years > 70:
                        errors.append(f"Row {row_num}: Invalid years_experience value")
                except ValueError:
                    errors.append(f"Row {row_num}: years_experience must be a number")

        return errors

    def _import_candidates(self, candidates_data, source, source_detail, tags,
                          update_existing, skip_duplicates, dry_run, batch_size):
        """Import candidates from validated data."""
        stats = {
            'total': len(candidates_data),
            'created': 0,
            'updated': 0,
            'skipped': 0,
            'errors': 0,
        }

        for i, candidate_data in enumerate(candidates_data):
            try:
                result = self._import_single_candidate(
                    candidate_data, source, source_detail, tags,
                    update_existing, skip_duplicates, dry_run
                )
                stats[result] += 1

                if (i + 1) % batch_size == 0:
                    self.stdout.write(f"  Processed {i + 1}/{len(candidates_data)} records...")

            except Exception as e:
                stats['errors'] += 1
                self.stdout.write(self.style.ERROR(f"  Error importing row {i + 1}: {e}"))

        return stats

    def _import_single_candidate(self, data, source, source_detail, tags,
                                 update_existing, skip_duplicates, dry_run):
        """Import a single candidate."""
        email = data['email'].strip().lower()

        # Check if exists
        existing = Candidate.objects.filter(email=email).first()

        if existing:
            if skip_duplicates:
                return 'skipped'
            if not update_existing:
                raise Exception(f"Duplicate email: {email}")
            if dry_run:
                return 'updated'

            # Update existing candidate
            self._update_candidate(existing, data, tags)
            existing.save()
            return 'updated'

        if dry_run:
            return 'created'

        # Create new candidate
        candidate = Candidate(
            email=email,
            first_name=data['first_name'].strip(),
            last_name=data['last_name'].strip(),
            phone=data.get('phone', '').strip(),
            headline=data.get('headline', '').strip(),
            summary=data.get('summary', '').strip(),
            current_company=data.get('current_company', '').strip(),
            current_title=data.get('current_title', '').strip(),
            city=data.get('city', '').strip(),
            state=data.get('state', '').strip(),
            country=data.get('country', '').strip() or 'Canada',
            source=source,
            source_detail=source_detail or data.get('source_detail', ''),
            linkedin_url=data.get('linkedin_url', '').strip(),
            github_url=data.get('github_url', '').strip(),
            portfolio_url=data.get('portfolio_url', '').strip(),
            consent_to_store=True,
            consent_date=timezone.now(),
        )

        # Years of experience
        if data.get('years_experience'):
            try:
                candidate.years_experience = int(data['years_experience'])
            except ValueError:
                pass

        # Skills (comma-separated)
        if data.get('skills'):
            candidate.skills = [s.strip() for s in data['skills'].split(',')]

        # Languages (comma-separated)
        if data.get('languages'):
            candidate.languages = [l.strip() for l in data['languages'].split(',')]

        # Tags
        candidate_tags = list(tags)  # Copy base tags
        if data.get('tags'):
            candidate_tags.extend([t.strip() for t in data['tags'].split(',')])
        candidate.tags = candidate_tags

        # Salary expectations
        if data.get('desired_salary_min'):
            try:
                candidate.desired_salary_min = float(data['desired_salary_min'])
            except ValueError:
                pass
        if data.get('desired_salary_max'):
            try:
                candidate.desired_salary_max = float(data['desired_salary_max'])
            except ValueError:
                pass

        # Willingness to relocate
        relocate = data.get('willing_to_relocate', '').lower()
        candidate.willing_to_relocate = relocate in ['yes', 'true', '1', 'y']

        candidate.save()
        return 'created'

    def _update_candidate(self, candidate, data, tags):
        """Update an existing candidate with new data."""
        # Only update non-empty fields
        if data.get('first_name'):
            candidate.first_name = data['first_name'].strip()
        if data.get('last_name'):
            candidate.last_name = data['last_name'].strip()
        if data.get('phone'):
            candidate.phone = data['phone'].strip()
        if data.get('headline'):
            candidate.headline = data['headline'].strip()
        if data.get('current_company'):
            candidate.current_company = data['current_company'].strip()
        if data.get('current_title'):
            candidate.current_title = data['current_title'].strip()
        if data.get('city'):
            candidate.city = data['city'].strip()
        if data.get('linkedin_url'):
            candidate.linkedin_url = data['linkedin_url'].strip()
        if data.get('skills'):
            new_skills = [s.strip() for s in data['skills'].split(',')]
            candidate.skills = list(set(candidate.skills + new_skills))
        if tags:
            candidate.tags = list(set(candidate.tags + tags))

        candidate.last_activity_at = timezone.now()
