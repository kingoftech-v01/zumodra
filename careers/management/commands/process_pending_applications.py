"""
Management command to process pending public applications into the ATS.
Converts PublicApplication records to Candidate and Application records.
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from django.utils import timezone
from tenants.models import Tenant
from careers.models import PublicApplication


class Command(BaseCommand):
    help = 'Process pending public applications into the ATS system'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant',
            type=str,
            help='Specific tenant slug (processes all active tenants if not specified)'
        )
        parser.add_argument(
            '--job',
            type=str,
            help='Specific job reference code'
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=0,
            help='Maximum number of applications to process (0 = unlimited)'
        )
        parser.add_argument(
            '--reprocess-errors',
            action='store_true',
            help='Reprocess applications that previously had errors'
        )
        parser.add_argument(
            '--skip-duplicates',
            action='store_true',
            help='Mark duplicates as processed instead of raising errors'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be processed without making changes'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed progress'
        )
        parser.add_argument(
            '--batch-size',
            type=int,
            default=50,
            help='Number of applications to process in each batch (default: 50)'
        )

    def handle(self, *args, **options):
        tenant_slug = options.get('tenant')
        job_code = options.get('job')
        limit = options.get('limit', 0)
        reprocess_errors = options.get('reprocess_errors', False)
        skip_duplicates = options.get('skip_duplicates', False)
        dry_run = options.get('dry_run', False)
        verbose = options.get('verbose', False)
        batch_size = options.get('batch_size', 50)

        if dry_run:
            self.stdout.write(self.style.WARNING("=== DRY RUN MODE ===\n"))

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
            'processed': 0,
            'created': 0,
            'duplicates': 0,
            'errors': 0,
        }

        for tenant in tenants:
            self.stdout.write(f"\nProcessing tenant: {tenant.name}")
            total_stats['tenants'] += 1

            connection.set_schema(tenant.schema_name)

            try:
                stats = self._process_tenant(
                    job_code, limit, reprocess_errors, skip_duplicates,
                    dry_run, verbose, batch_size
                )

                total_stats['processed'] += stats['processed']
                total_stats['created'] += stats['created']
                total_stats['duplicates'] += stats['duplicates']
                total_stats['errors'] += stats['errors']

                # Respect limit across tenants
                if limit > 0:
                    limit -= stats['processed']
                    if limit <= 0:
                        break

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  Error: {e}"))
                total_stats['errors'] += 1
            finally:
                connection.set_schema_to_public()

        # Print summary
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(self.style.SUCCESS("Processing Summary:"))
        self.stdout.write(f"  Tenants processed: {total_stats['tenants']}")
        self.stdout.write(f"  Applications processed: {total_stats['processed']}")
        self.stdout.write(f"  ATS records created: {total_stats['created']}")
        self.stdout.write(f"  Duplicates: {total_stats['duplicates']}")
        self.stdout.write(f"  Errors: {total_stats['errors']}")

    def _process_tenant(self, job_code, limit, reprocess_errors, skip_duplicates,
                        dry_run, verbose, batch_size):
        """Process pending applications for a tenant."""
        stats = {
            'processed': 0,
            'created': 0,
            'duplicates': 0,
            'errors': 0,
        }

        # Build queryset
        statuses = [PublicApplication.ApplicationStatus.PENDING]
        if reprocess_errors:
            statuses.append(PublicApplication.ApplicationStatus.ERROR)

        queryset = PublicApplication.objects.filter(status__in=statuses)

        if job_code:
            queryset = queryset.filter(job_listing__job__reference_code=job_code)

        queryset = queryset.order_by('submitted_at')

        if limit > 0:
            queryset = queryset[:limit]

        total = queryset.count()
        self.stdout.write(f"  Found {total} pending applications")

        if total == 0:
            return stats

        for i, application in enumerate(queryset.iterator()):
            try:
                result = self._process_application(
                    application, skip_duplicates, dry_run, verbose
                )
                stats['processed'] += 1
                stats[result] += 1

            except Exception as e:
                stats['errors'] += 1
                if verbose:
                    self.stdout.write(
                        self.style.ERROR(f"    Error: {application.email}: {e}")
                    )

            if (i + 1) % batch_size == 0:
                self.stdout.write(f"  Processed {i + 1}/{total}...")

        return stats

    def _process_application(self, application, skip_duplicates, dry_run, verbose):
        """Process a single public application."""
        if verbose:
            job_title = application.job_listing.job.title if application.job_listing else "General"
            self.stdout.write(
                f"    Processing: {application.first_name} {application.last_name} "
                f"-> {job_title}"
            )

        if dry_run:
            return 'created'

        # Use the model's built-in processing method
        success = application.process_to_ats()

        if application.status == PublicApplication.ApplicationStatus.DUPLICATE:
            if skip_duplicates:
                return 'duplicates'
            return 'duplicates'

        if success:
            return 'created'

        return 'errors'
