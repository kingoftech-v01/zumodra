"""
Management command to synchronize job listings with job postings.
Creates public listings for new jobs, updates existing, and handles closures.
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django.utils import timezone
from tenants.models import Tenant
from careers.models import JobListing, CareerPage
from ats.models import JobPosting


class Command(BaseCommand):
    help = 'Synchronize public job listings with ATS job postings'

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
            '--create-missing',
            action='store_true',
            default=True,
            help='Create listings for jobs without them (default: True)'
        )
        parser.add_argument(
            '--close-orphans',
            action='store_true',
            help='Mark listings as expired if job is closed/filled'
        )
        parser.add_argument(
            '--update-visibility',
            action='store_true',
            help='Update visibility settings from job posting'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be changed without making changes'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed progress'
        )

    def handle(self, *args, **options):
        tenant_slug = options.get('tenant')
        job_code = options.get('job')
        create_missing = options.get('create_missing', True)
        close_orphans = options.get('close_orphans', False)
        update_visibility = options.get('update_visibility', False)
        dry_run = options.get('dry_run', False)
        verbose = options.get('verbose', False)

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
            'jobs_checked': 0,
            'listings_created': 0,
            'listings_updated': 0,
            'listings_closed': 0,
            'errors': 0,
        }

        for tenant in tenants:
            self.stdout.write(f"\nProcessing tenant: {tenant.name}")
            total_stats['tenants'] += 1

            connection.set_schema(tenant.schema_name)

            try:
                stats = self._process_tenant(
                    job_code, create_missing, close_orphans, update_visibility,
                    dry_run, verbose
                )

                total_stats['jobs_checked'] += stats['jobs_checked']
                total_stats['listings_created'] += stats['listings_created']
                total_stats['listings_updated'] += stats['listings_updated']
                total_stats['listings_closed'] += stats['listings_closed']
                total_stats['errors'] += stats['errors']

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  Error: {e}"))
                total_stats['errors'] += 1
            finally:
                connection.set_schema_to_public()

        # Print summary
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(self.style.SUCCESS("Sync Summary:"))
        self.stdout.write(f"  Tenants processed: {total_stats['tenants']}")
        self.stdout.write(f"  Jobs checked: {total_stats['jobs_checked']}")
        self.stdout.write(f"  Listings created: {total_stats['listings_created']}")
        self.stdout.write(f"  Listings updated: {total_stats['listings_updated']}")
        self.stdout.write(f"  Listings closed: {total_stats['listings_closed']}")
        self.stdout.write(f"  Errors: {total_stats['errors']}")

    def _process_tenant(self, job_code, create_missing, close_orphans,
                        update_visibility, dry_run, verbose):
        """Sync job listings for a tenant."""
        stats = {
            'jobs_checked': 0,
            'listings_created': 0,
            'listings_updated': 0,
            'listings_closed': 0,
            'errors': 0,
        }

        # Get all job postings
        jobs_queryset = JobPosting.objects.all()
        if job_code:
            jobs_queryset = jobs_queryset.filter(reference_code=job_code)

        # Process open jobs
        open_jobs = jobs_queryset.filter(
            status=JobPosting.JobStatus.OPEN,
            published_on_career_page=True
        )

        for job in open_jobs:
            stats['jobs_checked'] += 1

            try:
                # Check if listing exists
                listing = JobListing.objects.filter(job=job).first()

                if not listing:
                    if create_missing:
                        if verbose:
                            self.stdout.write(f"    Creating listing for: {job.title}")

                        if not dry_run:
                            listing = JobListing.objects.create(
                                job=job,
                                published_at=timezone.now(),
                                is_featured=job.is_featured,
                            )
                        stats['listings_created'] += 1

                elif update_visibility:
                    # Update listing settings from job
                    updated = False

                    if listing.is_featured != job.is_featured:
                        listing.is_featured = job.is_featured
                        updated = True

                    if updated:
                        if verbose:
                            self.stdout.write(f"    Updating listing: {job.title}")
                        if not dry_run:
                            listing.save()
                        stats['listings_updated'] += 1

            except Exception as e:
                stats['errors'] += 1
                if verbose:
                    self.stdout.write(
                        self.style.ERROR(f"    Error for {job.title}: {e}")
                    )

        # Close orphan listings
        if close_orphans:
            closed_job_statuses = [
                JobPosting.JobStatus.CLOSED,
                JobPosting.JobStatus.FILLED,
                JobPosting.JobStatus.CANCELLED,
            ]

            orphan_listings = JobListing.objects.filter(
                job__status__in=closed_job_statuses,
                expires_at__isnull=True
            )

            for listing in orphan_listings:
                if verbose:
                    self.stdout.write(
                        f"    Closing listing: {listing.job.title} "
                        f"(job status: {listing.job.status})"
                    )

                if not dry_run:
                    listing.expires_at = timezone.now()
                    listing.save(update_fields=['expires_at'])

                stats['listings_closed'] += 1

        return stats
