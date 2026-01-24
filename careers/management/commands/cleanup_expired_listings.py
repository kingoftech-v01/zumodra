"""
Management command to clean up expired job listings.
Removes or archives listings that have passed their expiration date.
"""

from datetime import timedelta
from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django.utils import timezone
from tenants.models import Tenant
from careers.models import JobListing, PublicApplication
from jobs.models import JobPosting


class Command(BaseCommand):
    help = 'Clean up expired job listings and related data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant',
            type=str,
            help='Specific tenant slug (processes all active tenants if not specified)'
        )
        parser.add_argument(
            '--expired-days',
            type=int,
            default=0,
            help='Process listings expired more than N days ago (default: 0 = all expired)'
        )
        parser.add_argument(
            '--closed-job-days',
            type=int,
            default=30,
            help='Close listings for jobs closed more than N days ago (default: 30)'
        )
        parser.add_argument(
            '--archive',
            action='store_true',
            help='Archive listings instead of deleting'
        )
        parser.add_argument(
            '--delete-applications',
            action='store_true',
            help='Also delete unprocessed public applications for expired listings'
        )
        parser.add_argument(
            '--reset-counters',
            action='store_true',
            help='Reset view/click counters for active listings'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed progress'
        )

    def handle(self, *args, **options):
        tenant_slug = options.get('tenant')
        expired_days = options.get('expired_days', 0)
        closed_job_days = options.get('closed_job_days', 30)
        archive = options.get('archive', False)
        delete_applications = options.get('delete_applications', False)
        reset_counters = options.get('reset_counters', False)
        dry_run = options.get('dry_run', False)
        verbose = options.get('verbose', False)

        if dry_run:
            self.stdout.write(self.style.WARNING("=== DRY RUN MODE ===\n"))

        if archive:
            self.stdout.write("Mode: Archive expired listings")
        else:
            self.stdout.write("Mode: Delete expired listings")

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
            'listings_processed': 0,
            'listings_expired': 0,
            'applications_deleted': 0,
            'counters_reset': 0,
            'errors': 0,
        }

        for tenant in tenants:
            self.stdout.write(f"\nProcessing tenant: {tenant.name}")
            total_stats['tenants'] += 1

            connection.set_schema(tenant.schema_name)

            try:
                stats = self._process_tenant(
                    expired_days, closed_job_days, archive, delete_applications,
                    reset_counters, dry_run, verbose
                )

                total_stats['listings_processed'] += stats['listings_processed']
                total_stats['listings_expired'] += stats['listings_expired']
                total_stats['applications_deleted'] += stats['applications_deleted']
                total_stats['counters_reset'] += stats['counters_reset']
                total_stats['errors'] += stats['errors']

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  Error: {e}"))
                total_stats['errors'] += 1
            finally:
                connection.set_schema_to_public()

        # Print summary
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(self.style.SUCCESS("Cleanup Summary:"))
        self.stdout.write(f"  Tenants processed: {total_stats['tenants']}")
        self.stdout.write(f"  Listings processed: {total_stats['listings_processed']}")
        self.stdout.write(f"  Listings expired/deleted: {total_stats['listings_expired']}")
        self.stdout.write(f"  Applications deleted: {total_stats['applications_deleted']}")
        self.stdout.write(f"  Counters reset: {total_stats['counters_reset']}")
        self.stdout.write(f"  Errors: {total_stats['errors']}")

    def _process_tenant(self, expired_days, closed_job_days, archive,
                        delete_applications, reset_counters, dry_run, verbose):
        """Cleanup listings for a tenant."""
        stats = {
            'listings_processed': 0,
            'listings_expired': 0,
            'applications_deleted': 0,
            'counters_reset': 0,
            'errors': 0,
        }

        now = timezone.now()

        # 1. Process explicitly expired listings
        expired_cutoff = now - timedelta(days=expired_days) if expired_days > 0 else now

        expired_listings = JobListing.objects.filter(
            expires_at__lt=expired_cutoff
        )

        for listing in expired_listings:
            stats['listings_processed'] += 1

            try:
                if verbose:
                    self.stdout.write(
                        f"    Expired listing: {listing.job.title} "
                        f"(expired: {listing.expires_at.date()})"
                    )

                if delete_applications:
                    # Delete unprocessed public applications
                    deleted, _ = PublicApplication.objects.filter(
                        job_listing=listing,
                        status=PublicApplication.ApplicationStatus.PENDING
                    ).delete()

                    if not dry_run:
                        stats['applications_deleted'] += deleted

                if not dry_run:
                    if archive:
                        # Just mark as expired (already expired)
                        pass
                    else:
                        listing.delete()

                stats['listings_expired'] += 1

            except Exception as e:
                stats['errors'] += 1
                if verbose:
                    self.stdout.write(self.style.ERROR(f"      Error: {e}"))

        # 2. Expire listings for closed jobs
        closed_cutoff = now - timedelta(days=closed_job_days)
        closed_job_statuses = [
            JobPosting.JobStatus.CLOSED,
            JobPosting.JobStatus.FILLED,
            JobPosting.JobStatus.CANCELLED,
        ]

        stale_listings = JobListing.objects.filter(
            job__status__in=closed_job_statuses,
            job__closed_at__lt=closed_cutoff,
            expires_at__isnull=True  # Not already marked expired
        )

        for listing in stale_listings:
            stats['listings_processed'] += 1

            if verbose:
                self.stdout.write(
                    f"    Closing listing for closed job: {listing.job.title}"
                )

            if not dry_run:
                listing.expires_at = now
                listing.save(update_fields=['expires_at'])

            stats['listings_expired'] += 1

        # 3. Reset counters if requested
        if reset_counters:
            active_listings = JobListing.objects.filter(
                expires_at__isnull=True,
                job__status=JobPosting.JobStatus.OPEN
            )

            # Reset view and click counters (useful for analytics periods)
            count = active_listings.count()
            if count > 0:
                if verbose:
                    self.stdout.write(f"    Resetting counters for {count} active listings")

                if not dry_run:
                    active_listings.update(view_count=0, apply_click_count=0)

                stats['counters_reset'] = count

        return stats
