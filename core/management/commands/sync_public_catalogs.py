"""
Management Command: Sync Public Catalogs

Bulk sync all eligible data to public catalogs:
- Jobs → PublicJobCatalog
- Providers → PublicProviderCatalog
- Services → PublicServiceCatalog (existing)

Usage:
    # Sync all data for all tenants
    python manage.py sync_public_catalogs

    # Sync specific tenant
    python manage.py sync_public_catalogs --tenant=acmecorp

    # Sync specific catalog
    python manage.py sync_public_catalogs --catalog=jobs
    python manage.py sync_public_catalogs --catalog=providers
    python manage.py sync_public_catalogs --catalog=services

    # Async mode (queue Celery tasks)
    python manage.py sync_public_catalogs --async

    # Dry run (show what would be synced without actually syncing)
    python manage.py sync_public_catalogs --dry-run
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from tenants.models import Tenant
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Bulk sync all eligible data to public catalogs (jobs, providers, services)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant',
            type=str,
            help='Sync only this tenant (schema_name or domain)',
        )
        parser.add_argument(
            '--catalog',
            type=str,
            choices=['jobs', 'providers', 'services', 'all'],
            default='all',
            help='Which catalog to sync (default: all)',
        )
        parser.add_argument(
            '--async',
            action='store_true',
            dest='async_mode',
            help='Queue Celery tasks instead of synchronous sync',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be synced without actually syncing',
        )

    def handle(self, *args, **options):
        tenant_filter = options.get('tenant')
        catalog_filter = options.get('catalog')
        async_mode = options.get('async_mode')
        dry_run = options.get('dry_run')

        # Validate tenant if specified
        tenants = Tenant.objects.exclude(schema_name='public')
        if tenant_filter:
            tenants = tenants.filter(
                schema_name=tenant_filter
            ) | tenants.filter(
                domain_url=tenant_filter
            )
            if not tenants.exists():
                raise CommandError(f"Tenant '{tenant_filter}' not found")

        # Summary counters
        summary = {
            'tenants_processed': 0,
            'jobs': {'synced': 0, 'skipped': 0, 'errors': 0},
            'providers': {'synced': 0, 'skipped': 0, 'errors': 0},
            'services': {'synced': 0, 'skipped': 0, 'errors': 0},
        }

        self.stdout.write(
            self.style.SUCCESS(
                f"\n{'='*70}\n"
                f"  Sync Public Catalogs\n"
                f"{'='*70}"
            )
        )
        self.stdout.write(f"Mode: {'DRY RUN' if dry_run else ('ASYNC' if async_mode else 'SYNC')}")
        self.stdout.write(f"Catalog: {catalog_filter}")
        self.stdout.write(f"Tenants: {tenants.count()}\n")

        start_time = timezone.now()

        # Process each tenant
        for tenant in tenants:
            summary['tenants_processed'] += 1

            self.stdout.write(
                self.style.MIGRATE_HEADING(
                    f"\n[{summary['tenants_processed']}/{tenants.count()}] "
                    f"Processing: {tenant.name} ({tenant.schema_name})"
                )
            )

            # Sync Jobs
            if catalog_filter in ['all', 'jobs']:
                result = self._sync_jobs(tenant, async_mode, dry_run)
                summary['jobs']['synced'] += result['synced']
                summary['jobs']['skipped'] += result['skipped']
                summary['jobs']['errors'] += result['errors']

            # Sync Providers
            if catalog_filter in ['all', 'providers']:
                result = self._sync_providers(tenant, async_mode, dry_run)
                summary['providers']['synced'] += result['synced']
                summary['providers']['skipped'] += result['skipped']
                summary['providers']['errors'] += result['errors']

            # Sync Services (existing service catalog)
            if catalog_filter in ['all', 'services']:
                result = self._sync_services(tenant, async_mode, dry_run)
                summary['services']['synced'] += result['synced']
                summary['services']['skipped'] += result['skipped']
                summary['services']['errors'] += result['errors']

        # Print summary
        end_time = timezone.now()
        duration = (end_time - start_time).total_seconds()

        self.stdout.write(
            self.style.SUCCESS(
                f"\n{'='*70}\n"
                f"  Summary\n"
                f"{'='*70}"
            )
        )
        self.stdout.write(f"Tenants processed: {summary['tenants_processed']}")
        self.stdout.write(f"Duration: {duration:.2f}s\n")

        for catalog_name, stats in [('Jobs', 'jobs'), ('Providers', 'providers'), ('Services', 'services')]:
            if catalog_filter in ['all', stats]:
                self.stdout.write(
                    f"{catalog_name}:\n"
                    f"  ✓ Synced:  {summary[stats]['synced']}\n"
                    f"  ⊘ Skipped: {summary[stats]['skipped']}\n"
                    f"  ✗ Errors:  {summary[stats]['errors']}"
                )

        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    "\n⚠️  This was a DRY RUN - no data was actually synced"
                )
            )

        self.stdout.write(self.style.SUCCESS(f"\n{'='*70}\n✓ Done!\n"))

    def _sync_jobs(self, tenant, async_mode, dry_run):
        """Sync jobs for a specific tenant."""
        from ats.models import JobPosting
        from core.sync.job_sync import JobPublicSyncService
        from tenants.context import tenant_context

        result = {'synced': 0, 'skipped': 0, 'errors': 0}

        try:
            with tenant_context(tenant):
                # Get all eligible jobs
                jobs = JobPosting.objects.filter(
                    published_on_career_page=True,
                    is_internal_only=False,
                    status='open',
                )

                total = jobs.count()
                self.stdout.write(f"  Jobs: {total} eligible")

                if dry_run:
                    result['synced'] = total
                    return result

                if async_mode:
                    # Queue Celery tasks
                    from ats.tasks import bulk_sync_tenant_jobs
                    bulk_sync_tenant_jobs.delay(tenant.id)
                    result['synced'] = total
                    self.stdout.write(f"    ➤ Queued async task for {total} jobs")
                else:
                    # Synchronous sync
                    sync_service = JobPublicSyncService()
                    for job in jobs:
                        try:
                            if sync_service.should_sync(job):
                                sync_service.sync_to_public(job)
                                result['synced'] += 1
                            else:
                                result['skipped'] += 1
                        except Exception as e:
                            result['errors'] += 1
                            logger.error(f"Error syncing job {job.uuid}: {e}")

                    self.stdout.write(
                        f"    ✓ {result['synced']} synced, "
                        f"{result['skipped']} skipped, "
                        f"{result['errors']} errors"
                    )

        except Exception as e:
            logger.error(f"Error syncing jobs for {tenant.schema_name}: {e}", exc_info=True)
            result['errors'] += 1

        return result

    def _sync_providers(self, tenant, async_mode, dry_run):
        """Sync providers for a specific tenant."""
        from services.models import ServiceProvider
        from core.sync.provider_sync import ProviderPublicSyncService
        from tenants.context import tenant_context

        result = {'synced': 0, 'skipped': 0, 'errors': 0}

        try:
            with tenant_context(tenant):
                # Get all eligible providers
                providers = ServiceProvider.objects.filter(
                    marketplace_enabled=True,
                    is_active=True,
                    user__is_active=True,
                ).select_related('user')

                total = providers.count()
                self.stdout.write(f"  Providers: {total} eligible")

                if dry_run:
                    result['synced'] = total
                    return result

                if async_mode:
                    # Queue Celery tasks
                    from services.tasks import bulk_sync_tenant_providers
                    bulk_sync_tenant_providers.delay(tenant.id)
                    result['synced'] = total
                    self.stdout.write(f"    ➤ Queued async task for {total} providers")
                else:
                    # Synchronous sync
                    sync_service = ProviderPublicSyncService()
                    for provider in providers:
                        try:
                            if sync_service.should_sync(provider):
                                sync_service.sync_to_public(provider)
                                result['synced'] += 1
                            else:
                                result['skipped'] += 1
                        except Exception as e:
                            result['errors'] += 1
                            logger.error(f"Error syncing provider {provider.uuid}: {e}")

                    self.stdout.write(
                        f"    ✓ {result['synced']} synced, "
                        f"{result['skipped']} skipped, "
                        f"{result['errors']} errors"
                    )

        except Exception as e:
            logger.error(f"Error syncing providers for {tenant.schema_name}: {e}", exc_info=True)
            result['errors'] += 1

        return result

    def _sync_services(self, tenant, async_mode, dry_run):
        """Sync services for a specific tenant (existing PublicServiceCatalog)."""
        from services.models import Service
        from tenants.context import tenant_context

        result = {'synced': 0, 'skipped': 0, 'errors': 0}

        try:
            with tenant_context(tenant):
                # Get all eligible services
                services = Service.objects.filter(
                    is_public=True,
                    is_active=True,
                    provider__marketplace_enabled=True,
                ).select_related('provider')

                total = services.count()
                self.stdout.write(f"  Services: {total} eligible")

                if dry_run:
                    result['synced'] = total
                    return result

                # Services use the existing signal-based sync
                # Just count them for reporting
                result['synced'] = total
                self.stdout.write(f"    ℹ Services sync via existing signal mechanism")

        except Exception as e:
            logger.error(f"Error counting services for {tenant.schema_name}: {e}", exc_info=True)
            result['errors'] += 1

        return result
