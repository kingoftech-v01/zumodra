"""
Sync Public Catalogs Management Command

Synchronizes tenant data to public catalogs for cross-tenant browsing.
Currently supports:
- Jobs → PublicJobCatalog
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django_tenants.utils import get_tenant_model, schema_context
from core.sync.job_sync import JobCatalogSyncService


class Command(BaseCommand):
    help = 'Sync all tenant data to public catalogs (jobs, services, etc.)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant',
            type=str,
            help='Sync specific tenant schema (default: all tenants)',
        )
        parser.add_argument(
            '--jobs-only',
            action='store_true',
            help='Only sync jobs (skip services, providers, etc.)',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be synced without actually syncing',
        )

    def handle(self, *args, **options):
        tenant_schema = options.get('tenant')
        jobs_only = options.get('jobs_only', False)
        dry_run = options.get('dry_run', False)

        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No changes will be made'))

        self.stdout.write('=' * 70)
        self.stdout.write(self.style.SUCCESS('PUBLIC CATALOG SYNC'))
        self.stdout.write('=' * 70)

        # Get tenants to sync
        if tenant_schema:
            try:
                tenants = [get_tenant_model().objects.get(schema_name=tenant_schema)]
                self.stdout.write(f"Syncing tenant: {tenant_schema}")
            except get_tenant_model().DoesNotExist:
                raise CommandError(f"Tenant '{tenant_schema}' not found")
        else:
            tenants = get_tenant_model().objects.exclude(schema_name='public')
            self.stdout.write(f"Syncing all tenants ({tenants.count()} found)")

        self.stdout.write('')

        # Sync jobs for each tenant
        total_stats = {'synced': 0, 'failed': 0, 'removed': 0}

        for tenant in tenants:
            self.stdout.write('-' * 70)
            self.stdout.write(f"Tenant: {tenant.schema_name} ({tenant.name})")
            self.stdout.write('-' * 70)

            if not dry_run:
                try:
                    stats = self._sync_tenant_jobs(tenant.schema_name)

                    self.stdout.write(
                        self.style.SUCCESS(
                            f"  ✓ Jobs: {stats['synced']} synced, "
                            f"{stats['failed']} failed, {stats['removed']} removed"
                        )
                    )

                    total_stats['synced'] += stats['synced']
                    total_stats['failed'] += stats['failed']
                    total_stats['removed'] += stats['removed']

                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"  ✗ Error: {str(e)}"))
            else:
                # Dry run - just count
                with schema_context(tenant.schema_name):
                    from jobs.models import JobPosting
                    job_count = JobPosting.objects.filter(
                        status='open',
                        published_on_career_page=True
                    ).count()
                    self.stdout.write(f"  Would sync {job_count} jobs")

        self.stdout.write('')
        self.stdout.write('=' * 70)

        if not dry_run:
            self.stdout.write(self.style.SUCCESS('SYNC COMPLETE'))
            self.stdout.write(f"Total: {total_stats['synced']} synced, "
                            f"{total_stats['failed']} failed, {total_stats['removed']} removed")
        else:
            self.stdout.write(self.style.WARNING('DRY RUN COMPLETE (no changes made)'))

        self.stdout.write('=' * 70)

    def _sync_tenant_jobs(self, tenant_schema):
        """Sync all jobs for a specific tenant"""
        return JobCatalogSyncService.sync_all_jobs_for_tenant(tenant_schema)
