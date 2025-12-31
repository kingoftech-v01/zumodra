"""
Management command to clean up inactive tenants.
Handles trial expirations, suspended tenants, and data retention policies.
"""

from datetime import timedelta
from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django.utils import timezone
from tenants.models import Tenant, TenantUsage


class Command(BaseCommand):
    help = 'Clean up inactive, expired, or cancelled tenants'

    def add_arguments(self, parser):
        parser.add_argument(
            '--expired-trials',
            action='store_true',
            help='Mark expired trial tenants as suspended'
        )
        parser.add_argument(
            '--suspended-days',
            type=int,
            default=30,
            help='Delete tenants suspended for more than N days (default: 30)'
        )
        parser.add_argument(
            '--cancelled-days',
            type=int,
            default=90,
            help='Delete tenants cancelled for more than N days (default: 90)'
        )
        parser.add_argument(
            '--inactive-days',
            type=int,
            default=180,
            help='Warn about tenants with no activity for N days (default: 180)'
        )
        parser.add_argument(
            '--delete-schemas',
            action='store_true',
            help='Actually delete tenant schemas (DANGEROUS - cannot be undone)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Skip confirmation prompts'
        )

    def handle(self, *args, **options):
        dry_run = options.get('dry_run', False)
        force = options.get('force', False)
        delete_schemas = options.get('delete_schemas', False)

        if dry_run:
            self.stdout.write(self.style.WARNING("=== DRY RUN MODE ===\n"))

        stats = {
            'expired_trials': 0,
            'suspended': 0,
            'deleted': 0,
            'inactive_warned': 0,
        }

        # Process expired trials
        if options.get('expired_trials'):
            stats['expired_trials'] = self._process_expired_trials(dry_run)

        # Process suspended tenants
        suspended_days = options.get('suspended_days', 30)
        stats['suspended'] = self._process_suspended(
            suspended_days, delete_schemas, dry_run, force
        )

        # Process cancelled tenants
        cancelled_days = options.get('cancelled_days', 90)
        stats['deleted'] = self._process_cancelled(
            cancelled_days, delete_schemas, dry_run, force
        )

        # Warn about inactive tenants
        inactive_days = options.get('inactive_days', 180)
        stats['inactive_warned'] = self._warn_inactive(inactive_days)

        # Print summary
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(self.style.SUCCESS("Cleanup Summary:"))
        self.stdout.write(f"  Expired trials suspended: {stats['expired_trials']}")
        self.stdout.write(f"  Long-suspended processed: {stats['suspended']}")
        self.stdout.write(f"  Cancelled tenants deleted: {stats['deleted']}")
        self.stdout.write(f"  Inactive tenants warned: {stats['inactive_warned']}")

    def _process_expired_trials(self, dry_run):
        """Find and suspend expired trial tenants."""
        self.stdout.write("\nProcessing expired trial tenants...")

        expired_trials = Tenant.objects.filter(
            status=Tenant.TenantStatus.TRIAL,
            on_trial=True,
            trial_ends_at__lt=timezone.now()
        )

        count = expired_trials.count()
        if count == 0:
            self.stdout.write("  No expired trials found")
            return 0

        self.stdout.write(f"  Found {count} expired trial tenant(s)")

        if not dry_run:
            for tenant in expired_trials:
                tenant.status = Tenant.TenantStatus.SUSPENDED
                tenant.on_trial = False
                tenant.suspended_at = timezone.now()
                tenant.save(update_fields=['status', 'on_trial', 'suspended_at'])
                self.stdout.write(f"    Suspended: {tenant.name}")
        else:
            for tenant in expired_trials:
                self.stdout.write(f"    [DRY RUN] Would suspend: {tenant.name}")

        return count

    def _process_suspended(self, days, delete_schemas, dry_run, force):
        """Process tenants suspended for too long."""
        self.stdout.write(f"\nProcessing tenants suspended > {days} days...")

        cutoff_date = timezone.now() - timedelta(days=days)
        suspended = Tenant.objects.filter(
            status=Tenant.TenantStatus.SUSPENDED,
            suspended_at__lt=cutoff_date
        )

        count = suspended.count()
        if count == 0:
            self.stdout.write("  No long-suspended tenants found")
            return 0

        self.stdout.write(f"  Found {count} tenant(s) suspended > {days} days")

        if delete_schemas:
            if not force and not dry_run:
                confirm = input(f"\nDELETE {count} tenant schemas? Type 'DELETE' to confirm: ")
                if confirm != 'DELETE':
                    self.stdout.write(self.style.WARNING("Deletion cancelled"))
                    return 0

            for tenant in suspended:
                if dry_run:
                    self.stdout.write(f"    [DRY RUN] Would delete schema: {tenant.schema_name}")
                else:
                    self._delete_tenant(tenant)

        else:
            for tenant in suspended:
                days_suspended = (timezone.now() - tenant.suspended_at).days
                self.stdout.write(
                    f"    {tenant.name} - suspended {days_suspended} days "
                    f"(use --delete-schemas to remove)"
                )

        return count

    def _process_cancelled(self, days, delete_schemas, dry_run, force):
        """Process cancelled tenants for deletion."""
        self.stdout.write(f"\nProcessing tenants cancelled > {days} days...")

        cutoff_date = timezone.now() - timedelta(days=days)
        cancelled = Tenant.objects.filter(
            status=Tenant.TenantStatus.CANCELLED,
            updated_at__lt=cutoff_date
        )

        count = cancelled.count()
        if count == 0:
            self.stdout.write("  No old cancelled tenants found")
            return 0

        self.stdout.write(f"  Found {count} tenant(s) cancelled > {days} days")

        if delete_schemas:
            if not force and not dry_run:
                confirm = input(f"\nDELETE {count} cancelled tenant schemas? Type 'DELETE' to confirm: ")
                if confirm != 'DELETE':
                    self.stdout.write(self.style.WARNING("Deletion cancelled"))
                    return 0

            deleted = 0
            for tenant in cancelled:
                if dry_run:
                    self.stdout.write(f"    [DRY RUN] Would delete: {tenant.name}")
                else:
                    self._delete_tenant(tenant)
                    deleted += 1

            return deleted

        else:
            for tenant in cancelled:
                self.stdout.write(
                    f"    {tenant.name} (use --delete-schemas to remove)"
                )

        return count

    def _warn_inactive(self, days):
        """Warn about inactive tenants."""
        self.stdout.write(f"\nChecking for tenants inactive > {days} days...")

        cutoff_date = timezone.now() - timedelta(days=days)

        # Get tenants with no recent activity
        inactive_count = 0
        active_tenants = Tenant.objects.filter(
            status=Tenant.TenantStatus.ACTIVE
        )

        for tenant in active_tenants:
            try:
                usage = tenant.usage
                if usage.last_calculated_at and usage.last_calculated_at < cutoff_date:
                    inactive_count += 1
                    days_inactive = (timezone.now() - usage.last_calculated_at).days
                    self.stdout.write(
                        self.style.WARNING(
                            f"    {tenant.name} - no activity for {days_inactive} days"
                        )
                    )
            except TenantUsage.DoesNotExist:
                # No usage record means never used
                if tenant.created_at < cutoff_date:
                    inactive_count += 1
                    self.stdout.write(
                        self.style.WARNING(
                            f"    {tenant.name} - no usage record (created {tenant.created_at.date()})"
                        )
                    )

        if inactive_count == 0:
            self.stdout.write("  No inactive tenants found")

        return inactive_count

    def _delete_tenant(self, tenant):
        """Delete a tenant and optionally its schema."""
        self.stdout.write(f"    Deleting tenant: {tenant.name}...")

        schema_name = tenant.schema_name

        try:
            # Delete the tenant record (cascades to domains, settings, etc.)
            tenant.delete()

            # Drop the schema if configured
            if tenant.auto_drop_schema:
                # Validate schema name to prevent SQL injection
                # Schema names must be valid PostgreSQL identifiers
                import re
                if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', schema_name):
                    raise ValueError(f"Invalid schema name: {schema_name}")
                with connection.cursor() as cursor:
                    # Use quote_ident for safe identifier quoting
                    from django.db import connection as db_conn
                    cursor.execute(
                        "SELECT quote_ident(%s)",
                        [schema_name]
                    )
                    safe_schema = cursor.fetchone()[0]
                    cursor.execute(f'DROP SCHEMA IF EXISTS {safe_schema} CASCADE')
                self.stdout.write(self.style.SUCCESS(f"      Schema {schema_name} dropped"))
            else:
                self.stdout.write(
                    f"      Schema {schema_name} retained (auto_drop_schema=False)"
                )

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"      Error deleting {tenant.name}: {e}"))
