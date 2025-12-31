"""
Management command to clean up expired sessions and login history.
"""

from datetime import timedelta
from django.core.management.base import BaseCommand
from django.contrib.sessions.models import Session
from django.utils import timezone
from django.db import connection
from tenants.models import Tenant
from accounts.models import LoginHistory


class Command(BaseCommand):
    help = 'Clean up expired sessions and old login history records'

    def add_arguments(self, parser):
        parser.add_argument(
            '--sessions',
            action='store_true',
            help='Clean up expired Django sessions'
        )
        parser.add_argument(
            '--login-history',
            action='store_true',
            help='Clean up old login history records'
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help='Clean up both sessions and login history'
        )
        parser.add_argument(
            '--tenant',
            type=str,
            help='Specific tenant slug (for login history cleanup)'
        )
        parser.add_argument(
            '--history-days',
            type=int,
            default=90,
            help='Delete login history older than N days (default: 90)'
        )
        parser.add_argument(
            '--keep-failed',
            action='store_true',
            help='Keep failed login attempts (security audit trail)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without making changes'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed output'
        )

    def handle(self, *args, **options):
        do_sessions = options.get('sessions') or options.get('all')
        do_login_history = options.get('login_history') or options.get('all')
        tenant_slug = options.get('tenant')
        history_days = options.get('history_days', 90)
        keep_failed = options.get('keep_failed', False)
        dry_run = options.get('dry_run', False)
        verbose = options.get('verbose', False)

        if not (do_sessions or do_login_history):
            self.stdout.write(
                self.style.WARNING(
                    "No cleanup action specified. Use --sessions, --login-history, or --all"
                )
            )
            return

        if dry_run:
            self.stdout.write(self.style.WARNING("=== DRY RUN MODE ===\n"))

        stats = {
            'sessions_deleted': 0,
            'login_history_deleted': 0,
        }

        # Clean up expired sessions
        if do_sessions:
            stats['sessions_deleted'] = self._cleanup_sessions(dry_run, verbose)

        # Clean up login history
        if do_login_history:
            stats['login_history_deleted'] = self._cleanup_login_history(
                tenant_slug, history_days, keep_failed, dry_run, verbose
            )

        # Print summary
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(self.style.SUCCESS("Cleanup Summary:"))
        if do_sessions:
            self.stdout.write(f"  Sessions deleted: {stats['sessions_deleted']}")
        if do_login_history:
            self.stdout.write(f"  Login history deleted: {stats['login_history_deleted']}")

    def _cleanup_sessions(self, dry_run, verbose):
        """Clean up expired Django sessions."""
        self.stdout.write("\nCleaning up expired sessions...")

        # Count expired sessions
        expired = Session.objects.filter(expire_date__lt=timezone.now())
        count = expired.count()

        if count == 0:
            self.stdout.write("  No expired sessions found")
            return 0

        if verbose:
            self.stdout.write(f"  Found {count} expired session(s)")

        if dry_run:
            self.stdout.write(f"  [DRY RUN] Would delete {count} sessions")
        else:
            # Use Django's built-in clearsessions functionality
            deleted, _ = expired.delete()
            self.stdout.write(self.style.SUCCESS(f"  Deleted {deleted} sessions"))

        return count

    def _cleanup_login_history(self, tenant_slug, days, keep_failed, dry_run, verbose):
        """Clean up old login history records."""
        self.stdout.write(f"\nCleaning up login history older than {days} days...")

        cutoff_date = timezone.now() - timedelta(days=days)
        total_deleted = 0

        # Determine tenants to process
        if tenant_slug:
            try:
                tenants = [Tenant.objects.get(slug=tenant_slug)]
            except Tenant.DoesNotExist:
                self.stdout.write(self.style.ERROR(f"Tenant not found: {tenant_slug}"))
                return 0
        else:
            tenants = Tenant.objects.filter(
                status__in=[
                    Tenant.TenantStatus.ACTIVE,
                    Tenant.TenantStatus.TRIAL,
                ]
            )

        for tenant in tenants:
            if verbose:
                self.stdout.write(f"  Processing tenant: {tenant.name}")

            connection.set_schema(tenant.schema_name)

            try:
                # Build query
                queryset = LoginHistory.objects.filter(timestamp__lt=cutoff_date)

                if keep_failed:
                    # Keep failed login attempts for security audit
                    queryset = queryset.exclude(result=LoginHistory.LoginResult.FAILED)
                    if verbose:
                        self.stdout.write("    Keeping failed login attempts")

                count = queryset.count()

                if count > 0:
                    if dry_run:
                        if verbose:
                            self.stdout.write(f"    [DRY RUN] Would delete {count} records")
                    else:
                        deleted, _ = queryset.delete()
                        if verbose:
                            self.stdout.write(f"    Deleted {deleted} records")
                    total_deleted += count
                elif verbose:
                    self.stdout.write("    No old records found")

            finally:
                connection.set_schema_to_public()

        return total_deleted
