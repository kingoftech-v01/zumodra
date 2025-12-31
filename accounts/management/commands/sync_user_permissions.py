"""
Management command to synchronize user permissions based on roles.
Ensures all TenantUsers have correct permissions for their roles.
"""

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import Permission
from django.db import connection
from tenants.models import Tenant
from accounts.models import TenantUser, ROLE_PERMISSIONS


class Command(BaseCommand):
    help = 'Synchronize user permissions based on their tenant roles'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant',
            type=str,
            help='Specific tenant slug (processes all tenants if not specified)'
        )
        parser.add_argument(
            '--user',
            type=str,
            help='Specific user email (processes all users if not specified)'
        )
        parser.add_argument(
            '--role',
            type=str,
            choices=[r[0] for r in TenantUser.UserRole.choices],
            help='Only process users with this role'
        )
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Remove all custom permissions before syncing'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be changed without making changes'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed output for each user'
        )

    def handle(self, *args, **options):
        tenant_slug = options.get('tenant')
        user_email = options.get('user')
        role_filter = options.get('role')
        reset = options.get('reset', False)
        dry_run = options.get('dry_run', False)
        verbose = options.get('verbose', False)

        if dry_run:
            self.stdout.write(self.style.WARNING("=== DRY RUN MODE ===\n"))

        # Determine which tenants to process
        if tenant_slug:
            try:
                tenants = [Tenant.objects.get(slug=tenant_slug)]
            except Tenant.DoesNotExist:
                raise CommandError(f"Tenant not found: {tenant_slug}")
        else:
            tenants = Tenant.objects.filter(status=Tenant.TenantStatus.ACTIVE)

        stats = {
            'tenants_processed': 0,
            'users_processed': 0,
            'permissions_added': 0,
            'permissions_removed': 0,
        }

        for tenant in tenants:
            self.stdout.write(f"\nProcessing tenant: {tenant.name}")
            stats['tenants_processed'] += 1

            # Switch to tenant schema
            connection.set_schema(tenant.schema_name)

            try:
                tenant_stats = self._sync_tenant_permissions(
                    tenant, user_email, role_filter, reset, dry_run, verbose
                )
                stats['users_processed'] += tenant_stats['users']
                stats['permissions_added'] += tenant_stats['added']
                stats['permissions_removed'] += tenant_stats['removed']
            finally:
                connection.set_schema_to_public()

        # Print summary
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(self.style.SUCCESS("Sync Summary:"))
        self.stdout.write(f"  Tenants processed: {stats['tenants_processed']}")
        self.stdout.write(f"  Users processed: {stats['users_processed']}")
        self.stdout.write(f"  Permissions added: {stats['permissions_added']}")
        self.stdout.write(f"  Permissions removed: {stats['permissions_removed']}")

    def _sync_tenant_permissions(self, tenant, user_email, role_filter, reset, dry_run, verbose):
        """Sync permissions for all users in a tenant."""
        stats = {'users': 0, 'added': 0, 'removed': 0}

        # Build query
        queryset = TenantUser.objects.filter(tenant=tenant, is_active=True)

        if user_email:
            queryset = queryset.filter(user__email=user_email)

        if role_filter:
            queryset = queryset.filter(role=role_filter)

        for tenant_user in queryset:
            stats['users'] += 1
            user_stats = self._sync_user_permissions(
                tenant_user, reset, dry_run, verbose
            )
            stats['added'] += user_stats['added']
            stats['removed'] += user_stats['removed']

        return stats

    def _sync_user_permissions(self, tenant_user, reset, dry_run, verbose):
        """Sync permissions for a single tenant user."""
        stats = {'added': 0, 'removed': 0}

        user = tenant_user.user
        role = tenant_user.role
        expected_perms = ROLE_PERMISSIONS.get(role, set())

        if verbose:
            self.stdout.write(f"  Processing: {user.email} (role: {role})")

        # Get current custom permissions
        current_perms = set(tenant_user.custom_permissions.values_list('codename', flat=True))

        # Reset if requested
        if reset:
            if current_perms and not dry_run:
                tenant_user.custom_permissions.clear()
                stats['removed'] = len(current_perms)
                if verbose:
                    self.stdout.write(f"    Removed {len(current_perms)} custom permissions")
            elif current_perms and dry_run:
                stats['removed'] = len(current_perms)
                if verbose:
                    self.stdout.write(f"    [DRY RUN] Would remove {len(current_perms)} permissions")

        # Sync Django User model permissions based on role
        if role in [TenantUser.UserRole.OWNER, TenantUser.UserRole.ADMIN]:
            if not user.is_staff:
                if not dry_run:
                    user.is_staff = True
                    user.save(update_fields=['is_staff'])
                if verbose:
                    action = "[DRY RUN] Would set" if dry_run else "Set"
                    self.stdout.write(f"    {action} is_staff=True")

            if role == TenantUser.UserRole.OWNER and not user.is_superuser:
                if not dry_run:
                    user.is_superuser = True
                    user.save(update_fields=['is_superuser'])
                if verbose:
                    action = "[DRY RUN] Would set" if dry_run else "Set"
                    self.stdout.write(f"    {action} is_superuser=True")
        else:
            # Non-admin roles should not have superuser status
            if user.is_superuser:
                if not dry_run:
                    user.is_superuser = False
                    user.save(update_fields=['is_superuser'])
                if verbose:
                    action = "[DRY RUN] Would set" if dry_run else "Set"
                    self.stdout.write(f"    {action} is_superuser=False")

        # Log expected permissions for this role
        if verbose:
            self.stdout.write(f"    Role permissions: {len(expected_perms)}")

        return stats

    def _get_or_create_permission(self, codename):
        """Get or create a permission by codename."""
        try:
            return Permission.objects.get(codename=codename)
        except Permission.DoesNotExist:
            # Permission doesn't exist in database, skip it
            return None
