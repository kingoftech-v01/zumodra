"""
Management command to fix tenant user assignments.

This command ensures all users have:
1. A UserProfile
2. A TenantUser assignment to the specified tenant

Usage:
    python manage.py fix_tenant_users --tenant=beta
    python manage.py fix_tenant_users --tenant=beta --role=admin
    python manage.py fix_tenant_users --tenant=beta --dry-run
"""

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model

User = get_user_model()


class Command(BaseCommand):
    help = 'Fix tenant user assignments for existing users'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant',
            type=str,
            required=True,
            help='Tenant schema name (e.g., beta, demo)'
        )
        parser.add_argument(
            '--role',
            type=str,
            default='employee',
            choices=['owner', 'admin', 'hr_manager', 'recruiter', 'hiring_manager', 'employee', 'viewer'],
            help='Role to assign to users (default: employee)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes'
        )
        parser.add_argument(
            '--exclude-superusers',
            action='store_true',
            default=True,
            help='Exclude superusers from tenant assignment (default: True)'
        )

    def handle(self, *args, **options):
        from tenants.models import Tenant
        from accounts.models import TenantUser, UserProfile

        tenant_name = options['tenant']
        role = options['role']
        dry_run = options['dry_run']
        exclude_superusers = options['exclude_superusers']

        # Get the tenant
        try:
            tenant = Tenant.objects.get(schema_name=tenant_name)
        except Tenant.DoesNotExist:
            raise CommandError(f'Tenant "{tenant_name}" does not exist.')

        self.stdout.write(f'Tenant: {tenant.name} (schema: {tenant.schema_name})')
        self.stdout.write(f'Role: {role}')
        self.stdout.write(f'Dry run: {dry_run}')
        self.stdout.write('-' * 50)

        # Get all users
        users = User.objects.all()
        if exclude_superusers:
            users = users.filter(is_superuser=False)

        profiles_created = 0
        tenant_users_created = 0
        already_assigned = 0

        for user in users:
            self.stdout.write(f'\nProcessing user: {user.email}')

            # Check/create UserProfile
            profile_exists = UserProfile.objects.filter(user=user).exists()
            if not profile_exists:
                if not dry_run:
                    UserProfile.objects.create(user=user)
                self.stdout.write(self.style.SUCCESS(f'  + Created UserProfile'))
                profiles_created += 1
            else:
                self.stdout.write(f'  ✓ UserProfile exists')

            # Check/create TenantUser
            tenant_user = TenantUser.objects.filter(user=user, tenant=tenant).first()
            if tenant_user:
                self.stdout.write(f'  ✓ Already assigned to tenant (role: {tenant_user.role})')
                already_assigned += 1
            else:
                if not dry_run:
                    TenantUser.objects.create(
                        user=user,
                        tenant=tenant,
                        role=role,
                        is_active=True
                    )
                self.stdout.write(self.style.SUCCESS(f'  + Created TenantUser (role: {role})'))
                tenant_users_created += 1

        self.stdout.write('\n' + '=' * 50)
        self.stdout.write(self.style.SUCCESS(f'Summary:'))
        self.stdout.write(f'  Users processed: {users.count()}')
        self.stdout.write(f'  Profiles created: {profiles_created}')
        self.stdout.write(f'  TenantUsers created: {tenant_users_created}')
        self.stdout.write(f'  Already assigned: {already_assigned}')

        if dry_run:
            self.stdout.write(self.style.WARNING('\n[DRY RUN] No changes were made.'))
