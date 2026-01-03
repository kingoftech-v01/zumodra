"""
Create Demo Tenant with Wagtail 7.x migration fix.

This command creates a demo tenant while working around the Wagtail 7.x
migration bug where wagtailcore_grouppagepermission.permission_id is not
properly populated.

Usage:
    python manage.py create_demo_tenant
    python manage.py create_demo_tenant --domain zumodra.com
    BASE_DOMAIN=zumodra.com python manage.py create_demo_tenant
"""

import os
from django.core.management.base import BaseCommand
from django.db import connection


class Command(BaseCommand):
    help = 'Create a demo tenant with Wagtail 7.x migration fix'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Delete existing demo tenant if it exists'
        )
        parser.add_argument(
            '--domain',
            type=str,
            default=os.environ.get('BASE_DOMAIN', 'localhost'),
            help='Base domain for the tenant (e.g., zumodra.com). Default: localhost or BASE_DOMAIN env var'
        )

    def handle(self, *args, **options):
        from tenants.models import Tenant, Domain, Plan

        # Get base domain
        base_domain = options.get('domain', 'localhost')
        tenant_domain = f'demo.{base_domain}'

        self.stdout.write(self.style.MIGRATE_HEADING('Creating Demo Tenant'))
        self.stdout.write('=' * 60)
        self.stdout.write(f'Base Domain: {base_domain}')
        self.stdout.write(f'Tenant Domain: {tenant_domain}')

        # Check if demo tenant already exists
        existing = Tenant.objects.filter(slug='demo').first()
        if existing:
            if options.get('force'):
                self.stdout.write(self.style.WARNING(f'Demo tenant exists: {existing.schema_name}'))
                self.stdout.write('Deleting existing tenant...')
                # Drop schema directly to avoid FK issues
                with connection.cursor() as cursor:
                    cursor.execute(f'DROP SCHEMA IF EXISTS {existing.schema_name} CASCADE')
                # Delete the record
                Tenant.objects.filter(slug='demo').delete()
                self.stdout.write(self.style.SUCCESS('Deleted.'))
            else:
                self.stdout.write(self.style.ERROR(
                    f'Demo tenant already exists. Use --force to recreate.'
                ))
                return

        # Get plan
        plan = Plan.objects.filter(plan_type='professional').first()
        if not plan:
            plan = Plan.objects.first()
        self.stdout.write(f'Using plan: {plan}')

        # Install the Wagtail migration fix
        self._install_migration_fix()

        # Step 1: Create tenant (triggers auto_create_schema and migrations)
        self.stdout.write('\n[1] Creating tenant (with schema and migrations)...')
        self.stdout.write('   This may take a few minutes...')

        try:
            tenant = Tenant.objects.create(
                name='Demo Company',
                slug='demo',
                schema_name='demo',
                owner_email='admin@demo.zumodra.local',
                plan=plan,
            )
            self.stdout.write(self.style.SUCCESS(f'   Created tenant: {tenant.name} ({tenant.schema_name})'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Failed to create tenant: {e}'))
            # Clean up
            with connection.cursor() as cursor:
                cursor.execute('DROP SCHEMA IF EXISTS demo CASCADE')
            raise

        # Step 2: Create domain
        self.stdout.write('\n[2] Creating domain...')
        Domain.objects.get_or_create(
            domain=tenant_domain,
            defaults={'tenant': tenant, 'is_primary': True}
        )
        self.stdout.write(self.style.SUCCESS(f'   Created domain: {tenant_domain}'))

        # Step 3: Create demo data
        self.stdout.write('\n[3] Creating demo users and data...')
        self._create_demo_data(tenant)

        self.stdout.write('\n' + '=' * 60)
        self.stdout.write(self.style.SUCCESS('DEMO TENANT CREATED SUCCESSFULLY!'))
        self.stdout.write('=' * 60)
        self.stdout.write(f'\nDomain: {tenant_domain}')
        self.stdout.write(f'Admin Email: admin@demo.{base_domain}')
        self.stdout.write(f'Password: Demo@2024!')
        self.stdout.write(f'\nTo access in development, add to /etc/hosts:')
        self.stdout.write(f'  127.0.0.1 {tenant_domain}')

    def _install_migration_fix(self):
        """
        Install a signal handler to fix the wagtail grouppagepermission issue.

        The issue is that migration 0086_populate_grouppagepermission_permission
        doesn't properly populate permission_id, leaving NULL values.
        Migration 0087 then tries to make the field NOT NULL and fails.

        Our fix: Delete rows with NULL permission_id before 0087 runs.
        These permissions will be recreated properly by Django/Wagtail.
        """
        from django.db.migrations import RunPython
        from django.db.migrations.executor import MigrationExecutor

        original_apply = MigrationExecutor.apply_migration

        def patched_apply(self, state, migration, fake=False, fake_initial=False):
            # Check if this is migration 0087 for wagtailcore
            if (migration.app_label == 'wagtailcore' and
                    '0087' in migration.name):
                # Delete rows with NULL permission_id
                try:
                    with connection.cursor() as cursor:
                        # Get the current schema
                        cursor.execute("SELECT current_schema()")
                        schema = cursor.fetchone()[0]
                        if schema and schema != 'public':
                            cursor.execute(f"""
                                DELETE FROM {schema}.wagtailcore_grouppagepermission
                                WHERE permission_id IS NULL
                            """)
                except Exception as e:
                    # Log but continue - the table might not exist yet
                    pass

            return original_apply(self, state, migration, fake, fake_initial)

        MigrationExecutor.apply_migration = patched_apply
        self.stdout.write('   Installed Wagtail migration fix')

    def _create_demo_data(self, tenant):
        """Create demo users and basic data."""
        from django.contrib.auth import get_user_model
        from django_tenants.utils import schema_context

        User = get_user_model()

        with schema_context('demo'):
            # Import tenant-specific models within schema context
            from accounts.models import TenantUser

            # Create admin user
            admin, created = User.objects.get_or_create(
                email='admin@demo.zumodra.local',
                defaults={
                    'first_name': 'Demo',
                    'last_name': 'Admin',
                    'is_active': True,
                    'is_staff': True,
                    'is_superuser': True,
                }
            )
            if created:
                admin.set_password('Demo@2024!')
                admin.save()
                self.stdout.write(f'   Created admin user: {admin.email}')
            else:
                self.stdout.write(f'   Admin user exists: {admin.email}')

            # Create TenantUser relationship
            TenantUser.objects.get_or_create(
                user=admin,
                tenant=tenant,
                defaults={
                    'role': 'OWNER',
                    'is_active': True,
                    'is_primary_tenant': True,
                }
            )
            self.stdout.write('   Created tenant user relationship')
