"""
Fix tenant migrations for existing databases.

This command fixes "relation already exists" errors by faking migrations
for apps where tables already exist in the database.

Usage:
    python manage.py fix_tenant_migrations
    python manage.py fix_tenant_migrations --tenant=demo
    python manage.py fix_tenant_migrations --all-tenants
"""

from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.db import connection
from django_tenants.utils import schema_context, get_tenant_model


class Command(BaseCommand):
    help = 'Fix migration state for multi-tenant database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant',
            type=str,
            help='Specific tenant schema to fix'
        )
        parser.add_argument(
            '--all-tenants',
            action='store_true',
            help='Fix all tenant schemas'
        )
        parser.add_argument(
            '--public-only',
            action='store_true',
            help='Only fix public schema'
        )

    def handle(self, *args, **options):
        # Apps that commonly cause "relation already exists" errors
        SHARED_APPS_TO_FAKE = [
            'contenttypes',
            'auth',
            'sites',
            'admin',
            'sessions',
            'django_celery_beat',
            'axes',
            'admin_honeypot',
        ]

        TENANT_APPS_TO_FAKE = [
            'contenttypes',
            'django_otp',
            'allauth',
            'account',  # allauth.account
            'socialaccount',  # allauth.socialaccount
            'auditlog',
            'taggit',
            'wagtailcore',
            'wagtailadmin',
            'wagtaildocs',
            'wagtailembeds',
            'wagtailforms',
            'wagtailredirects',
            'wagtailsearch',
            'wagtailusers',
            'wagtailimages',
        ]

        self.stdout.write(self.style.NOTICE('Starting migration fix...'))

        # Fix public schema
        if not options.get('tenant') or options.get('public_only'):
            self.stdout.write(self.style.NOTICE('\n=== Fixing PUBLIC schema ==='))
            with schema_context('public'):
                for app in SHARED_APPS_TO_FAKE:
                    try:
                        self.stdout.write(f'  Faking migrations for {app}...')
                        call_command('migrate', app, '--fake', verbosity=0)
                        self.stdout.write(self.style.SUCCESS(f'  ✓ {app}'))
                    except Exception as e:
                        self.stdout.write(self.style.WARNING(f'  ⚠ {app}: {str(e)[:50]}'))

        if options.get('public_only'):
            self.stdout.write(self.style.SUCCESS('\nPublic schema fixed!'))
            return

        # Get tenants to fix
        Tenant = get_tenant_model()

        if options.get('tenant'):
            tenants = Tenant.objects.filter(schema_name=options['tenant'])
            if not tenants.exists():
                self.stdout.write(self.style.ERROR(f"Tenant '{options['tenant']}' not found"))
                return
        elif options.get('all_tenants'):
            tenants = Tenant.objects.exclude(schema_name='public')
        else:
            # Default: fix public only, show instructions for tenants
            self.stdout.write(self.style.SUCCESS('\nPublic schema fixed!'))
            self.stdout.write(self.style.NOTICE(
                '\nTo fix tenant schemas, run with --all-tenants or --tenant=<schema_name>'
            ))
            return

        # Fix tenant schemas
        for tenant in tenants:
            self.stdout.write(self.style.NOTICE(f'\n=== Fixing tenant: {tenant.schema_name} ==='))
            with schema_context(tenant.schema_name):
                for app in TENANT_APPS_TO_FAKE:
                    try:
                        self.stdout.write(f'  Faking migrations for {app}...')
                        call_command('migrate', app, '--fake', verbosity=0)
                        self.stdout.write(self.style.SUCCESS(f'  ✓ {app}'))
                    except Exception as e:
                        self.stdout.write(self.style.WARNING(f'  ⚠ {app}: {str(e)[:50]}'))

        self.stdout.write(self.style.SUCCESS('\n✓ Migration fix complete!'))
        self.stdout.write(self.style.NOTICE(
            '\nNow run: python manage.py migrate_schemas'
        ))
