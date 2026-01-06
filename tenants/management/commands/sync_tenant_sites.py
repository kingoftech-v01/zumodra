"""
Management command to create/sync Site objects for all tenants.

This is required for django-allauth to function properly in tenant schemas
when django.contrib.sites is in TENANT_APPS.

Usage:
    python manage.py sync_tenant_sites
"""

from django.core.management.base import BaseCommand
from django.contrib.sites.models import Site
from django_tenants.utils import schema_context, get_tenant_model


class Command(BaseCommand):
    help = 'Create or sync Site objects for all tenant schemas'

    def add_arguments(self, parser):
        parser.add_argument(
            '--schema',
            type=str,
            help='Sync Site for a specific tenant schema only',
        )

    def handle(self, *args, **options):
        TenantModel = get_tenant_model()
        schema_filter = options.get('schema')

        if schema_filter:
            tenants = TenantModel.objects.filter(schema_name=schema_filter)
        else:
            tenants = TenantModel.objects.all()

        if not tenants.exists():
            self.stdout.write(self.style.WARNING('No tenants found.'))
            return

        for tenant in tenants:
            self.sync_tenant_site(tenant)

        self.stdout.write(self.style.SUCCESS(
            f'Successfully synced Site objects for {tenants.count()} tenant(s).'
        ))

    def sync_tenant_site(self, tenant):
        """Create or update the Site object for a tenant."""
        try:
            with schema_context(tenant.schema_name):
                # Get the tenant's primary domain
                primary_domain = tenant.get_primary_domain()
                domain_name = (
                    primary_domain.domain
                    if primary_domain
                    else f"{tenant.schema_name}.zumodra.rhematek-solutions.com"
                )

                # Create or update the Site for this tenant
                site, created = Site.objects.update_or_create(
                    pk=1,  # Use pk=1 to match SITE_ID setting
                    defaults={
                        'domain': domain_name,
                        'name': tenant.name or tenant.schema_name.title()
                    }
                )

                action = 'Created' if created else 'Updated'
                self.stdout.write(
                    f"  {action} Site for {tenant.schema_name}: {domain_name}"
                )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"  Error syncing Site for {tenant.schema_name}: {e}")
            )
