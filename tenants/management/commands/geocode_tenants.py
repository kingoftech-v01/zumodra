"""
Management command to geocode existing tenants.

This command geocodes all tenants that have address information but no location coordinates.
Implements TODO-CAREERS-001 from careers/TODO.md.

Usage:
    python manage.py geocode_tenants [--all] [--force] [--limit N]
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from tenants.models import Tenant
from core.geocoding import GeocodingService
import time


class Command(BaseCommand):
    help = 'Geocode tenant addresses to coordinates for map display'

    def add_arguments(self, parser):
        parser.add_argument(
            '--all',
            action='store_true',
            help='Geocode all tenants (including those already geocoded)',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force re-geocoding even if location already exists',
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=None,
            help='Limit number of tenants to geocode (for testing)',
        )
        parser.add_argument(
            '--company-only',
            action='store_true',
            help='Only geocode company tenants (skip freelancers)',
        )
        parser.add_argument(
            '--active-only',
            action='store_true',
            default=True,
            help='Only geocode active tenants (default: True)',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting tenant geocoding...'))

        # Build queryset
        queryset = Tenant.objects.all()

        # Filter by status
        if options['active_only']:
            queryset = queryset.filter(status=Tenant.TenantStatus.ACTIVE)
            self.stdout.write('Filtering: Active tenants only')

        # Filter by tenant type
        if options['company_only']:
            queryset = queryset.filter(tenant_type=Tenant.TenantType.COMPANY)
            self.stdout.write('Filtering: Company tenants only')

        # Filter out tenants without sufficient address info
        queryset = queryset.exclude(city='').exclude(country='')

        # Filter out already geocoded tenants (unless --force)
        if not options['force']:
            queryset = queryset.filter(location__isnull=True)
            self.stdout.write('Filtering: Tenants without coordinates only')

        # Apply limit
        if options['limit']:
            queryset = queryset[:options['limit']]
            self.stdout.write(f'Limiting to {options["limit"]} tenants')

        total_count = queryset.count()
        self.stdout.write(f'\nFound {total_count} tenants to geocode\n')

        if total_count == 0:
            self.stdout.write(self.style.WARNING('No tenants to geocode.'))
            return

        # Geocode tenants
        success_count = 0
        failure_count = 0
        skipped_count = 0

        for idx, tenant in enumerate(queryset, 1):
            self.stdout.write(f'[{idx}/{total_count}] Processing: {tenant.name}')

            # Display address
            address_parts = [tenant.city, tenant.state, tenant.country]
            address_str = ', '.join([p for p in address_parts if p])
            self.stdout.write(f'  Address: {address_str}')

            try:
                # Skip if already has location and not forcing
                if tenant.location and not options['force']:
                    self.stdout.write(self.style.WARNING(f'  Skipped (already geocoded)'))
                    skipped_count += 1
                    continue

                # Geocode
                GeocodingService.geocode_tenant(tenant)

                # Refresh from DB to get updated location
                tenant.refresh_from_db()

                if tenant.location:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'  ✓ Success: ({tenant.latitude:.6f}, {tenant.longitude:.6f})'
                        )
                    )
                    success_count += 1
                else:
                    self.stdout.write(self.style.ERROR(f'  ✗ Failed: No coordinates returned'))
                    failure_count += 1

                # Rate limiting: Nominatim requires 1 req/sec
                # Sleep for 1 second between requests
                if idx < total_count:
                    time.sleep(1)

            except Exception as e:
                self.stdout.write(self.style.ERROR(f'  ✗ Error: {e}'))
                failure_count += 1

        # Summary
        self.stdout.write('\n' + '=' * 60)
        self.stdout.write(self.style.SUCCESS('\nGeocoding Summary:'))
        self.stdout.write(f'  Total processed: {total_count}')
        self.stdout.write(self.style.SUCCESS(f'  ✓ Successful: {success_count}'))
        self.stdout.write(self.style.ERROR(f'  ✗ Failed: {failure_count}'))
        self.stdout.write(self.style.WARNING(f'  - Skipped: {skipped_count}'))
        self.stdout.write('=' * 60 + '\n')

        if failure_count > 0:
            self.stdout.write(
                self.style.WARNING(
                    '\nNote: Some geocoding requests failed. This is normal if addresses '
                    'are invalid or incomplete. Check logs for details.'
                )
            )

        self.stdout.write(
            self.style.SUCCESS(
                f'\n✓ Geocoding complete! {success_count}/{total_count} tenants geocoded.'
            )
        )
