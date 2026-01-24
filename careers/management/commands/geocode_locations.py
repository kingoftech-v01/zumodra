"""
Management command to geocode existing tenants, jobs, and services.
"""

from django.core.management.base import BaseCommand
from tenants.models import Tenant
from jobs.models import JobPosting
from services.models import Service
from core.geocoding import GeocodingService


class Command(BaseCommand):
    help = 'Geocode existing locations for tenants, jobs, and services'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenants',
            action='store_true',
            help='Geocode tenant addresses'
        )
        parser.add_argument(
            '--jobs',
            action='store_true',
            help='Geocode job locations'
        )
        parser.add_argument(
            '--services',
            action='store_true',
            help='Geocode service provider locations'
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help='Geocode all locations (tenants, jobs, services)'
        )

    def handle(self, *args, **options):
        geocode_all = options.get('all')

        if geocode_all or options.get('tenants'):
            self.geocode_tenants()

        if geocode_all or options.get('jobs'):
            self.geocode_jobs()

        if geocode_all or options.get('services'):
            self.geocode_services()

    def geocode_tenants(self):
        tenants = Tenant.objects.filter(
            location_coordinates__isnull=True,
            geocode_attempted=False
        ).exclude(city='')

        count = tenants.count()
        self.stdout.write(f'Geocoding {count} tenants...')

        for i, tenant in enumerate(tenants, 1):
            GeocodingService.geocode_tenant(tenant)
            self.stdout.write(f'  [{i}/{count}] {tenant.name}')

        self.stdout.write(self.style.SUCCESS(f'Geocoded {count} tenants'))

    def geocode_jobs(self):
        jobs = JobPosting.objects.filter(
            location_coordinates__isnull=True,
            geocode_attempted=False
        ).exclude(location_city='')

        count = jobs.count()
        self.stdout.write(f'Geocoding {count} jobs...')

        for i, job in enumerate(jobs, 1):
            GeocodingService.geocode_job(job)
            self.stdout.write(f'  [{i}/{count}] {job.title}')

        self.stdout.write(self.style.SUCCESS(f'Geocoded {count} jobs'))

    def geocode_services(self):
        """Geocode service provider locations."""
        services = Service.objects.filter(
            is_active=True,
            provider__isnull=False
        )

        # Filter services where provider doesn't have coordinates
        services_to_geocode = []
        for service in services:
            provider = service.provider
            has_coords = False

            # Check if provider already has coordinates
            if hasattr(provider, 'location') and provider.location:
                has_coords = True
            elif hasattr(provider, 'location_lat') and provider.location_lat:
                has_coords = True

            if not has_coords and hasattr(provider, 'city') and provider.city:
                services_to_geocode.append(service)

        count = len(services_to_geocode)
        self.stdout.write(f'Geocoding {count} service providers...')

        success_count = 0
        for i, service in enumerate(services_to_geocode, 1):
            coords = GeocodingService.geocode_service(service)
            if coords:
                success_count += 1
            self.stdout.write(f'  [{i}/{count}] Service {service.pk} - {service.name}')

        self.stdout.write(
            self.style.SUCCESS(f'Geocoded {success_count}/{count} service providers')
        )
