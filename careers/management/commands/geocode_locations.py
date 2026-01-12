"""
Management command to geocode existing tenants, jobs, and services.
"""

from django.core.management.base import BaseCommand
from tenants.models import Tenant
from ats.models import JobPosting
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
            '--all',
            action='store_true',
            help='Geocode all locations'
        )

    def handle(self, *args, **options):
        geocode_all = options.get('all')

        if geocode_all or options.get('tenants'):
            self.geocode_tenants()

        if geocode_all or options.get('jobs'):
            self.geocode_jobs()

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
