"""
Management command to sync Django Site framework with domain configuration.

This command updates the default Site object to use the domain configured
in environment variables (PRIMARY_DOMAIN, SITE_URL). Should be run on
startup or when domain configuration changes.
"""

import os
from django.core.management.base import BaseCommand
from django.conf import settings
from django.contrib.sites.models import Site


class Command(BaseCommand):
    help = 'Sync Django Site framework with domain configuration from environment'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be changed without making changes'
        )
        parser.add_argument(
            '--site-id',
            type=int,
            default=1,
            help='Site ID to update (default: 1)'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force update even if domain appears unchanged'
        )

    def handle(self, *args, **options):
        dry_run = options.get('dry_run', False)
        site_id = options['site_id']
        force = options.get('force', False)

        # Get domain from centralized configuration
        domain = self._get_configured_domain()
        site_name = self._get_site_name()

        if not domain:
            self.stdout.write(self.style.WARNING(
                "No domain configured. Set PRIMARY_DOMAIN or SITE_URL in environment."
            ))
            return

        self.stdout.write(f"Configured domain: {domain}")
        self.stdout.write(f"Site name: {site_name}")
        self.stdout.write(f"Target Site ID: {site_id}")

        if dry_run:
            self.stdout.write(self.style.WARNING("\n[DRY RUN MODE]"))

        try:
            site = Site.objects.get(id=site_id)
            current_domain = site.domain
            current_name = site.name

            self.stdout.write(f"\nCurrent Site configuration:")
            self.stdout.write(f"  Domain: {current_domain}")
            self.stdout.write(f"  Name: {current_name}")

            needs_update = (
                force or
                current_domain != domain or
                (site_name and current_name != site_name)
            )

            if not needs_update:
                self.stdout.write(self.style.SUCCESS("\nSite is already up to date."))
                return

            if dry_run:
                self.stdout.write(f"\nWould update Site {site_id}:")
                self.stdout.write(f"  Domain: {current_domain} -> {domain}")
                if site_name:
                    self.stdout.write(f"  Name: {current_name} -> {site_name}")
            else:
                site.domain = domain
                if site_name:
                    site.name = site_name
                site.save()

                self.stdout.write(self.style.SUCCESS(f"\nSite {site_id} updated successfully!"))
                self.stdout.write(f"  Domain: {domain}")
                if site_name:
                    self.stdout.write(f"  Name: {site_name}")

        except Site.DoesNotExist:
            if dry_run:
                self.stdout.write(f"\nWould create Site {site_id}:")
                self.stdout.write(f"  Domain: {domain}")
                self.stdout.write(f"  Name: {site_name or domain}")
            else:
                Site.objects.create(
                    id=site_id,
                    domain=domain,
                    name=site_name or domain,
                )
                self.stdout.write(self.style.SUCCESS(f"\nCreated Site {site_id}:"))
                self.stdout.write(f"  Domain: {domain}")
                self.stdout.write(f"  Name: {site_name or domain}")

    def _get_configured_domain(self):
        """Get domain from centralized configuration."""
        # Try environment variables first
        site_url = os.environ.get('SITE_URL')
        if site_url:
            # Extract domain from URL
            from urllib.parse import urlparse
            parsed = urlparse(site_url)
            return parsed.netloc or parsed.path.split('/')[0]

        # Try settings
        site_url = getattr(settings, 'SITE_URL', '')
        if site_url:
            from urllib.parse import urlparse
            parsed = urlparse(site_url)
            return parsed.netloc or parsed.path.split('/')[0]

        # Fall back to PRIMARY_DOMAIN
        domain = os.environ.get('PRIMARY_DOMAIN') or getattr(settings, 'PRIMARY_DOMAIN', '')

        # If still nothing in production, this is an error
        if not domain and not getattr(settings, 'DEBUG', False):
            return None

        # In development, default to localhost with port
        if not domain:
            port = os.environ.get('WEB_PORT', '8002')
            domain = f"localhost:{port}"

        return domain

    def _get_site_name(self):
        """Get site name from configuration."""
        # Try environment first
        name = os.environ.get('SITE_NAME')
        if name:
            return name

        # Try settings
        name = getattr(settings, 'SITE_NAME', '')
        if name:
            return name

        # Use project name from settings or default
        return getattr(settings, 'PROJECT_NAME', 'Zumodra')
