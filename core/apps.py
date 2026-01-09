"""
Core App Configuration
"""

import os
import sys
from django.apps import AppConfig


class CoreConfig(AppConfig):
    """Configuration for the core application."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'
    verbose_name = 'Core Infrastructure'

    def ready(self):
        """Import signals and perform startup tasks."""
        # Connect all cache invalidation signals
        from core.cache import connect_all_cache_signals
        connect_all_cache_signals()

        # Sync Django Site framework with domain config on server startup
        # Skip during migrations, tests, or other non-server commands
        self._sync_site_domain_if_needed()

    def _sync_site_domain_if_needed(self):
        """Sync Site domain from environment config on startup."""
        # Skip if running migrations, shell, or test commands
        running_server = (
            'runserver' in sys.argv or
            'daphne' in sys.argv[0] if sys.argv else False or
            'gunicorn' in sys.argv[0] if sys.argv else False or
            'uvicorn' in sys.argv[0] if sys.argv else False or
            os.environ.get('RUN_MAIN') == 'true'  # Django reloader
        )

        if not running_server:
            return

        # Only sync on first startup, not during reloader restarts
        if os.environ.get('SITE_SYNCED'):
            return

        try:
            from django.contrib.sites.models import Site
            from django.conf import settings

            # Get configured domain
            site_url = getattr(settings, 'SITE_URL', '')
            if site_url:
                from urllib.parse import urlparse
                parsed = urlparse(site_url)
                domain = parsed.netloc or parsed.path.split('/')[0]
            else:
                domain = getattr(settings, 'PRIMARY_DOMAIN', '')
                if not domain:
                    port = os.environ.get('WEB_PORT', '8002')
                    domain = f"localhost:{port}" if getattr(settings, 'DEBUG', False) else ''

            if not domain:
                return

            # Update or create the default site
            site_id = getattr(settings, 'SITE_ID', 1)
            site_name = getattr(settings, 'SITE_NAME', 'Zumodra')

            site, created = Site.objects.update_or_create(
                id=site_id,
                defaults={
                    'domain': domain,
                    'name': site_name,
                }
            )

            # Mark as synced to avoid running again during reloader
            os.environ['SITE_SYNCED'] = 'true'

        except Exception:
            # Silently ignore errors during startup (table may not exist yet)
            pass
