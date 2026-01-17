"""Services Public Catalog app configuration."""

from django.apps import AppConfig


class ServicesPublicConfig(AppConfig):
    """Configuration for the services_public app."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'services_public'
    verbose_name = 'Public Service Catalog'

    def ready(self):
        """
        Initialize app when Django starts.

        Imports and registers signal handlers for syncing tenant services to public catalog.
        """
        try:
            import services_public.signals  # noqa: F401
        except ImportError:
            pass
