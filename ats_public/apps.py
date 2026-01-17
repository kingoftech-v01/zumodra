"""ATS Public Catalog app configuration."""

from django.apps import AppConfig


class AtsPublicConfig(AppConfig):
    """Configuration for the ats_public app."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ats_public'
    verbose_name = 'Public Job Catalog'

    def ready(self):
        """
        Initialize app when Django starts.

        Imports and registers signal handlers for syncing tenant jobs to public catalog.
        """
        try:
            import ats_public.signals  # noqa: F401
        except ImportError:
            pass
