"""
Core App Configuration
"""

from django.apps import AppConfig


class CoreConfig(AppConfig):
    """Configuration for the core application."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'
    verbose_name = 'Core Infrastructure'

    def ready(self):
        """Import signals and perform startup tasks."""
        pass
