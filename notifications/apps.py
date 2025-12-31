"""
Notifications App Configuration.
"""

from django.apps import AppConfig


class NotificationsConfig(AppConfig):
    """Configuration for the notifications app."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'notifications'
    verbose_name = 'Notifications'

    def ready(self):
        """Register signals when app is ready."""
        # Import signals to register them
        import notifications.signals  # noqa: F401
