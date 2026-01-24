from django.apps import AppConfig


class CoreIdentityConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core_identity'
    verbose_name = 'Core Identity & Verification (Public Schema)'

    def ready(self):
        """Import signal handlers when app is ready."""
        import core_identity.signals  # noqa
