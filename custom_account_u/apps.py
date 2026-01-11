from django.apps import AppConfig


class CustomAccountUConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'custom_account_u'
    verbose_name = 'Custom Account (Public Schema)'

    def ready(self):
        """Import signal handlers when app is ready."""
        import custom_account_u.signals  # noqa
