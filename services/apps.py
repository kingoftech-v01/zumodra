from django.apps import AppConfig


class ServicesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'services'

    def ready(self):
        """
        Register signal handlers when app is ready.
        Imports signals module to connect marketplace sync handlers.
        """
        import services.signals  # noqa: F401
