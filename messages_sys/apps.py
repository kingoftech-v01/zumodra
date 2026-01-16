from django.apps import AppConfig


class MessagesSysConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'messages_sys'

    def ready(self):
        """Import signals when the app is ready."""
        import messages_sys.signals  # noqa
