from django.apps import AppConfig


class IntegrationsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'integrations'
    verbose_name = 'Third-Party Integrations'

    def ready(self):
        # Import signal handlers when app is ready
        try:
            import integrations.signals  # noqa
        except ImportError:
            pass

        # Connect outbound webhook signals
        try:
            from integrations.webhook_signals import connect_all_webhook_signals
            connect_all_webhook_signals()
        except ImportError:
            pass
