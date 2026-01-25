from django.apps import AppConfig


class FinanceWebhooksConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "finance_webhooks"
    verbose_name = "Finance Webhooks"

    def ready(self):
        """Import signals when app is ready"""
        try:
            import finance_webhooks.signals  # noqa: F401
        except ImportError:
            pass
