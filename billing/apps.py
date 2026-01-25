from django.apps import AppConfig


class BillingConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "billing"
    verbose_name = "Platform Billing"

    def ready(self):
        """Import signals when app is ready"""
        try:
            import billing.signals  # noqa: F401
        except ImportError:
            pass
