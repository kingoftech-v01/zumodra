from django.apps import AppConfig


class PaymentsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "payments"
    verbose_name = "Tenant Payments"

    def ready(self):
        """Import signals when app is ready"""
        try:
            import payments.signals  # noqa: F401
        except ImportError:
            pass
