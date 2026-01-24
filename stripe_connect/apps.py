from django.apps import AppConfig


class StripeConnectConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "stripe_connect"
    verbose_name = "Stripe Connect"

    def ready(self):
        """Import signals when app is ready"""
        try:
            import stripe_connect.signals  # noqa: F401
        except ImportError:
            pass
