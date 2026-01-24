from django.apps import AppConfig


class TaxConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "tax"
    verbose_name = "Tax"

    def ready(self):
        """Import signals when app is ready"""
        try:
            import tax.signals  # noqa: F401
        except ImportError:
            pass
