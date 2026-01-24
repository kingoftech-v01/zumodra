from django.apps import AppConfig


class AccountingConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "accounting"
    verbose_name = "Accounting Integration"

    def ready(self):
        """Import signals when app is ready"""
        try:
            import accounting.signals  # noqa: F401
        except ImportError:
            pass
