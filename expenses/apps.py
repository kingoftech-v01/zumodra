from django.apps import AppConfig


class ExpensesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "expenses"
    verbose_name = "Expenses"

    def ready(self):
        """Import signals when app is ready"""
        try:
            import expenses.signals  # noqa: F401
        except ImportError:
            pass
