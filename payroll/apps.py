from django.apps import AppConfig


class PayrollConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "payroll"
    verbose_name = "Payroll"

    def ready(self):
        """Import signals when app is ready"""
        try:
            import payroll.signals  # noqa: F401
        except ImportError:
            pass
