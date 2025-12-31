from django.apps import AppConfig


class HrCoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'hr_core'
    verbose_name = 'HR Core Operations'

    def ready(self):
        import hr_core.signals  # noqa
