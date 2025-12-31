from django.apps import AppConfig


class AtsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ats'
    verbose_name = 'Applicant Tracking System'

    def ready(self):
        import ats.signals  # noqa
