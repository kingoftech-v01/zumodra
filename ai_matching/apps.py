from django.apps import AppConfig


class AiMatchingConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ai_matching'
    verbose_name = 'AI Matching Service'

    def ready(self):
        # Import signals if needed
        pass
