from django.apps import AppConfig


class AnalyticsConfig(AppConfig):
    """
    Analytics App Configuration

    This app provides comprehensive HR and recruitment analytics including:
    - Recruitment metrics and dashboards
    - Diversity analytics (EEOC compliant)
    - Hiring funnel analytics
    - Time-to-hire tracking
    - Source effectiveness analysis
    - Employee retention metrics
    - Time-off analytics
    - Performance distribution
    """

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'analytics'
    verbose_name = 'HR Analytics & Reporting'

    def ready(self):
        """
        Import signals and register tasks when the app is ready.
        """
        # Import signals if any
        try:
            from . import signals  # noqa: F401
        except ImportError:
            pass

        # Register Celery tasks
        try:
            from . import tasks  # noqa: F401
        except ImportError:
            pass
