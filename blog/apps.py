"""
Blog App Configuration Module
==============================

Django configuration for the blog application, including signal
loading at application startup.
"""

from django.apps import AppConfig


class BlogConfig(AppConfig):
    """
    Configuration for the Blog application in the Zumodra project.

    This class configures the basic settings for the blog app and loads
    necessary signals when the application starts.

    Attributes:
        default_auto_field (str): Default field type for primary keys
            Uses BigAutoField to support large amounts of data
        name (str): Python name of the application ('blog')

    Methods:
        ready(): Called when Django has loaded all models
            Imports signals to activate them

    Usage:
        This class is referenced in INSTALLED_APPS via:
        'blog.apps.BlogConfig' or simply 'blog'

    Note:
        The ready() method is called ONCE at startup.
        Never perform heavy operations or DB queries here.
    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'blog'

    def ready(self):
        """
        Hook called by Django when the application is ready.

        This method executes after all models have been loaded
        but before the server starts processing requests.

        Actions:
            - Imports blog.signals to register signal handlers
            - Signals (create_user_profile, save_user_profile) are
              activated via @receiver decorators

        Timing:
            Called ONCE at Django startup (runserver, gunicorn, etc.)

        Important:
            - NEVER make DB queries here (tables may not exist)
            - Don't perform blocking operations
            - Imports must be in the method (not top-level)
              to avoid circular imports

        Example:
            At server startup:
            1. Django loads all models
            2. Django calls ready() for each app
            3. blog.signals is imported
            4. @receiver decorators register the handlers
            5. Signals are active for all requests
        """
        # Local import to avoid circular imports
        # Signals are registered via @receiver decorators
        import blog.signals  # noqa: F401 (imported for side-effect)
