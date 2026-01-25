from django.apps import AppConfig


class TenantProfilesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'tenant_profiles'
    verbose_name = 'Tenant Profiles & Membership (Tenant Schema)'

    def ready(self):
        """Import signal handlers when app is ready."""
        try:
            import tenant_profiles.signals  # noqa
        except ImportError:
            pass  # Signals not yet implemented
