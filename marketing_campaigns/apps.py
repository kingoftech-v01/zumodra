"""Marketing Campaigns app configuration."""

from django.apps import AppConfig


class MarketingCampaignsConfig(AppConfig):
    """Configuration for the marketing_campaigns app."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'marketing_campaigns'
    verbose_name = 'Marketing & Campaigns'

    def ready(self):
        """
        Initialize app when Django starts.

        Imports signal handlers for:
        - Contact sync to Mailchimp
        - Campaign tracking
        - Visit event logging
        """
        try:
            import marketing_campaigns.signals  # noqa: F401
        except ImportError:
            pass
