"""
Marketing Campaigns App

Unified marketing and newsletter campaign management with tenant isolation.

This app merges functionality from:
- marketing/ (visitor tracking, leads, conversions)
- newsletter/ (email campaigns, subscriptions, Mailchimp integration)

All models are tenant-aware (TENANT_APPS) for proper data isolation.
"""

default_app_config = 'marketing_campaigns.apps.MarketingCampaignsConfig'
