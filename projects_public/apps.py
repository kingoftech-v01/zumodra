"""
Projects Public app configuration.

This app provides the public catalog for browsing project opportunities.
Denormalized data synced from tenant-posted projects for fast cross-tenant queries.

Features:
- Public browsing (no authentication required)
- Cross-tenant project search
- Geographic filtering (PostGIS)
- Category/skill filtering
- Redirects to tenant domain for applications
"""

from django.apps import AppConfig


class ProjectsPublicConfig(AppConfig):
    """Configuration for the projects_public app."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'projects_public'
    verbose_name = 'Public Project Catalog'
