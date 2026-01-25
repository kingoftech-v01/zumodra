"""
Projects app configuration.

This app manages project missions/mandates posted by company tenants.
Projects are specific, time-bound assignments with deliverables and milestones.

Different from services (ongoing offerings), projects have:
- Fixed timeline (start/end dates)
- Specific deliverables
- Milestone-based payments
- Proposal workflow (providers bid on projects)
"""

from django.apps import AppConfig


class ProjectsConfig(AppConfig):
    """Configuration for the projects app."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'projects'
    verbose_name = 'Project Missions'

    def ready(self):
        """Import signal handlers when app is ready."""
        import projects.signals  # noqa: F401
