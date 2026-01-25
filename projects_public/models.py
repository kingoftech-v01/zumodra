"""
Projects Public Models - Public project catalog.

This module defines the denormalized public catalog for cross-tenant project browsing.
Data is synced from tenant-posted projects via Django signals and Celery tasks.

Architecture:
- SHARED_APPS (public schema)
- Read-only for public browsing
- No authentication required
- Denormalized for performance
- PostGIS for geographic queries
"""

import uuid
from django.db import models
from django.contrib.postgres.fields import ArrayField
from django.contrib.gis.db import models as gis_models
from django.utils.translation import gettext_lazy as _


# ============================================================================
# PUBLIC PROJECT CATALOG
# ============================================================================

class PublicProjectCatalog(models.Model):
    """
    Public catalog entry for browsing project opportunities.

    Denormalized data from tenant Project model for fast cross-tenant queries.
    Updated via Celery tasks triggered by signals.

    Features:
    - No authentication required (public access)
    - Geographic search (PostGIS)
    - Full-text search
    - Category/skill filtering
    - Redirects to tenant domain for applications
    """

    uuid = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        unique=True,
        db_index=True
    )

    # Source reference (NOT a foreign key - cross-schema)
    tenant_project_id = models.IntegerField(
        help_text=_('Original project ID in tenant schema')
    )
    tenant_id = models.IntegerField(
        help_text=_('Tenant ID that posted this project')
    )
    tenant_schema = models.CharField(
        max_length=100,
        help_text=_('Tenant schema name')
    )

    # Project info (denormalized)
    title = models.CharField(max_length=255, db_index=True)
    description = models.TextField()
    short_description = models.CharField(max_length=500, blank=True)

    # Classification
    category_name = models.CharField(max_length=100, db_index=True)
    category_slug = models.SlugField(max_length=120)
    required_skills = ArrayField(
        models.CharField(max_length=100),
        default=list
    )
    experience_level = models.CharField(max_length=20, db_index=True)

    # Timeline
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    estimated_duration_weeks = models.PositiveIntegerField(null=True, blank=True)
    deadline = models.DateField(null=True, blank=True, db_index=True)

    # Budget
    budget_type = models.CharField(max_length=20, db_index=True)
    budget_min = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        db_index=True
    )
    budget_max = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        db_index=True
    )
    budget_currency = models.CharField(max_length=3, default='CAD')

    # Location
    location_type = models.CharField(max_length=20, db_index=True)
    location_city = models.CharField(max_length=100, blank=True, db_index=True)
    location_country = models.CharField(max_length=100, blank=True, db_index=True)
    location_coordinates = gis_models.PointField(
        null=True,
        blank=True,
        geography=True,
        help_text=_('Geographic coordinates for location-based search')
    )

    # Company info (denormalized from tenant)
    company_name = models.CharField(max_length=255, db_index=True)
    company_logo_url = models.URLField(blank=True)
    company_domain = models.CharField(max_length=253)  # Tenant domain

    # Application info
    max_proposals = models.PositiveIntegerField(default=20)
    proposal_count = models.PositiveIntegerField(default=0)
    proposal_deadline = models.DateTimeField(null=True, blank=True)

    # Status
    is_open = models.BooleanField(default=True, db_index=True)
    is_featured = models.BooleanField(default=False, db_index=True)

    # Publication
    published_at = models.DateTimeField(db_index=True)
    synced_at = models.DateTimeField(auto_now=True)

    # Metadata for SEO
    meta_title = models.CharField(max_length=200, blank=True)
    meta_description = models.CharField(max_length=300, blank=True)

    class Meta:
        verbose_name = _('Public Project')
        verbose_name_plural = _('Public Project Catalog')
        ordering = ['-published_at']
        indexes = [
            # Core browsing indexes
            models.Index(fields=['is_open', '-published_at']),
            models.Index(fields=['category_slug', 'is_open']),
            models.Index(fields=['location_country', 'is_open']),
            models.Index(fields=['budget_max', 'is_open']),

            # Combined indexes for common filters
            models.Index(fields=['category_slug', 'location_type', 'is_open']),
            models.Index(fields=['experience_level', 'budget_type', 'is_open']),

            # Unique source reference
            models.Index(fields=['tenant_id', 'tenant_project_id']),
        ]
        # Unique constraint on source
        unique_together = [['tenant_id', 'tenant_project_id']]

    def __str__(self):
        return f"{self.title} - {self.company_name}"

    @property
    def project_url(self):
        """
        Generate URL to view project on tenant domain.

        Redirects users to tenant's domain for full project details and application.
        """
        return f"https://{self.company_domain}/projects/{self.uuid}/"

    @property
    def application_url(self):
        """Generate URL to apply for project on tenant domain."""
        return f"https://{self.company_domain}/projects/{self.uuid}/apply/"

    @property
    def is_accepting_proposals(self):
        """Check if project is still accepting proposals."""
        if not self.is_open:
            return False
        if self.proposal_count >= self.max_proposals:
            return False
        if self.proposal_deadline:
            from django.utils import timezone
            if timezone.now() > self.proposal_deadline:
                return False
        return True

    @property
    def budget_range_display(self):
        """Format budget range for display."""
        if self.budget_type == 'NEGOTIABLE':
            return _('Negotiable')
        if self.budget_min and self.budget_max:
            if self.budget_min == self.budget_max:
                return f"{self.budget_currency} {self.budget_min:,.2f}"
            return f"{self.budget_currency} {self.budget_min:,.2f} - {self.budget_max:,.2f}"
        if self.budget_min:
            return f"{self.budget_currency} {self.budget_min:,.2f}+"
        if self.budget_max:
            return f"{self.budget_currency} {self.budget_max:,.2f}"
        return _('Not specified')

    @property
    def duration_display(self):
        """Format estimated duration for display."""
        if self.estimated_duration_weeks:
            weeks = self.estimated_duration_weeks
            if weeks < 4:
                return f"{weeks} week{'s' if weeks > 1 else ''}"
            months = weeks / 4
            return f"{months:.1f} month{'s' if months > 1 else ''}"
        return _('Not specified')


# ============================================================================
# PUBLIC PROJECT STATS
# ============================================================================

class PublicProjectStats(models.Model):
    """
    Aggregate statistics for public project catalog.

    Updated periodically via Celery Beat task.
    Used for dashboard and analytics.
    """

    # Timestamp
    snapshot_date = models.DateField(
        unique=True,
        help_text=_('Date of this snapshot')
    )

    # Overall stats
    total_projects = models.PositiveIntegerField(default=0)
    open_projects = models.PositiveIntegerField(default=0)
    total_companies = models.PositiveIntegerField(default=0)

    # By category
    by_category = models.JSONField(
        default=dict,
        help_text=_('Project counts by category')
    )

    # By location
    by_country = models.JSONField(
        default=dict,
        help_text=_('Project counts by country')
    )

    # By budget range
    by_budget_range = models.JSONField(
        default=dict,
        help_text=_('Project counts by budget range')
    )

    # Average metrics
    avg_budget = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True
    )
    avg_duration_weeks = models.FloatField(null=True, blank=True)
    avg_proposals_per_project = models.FloatField(null=True, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Public Project Stats')
        verbose_name_plural = _('Public Project Stats')
        ordering = ['-snapshot_date']

    def __str__(self):
        return f"Project Stats - {self.snapshot_date}"
