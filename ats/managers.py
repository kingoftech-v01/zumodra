"""
ATS Managers - Tenant-aware model managers for the Applicant Tracking System.

This module provides custom Manager classes that:
- Automatically filter by tenant for multi-tenant isolation
- Combine QuerySet optimizations with tenant scoping
- Provide convenient accessor methods for common operations
- Support Zumodra's enterprise/circusale hierarchy
"""

from django.db import models
from django.db.models import Count, Avg, Q, F

from .querysets import (
    JobPostingQuerySet,
    CandidateQuerySet,
    ApplicationQuerySet,
    InterviewQuerySet,
    PipelineStageQuerySet,
    OfferQuerySet,
)


class TenantAwareManager(models.Manager):
    """
    Base manager class for tenant-aware models.

    Provides tenant isolation through automatic filtering when
    tenant context is available. Subclasses should define the
    tenant field path (e.g., 'job__tenant' or direct 'tenant').
    """

    tenant_field = 'tenant'

    def get_queryset(self):
        """
        Return base queryset. Override in subclass to use custom QuerySet.
        """
        return super().get_queryset()

    def for_tenant(self, tenant):
        """
        Filter queryset for a specific tenant.

        Args:
            tenant: Tenant instance or tenant ID

        Returns:
            QuerySet: Filtered to tenant
        """
        if hasattr(tenant, 'id'):
            tenant_id = tenant.id
        else:
            tenant_id = tenant

        filter_kwargs = {f'{self.tenant_field}_id': tenant_id}
        return self.get_queryset().filter(**filter_kwargs)

    def for_tenant_by_schema(self, schema_name):
        """
        Filter queryset by tenant schema name.

        For django-tenants compatibility where tenant is identified by schema.

        Args:
            schema_name: Tenant schema name string

        Returns:
            QuerySet: Filtered to tenant
        """
        filter_kwargs = {f'{self.tenant_field}__schema_name': schema_name}
        return self.get_queryset().filter(**filter_kwargs)


class TenantAwareJobPostingManager(TenantAwareManager):
    """
    Tenant-aware manager for JobPosting model.

    Combines tenant isolation with JobPostingQuerySet optimizations.
    Ideal for enterprise multi-tenant deployments where each tenant
    manages their own job postings.
    """

    # JobPosting may be linked to tenant via hiring_manager or created_by user
    # Adjust based on actual tenant relationship in your models
    tenant_field = 'tenant'

    def get_queryset(self):
        """Return JobPostingQuerySet for optimized queries."""
        return JobPostingQuerySet(self.model, using=self._db)

    # Convenience accessors that combine tenant filtering with common queries

    def active_for_tenant(self, tenant):
        """Get active job postings for a tenant."""
        return self.for_tenant(tenant).active()

    def published_for_tenant(self, tenant):
        """Get published (public) job postings for a tenant."""
        return self.for_tenant(tenant).published()

    def with_stats_for_tenant(self, tenant):
        """Get job postings with applicant stats for a tenant."""
        return self.for_tenant(tenant).with_applicant_stats()

    # Public career page queries (no tenant filter - for public listings)

    def public_listings(self):
        """
        Get all publicly visible job listings across tenants.
        Used for public job boards/aggregated career pages.
        """
        return self.get_queryset().filter(
            status='open',
            published_on_career_page=True,
            is_internal_only=False
        )

    def featured_listings(self):
        """Get featured public job listings."""
        return self.public_listings().filter(is_featured=True)

    # Department/category operations

    def by_department_for_tenant(self, tenant, department_id):
        """Get jobs in a specific department for a tenant."""
        return self.for_tenant(tenant).by_department(department_id)

    # Search operations

    def search_for_tenant(self, tenant, query):
        """Full-text search within tenant's jobs."""
        return self.for_tenant(tenant).search(query)

    def search_public(self, query):
        """Full-text search across all public listings."""
        return self.public_listings().search(query)

    # Analytics helpers

    def get_posting_stats(self, tenant):
        """
        Get aggregated stats for a tenant's job postings.

        Returns dict with counts by status.
        """
        return self.for_tenant(tenant).aggregate(
            total=Count('id'),
            open=Count('id', filter=Q(status='open')),
            draft=Count('id', filter=Q(status='draft')),
            closed=Count('id', filter=Q(status='closed')),
            filled=Count('id', filter=Q(status='filled')),
        )


class TenantAwareCandidateManager(TenantAwareManager):
    """
    Tenant-aware manager for Candidate model.

    Provides tenant isolation for candidate pools. In multi-tenant
    ATS, candidates may be shared or tenant-specific depending on
    configuration.
    """

    # Candidates may link to tenant via applications or directly
    # Adjust based on your tenant relationship
    tenant_field = 'tenant'

    def get_queryset(self):
        """Return CandidateQuerySet for optimized queries."""
        return CandidateQuerySet(self.model, using=self._db)

    def for_tenant(self, tenant):
        """
        Get candidates associated with a tenant.

        For shared candidate pools, may need to filter by applications.
        """
        return self.get_queryset().filter(
            applications__job__tenant=tenant
        ).distinct()

    def search_for_tenant(self, tenant, query):
        """Search candidates within tenant context."""
        return self.for_tenant(tenant).searchable(query)

    def by_skills_for_tenant(self, tenant, skills, match_all=False):
        """Find candidates with specific skills for a tenant."""
        return self.for_tenant(tenant).by_skills(skills, match_all)

    def active_talent_pool(self, tenant):
        """Get active candidate pool for a tenant."""
        return self.for_tenant(tenant).active().with_resume()

    def referred_candidates(self, tenant):
        """Get employee-referred candidates for a tenant."""
        return self.for_tenant(tenant).referred_by_employee()

    # Source tracking

    def by_source_for_tenant(self, tenant, source):
        """Get candidates from a specific source for a tenant."""
        return self.for_tenant(tenant).by_source(source)

    def get_source_breakdown(self, tenant):
        """
        Get candidate count by source for a tenant.

        Returns dict with source counts.
        """
        return self.for_tenant(tenant).values('source').annotate(
            count=Count('id')
        ).order_by('-count')


class TenantAwareApplicationManager(TenantAwareManager):
    """
    Tenant-aware manager for Application model.

    Provides tenant-scoped application management with pipeline
    stage filtering and workflow operations.
    """

    # Applications link to tenant via job posting
    tenant_field = 'job__tenant'

    def get_queryset(self):
        """Return ApplicationQuerySet for optimized queries."""
        return ApplicationQuerySet(self.model, using=self._db)

    def for_tenant(self, tenant):
        """Get applications for jobs owned by tenant."""
        if hasattr(tenant, 'id'):
            return self.get_queryset().filter(job__tenant_id=tenant.id)
        return self.get_queryset().filter(job__tenant_id=tenant)

    def for_job(self, job):
        """
        Get all applications for a specific job.

        Args:
            job: JobPosting instance or ID

        Returns:
            QuerySet: Applications for the job
        """
        return self.get_queryset().by_job(job)

    def pending_for_tenant(self, tenant):
        """Get applications pending review for a tenant."""
        return self.for_tenant(tenant).pending_review()

    def active_for_tenant(self, tenant):
        """Get active (in-progress) applications for a tenant."""
        return self.for_tenant(tenant).active()

    def by_stage_for_tenant(self, tenant, stage):
        """Get applications in a specific stage for a tenant."""
        return self.for_tenant(tenant).by_pipeline_stage(stage)

    def assigned_to_user(self, tenant, user):
        """Get applications assigned to a specific user within tenant."""
        return self.for_tenant(tenant).assigned_to(user)

    def stale_for_tenant(self, tenant, days=14):
        """Get stale applications needing attention."""
        return self.for_tenant(tenant).stale(days)

    def high_potential(self, tenant, min_score=80):
        """Get high-potential applications for a tenant."""
        return self.for_tenant(tenant).high_match_score(min_score)

    # Pipeline analytics

    def get_pipeline_distribution(self, tenant, job=None):
        """
        Get application count by pipeline stage.

        Args:
            tenant: Tenant to filter by
            job: Optional specific job to filter

        Returns:
            QuerySet: Stages with application counts
        """
        qs = self.for_tenant(tenant)
        if job:
            qs = qs.by_job(job)

        return qs.values(
            'current_stage__name',
            'current_stage__stage_type',
            'current_stage__color'
        ).annotate(
            count=Count('id')
        ).order_by('current_stage__order')

    def get_status_breakdown(self, tenant):
        """Get application count by status for a tenant."""
        return self.for_tenant(tenant).values('status').annotate(
            count=Count('id')
        ).order_by('-count')


class TenantAwareInterviewManager(TenantAwareManager):
    """
    Tenant-aware manager for Interview model.

    Manages interview scheduling and feedback collection
    with tenant isolation.
    """

    # Interviews link to tenant via application -> job
    tenant_field = 'application__job__tenant'

    def get_queryset(self):
        """Return InterviewQuerySet for optimized queries."""
        return InterviewQuerySet(self.model, using=self._db)

    def for_tenant(self, tenant):
        """Get interviews for tenant."""
        if hasattr(tenant, 'id'):
            return self.get_queryset().filter(
                application__job__tenant_id=tenant.id
            )
        return self.get_queryset().filter(
            application__job__tenant_id=tenant
        )

    def upcoming_for_tenant(self, tenant, days=7):
        """Get upcoming interviews for a tenant."""
        return self.for_tenant(tenant).upcoming(days)

    def today_for_tenant(self, tenant):
        """Get today's interviews for a tenant."""
        return self.for_tenant(tenant).today()

    def needs_feedback_for_tenant(self, tenant):
        """Get interviews needing feedback for a tenant."""
        return self.for_tenant(tenant).needs_feedback()

    def for_interviewer(self, user):
        """
        Get interviews where user is an interviewer.

        Not tenant-filtered - shows user's interviews across tenants.
        """
        return self.get_queryset().by_interviewer(user)

    def for_interviewer_in_tenant(self, tenant, user):
        """Get user's interviews within a specific tenant."""
        return self.for_tenant(tenant).by_interviewer(user)

    def for_organizer(self, user):
        """Get interviews organized by user."""
        return self.get_queryset().by_organizer(user)

    # Notifications

    def pending_notifications(self, tenant):
        """Get interviews pending notification."""
        return self.for_tenant(tenant).not_notified().scheduled()

    # Analytics

    def get_interview_stats(self, tenant):
        """
        Get interview statistics for a tenant.

        Returns dict with counts by status.
        """
        return self.for_tenant(tenant).aggregate(
            total=Count('id'),
            scheduled=Count('id', filter=Q(status='scheduled')),
            completed=Count('id', filter=Q(status='completed')),
            cancelled=Count('id', filter=Q(status='cancelled')),
            no_shows=Count('id', filter=Q(status='no_show')),
        )


class TenantAwarePipelineManager(TenantAwareManager):
    """
    Tenant-aware manager for Pipeline model.

    Manages recruitment pipelines (Kanban boards) with tenant isolation.
    """

    tenant_field = 'tenant'

    def for_tenant(self, tenant):
        """Get pipelines for a tenant."""
        if hasattr(tenant, 'id'):
            return self.get_queryset().filter(tenant_id=tenant.id)
        return self.get_queryset().filter(tenant_id=tenant)

    def active_for_tenant(self, tenant):
        """Get active pipelines for a tenant."""
        return self.for_tenant(tenant).filter(is_active=True)

    def get_default_pipeline(self, tenant):
        """
        Get the default pipeline for a tenant.

        Returns:
            Pipeline instance or None
        """
        return self.for_tenant(tenant).filter(is_default=True).first()

    def get_or_create_default(self, tenant, created_by=None):
        """
        Get or create a default pipeline for a tenant.

        Args:
            tenant: Tenant instance
            created_by: User creating the pipeline

        Returns:
            (Pipeline, created) tuple
        """
        pipeline = self.get_default_pipeline(tenant)
        if pipeline:
            return pipeline, False

        # Create default pipeline with standard stages
        from ats.models import Pipeline, PipelineStage

        pipeline = Pipeline.objects.create(
            tenant=tenant,
            name='Default Pipeline',
            is_default=True,
            created_by=created_by
        )

        # Create standard stages
        stages = [
            ('New', 'new', '#6B7280', 0),
            ('Screening', 'screening', '#3B82F6', 1),
            ('Interview', 'interview', '#8B5CF6', 2),
            ('Assessment', 'assessment', '#F59E0B', 3),
            ('Offer', 'offer', '#10B981', 4),
            ('Hired', 'hired', '#059669', 5),
            ('Rejected', 'rejected', '#EF4444', 6),
        ]

        for name, stage_type, color, order in stages:
            PipelineStage.objects.create(
                pipeline=pipeline,
                name=name,
                stage_type=stage_type,
                color=color,
                order=order
            )

        return pipeline, True


class TenantAwarePipelineStageManager(TenantAwareManager):
    """
    Tenant-aware manager for PipelineStage model.
    """

    tenant_field = 'pipeline__tenant'

    def get_queryset(self):
        """Return PipelineStageQuerySet for optimized queries."""
        return PipelineStageQuerySet(self.model, using=self._db)

    def for_tenant(self, tenant):
        """Get pipeline stages for a tenant."""
        if hasattr(tenant, 'id'):
            return self.get_queryset().filter(pipeline__tenant_id=tenant.id)
        return self.get_queryset().filter(pipeline__tenant_id=tenant)

    def for_pipeline(self, pipeline):
        """Get stages for a specific pipeline."""
        return self.get_queryset().by_pipeline(pipeline).ordered()

    def active_for_pipeline(self, pipeline):
        """Get active stages for a pipeline in order."""
        return self.for_pipeline(pipeline).active()


class TenantAwareOfferManager(TenantAwareManager):
    """
    Tenant-aware manager for Offer model.

    Manages job offers with tenant isolation.
    """

    tenant_field = 'application__job__tenant'

    def get_queryset(self):
        """Return OfferQuerySet for optimized queries."""
        return OfferQuerySet(self.model, using=self._db)

    def for_tenant(self, tenant):
        """Get offers for a tenant."""
        if hasattr(tenant, 'id'):
            return self.get_queryset().filter(
                application__job__tenant_id=tenant.id
            )
        return self.get_queryset().filter(
            application__job__tenant_id=tenant
        )

    def pending_for_tenant(self, tenant):
        """Get offers awaiting response for a tenant."""
        return self.for_tenant(tenant).pending()

    def pending_approval_for_tenant(self, tenant):
        """Get offers needing approval for a tenant."""
        return self.for_tenant(tenant).pending_approval()

    def expiring_soon_for_tenant(self, tenant, days=3):
        """Get offers expiring soon for a tenant."""
        return self.for_tenant(tenant).expiring_soon(days)

    def get_offer_stats(self, tenant):
        """
        Get offer statistics for a tenant.

        Returns dict with counts and rates.
        """
        qs = self.for_tenant(tenant)
        total = qs.count()
        accepted = qs.filter(status='accepted').count()
        declined = qs.filter(status='declined').count()

        return {
            'total': total,
            'pending': qs.filter(status='sent').count(),
            'accepted': accepted,
            'declined': declined,
            'acceptance_rate': (accepted / total * 100) if total > 0 else 0,
        }


# For circusale-level isolation (division within tenant)
class CircusaleAwareManager(TenantAwareManager):
    """
    Manager providing circusale (division) level isolation.

    Used for resources that belong to specific business units
    within a tenant/enterprise.
    """

    circusale_field = 'circusale'

    def for_circusale(self, circusale):
        """
        Filter queryset for a specific circusale.

        Args:
            circusale: Circusale instance or ID

        Returns:
            QuerySet: Filtered to circusale
        """
        if hasattr(circusale, 'id'):
            circusale_id = circusale.id
        else:
            circusale_id = circusale

        filter_kwargs = {f'{self.circusale_field}_id': circusale_id}
        return self.get_queryset().filter(**filter_kwargs)

    def for_user_circusales(self, user):
        """
        Filter to circusales the user has access to.

        Args:
            user: User instance with circusale relationship

        Returns:
            QuerySet: Filtered to user's accessible circusales
        """
        # Assumes user has tenant_user with circusale
        if hasattr(user, 'tenantuser') and hasattr(user.tenantuser, 'circusale'):
            return self.for_circusale(user.tenantuser.circusale)
        return self.get_queryset().none()
