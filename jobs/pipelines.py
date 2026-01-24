"""
ATS Pipeline Management - Advanced Pipeline Features

This module provides enhanced pipeline management functionality:
- PipelineTemplate: Predefined pipeline templates for different hiring needs
- SLA tracking per stage with escalation
- Pipeline analytics and bottleneck detection
- Pipeline comparison for A/B testing

All classes are tenant-aware and follow Zumodra's multi-tenant architecture.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from django.db import models, transaction
from django.db.models import Avg, Count, F, Q, Sum
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from core.db.models import TenantAwareModel
from core.db.managers import TenantAwareManager

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class PipelineTemplateType(str, Enum):
    """Predefined pipeline template types."""
    TECHNICAL = 'technical'
    EXECUTIVE = 'executive'
    INTERN = 'intern'
    CONTRACTOR = 'contractor'
    GENERAL = 'general'
    HIGH_VOLUME = 'high_volume'


class SLAStatus(str, Enum):
    """SLA status indicators."""
    ON_TRACK = 'on_track'
    WARNING = 'warning'
    CRITICAL = 'critical'
    BREACHED = 'breached'


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class StageTemplate:
    """Template for a pipeline stage."""
    name: str
    stage_type: str
    description: str = ''
    order: int = 0
    color: str = '#6B7280'
    target_days: int = 3
    warning_threshold_days: int = 2
    critical_threshold_days: int = 4
    auto_reject_after_days: int = 0
    send_email_on_enter: bool = False


@dataclass
class SLAMetrics:
    """SLA metrics for a stage or application."""
    status: SLAStatus
    days_in_stage: int
    target_days: int
    warning_threshold: int
    critical_threshold: int
    time_remaining: Optional[timedelta] = None
    is_breached: bool = False
    breach_date: Optional[datetime] = None


@dataclass
class StageAnalytics:
    """Analytics for a single pipeline stage."""
    stage_id: str
    stage_name: str
    stage_type: str
    application_count: int
    average_time_days: float
    median_time_days: float
    conversion_rate: float
    drop_off_rate: float
    sla_compliance_rate: float
    bottleneck_score: float


@dataclass
class PipelineAnalytics:
    """Comprehensive analytics for a pipeline."""
    pipeline_id: str
    pipeline_name: str
    total_applications: int
    active_applications: int
    hired_count: int
    rejected_count: int
    withdrawn_count: int
    average_time_to_hire_days: Optional[float]
    overall_conversion_rate: float
    stage_analytics: List[StageAnalytics]
    bottleneck_stages: List[str]
    sla_compliance_rate: float


@dataclass
class PipelineComparison:
    """Comparison results between two pipelines."""
    pipeline_a_id: str
    pipeline_a_name: str
    pipeline_b_id: str
    pipeline_b_name: str
    metrics_comparison: Dict[str, Dict[str, Any]]
    winner: Optional[str]
    confidence_level: float
    recommendations: List[str]


# =============================================================================
# PIPELINE TEMPLATE MODEL
# =============================================================================

class PipelineTemplate(TenantAwareModel):
    """
    Predefined pipeline templates for quick setup.

    Provides industry-standard hiring workflows that can be
    customized per tenant.
    """

    name = models.CharField(max_length=100)
    template_type = models.CharField(
        max_length=20,
        choices=[(t.value, t.name.replace('_', ' ').title()) for t in PipelineTemplateType],
        default=PipelineTemplateType.GENERAL.value
    )
    description = models.TextField(blank=True)
    is_system_template = models.BooleanField(
        default=False,
        help_text=_('System templates are available to all tenants')
    )
    stages_config = models.JSONField(
        default=list,
        help_text=_('JSON configuration for pipeline stages')
    )
    recommended_for = models.JSONField(
        default=list,
        help_text=_('Job types this template is recommended for')
    )
    average_time_to_hire_days = models.PositiveIntegerField(
        default=30,
        help_text=_('Expected average days to complete this pipeline')
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _('Pipeline Template')
        verbose_name_plural = _('Pipeline Templates')
        ordering = ['template_type', 'name']
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'name'],
                name='ats_pipelinetemplate_unique_tenant_name'
            )
        ]

    def __str__(self):
        return f"{self.name} ({self.get_template_type_display()})"

    def get_stages(self) -> List[StageTemplate]:
        """Return stage templates from config."""
        stages = []
        for idx, config in enumerate(self.stages_config):
            stages.append(StageTemplate(
                name=config.get('name', f'Stage {idx + 1}'),
                stage_type=config.get('stage_type', 'screening'),
                description=config.get('description', ''),
                order=config.get('order', idx),
                color=config.get('color', '#6B7280'),
                target_days=config.get('target_days', 3),
                warning_threshold_days=config.get('warning_threshold_days', 2),
                critical_threshold_days=config.get('critical_threshold_days', 4),
                auto_reject_after_days=config.get('auto_reject_after_days', 0),
                send_email_on_enter=config.get('send_email_on_enter', False),
            ))
        return stages


# =============================================================================
# STAGE SLA CONFIGURATION MODEL
# =============================================================================

class StageSLAConfig(models.Model):
    """
    SLA configuration for a pipeline stage.

    Tracks target times and thresholds for stage progression,
    enabling escalation when SLAs are breached.

    Tenant isolation is achieved through the parent PipelineStage model.
    Access tenant via self.stage.pipeline.tenant.
    """

    stage = models.OneToOneField(
        'jobs.PipelineStage',
        on_delete=models.CASCADE,
        related_name='sla_config'
    )

    @property
    def tenant(self):
        """Access tenant through parent stage's pipeline."""
        return self.stage.pipeline.tenant if self.stage and self.stage.pipeline else None

    def validate_tenant_access(self, request_tenant):
        """
        Validate that the requesting tenant has access to this SLA config.

        Args:
            request_tenant: The tenant making the request

        Returns:
            True if access is valid, False otherwise
        """
        return self.tenant == request_tenant
    target_days = models.PositiveIntegerField(
        default=3,
        help_text=_('Target number of days to complete this stage')
    )
    warning_threshold_days = models.PositiveIntegerField(
        default=2,
        help_text=_('Days after which a warning is triggered')
    )
    critical_threshold_days = models.PositiveIntegerField(
        default=4,
        help_text=_('Days after which status becomes critical')
    )
    auto_escalate = models.BooleanField(
        default=True,
        help_text=_('Automatically escalate when SLA is breached')
    )
    escalation_email = models.EmailField(
        blank=True,
        help_text=_('Email to notify on escalation')
    )
    escalation_user = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='sla_escalations',
        help_text=_('User to notify on escalation')
    )

    class Meta:
        verbose_name = _('Stage SLA Configuration')
        verbose_name_plural = _('Stage SLA Configurations')

    def __str__(self):
        return f"SLA for {self.stage.name}"

    def get_sla_status(self, days_in_stage: int) -> SLAStatus:
        """
        Determine SLA status based on days in stage.

        Args:
            days_in_stage: Number of days application has been in stage

        Returns:
            SLAStatus indicating current status
        """
        if days_in_stage <= self.warning_threshold_days:
            return SLAStatus.ON_TRACK
        elif days_in_stage <= self.target_days:
            return SLAStatus.WARNING
        elif days_in_stage <= self.critical_threshold_days:
            return SLAStatus.CRITICAL
        else:
            return SLAStatus.BREACHED


# =============================================================================
# SLA ESCALATION MODEL
# =============================================================================

class SLAEscalation(TenantAwareModel):
    """
    Record of SLA escalations for tracking and audit.
    """

    application = models.ForeignKey(
        'jobs.Application',
        on_delete=models.CASCADE,
        related_name='sla_escalations'
    )
    stage = models.ForeignKey(
        'jobs.PipelineStage',
        on_delete=models.CASCADE,
        related_name='escalations'
    )
    escalation_type = models.CharField(
        max_length=20,
        choices=[
            ('warning', _('Warning')),
            ('critical', _('Critical')),
            ('breached', _('Breached')),
        ]
    )
    escalated_to = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='received_escalations'
    )
    escalated_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resolved_escalations'
    )
    resolution_notes = models.TextField(blank=True)
    days_in_stage_at_escalation = models.PositiveIntegerField(default=0)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _('SLA Escalation')
        verbose_name_plural = _('SLA Escalations')
        ordering = ['-escalated_at']

    def __str__(self):
        return f"Escalation for {self.application} at {self.stage.name}"

    @property
    def is_resolved(self) -> bool:
        """Check if escalation has been resolved."""
        return self.resolved_at is not None

    def resolve(self, user, notes: str = ''):
        """Mark escalation as resolved."""
        self.resolved_at = timezone.now()
        self.resolved_by = user
        self.resolution_notes = notes
        self.save(update_fields=['resolved_at', 'resolved_by', 'resolution_notes'])


# =============================================================================
# PIPELINE TEMPLATE SERVICE
# =============================================================================

class PipelineTemplateService:
    """
    Service for managing pipeline templates.
    """

    # Predefined template configurations
    TEMPLATE_CONFIGS = {
        PipelineTemplateType.TECHNICAL: {
            'name': 'Technical Hiring',
            'description': 'Standard pipeline for software engineering roles',
            'average_time_to_hire_days': 35,
            'recommended_for': ['software_engineer', 'developer', 'data_scientist'],
            'stages': [
                {'name': 'Applied', 'stage_type': 'new', 'target_days': 2, 'color': '#6366F1'},
                {'name': 'Resume Screening', 'stage_type': 'screening', 'target_days': 3, 'color': '#8B5CF6'},
                {'name': 'Phone Screen', 'stage_type': 'screening', 'target_days': 5, 'color': '#A855F7'},
                {'name': 'Technical Assessment', 'stage_type': 'assessment', 'target_days': 7, 'color': '#D946EF'},
                {'name': 'Technical Interview', 'stage_type': 'interview', 'target_days': 5, 'color': '#EC4899'},
                {'name': 'Culture Fit', 'stage_type': 'interview', 'target_days': 3, 'color': '#F43F5E'},
                {'name': 'Reference Check', 'stage_type': 'reference', 'target_days': 5, 'color': '#F97316'},
                {'name': 'Offer', 'stage_type': 'offer', 'target_days': 5, 'color': '#22C55E'},
                {'name': 'Hired', 'stage_type': 'hired', 'target_days': 0, 'color': '#10B981'},
            ]
        },
        PipelineTemplateType.EXECUTIVE: {
            'name': 'Executive Search',
            'description': 'Extended pipeline for senior leadership roles',
            'average_time_to_hire_days': 60,
            'recommended_for': ['director', 'vp', 'c_level', 'executive'],
            'stages': [
                {'name': 'Sourced', 'stage_type': 'new', 'target_days': 5, 'color': '#6366F1'},
                {'name': 'Initial Outreach', 'stage_type': 'screening', 'target_days': 7, 'color': '#8B5CF6'},
                {'name': 'Executive Screening', 'stage_type': 'screening', 'target_days': 7, 'color': '#A855F7'},
                {'name': 'Leadership Assessment', 'stage_type': 'assessment', 'target_days': 10, 'color': '#D946EF'},
                {'name': 'Panel Interview', 'stage_type': 'interview', 'target_days': 7, 'color': '#EC4899'},
                {'name': 'Board Interview', 'stage_type': 'interview', 'target_days': 7, 'color': '#F43F5E'},
                {'name': 'Background Check', 'stage_type': 'reference', 'target_days': 10, 'color': '#F97316'},
                {'name': 'Compensation Negotiation', 'stage_type': 'offer', 'target_days': 10, 'color': '#EAB308'},
                {'name': 'Offer Extended', 'stage_type': 'offer', 'target_days': 7, 'color': '#22C55E'},
                {'name': 'Hired', 'stage_type': 'hired', 'target_days': 0, 'color': '#10B981'},
            ]
        },
        PipelineTemplateType.INTERN: {
            'name': 'Intern/Entry-Level',
            'description': 'Streamlined pipeline for internships and entry-level positions',
            'average_time_to_hire_days': 14,
            'recommended_for': ['intern', 'entry_level', 'graduate'],
            'stages': [
                {'name': 'Applied', 'stage_type': 'new', 'target_days': 1, 'color': '#6366F1'},
                {'name': 'Resume Review', 'stage_type': 'screening', 'target_days': 2, 'color': '#8B5CF6'},
                {'name': 'Video Screen', 'stage_type': 'screening', 'target_days': 3, 'color': '#A855F7'},
                {'name': 'Assessment', 'stage_type': 'assessment', 'target_days': 3, 'color': '#D946EF'},
                {'name': 'Final Interview', 'stage_type': 'interview', 'target_days': 3, 'color': '#EC4899'},
                {'name': 'Offer', 'stage_type': 'offer', 'target_days': 2, 'color': '#22C55E'},
                {'name': 'Hired', 'stage_type': 'hired', 'target_days': 0, 'color': '#10B981'},
            ]
        },
        PipelineTemplateType.CONTRACTOR: {
            'name': 'Contractor/Freelance',
            'description': 'Fast-track pipeline for contract positions',
            'average_time_to_hire_days': 7,
            'recommended_for': ['contractor', 'freelance', 'consultant', 'temp'],
            'stages': [
                {'name': 'Applied', 'stage_type': 'new', 'target_days': 1, 'color': '#6366F1'},
                {'name': 'Skills Review', 'stage_type': 'screening', 'target_days': 1, 'color': '#8B5CF6'},
                {'name': 'Technical Check', 'stage_type': 'assessment', 'target_days': 2, 'color': '#D946EF'},
                {'name': 'Client Interview', 'stage_type': 'interview', 'target_days': 2, 'color': '#EC4899'},
                {'name': 'Contract Offer', 'stage_type': 'offer', 'target_days': 1, 'color': '#22C55E'},
                {'name': 'Engaged', 'stage_type': 'hired', 'target_days': 0, 'color': '#10B981'},
            ]
        },
        PipelineTemplateType.HIGH_VOLUME: {
            'name': 'High-Volume Hiring',
            'description': 'Automated pipeline for mass hiring campaigns',
            'average_time_to_hire_days': 10,
            'recommended_for': ['customer_service', 'retail', 'warehouse', 'seasonal'],
            'stages': [
                {'name': 'Applied', 'stage_type': 'new', 'target_days': 1, 'color': '#6366F1'},
                {'name': 'Auto-Screen', 'stage_type': 'screening', 'target_days': 1, 'color': '#8B5CF6'},
                {'name': 'Group Interview', 'stage_type': 'interview', 'target_days': 3, 'color': '#EC4899'},
                {'name': 'Background Check', 'stage_type': 'reference', 'target_days': 3, 'color': '#F97316'},
                {'name': 'Offer', 'stage_type': 'offer', 'target_days': 2, 'color': '#22C55E'},
                {'name': 'Hired', 'stage_type': 'hired', 'target_days': 0, 'color': '#10B981'},
            ]
        },
    }

    @classmethod
    def get_template_config(cls, template_type: PipelineTemplateType) -> Dict[str, Any]:
        """
        Get the configuration for a template type.

        Args:
            template_type: The type of template

        Returns:
            Configuration dictionary for the template
        """
        return cls.TEMPLATE_CONFIGS.get(
            template_type,
            cls.TEMPLATE_CONFIGS[PipelineTemplateType.TECHNICAL]
        )

    @classmethod
    @transaction.atomic
    def create_pipeline_from_template(
        cls,
        tenant,
        template_type: PipelineTemplateType,
        name: str = None,
        user=None
    ):
        """
        Create a new pipeline from a template.

        Args:
            tenant: The tenant to create the pipeline for
            template_type: Type of template to use
            name: Optional custom name for the pipeline
            user: User creating the pipeline

        Returns:
            Created Pipeline instance
        """
        from jobs.models import Pipeline, PipelineStage

        config = cls.get_template_config(template_type)
        pipeline_name = name or config['name']

        # Create the pipeline
        pipeline = Pipeline.objects.create(
            tenant=tenant,
            name=pipeline_name,
            description=config['description'],
            is_default=False,
            created_by=user,
        )

        # Create stages with SLA configs
        for idx, stage_config in enumerate(config['stages']):
            stage = PipelineStage.objects.create(
                pipeline=pipeline,
                name=stage_config['name'],
                stage_type=stage_config['stage_type'],
                color=stage_config.get('color', '#6B7280'),
                order=idx,
                is_active=True,
                auto_reject_after_days=stage_config.get('auto_reject_after_days', 0),
                send_email_on_enter=stage_config.get('send_email_on_enter', False),
            )

            # Create SLA config for the stage
            StageSLAConfig.objects.create(
                stage=stage,
                target_days=stage_config.get('target_days', 3),
                warning_threshold_days=stage_config.get('warning_threshold_days',
                    max(1, stage_config.get('target_days', 3) - 1)),
                critical_threshold_days=stage_config.get('critical_threshold_days',
                    stage_config.get('target_days', 3) + 2),
                auto_escalate=True,
            )

        logger.info(
            f"Created pipeline '{pipeline_name}' from template {template_type.value} "
            f"for tenant {tenant.id}"
        )

        return pipeline

    @classmethod
    def get_recommended_template(cls, job_type: str) -> PipelineTemplateType:
        """
        Get recommended template type based on job type.

        Args:
            job_type: Type of job (e.g., 'software_engineer', 'intern')

        Returns:
            Recommended PipelineTemplateType
        """
        job_type_lower = job_type.lower()

        for template_type, config in cls.TEMPLATE_CONFIGS.items():
            if any(rec in job_type_lower for rec in config['recommended_for']):
                return template_type

        return PipelineTemplateType.GENERAL


# =============================================================================
# SLA TRACKING SERVICE
# =============================================================================

class SLATrackingService:
    """
    Service for tracking and managing SLAs across pipelines.
    """

    @staticmethod
    def get_application_sla_status(application) -> Optional[SLAMetrics]:
        """
        Get SLA status for an application's current stage.

        Args:
            application: The application to check

        Returns:
            SLAMetrics or None if no SLA config exists
        """
        if not application.current_stage:
            return None

        try:
            sla_config = application.current_stage.sla_config
        except StageSLAConfig.DoesNotExist:
            return None

        # Calculate days in current stage
        if application.last_stage_change_at:
            days_in_stage = (timezone.now() - application.last_stage_change_at).days
        else:
            days_in_stage = (timezone.now() - application.applied_at).days

        status = sla_config.get_sla_status(days_in_stage)
        is_breached = status == SLAStatus.BREACHED

        # Calculate time remaining
        time_remaining = None
        if not is_breached:
            remaining_days = sla_config.target_days - days_in_stage
            if remaining_days > 0:
                time_remaining = timedelta(days=remaining_days)

        return SLAMetrics(
            status=status,
            days_in_stage=days_in_stage,
            target_days=sla_config.target_days,
            warning_threshold=sla_config.warning_threshold_days,
            critical_threshold=sla_config.critical_threshold_days,
            time_remaining=time_remaining,
            is_breached=is_breached,
            breach_date=timezone.now() if is_breached else None,
        )

    @staticmethod
    def get_pipeline_sla_summary(pipeline, tenant) -> Dict[str, Any]:
        """
        Get SLA summary for all applications in a pipeline.

        Args:
            pipeline: The pipeline to analyze
            tenant: The tenant context

        Returns:
            Dictionary with SLA summary statistics
        """
        from jobs.models import Application

        applications = Application.objects.filter(
            tenant=tenant,
            job__pipeline=pipeline,
            status__in=Application.ACTIVE_STATUSES
        ).select_related('current_stage')

        summary = {
            'total_active': applications.count(),
            'on_track': 0,
            'warning': 0,
            'critical': 0,
            'breached': 0,
            'no_sla': 0,
            'compliance_rate': 0.0,
            'at_risk': [],
        }

        for app in applications:
            sla_status = SLATrackingService.get_application_sla_status(app)

            if not sla_status:
                summary['no_sla'] += 1
                continue

            status_key = sla_status.status.value
            summary[status_key] += 1

            # Track at-risk applications
            if sla_status.status in [SLAStatus.CRITICAL, SLAStatus.BREACHED]:
                summary['at_risk'].append({
                    'application_id': str(app.id),
                    'candidate_name': app.candidate.full_name,
                    'stage': app.current_stage.name if app.current_stage else 'Unknown',
                    'days_in_stage': sla_status.days_in_stage,
                    'status': sla_status.status.value,
                })

        # Calculate compliance rate
        total_with_sla = summary['total_active'] - summary['no_sla']
        if total_with_sla > 0:
            compliant = summary['on_track'] + summary['warning']
            summary['compliance_rate'] = round((compliant / total_with_sla) * 100, 2)

        return summary

    @staticmethod
    @transaction.atomic
    def check_and_escalate(tenant, user=None) -> List[SLAEscalation]:
        """
        Check all active applications for SLA breaches and create escalations.

        Args:
            tenant: The tenant to check
            user: Optional user performing the action (for permission checks)

        Returns:
            List of newly created escalations

        Raises:
            PermissionError: If user lacks required permissions
        """
        from jobs.models import Application

        # Permission check: require user with appropriate role
        if user is not None:
            if not hasattr(user, 'has_perm') or not (
                user.has_perm('jobs.manage_sla') or
                user.has_perm('jobs.view_all_applications') or
                getattr(user, 'is_superuser', False)
            ):
                logger.warning(
                    f"User {user.id} attempted SLA escalation check without permission"
                )
                raise PermissionError("User lacks permission to perform SLA escalation checks")

        applications = Application.objects.filter(
            tenant=tenant,
            status__in=Application.ACTIVE_STATUSES
        ).select_related('current_stage', 'current_stage__sla_config')

        new_escalations = []

        for app in applications:
            if not app.current_stage:
                continue

            try:
                sla_config = app.current_stage.sla_config
            except StageSLAConfig.DoesNotExist:
                continue

            if not sla_config.auto_escalate:
                continue

            sla_status = SLATrackingService.get_application_sla_status(app)
            if not sla_status:
                continue

            # Determine escalation type
            escalation_type = None
            if sla_status.status == SLAStatus.BREACHED:
                escalation_type = 'breached'
            elif sla_status.status == SLAStatus.CRITICAL:
                escalation_type = 'critical'
            elif sla_status.status == SLAStatus.WARNING:
                escalation_type = 'warning'

            if not escalation_type:
                continue

            # Check if escalation already exists for this status
            existing = SLAEscalation.objects.filter(
                application=app,
                stage=app.current_stage,
                escalation_type=escalation_type,
                resolved_at__isnull=True
            ).exists()

            if existing:
                continue

            # Create new escalation
            escalation = SLAEscalation.objects.create(
                tenant=tenant,
                application=app,
                stage=app.current_stage,
                escalation_type=escalation_type,
                escalated_to=sla_config.escalation_user,
                days_in_stage_at_escalation=sla_status.days_in_stage,
            )
            new_escalations.append(escalation)

            logger.info(
                f"SLA escalation created: {escalation_type} for application "
                f"{app.id} at stage {app.current_stage.name}"
            )

        return new_escalations


# =============================================================================
# PIPELINE ANALYTICS SERVICE
# =============================================================================

class PipelineAnalyticsService:
    """
    Service for pipeline analytics and insights.
    """

    @staticmethod
    def get_stage_analytics(stage, tenant, date_from=None, date_to=None) -> StageAnalytics:
        """
        Get detailed analytics for a single stage.

        Args:
            stage: The pipeline stage to analyze
            tenant: Tenant context
            date_from: Optional start date filter
            date_to: Optional end date filter

        Returns:
            StageAnalytics with metrics
        """
        from jobs.models import Application, ApplicationActivity

        # Base query for applications that reached this stage
        activities = ApplicationActivity.objects.filter(
            application__tenant=tenant,
            activity_type='stage_change',
            new_value=stage.name
        )

        if date_from:
            activities = activities.filter(created_at__gte=date_from)
        if date_to:
            activities = activities.filter(created_at__lte=date_to)

        reached_count = activities.values('application').distinct().count()

        # Current applications in stage
        current_apps = Application.objects.filter(
            tenant=tenant,
            current_stage=stage
        )
        if date_from:
            current_apps = current_apps.filter(applied_at__gte=date_from)

        current_count = current_apps.count()

        # Calculate time in stage metrics
        time_data = []
        exit_activities = ApplicationActivity.objects.filter(
            application__tenant=tenant,
            activity_type='stage_change',
            old_value=stage.name
        )

        for exit_act in exit_activities:
            entry = ApplicationActivity.objects.filter(
                application=exit_act.application,
                activity_type='stage_change',
                new_value=stage.name,
                created_at__lt=exit_act.created_at
            ).order_by('-created_at').first()

            if entry:
                duration = (exit_act.created_at - entry.created_at).days
                time_data.append(duration)

        avg_time = sum(time_data) / len(time_data) if time_data else 0
        sorted_times = sorted(time_data)
        median_time = sorted_times[len(sorted_times) // 2] if sorted_times else 0

        # Conversion rate (moved to next stage vs total that entered)
        moved_forward = exit_activities.exclude(
            application__status__in=['rejected', 'withdrawn']
        ).count()
        conversion_rate = (moved_forward / reached_count * 100) if reached_count > 0 else 0

        # Drop-off rate
        dropped = exit_activities.filter(
            application__status__in=['rejected', 'withdrawn']
        ).count()
        drop_off_rate = (dropped / reached_count * 100) if reached_count > 0 else 0

        # SLA compliance
        sla_compliant = 0
        try:
            sla_config = stage.sla_config
            for duration in time_data:
                if duration <= sla_config.target_days:
                    sla_compliant += 1
            sla_compliance_rate = (sla_compliant / len(time_data) * 100) if time_data else 100
        except StageSLAConfig.DoesNotExist:
            sla_compliance_rate = 100

        # Bottleneck score (higher = worse)
        # Based on: high avg time + low conversion + high current count
        bottleneck_score = 0
        if avg_time > 5:
            bottleneck_score += min(avg_time / 10, 3)  # Max 3 points for time
        if conversion_rate < 50:
            bottleneck_score += (100 - conversion_rate) / 50  # Max 2 points
        if current_count > 10:
            bottleneck_score += min(current_count / 20, 2)  # Max 2 points

        return StageAnalytics(
            stage_id=str(stage.id),
            stage_name=stage.name,
            stage_type=stage.stage_type,
            application_count=current_count,
            average_time_days=round(avg_time, 2),
            median_time_days=median_time,
            conversion_rate=round(conversion_rate, 2),
            drop_off_rate=round(drop_off_rate, 2),
            sla_compliance_rate=round(sla_compliance_rate, 2),
            bottleneck_score=round(bottleneck_score, 2),
        )

    @staticmethod
    def get_pipeline_analytics(pipeline, tenant, date_from=None, date_to=None) -> PipelineAnalytics:
        """
        Get comprehensive analytics for a pipeline.

        Args:
            pipeline: The pipeline to analyze
            tenant: Tenant context
            date_from: Optional start date filter
            date_to: Optional end date filter

        Returns:
            PipelineAnalytics with full metrics
        """
        from jobs.models import Application

        # Base application query
        applications = Application.objects.filter(
            tenant=tenant,
            job__pipeline=pipeline
        )

        if date_from:
            applications = applications.filter(applied_at__gte=date_from)
        if date_to:
            applications = applications.filter(applied_at__lte=date_to)

        total = applications.count()
        active = applications.filter(status__in=Application.ACTIVE_STATUSES).count()
        hired = applications.filter(status='hired').count()
        rejected = applications.filter(status='rejected').count()
        withdrawn = applications.filter(status='withdrawn').count()

        # Average time to hire
        hired_apps = applications.filter(
            status='hired',
            hired_at__isnull=False
        )
        avg_time_to_hire = None
        if hired_apps.exists():
            total_days = sum(
                (app.hired_at - app.applied_at).days
                for app in hired_apps
            )
            avg_time_to_hire = total_days / hired_apps.count()

        # Overall conversion rate
        conversion_rate = (hired / total * 100) if total > 0 else 0

        # Stage analytics
        stage_analytics = []
        bottleneck_stages = []
        total_sla_compliance = 0
        stage_count = 0

        for stage in pipeline.stages.filter(is_active=True).order_by('order'):
            stage_stats = PipelineAnalyticsService.get_stage_analytics(
                stage, tenant, date_from, date_to
            )
            stage_analytics.append(stage_stats)

            # Track bottlenecks (score > 3)
            if stage_stats.bottleneck_score > 3:
                bottleneck_stages.append(stage_stats.stage_name)

            total_sla_compliance += stage_stats.sla_compliance_rate
            stage_count += 1

        avg_sla_compliance = total_sla_compliance / stage_count if stage_count > 0 else 100

        return PipelineAnalytics(
            pipeline_id=str(pipeline.id),
            pipeline_name=pipeline.name,
            total_applications=total,
            active_applications=active,
            hired_count=hired,
            rejected_count=rejected,
            withdrawn_count=withdrawn,
            average_time_to_hire_days=round(avg_time_to_hire, 2) if avg_time_to_hire else None,
            overall_conversion_rate=round(conversion_rate, 2),
            stage_analytics=stage_analytics,
            bottleneck_stages=bottleneck_stages,
            sla_compliance_rate=round(avg_sla_compliance, 2),
        )

    @staticmethod
    def compare_pipelines(
        pipeline_a,
        pipeline_b,
        tenant,
        date_from=None,
        date_to=None
    ) -> PipelineComparison:
        """
        Compare two pipelines for A/B testing.

        Args:
            pipeline_a: First pipeline
            pipeline_b: Second pipeline
            tenant: Tenant context
            date_from: Optional start date
            date_to: Optional end date

        Returns:
            PipelineComparison with detailed comparison
        """
        analytics_a = PipelineAnalyticsService.get_pipeline_analytics(
            pipeline_a, tenant, date_from, date_to
        )
        analytics_b = PipelineAnalyticsService.get_pipeline_analytics(
            pipeline_b, tenant, date_from, date_to
        )

        # Compare key metrics
        metrics = {
            'conversion_rate': {
                'pipeline_a': analytics_a.overall_conversion_rate,
                'pipeline_b': analytics_b.overall_conversion_rate,
                'difference': analytics_a.overall_conversion_rate - analytics_b.overall_conversion_rate,
                'better': 'a' if analytics_a.overall_conversion_rate > analytics_b.overall_conversion_rate else 'b'
            },
            'time_to_hire': {
                'pipeline_a': analytics_a.average_time_to_hire_days,
                'pipeline_b': analytics_b.average_time_to_hire_days,
                'difference': (analytics_a.average_time_to_hire_days or 0) - (analytics_b.average_time_to_hire_days or 0),
                'better': 'a' if (analytics_a.average_time_to_hire_days or 999) < (analytics_b.average_time_to_hire_days or 999) else 'b'
            },
            'sla_compliance': {
                'pipeline_a': analytics_a.sla_compliance_rate,
                'pipeline_b': analytics_b.sla_compliance_rate,
                'difference': analytics_a.sla_compliance_rate - analytics_b.sla_compliance_rate,
                'better': 'a' if analytics_a.sla_compliance_rate > analytics_b.sla_compliance_rate else 'b'
            },
            'bottleneck_count': {
                'pipeline_a': len(analytics_a.bottleneck_stages),
                'pipeline_b': len(analytics_b.bottleneck_stages),
                'difference': len(analytics_a.bottleneck_stages) - len(analytics_b.bottleneck_stages),
                'better': 'a' if len(analytics_a.bottleneck_stages) < len(analytics_b.bottleneck_stages) else 'b'
            }
        }

        # Determine overall winner
        a_wins = sum(1 for m in metrics.values() if m['better'] == 'a')
        b_wins = sum(1 for m in metrics.values() if m['better'] == 'b')

        if a_wins > b_wins:
            winner = 'a'
        elif b_wins > a_wins:
            winner = 'b'
        else:
            winner = None  # Tie

        # Calculate confidence level based on sample size
        total_samples = analytics_a.total_applications + analytics_b.total_applications
        if total_samples < 20:
            confidence = 0.3
        elif total_samples < 50:
            confidence = 0.5
        elif total_samples < 100:
            confidence = 0.7
        else:
            confidence = 0.9

        # Generate recommendations
        recommendations = []

        if metrics['conversion_rate']['difference'] > 5:
            recommendations.append(
                f"Pipeline {'A' if metrics['conversion_rate']['better'] == 'a' else 'B'} "
                f"has significantly better conversion rate"
            )

        if abs(metrics['time_to_hire']['difference'] or 0) > 7:
            faster = 'A' if metrics['time_to_hire']['better'] == 'a' else 'B'
            recommendations.append(
                f"Pipeline {faster} is significantly faster to hire"
            )

        if analytics_a.bottleneck_stages:
            recommendations.append(
                f"Pipeline A has bottlenecks at: {', '.join(analytics_a.bottleneck_stages)}"
            )
        if analytics_b.bottleneck_stages:
            recommendations.append(
                f"Pipeline B has bottlenecks at: {', '.join(analytics_b.bottleneck_stages)}"
            )

        return PipelineComparison(
            pipeline_a_id=str(pipeline_a.id),
            pipeline_a_name=pipeline_a.name,
            pipeline_b_id=str(pipeline_b.id),
            pipeline_b_name=pipeline_b.name,
            metrics_comparison=metrics,
            winner=winner,
            confidence_level=confidence,
            recommendations=recommendations,
        )
