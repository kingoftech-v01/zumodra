"""
ATS Models - Applicant Tracking System

This module implements the core ATS functionality:
- Job Postings with customizable fields
- Recruitment Pipelines (Kanban stages)
- Candidates and Applications
- Interview scheduling with slot management and templates
- Offer management with approval workflows
- Advanced filtering (30+ filters)

All models inherit from TenantAwareModel for multi-tenant isolation.
"""

import uuid
from decimal import Decimal
from datetime import timedelta
from typing import Optional, List, Dict, Any

from django.db import models, transaction
from django.db.models import F, Q
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.search import SearchVectorField
from django.contrib.gis.db import models as gis_models
from django.core.validators import MinValueValidator, MaxValueValidator, FileExtensionValidator, MaxLengthValidator
from django.core.exceptions import ValidationError
from django.template import Template, Context

from core.db.models import TenantAwareModel, TenantSoftDeleteModel
from core.db.managers import TenantAwareManager, TenantSoftDeleteManager
from core.db.exceptions import ConcurrentModificationError


# =============================================================================
# TENANT-AWARE MANAGERS FOR NON-TENANTAWARE MODELS
# =============================================================================

class ApplicationTenantManager(models.Manager):
    """
    Manager for models that access tenant through Application FK.

    Use this for Interview, Offer, InterviewFeedback models that
    have an 'application' foreign key linking to a TenantAwareModel.
    """

    def for_tenant(self, tenant):
        """
        Filter queryset to only include items for the specified tenant.

        Args:
            tenant: The tenant to filter by

        Returns:
            QuerySet filtered by tenant through application
        """
        return self.get_queryset().filter(application__tenant=tenant)

    def get_queryset_for_tenant(self, tenant):
        """Alias for for_tenant for consistency with TenantAwareManager."""
        return self.for_tenant(tenant)


class InterviewTenantManager(ApplicationTenantManager):
    """
    Tenant-aware manager for Interview model.

    Filters interviews through the application's tenant.
    """

    def upcoming(self, tenant=None):
        """Get upcoming interviews, optionally filtered by tenant."""
        from django.utils import timezone
        qs = self.get_queryset().filter(
            status__in=['scheduled', 'confirmed'],
            scheduled_start__gt=timezone.now()
        )
        if tenant:
            qs = qs.filter(application__tenant=tenant)
        return qs.order_by('scheduled_start')

    def for_interviewer(self, user, tenant=None):
        """Get interviews for a specific interviewer."""
        qs = self.get_queryset().filter(interviewers=user)
        if tenant:
            qs = qs.filter(application__tenant=tenant)
        return qs


class OfferTenantManager(ApplicationTenantManager):
    """
    Tenant-aware manager for Offer model.

    Filters offers through the application's tenant.
    """

    def pending_approval(self, tenant=None):
        """Get offers pending approval, optionally filtered by tenant."""
        qs = self.get_queryset().filter(status='pending_approval')
        if tenant:
            qs = qs.filter(application__tenant=tenant)
        return qs.order_by('-created_at')

    def active(self, tenant=None):
        """Get active offers (not expired, declined, or withdrawn)."""
        qs = self.get_queryset().exclude(
            status__in=['expired', 'declined', 'withdrawn']
        )
        if tenant:
            qs = qs.filter(application__tenant=tenant)
        return qs


class InterviewFeedbackTenantManager(models.Manager):
    """
    Tenant-aware manager for InterviewFeedback model.

    Filters feedback through interview -> application -> tenant.
    """

    def for_tenant(self, tenant):
        """Filter queryset to only include items for the specified tenant."""
        return self.get_queryset().filter(interview__application__tenant=tenant)

    def for_interviewer(self, user, tenant=None):
        """Get feedback submitted by a specific interviewer."""
        qs = self.get_queryset().filter(interviewer=user)
        if tenant:
            qs = qs.filter(interview__application__tenant=tenant)
        return qs


# =============================================================================
# INTERVIEW TYPE CHOICES (shared across models)
# =============================================================================

class InterviewType(models.TextChoices):
    """Interview type choices used by Interview and InterviewTemplate models."""
    PHONE = 'phone', _('Phone Screen')
    VIDEO = 'video', _('Video Interview')
    IN_PERSON = 'in_person', _('In-Person')
    TECHNICAL = 'technical', _('Technical Interview')
    PANEL = 'panel', _('Panel Interview')
    ASSESSMENT = 'assessment', _('Assessment/Test')
    FINAL = 'final', _('Final Interview')
    CULTURE_FIT = 'culture_fit', _('Culture Fit')
    CASE_STUDY = 'case_study', _('Case Study')
    BEHAVIORAL = 'behavioral', _('Behavioral Interview')


# =============================================================================
# MEETING PROVIDER CHOICES
# =============================================================================

class MeetingProvider(models.TextChoices):
    """Video conferencing provider choices."""
    ZOOM = 'zoom', _('Zoom')
    TEAMS = 'teams', _('Microsoft Teams')
    MEET = 'meet', _('Google Meet')
    WEBEX = 'webex', _('Cisco Webex')
    CUSTOM = 'custom', _('Custom/Other')


# =============================================================================
# E-SIGN PROVIDER CHOICES
# =============================================================================

class ESignProvider(models.TextChoices):
    """E-signature provider choices."""
    DOCUSIGN = 'docusign', _('DocuSign')
    HELLOSIGN = 'hellosign', _('HelloSign/Dropbox Sign')
    ADOBE_SIGN = 'adobe_sign', _('Adobe Sign')
    PANDADOC = 'pandadoc', _('PandaDoc')
    MANUAL = 'manual', _('Manual/Offline')


# =============================================================================
# JOB CATEGORY MODEL
# =============================================================================

class JobCategory(TenantAwareModel):
    """
    Job categories/departments for organization.

    Supports hierarchical structure with parent-child relationships.
    Categories help organize job postings for better navigation.
    """

    name = models.CharField(max_length=100)
    slug = models.SlugField(max_length=100)
    description = models.TextField(blank=True)
    parent = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='children'
    )
    icon = models.CharField(max_length=50, blank=True, help_text=_('Icon class name'))
    color = models.CharField(max_length=7, default='#3B82F6')
    sort_order = models.PositiveIntegerField(default=0)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _('Job Category')
        verbose_name_plural = _('Job Categories')
        ordering = ['sort_order', 'name']
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'slug'],
                name='ats_jobcategory_unique_tenant_slug'
            )
        ]

    def __str__(self):
        if self.parent:
            return f"{self.parent.name} > {self.name}"
        return self.name

    def clean(self):
        """Validate category constraints."""
        super().clean()
        # Prevent circular parent references
        if self.parent:
            if self.parent == self:
                raise ValidationError({'parent': _('A category cannot be its own parent.')})
            # Check for circular reference
            ancestor = self.parent
            visited = {self.pk} if self.pk else set()
            while ancestor:
                if ancestor.pk in visited:
                    raise ValidationError({'parent': _('Circular parent reference detected.')})
                visited.add(ancestor.pk)
                ancestor = ancestor.parent

    @property
    def full_path(self) -> str:
        """Return the full category path (e.g., 'Engineering > Backend')."""
        path_parts = [self.name]
        parent = self.parent
        while parent:
            path_parts.insert(0, parent.name)
            parent = parent.parent
        return ' > '.join(path_parts)

    @property
    def depth(self) -> int:
        """Return the depth level in the hierarchy (0 for root)."""
        level = 0
        parent = self.parent
        while parent:
            level += 1
            parent = parent.parent
        return level

    @property
    def open_jobs_count(self) -> int:
        """Return count of open jobs in this category."""
        return self.jobs.filter(status='open').count()

    def get_descendants(self, include_self: bool = False) -> List['JobCategory']:
        """Return all descendant categories."""
        descendants = []
        if include_self:
            descendants.append(self)
        for child in self.children.filter(is_active=True):
            descendants.append(child)
            descendants.extend(child.get_descendants())
        return descendants

    def get_ancestors(self, include_self: bool = False) -> List['JobCategory']:
        """Return all ancestor categories from root to parent."""
        ancestors = []
        if include_self:
            ancestors.append(self)
        parent = self.parent
        while parent:
            ancestors.insert(0, parent)
            parent = parent.parent
        return ancestors


# =============================================================================
# PIPELINE MODEL
# =============================================================================

class Pipeline(TenantAwareModel):
    """
    Customizable recruitment pipeline (Kanban board).

    Each tenant can have multiple pipelines for different job types.
    Pipelines define the workflow stages that applications go through.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    is_default = models.BooleanField(
        default=False,
        help_text=_('Use as default pipeline for new jobs')
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_pipelines'
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _('Pipeline')
        verbose_name_plural = _('Pipelines')
        ordering = ['-is_default', 'name']
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'name'],
                name='ats_pipeline_unique_tenant_name'
            ),
            # Partial unique constraint: only one default pipeline per tenant
            models.UniqueConstraint(
                fields=['tenant'],
                condition=models.Q(is_default=True),
                name='ats_pipeline_unique_default_per_tenant'
            ),
        ]

    def __str__(self):
        return self.name

    def clean(self):
        """Validate pipeline constraints."""
        super().clean()
        # Only one default pipeline per tenant
        if self.is_default:
            existing_default = Pipeline.objects.filter(
                tenant=self.tenant,
                is_default=True
            ).exclude(pk=self.pk).first()
            if existing_default:
                raise ValidationError({
                    'is_default': _('Another pipeline is already set as default. '
                                   'Please unset it first.')
                })

    def get_stages_ordered(self):
        """Return active stages in order."""
        return self.stages.filter(is_active=True).order_by('order')

    @property
    def stages_count(self) -> int:
        """Return count of active stages."""
        return self.stages.filter(is_active=True).count()

    @property
    def total_applications(self) -> int:
        """Return total applications across all jobs using this pipeline."""
        from django.db.models import Count
        return Application.objects.filter(
            job__pipeline=self
        ).count()

    @property
    def average_time_to_hire(self) -> Optional[timedelta]:
        """Calculate average time from application to hire."""
        hired_apps = Application.objects.filter(
            job__pipeline=self,
            status='hired',
            hired_at__isnull=False
        ).exclude(applied_at__isnull=True)

        if not hired_apps.exists():
            return None

        total_days = 0
        count = 0
        for app in hired_apps:
            if app.hired_at and app.applied_at:
                total_days += (app.hired_at - app.applied_at).days
                count += 1

        if count == 0:
            return None
        return timedelta(days=total_days // count)

    @property
    def conversion_rate(self) -> float:
        """Calculate hire rate (hired / total applications)."""
        total = self.total_applications
        if total == 0:
            return 0.0
        hired = Application.objects.filter(
            job__pipeline=self,
            status='hired'
        ).count()
        return round((hired / total) * 100, 2)

    def get_stage_metrics(self) -> List[Dict[str, Any]]:
        """Return metrics for each stage in the pipeline."""
        metrics = []
        for stage in self.get_stages_ordered():
            app_count = Application.objects.filter(current_stage=stage).count()
            metrics.append({
                'stage_id': stage.id,
                'stage_name': stage.name,
                'stage_type': stage.stage_type,
                'color': stage.color,
                'application_count': app_count,
                'average_time_in_stage': stage.average_time_in_stage,
            })
        return metrics

    def clone(self, new_name: str = None, created_by=None) -> 'Pipeline':
        """Clone this pipeline with all its stages."""
        new_pipeline = Pipeline.objects.create(
            tenant=self.tenant,
            name=new_name or f"Copy of {self.name}",
            description=self.description,
            is_default=False,
            created_by=created_by or self.created_by,
        )

        for stage in self.stages.all().order_by('order'):
            PipelineStage.objects.create(
                pipeline=new_pipeline,
                name=stage.name,
                stage_type=stage.stage_type,
                description=stage.description,
                color=stage.color,
                order=stage.order,
                is_active=stage.is_active,
                auto_reject_after_days=stage.auto_reject_after_days,
                send_email_on_enter=stage.send_email_on_enter,
                email_template_id=stage.email_template_id,
            )

        return new_pipeline

    def set_as_default(self):
        """Set this pipeline as the default for the tenant."""
        # Remove default from other pipelines
        Pipeline.objects.filter(
            tenant=self.tenant,
            is_default=True
        ).update(is_default=False)
        # Set this as default
        self.is_default = True
        self.save(update_fields=['is_default', 'updated_at'])


# =============================================================================
# INTERVIEW SLOT MODEL
# =============================================================================

class InterviewSlot(TenantAwareModel):
    """
    Represents available interview time slots for interviewers.

    Supports recurring slots via iCal RRULE format for easy calendar integration.
    Interviewers can set up their availability, and schedulers can book slots
    for interviews.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    interviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='interview_slots'
    )

    # Time slot details
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    is_available = models.BooleanField(
        default=True,
        help_text=_('Whether this slot is available for booking')
    )
    timezone = models.CharField(max_length=50, default='UTC')

    # Recurrence settings
    recurring = models.BooleanField(
        default=False,
        help_text=_('Whether this slot repeats')
    )
    recurrence_rule = models.CharField(
        max_length=255,
        blank=True,
        help_text=_('iCal RRULE format (e.g., FREQ=WEEKLY;BYDAY=MO,WE,FR)')
    )
    recurrence_end_date = models.DateField(
        null=True,
        blank=True,
        help_text=_('When the recurring slot series ends')
    )

    # Booking info
    booked_by_interview = models.OneToOneField(
        'Interview',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='booked_slot',
        help_text=_('The interview that booked this slot')
    )
    booked_at = models.DateTimeField(null=True, blank=True)

    # Slot type/preference
    slot_type = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('Type of interviews this slot is for (e.g., phone, technical)')
    )
    notes = models.TextField(
        blank=True,
        help_text=_('Notes about this availability slot')
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _('Interview Slot')
        verbose_name_plural = _('Interview Slots')
        ordering = ['start_time']
        indexes = [
            models.Index(fields=['interviewer', 'start_time']),
            models.Index(fields=['is_available', 'start_time']),
            models.Index(fields=['start_time', 'end_time']),
        ]
        constraints = [
            # End time must be after start time
            models.CheckConstraint(
                check=Q(end_time__gt=F('start_time')),
                name='ats_interviewslot_end_after_start'
            ),
        ]

    def __str__(self):
        return f"{self.interviewer} - {self.start_time.strftime('%Y-%m-%d %H:%M')}"

    def clean(self):
        """Validate slot constraints."""
        super().clean()
        errors = {}

        if self.end_time and self.start_time:
            if self.end_time <= self.start_time:
                errors['end_time'] = _('End time must be after start time.')

        if self.recurring and not self.recurrence_rule:
            errors['recurrence_rule'] = _(
                'Recurrence rule is required for recurring slots.'
            )

        if errors:
            raise ValidationError(errors)

    @property
    def duration_minutes(self) -> int:
        """Return the duration of the slot in minutes."""
        if self.start_time and self.end_time:
            delta = self.end_time - self.start_time
            return int(delta.total_seconds() / 60)
        return 0

    @property
    def is_booked(self) -> bool:
        """Check if the slot is booked."""
        return self.booked_by_interview is not None

    @property
    def is_past(self) -> bool:
        """Check if the slot is in the past."""
        return self.end_time < timezone.now()

    @property
    def can_be_booked(self) -> bool:
        """Check if the slot can be booked."""
        return self.is_available and not self.is_booked and not self.is_past

    def book(self, interview: 'Interview') -> bool:
        """
        Book this slot for an interview.

        Args:
            interview: The Interview to book this slot for.

        Returns:
            True if booking was successful, False otherwise.
        """
        if not self.can_be_booked:
            return False

        self.booked_by_interview = interview
        self.booked_at = timezone.now()
        self.is_available = False
        self.save(update_fields=['booked_by_interview', 'booked_at', 'is_available', 'updated_at'])
        return True

    def release(self) -> None:
        """Release the booking on this slot."""
        self.booked_by_interview = None
        self.booked_at = None
        self.is_available = True
        self.save(update_fields=['booked_by_interview', 'booked_at', 'is_available', 'updated_at'])

    def get_overlapping_slots(self) -> models.QuerySet:
        """Find slots that overlap with this one for the same interviewer."""
        return InterviewSlot.objects.filter(
            interviewer=self.interviewer,
            start_time__lt=self.end_time,
            end_time__gt=self.start_time
        ).exclude(pk=self.pk)

    @classmethod
    def get_available_slots(
        cls,
        tenant,
        start_date: 'datetime',
        end_date: 'datetime',
        interviewer=None,
        slot_type: str = None,
        duration_minutes: int = None
    ) -> models.QuerySet:
        """
        Get available interview slots within a date range.

        Args:
            tenant: The tenant to filter by.
            start_date: Start of the date range.
            end_date: End of the date range.
            interviewer: Optional specific interviewer to filter by.
            slot_type: Optional slot type to filter by.
            duration_minutes: Optional minimum duration to filter by.

        Returns:
            QuerySet of available InterviewSlot objects.
        """
        qs = cls.objects.filter(
            tenant=tenant,
            is_available=True,
            booked_by_interview__isnull=True,
            start_time__gte=start_date,
            end_time__lte=end_date
        )

        if interviewer:
            qs = qs.filter(interviewer=interviewer)

        if slot_type:
            qs = qs.filter(slot_type=slot_type)

        if duration_minutes:
            # Filter slots that are at least the required duration
            from django.db.models.functions import Extract
            qs = qs.annotate(
                duration=Extract(F('end_time') - F('start_time'), 'epoch') / 60
            ).filter(duration__gte=duration_minutes)

        return qs.order_by('start_time')


# =============================================================================
# INTERVIEW TEMPLATE MODEL
# =============================================================================

class InterviewTemplate(TenantAwareModel):
    """
    Template for standardized interviews.

    Provides reusable interview structures with predefined questions,
    scorecard criteria, and default settings. Helps ensure consistency
    in the interview process across the organization.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(
        max_length=100,
        help_text=_('Name of the interview template')
    )
    interview_type = models.CharField(
        max_length=20,
        choices=InterviewType.choices,
        default=InterviewType.VIDEO
    )

    # Default settings
    default_duration = models.DurationField(
        default=timedelta(hours=1),
        help_text=_('Default duration for interviews using this template')
    )
    required_interviewers = models.PositiveIntegerField(
        default=1,
        validators=[MinValueValidator(1)],
        help_text=_('Minimum number of interviewers required')
    )

    # Questions and evaluation criteria
    questions = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            'List of questions with structure: '
            '[{"question": "...", "category": "...", "expected_answer": "...", "weight": 1}]'
        )
    )
    scorecard_criteria = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            'Rating criteria with structure: '
            '[{"name": "...", "description": "...", "weight": 1, "max_score": 5}]'
        )
    )

    # Interview guidance
    instructions = models.TextField(
        blank=True,
        help_text=_('Instructions for interviewers using this template')
    )
    preparation_guide = models.TextField(
        blank=True,
        help_text=_('Preparation guide for interviewers')
    )
    candidate_instructions = models.TextField(
        blank=True,
        help_text=_('Instructions to send to candidates')
    )

    # Settings
    is_active = models.BooleanField(default=True)
    allow_multiple_interviewers = models.BooleanField(
        default=True,
        help_text=_('Whether multiple interviewers can conduct this interview type')
    )
    requires_feedback_before_discussion = models.BooleanField(
        default=True,
        help_text=_('Interviewers must submit feedback before seeing others\' feedback')
    )

    # Categorization
    department = models.CharField(max_length=100, blank=True)
    job_level = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('Job level this template is designed for (e.g., Junior, Senior)')
    )
    skills_assessed = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True,
        help_text=_('Skills that this interview assesses')
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_interview_templates'
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _('Interview Template')
        verbose_name_plural = _('Interview Templates')
        ordering = ['name']
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'name'],
                name='ats_interviewtemplate_unique_tenant_name'
            ),
            models.CheckConstraint(
                check=Q(required_interviewers__gte=1),
                name='ats_interviewtemplate_min_interviewers'
            ),
        ]

    def __str__(self):
        return f"{self.name} ({self.get_interview_type_display()})"

    @property
    def questions_count(self) -> int:
        """Return the number of questions in the template."""
        return len(self.questions) if self.questions else 0

    @property
    def criteria_count(self) -> int:
        """Return the number of scorecard criteria."""
        return len(self.scorecard_criteria) if self.scorecard_criteria else 0

    @property
    def max_possible_score(self) -> float:
        """Calculate the maximum possible score based on criteria."""
        if not self.scorecard_criteria:
            return 0
        return sum(
            c.get('max_score', 5) * c.get('weight', 1)
            for c in self.scorecard_criteria
        )

    def clone(self, new_name: str = None, created_by=None) -> 'InterviewTemplate':
        """Clone this template with a new name."""
        return InterviewTemplate.objects.create(
            tenant=self.tenant,
            name=new_name or f"Copy of {self.name}",
            interview_type=self.interview_type,
            default_duration=self.default_duration,
            required_interviewers=self.required_interviewers,
            questions=list(self.questions) if self.questions else [],
            scorecard_criteria=list(self.scorecard_criteria) if self.scorecard_criteria else [],
            instructions=self.instructions,
            preparation_guide=self.preparation_guide,
            candidate_instructions=self.candidate_instructions,
            is_active=True,
            allow_multiple_interviewers=self.allow_multiple_interviewers,
            requires_feedback_before_discussion=self.requires_feedback_before_discussion,
            department=self.department,
            job_level=self.job_level,
            skills_assessed=list(self.skills_assessed) if self.skills_assessed else [],
            created_by=created_by,
        )

    def add_question(
        self,
        question: str,
        category: str = '',
        expected_answer: str = '',
        weight: int = 1
    ) -> None:
        """Add a question to the template."""
        if not self.questions:
            self.questions = []
        self.questions.append({
            'question': question,
            'category': category,
            'expected_answer': expected_answer,
            'weight': weight
        })
        self.save(update_fields=['questions', 'updated_at'])

    def add_criterion(
        self,
        name: str,
        description: str = '',
        weight: int = 1,
        max_score: int = 5
    ) -> None:
        """Add a scorecard criterion to the template."""
        if not self.scorecard_criteria:
            self.scorecard_criteria = []
        self.scorecard_criteria.append({
            'name': name,
            'description': description,
            'weight': weight,
            'max_score': max_score
        })
        self.save(update_fields=['scorecard_criteria', 'updated_at'])


# =============================================================================
# PIPELINE STAGE MODEL
# =============================================================================

class PipelineStage(models.Model):
    """
    Individual stage in a recruitment pipeline.

    E.g., "New", "Screening", "Interview", "Offer", "Hired".
    Each stage represents a step in the hiring workflow.
    """

    class StageType(models.TextChoices):
        NEW = 'new', _('New/Applied')
        SCREENING = 'screening', _('Screening')
        ASSESSMENT = 'assessment', _('Assessment')
        INTERVIEW = 'interview', _('Interview')
        REFERENCE = 'reference', _('Reference Check')
        OFFER = 'offer', _('Offer')
        HIRED = 'hired', _('Hired')
        REJECTED = 'rejected', _('Rejected')
        WITHDRAWN = 'withdrawn', _('Withdrawn')
        ON_HOLD = 'on_hold', _('On Hold')

    # Terminal stages where applications cannot advance
    TERMINAL_STAGES = {StageType.HIRED, StageType.REJECTED, StageType.WITHDRAWN}

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    pipeline = models.ForeignKey(
        Pipeline,
        on_delete=models.CASCADE,
        related_name='stages'
    )
    name = models.CharField(max_length=100)
    stage_type = models.CharField(
        max_length=20,
        choices=StageType.choices,
        default=StageType.NEW
    )
    description = models.TextField(blank=True)
    color = models.CharField(max_length=7, default='#6B7280')
    order = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)

    # Automation triggers
    auto_reject_after_days = models.PositiveIntegerField(
        default=0,
        help_text=_('Auto-reject after X days in this stage (0=disabled)')
    )
    send_email_on_enter = models.BooleanField(default=False)
    email_template_id = models.CharField(max_length=100, blank=True)

    # Stats
    average_time_in_stage = models.DurationField(null=True, blank=True)

    class Meta:
        verbose_name = _('Pipeline Stage')
        verbose_name_plural = _('Pipeline Stages')
        ordering = ['pipeline', 'order']
        unique_together = ['pipeline', 'order']

    def __str__(self):
        return f"{self.pipeline.name} - {self.name}"

    def clean(self):
        """Validate stage constraints."""
        super().clean()
        if self.order < 0:
            raise ValidationError({'order': _('Order must be a non-negative integer.')})

    @property
    def is_terminal(self) -> bool:
        """Check if this is a terminal stage (hired, rejected, withdrawn)."""
        return self.stage_type in self.TERMINAL_STAGES

    @property
    def is_first_stage(self) -> bool:
        """Check if this is the first stage in the pipeline."""
        first_stage = self.pipeline.stages.filter(
            is_active=True
        ).order_by('order').first()
        return first_stage and first_stage.pk == self.pk

    @property
    def is_last_stage(self) -> bool:
        """Check if this is the last non-terminal stage."""
        last_stage = self.pipeline.stages.filter(
            is_active=True
        ).exclude(
            stage_type__in=self.TERMINAL_STAGES
        ).order_by('-order').first()
        return last_stage and last_stage.pk == self.pk

    @property
    def application_count(self) -> int:
        """Return count of applications in this stage."""
        return self.applications.count()

    def get_next_stage(self) -> Optional['PipelineStage']:
        """Get the next stage in the pipeline."""
        return self.pipeline.stages.filter(
            is_active=True,
            order__gt=self.order
        ).order_by('order').first()

    def get_previous_stage(self) -> Optional['PipelineStage']:
        """Get the previous stage in the pipeline."""
        return self.pipeline.stages.filter(
            is_active=True,
            order__lt=self.order
        ).order_by('-order').first()

    def calculate_average_time(self) -> Optional[timedelta]:
        """Calculate average time applications spend in this stage."""
        from django.db.models import Avg, F
        from django.db.models.functions import Extract

        # Get applications that have moved past this stage
        activities = ApplicationActivity.objects.filter(
            activity_type='stage_change',
            old_value=self.name
        ).exclude(new_value=self.name)

        if not activities.exists():
            return None

        total_seconds = 0
        count = 0
        for activity in activities:
            # Find when they entered this stage
            entry = ApplicationActivity.objects.filter(
                application=activity.application,
                activity_type='stage_change',
                new_value=self.name,
                created_at__lt=activity.created_at
            ).order_by('-created_at').first()

            if entry:
                duration = activity.created_at - entry.created_at
                total_seconds += duration.total_seconds()
                count += 1

        if count == 0:
            return None

        avg_seconds = total_seconds / count
        return timedelta(seconds=avg_seconds)

    def update_average_time(self):
        """Update the cached average time in stage."""
        self.average_time_in_stage = self.calculate_average_time()
        self.save(update_fields=['average_time_in_stage'])


# =============================================================================
# JOB POSTING MODEL
# =============================================================================

class JobPosting(TenantSoftDeleteModel):
    """
    Job posting/requisition with all details.

    Supports rich content, multiple locations, custom fields, and full
    lifecycle management from draft to filled/closed.
    """

    class JobStatus(models.TextChoices):
        DRAFT = 'draft', _('Draft')
        PENDING_APPROVAL = 'pending_approval', _('Pending Approval')
        OPEN = 'open', _('Open')
        ON_HOLD = 'on_hold', _('On Hold')
        CLOSED = 'closed', _('Closed')
        FILLED = 'filled', _('Filled')
        CANCELLED = 'cancelled', _('Cancelled')

    class JobType(models.TextChoices):
        FULL_TIME = 'full_time', _('Full-time')
        PART_TIME = 'part_time', _('Part-time')
        CONTRACT = 'contract', _('Contract')
        INTERNSHIP = 'internship', _('Internship')
        TEMPORARY = 'temporary', _('Temporary')
        FREELANCE = 'freelance', _('Freelance')

    class ExperienceLevel(models.TextChoices):
        ENTRY = 'entry', _('Entry Level')
        JUNIOR = 'junior', _('Junior (1-2 years)')
        MID = 'mid', _('Mid-Level (3-5 years)')
        SENIOR = 'senior', _('Senior (5-8 years)')
        LEAD = 'lead', _('Lead (8+ years)')
        EXECUTIVE = 'executive', _('Executive')

    class RemotePolicy(models.TextChoices):
        ON_SITE = 'on_site', _('On-site')
        REMOTE = 'remote', _('Fully Remote')
        HYBRID = 'hybrid', _('Hybrid')
        FLEXIBLE = 'flexible', _('Flexible')

    # Status that allow applications
    OPEN_STATUSES = {JobStatus.OPEN}
    # Status that indicate job is complete
    CLOSED_STATUSES = {JobStatus.CLOSED, JobStatus.FILLED, JobStatus.CANCELLED}

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Basic Info
    title = models.CharField(max_length=200)
    slug = models.SlugField(max_length=220, blank=True)
    reference_code = models.CharField(
        max_length=50,
        unique=True,
        help_text=_('Unique job reference code')
    )
    category = models.ForeignKey(
        JobCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='jobs'
    )

    # Status & Pipeline
    status = models.CharField(
        max_length=20,
        choices=JobStatus.choices,
        default=JobStatus.DRAFT
    )
    pipeline = models.ForeignKey(
        Pipeline,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='jobs'
    )

    # Job Details
    description = models.TextField(help_text=_('Full job description (HTML supported)'))
    responsibilities = models.TextField(blank=True)
    requirements = models.TextField(blank=True)
    nice_to_have = models.TextField(blank=True, help_text=_('Preferred qualifications'))
    benefits = models.TextField(blank=True)

    # Type & Level
    job_type = models.CharField(
        max_length=20,
        choices=JobType.choices,
        default=JobType.FULL_TIME
    )
    experience_level = models.CharField(
        max_length=20,
        choices=ExperienceLevel.choices,
        default=ExperienceLevel.MID
    )

    # Location
    remote_policy = models.CharField(
        max_length=20,
        choices=RemotePolicy.choices,
        default=RemotePolicy.ON_SITE
    )
    location_city = models.CharField(max_length=100, blank=True)
    location_state = models.CharField(max_length=100, blank=True)
    location_country = models.CharField(max_length=100, blank=True, default='Canada')
    location_coordinates = gis_models.PointField(null=True, blank=True)

    # Compensation
    salary_min = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True
    )
    salary_max = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True
    )
    salary_currency = models.CharField(max_length=3, default='CAD')
    salary_period = models.CharField(
        max_length=20,
        choices=[
            ('hourly', _('Hourly')),
            ('daily', _('Daily')),
            ('weekly', _('Weekly')),
            ('monthly', _('Monthly')),
            ('yearly', _('Yearly')),
        ],
        default='yearly'
    )
    show_salary = models.BooleanField(default=False)
    equity_offered = models.BooleanField(default=False)
    equity_range = models.CharField(max_length=50, blank=True)

    # Skills & Requirements
    required_skills = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True
    )
    preferred_skills = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True
    )
    education_requirements = models.TextField(blank=True)
    certifications_required = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True
    )
    languages_required = ArrayField(
        models.CharField(max_length=50),
        default=list,
        blank=True
    )

    # Hiring Details
    positions_count = models.PositiveIntegerField(default=1)
    hiring_manager = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='managed_jobs'
    )
    recruiter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='recruiting_jobs'
    )
    team = models.CharField(max_length=100, blank=True)
    reports_to = models.CharField(max_length=100, blank=True)

    # Application Settings
    application_deadline = models.DateTimeField(null=True, blank=True)
    require_cover_letter = models.BooleanField(default=False)
    require_resume = models.BooleanField(default=True)
    custom_questions = models.JSONField(default=list, blank=True)
    application_email = models.EmailField(blank=True)
    external_apply_url = models.URLField(blank=True)

    # Visibility
    is_internal_only = models.BooleanField(default=False)
    is_featured = models.BooleanField(default=False)
    published_on_career_page = models.BooleanField(default=True)
    published_on_job_boards = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of job boards to publish to')
    )

    # SEO & Search
    search_vector = SearchVectorField(null=True, blank=True)
    meta_title = models.CharField(max_length=200, blank=True)
    meta_description = models.TextField(blank=True, max_length=500)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    published_at = models.DateTimeField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    # Creator
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_jobs'
    )

    # Optimistic locking version counter
    version = models.PositiveIntegerField(
        default=1,
        verbose_name=_('Version'),
        help_text=_('Record version for optimistic locking.')
    )

    objects = TenantSoftDeleteManager()
    all_objects = TenantSoftDeleteManager(alive_only=False)

    class Meta:
        verbose_name = _('Job Posting')
        verbose_name_plural = _('Job Postings')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['category', 'status']),
            models.Index(fields=['job_type', 'experience_level']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'reference_code'],
                name='ats_jobposting_unique_tenant_reference'
            ),
            models.UniqueConstraint(
                fields=['tenant', 'slug'],
                name='ats_jobposting_unique_tenant_slug',
                condition=models.Q(slug__gt=''),
            ),
            # CHECK constraint: salary_min <= salary_max
            models.CheckConstraint(
                check=(
                    models.Q(salary_min__isnull=True) |
                    models.Q(salary_max__isnull=True) |
                    models.Q(salary_min__lte=F('salary_max'))
                ),
                name='ats_jobposting_salary_min_lte_max'
            ),
            # CHECK constraint: positions_count >= 1
            models.CheckConstraint(
                check=models.Q(positions_count__gte=1),
                name='ats_jobposting_positions_count_gte_1'
            ),
        ]

    def __str__(self):
        return f"{self.title} ({self.reference_code})"

    def clean(self):
        """Validate job posting constraints."""
        super().clean()
        errors = {}

        # Salary validation
        if self.salary_min and self.salary_max:
            if self.salary_min > self.salary_max:
                errors['salary_min'] = _('Minimum salary cannot exceed maximum salary.')

        # Deadline validation
        if self.application_deadline and self.application_deadline < timezone.now():
            if self.status == self.JobStatus.OPEN:
                errors['application_deadline'] = _(
                    'Application deadline cannot be in the past for an open job.'
                )

        # Positions count
        if self.positions_count < 1:
            errors['positions_count'] = _('Must have at least 1 position.')

        if errors:
            raise ValidationError(errors)

    def save(self, *args, **kwargs):
        """
        Save with optimistic locking to prevent concurrent modification conflicts.

        Uses atomic version increment with F() expression to prevent race conditions.
        Verifies version hasn't changed since the record was read.

        Raises:
            ConcurrentModificationError: If the record was modified by another
                process since it was read.
        """
        # Auto-populate tenant if not set
        if not self.tenant_id:
            try:
                from django.db import connection
                tenant = getattr(connection, 'tenant', None)
                if tenant:
                    self.tenant = tenant
            except Exception:
                pass

        # Optimistic locking for existing records
        if self.pk:
            expected_version = self.version
            # Check if the record still has the expected version
            current_version = JobPosting.all_objects.filter(pk=self.pk).values_list(
                'version', flat=True
            ).first()

            if current_version is not None and current_version != expected_version:
                raise ConcurrentModificationError(
                    model_name='JobPosting',
                    object_id=self.pk,
                    expected_version=expected_version,
                    actual_version=current_version
                )

            # Use atomic increment with update() and F() expression
            update_fields = kwargs.get('update_fields')
            if update_fields is None:
                # Full save - use atomic update for version
                JobPosting.all_objects.filter(pk=self.pk, version=expected_version).update(
                    version=F('version') + 1
                )
                # Update local version number
                self.version = expected_version + 1

        super().save(*args, **kwargs)

    def delete(self, using=None, keep_parents=False, user=None, cascade_to_applications=True):
        """
        Soft delete the job posting with optional cascade to applications.

        When a job posting is soft-deleted, all its applications should also
        be soft-deleted to maintain referential integrity for soft-deleted data.

        Args:
            using: Database alias to use.
            keep_parents: Unused, kept for API compatibility.
            user: The user performing the deletion.
            cascade_to_applications: If True, cascade soft delete to applications.
        """
        # First cascade soft delete to applications if requested
        if cascade_to_applications:
            for application in self.applications.all():
                application.is_deleted = True
                application.deleted_at = timezone.now()
                application.save(update_fields=['is_deleted', 'deleted_at', 'updated_at'])

        # Then soft delete the job posting itself
        super().delete(using=using, keep_parents=keep_parents, user=user)

    @property
    def is_open(self) -> bool:
        """Check if the job is accepting applications."""
        return self.status in self.OPEN_STATUSES

    @property
    def is_closed(self) -> bool:
        """Check if the job is closed."""
        return self.status in self.CLOSED_STATUSES

    @property
    def is_publishable(self) -> bool:
        """Check if the job can be published."""
        # Must have required fields
        if not self.title or not self.description:
            return False
        # Must be in draft or on_hold status
        if self.status not in {self.JobStatus.DRAFT, self.JobStatus.ON_HOLD}:
            return False
        # Must have a pipeline
        if not self.pipeline:
            return False
        return True

    @property
    def can_accept_applications(self) -> bool:
        """Check if the job can accept new applications."""
        if not self.is_open:
            return False
        if self.application_deadline and self.application_deadline < timezone.now():
            return False
        # Check if positions are filled
        hired_count = self.applications.filter(status='hired').count()
        if hired_count >= self.positions_count:
            return False
        return True

    @property
    def salary_range_display(self) -> Optional[str]:
        """Return formatted salary range string."""
        if not self.salary_min and not self.salary_max:
            return None
        if self.salary_min and self.salary_max:
            return f"{self.salary_currency} {self.salary_min:,.0f} - {self.salary_max:,.0f}"
        if self.salary_min:
            return f"{self.salary_currency} {self.salary_min:,.0f}+"
        return f"Up to {self.salary_currency} {self.salary_max:,.0f}"

    @property
    def location_display(self) -> str:
        """Return formatted location string."""
        parts = [self.location_city, self.location_state, self.location_country]
        return ', '.join(filter(None, parts))

    @property
    def applications_count(self) -> int:
        """Return total number of applications."""
        return self.applications.count()

    @property
    def active_applications_count(self) -> int:
        """Return count of applications not rejected/withdrawn."""
        return self.applications.exclude(
            status__in=['rejected', 'withdrawn']
        ).count()

    @property
    def days_open(self) -> Optional[int]:
        """Return number of days the job has been open."""
        if not self.published_at:
            return None
        end_date = self.closed_at or timezone.now()
        return (end_date - self.published_at).days

    @property
    def positions_remaining(self) -> int:
        """Return number of positions still to be filled."""
        hired_count = self.applications.filter(status='hired').count()
        return max(0, self.positions_count - hired_count)

    def get_application_stats(self) -> Dict[str, int]:
        """Return application statistics by status."""
        from django.db.models import Count
        stats = dict(
            self.applications.values('status').annotate(
                count=Count('id')
            ).values_list('status', 'count')
        )
        return stats

    def get_applications_by_stage(self) -> Dict[str, int]:
        """Return application counts grouped by pipeline stage."""
        if not self.pipeline:
            return {}

        result = {}
        for stage in self.pipeline.stages.filter(is_active=True):
            result[stage.name] = self.applications.filter(current_stage=stage).count()
        return result

    def publish(self, user=None):
        """Publish the job posting."""
        if not self.is_publishable:
            raise ValidationError(_('This job posting cannot be published.'))
        self.status = self.JobStatus.OPEN
        self.published_at = timezone.now()
        self.save(update_fields=['status', 'published_at', 'updated_at'])

    def close(self, reason: str = 'filled', user=None):
        """Close the job posting."""
        status_map = {
            'filled': self.JobStatus.FILLED,
            'cancelled': self.JobStatus.CANCELLED,
            'closed': self.JobStatus.CLOSED,
        }
        self.status = status_map.get(reason, self.JobStatus.CLOSED)
        self.closed_at = timezone.now()
        self.save(update_fields=['status', 'closed_at', 'updated_at'])

    def put_on_hold(self, user=None):
        """Put the job posting on hold."""
        if self.is_closed:
            raise ValidationError(_('Cannot put a closed job on hold.'))
        self.status = self.JobStatus.ON_HOLD
        self.save(update_fields=['status', 'updated_at'])

    def reopen(self, user=None):
        """Reopen a closed or on-hold job."""
        if self.status not in {self.JobStatus.ON_HOLD, self.JobStatus.CLOSED}:
            raise ValidationError(_('Only closed or on-hold jobs can be reopened.'))
        self.status = self.JobStatus.OPEN
        self.closed_at = None
        self.save(update_fields=['status', 'closed_at', 'updated_at'])

    def clone(self, new_title: str = None, new_reference_code: str = None,
              created_by=None) -> 'JobPosting':
        """Clone this job posting."""
        new_job = JobPosting(
            tenant=self.tenant,
            title=new_title or f"Copy of {self.title}",
            slug='',
            reference_code=new_reference_code or f"{self.reference_code}-COPY",
            category=self.category,
            status=self.JobStatus.DRAFT,
            pipeline=self.pipeline,
            description=self.description,
            responsibilities=self.responsibilities,
            requirements=self.requirements,
            nice_to_have=self.nice_to_have,
            benefits=self.benefits,
            job_type=self.job_type,
            experience_level=self.experience_level,
            remote_policy=self.remote_policy,
            location_city=self.location_city,
            location_state=self.location_state,
            location_country=self.location_country,
            salary_min=self.salary_min,
            salary_max=self.salary_max,
            salary_currency=self.salary_currency,
            salary_period=self.salary_period,
            show_salary=self.show_salary,
            required_skills=list(self.required_skills),
            preferred_skills=list(self.preferred_skills),
            positions_count=self.positions_count,
            hiring_manager=self.hiring_manager,
            recruiter=self.recruiter,
            require_cover_letter=self.require_cover_letter,
            require_resume=self.require_resume,
            custom_questions=list(self.custom_questions),
            is_internal_only=self.is_internal_only,
            created_by=created_by or self.created_by,
        )
        new_job.save()
        return new_job


# =============================================================================
# CANDIDATE MODEL
# =============================================================================

class Candidate(TenantSoftDeleteModel):
    """
    Candidate profile for the ATS.

    Can be linked to a user account or standalone. Stores all candidate
    information including professional history, skills, and documents.
    """

    class Source(models.TextChoices):
        CAREER_PAGE = 'career_page', _('Career Page')
        LINKEDIN = 'linkedin', _('LinkedIn')
        INDEED = 'indeed', _('Indeed')
        REFERRAL = 'referral', _('Employee Referral')
        AGENCY = 'agency', _('Recruitment Agency')
        DIRECT = 'direct', _('Direct Application')
        IMPORTED = 'imported', _('Imported')
        OTHER = 'other', _('Other')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Link to user (optional)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='candidate_profile_ats'
    )

    # Basic Info
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.CharField(max_length=30, blank=True)

    # Professional
    headline = models.CharField(max_length=200, blank=True)
    summary = models.TextField(blank=True, validators=[MaxLengthValidator(5000)])
    current_company = models.CharField(max_length=200, blank=True)
    current_title = models.CharField(max_length=200, blank=True)
    years_experience = models.PositiveIntegerField(null=True, blank=True)

    # Location
    city = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    country = models.CharField(max_length=100, blank=True)
    willing_to_relocate = models.BooleanField(default=False)
    location_coordinates = gis_models.PointField(null=True, blank=True)

    # Documents
    resume = models.FileField(
        upload_to='resumes/',
        blank=True,
        null=True,
        validators=[
            FileExtensionValidator(allowed_extensions=['pdf', 'doc', 'docx', 'rtf', 'txt'])
        ],
        help_text=_("Allowed formats: PDF, DOC, DOCX, RTF, TXT. Max size: 10MB")
    )
    resume_text = models.TextField(blank=True, help_text=_('Parsed resume text'))
    cover_letter = models.TextField(blank=True, validators=[MaxLengthValidator(10000)])
    portfolio_url = models.URLField(blank=True)

    # Skills & Education
    skills = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True
    )
    education = models.JSONField(default=list, blank=True)
    certifications = models.JSONField(default=list, blank=True)
    work_experience = models.JSONField(default=list, blank=True)
    languages = ArrayField(
        models.CharField(max_length=50),
        default=list,
        blank=True
    )

    # Social
    linkedin_url = models.URLField(blank=True)
    github_url = models.URLField(blank=True)
    twitter_url = models.URLField(blank=True)
    website_url = models.URLField(blank=True)

    # Preferences
    desired_salary_min = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True
    )
    desired_salary_max = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True
    )
    notice_period_days = models.PositiveIntegerField(null=True, blank=True)
    work_authorization = models.CharField(max_length=100, blank=True)

    # Source & Tracking
    source = models.CharField(
        max_length=20,
        choices=Source.choices,
        default=Source.DIRECT
    )
    source_detail = models.CharField(max_length=200, blank=True)
    referred_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='referred_candidates'
    )

    # Search
    search_vector = SearchVectorField(null=True, blank=True)

    # Tags
    tags = ArrayField(
        models.CharField(max_length=50),
        default=list,
        blank=True
    )

    # GDPR
    consent_to_store = models.BooleanField(default=True)
    consent_date = models.DateTimeField(null=True, blank=True)
    data_retention_until = models.DateField(null=True, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_activity_at = models.DateTimeField(null=True, blank=True)

    # Optimistic locking version counter
    version = models.PositiveIntegerField(
        default=1,
        verbose_name=_('Version'),
        help_text=_('Record version for optimistic locking.')
    )

    objects = TenantSoftDeleteManager()
    all_objects = TenantSoftDeleteManager(alive_only=False)

    class Meta:
        verbose_name = _('Candidate')
        verbose_name_plural = _('Candidates')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['source', 'created_at']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'email'],
                name='ats_candidate_unique_tenant_email'
            ),
        ]

    def __str__(self):
        return f"{self.first_name} {self.last_name}"

    def save(self, *args, **kwargs):
        """
        Save with optimistic locking to prevent concurrent modification conflicts.

        Uses atomic version increment with F() expression to prevent race conditions.
        Verifies version hasn't changed since the record was read.

        Raises:
            ConcurrentModificationError: If the record was modified by another
                process since it was read.
        """
        # Auto-populate tenant if not set
        if not self.tenant_id:
            try:
                from django.db import connection
                tenant = getattr(connection, 'tenant', None)
                if tenant:
                    self.tenant = tenant
            except Exception:
                pass

        # Optimistic locking for existing records
        if self.pk:
            expected_version = self.version
            # Check if the record still has the expected version
            current_version = Candidate.all_objects.filter(pk=self.pk).values_list(
                'version', flat=True
            ).first()

            if current_version is not None and current_version != expected_version:
                raise ConcurrentModificationError(
                    model_name='Candidate',
                    object_id=self.pk,
                    expected_version=expected_version,
                    actual_version=current_version
                )

            # Use atomic increment with update() and F() expression
            update_fields = kwargs.get('update_fields')
            if update_fields is None:
                # Full save - use atomic update for version
                Candidate.all_objects.filter(pk=self.pk, version=expected_version).update(
                    version=F('version') + 1
                )
                # Update local version number
                self.version = expected_version + 1

        super().save(*args, **kwargs)

    def clean(self):
        """Validate candidate constraints."""
        super().clean()
        errors = {}

        # Validate email format
        if self.email and '@' not in self.email:
            errors['email'] = _('Invalid email format.')

        # Validate salary expectations
        if self.desired_salary_min and self.desired_salary_max:
            if self.desired_salary_min > self.desired_salary_max:
                errors['desired_salary_min'] = _(
                    'Minimum salary cannot exceed maximum.'
                )

        if errors:
            raise ValidationError(errors)

    @property
    def full_name(self) -> str:
        """Return the candidate's full name."""
        return f"{self.first_name} {self.last_name}"

    @property
    def initials(self) -> str:
        """Return the candidate's initials."""
        return f"{self.first_name[0] if self.first_name else ''}{self.last_name[0] if self.last_name else ''}"

    @property
    def location_display(self) -> str:
        """Return formatted location string."""
        parts = [self.city, self.state, self.country]
        return ', '.join(filter(None, parts))

    @property
    def applications_count(self) -> int:
        """Return total number of applications."""
        return self.applications.count()

    @property
    def active_applications_count(self) -> int:
        """Return count of active applications."""
        return self.applications.exclude(
            status__in=['rejected', 'withdrawn', 'hired']
        ).count()

    @property
    def is_currently_employed(self) -> bool:
        """Check if candidate appears to be currently employed."""
        return bool(self.current_company and self.current_title)

    @property
    def days_since_last_activity(self) -> Optional[int]:
        """Return days since last activity."""
        if not self.last_activity_at:
            return None
        return (timezone.now() - self.last_activity_at).days

    @property
    def has_valid_consent(self) -> bool:
        """Check if candidate has valid data storage consent."""
        if not self.consent_to_store:
            return False
        if self.data_retention_until and self.data_retention_until < timezone.now().date():
            return False
        return True

    def get_skill_match_score(self, job: JobPosting) -> float:
        """Calculate skill match percentage against a job."""
        if not job.required_skills:
            return 100.0

        candidate_skills = set(s.lower() for s in self.skills)
        required_skills = set(s.lower() for s in job.required_skills)

        if not required_skills:
            return 100.0

        matched = len(candidate_skills & required_skills)
        return round((matched / len(required_skills)) * 100, 2)

    def update_last_activity(self):
        """Update the last activity timestamp."""
        self.last_activity_at = timezone.now()
        self.save(update_fields=['last_activity_at', 'updated_at'])

    def add_tag(self, tag: str):
        """Add a tag to the candidate."""
        tag = tag.strip().lower()
        if tag and tag not in self.tags:
            self.tags.append(tag)
            self.save(update_fields=['tags', 'updated_at'])

    def remove_tag(self, tag: str):
        """Remove a tag from the candidate."""
        tag = tag.strip().lower()
        if tag in self.tags:
            self.tags.remove(tag)
            self.save(update_fields=['tags', 'updated_at'])

    def merge_from(self, other_candidate: 'Candidate', delete_other: bool = True):
        """
        Merge another candidate's data into this one.

        Transfers applications and enriches missing data.
        """
        # Transfer applications
        other_candidate.applications.update(candidate=self)

        # Merge skills (unique)
        self.skills = list(set(self.skills + other_candidate.skills))

        # Merge tags (unique)
        self.tags = list(set(self.tags + other_candidate.tags))

        # Fill in missing fields
        if not self.phone and other_candidate.phone:
            self.phone = other_candidate.phone
        if not self.headline and other_candidate.headline:
            self.headline = other_candidate.headline
        if not self.linkedin_url and other_candidate.linkedin_url:
            self.linkedin_url = other_candidate.linkedin_url
        if not self.github_url and other_candidate.github_url:
            self.github_url = other_candidate.github_url
        if not self.resume and other_candidate.resume:
            self.resume = other_candidate.resume

        self.save()

        if delete_other:
            other_candidate.delete()


# =============================================================================
# APPLICATION MODEL
# =============================================================================

class Application(TenantAwareModel):
    """
    Job application linking a candidate to a job posting.

    Tracks the candidate's progress through the pipeline stages,
    interview scheduling, ratings, and final outcome.
    """

    class ApplicationStatus(models.TextChoices):
        NEW = 'new', _('New')
        IN_REVIEW = 'in_review', _('In Review')
        SHORTLISTED = 'shortlisted', _('Shortlisted')
        INTERVIEWING = 'interviewing', _('Interviewing')
        OFFER_PENDING = 'offer_pending', _('Offer Pending')
        OFFER_EXTENDED = 'offer_extended', _('Offer Extended')
        HIRED = 'hired', _('Hired')
        REJECTED = 'rejected', _('Rejected')
        WITHDRAWN = 'withdrawn', _('Withdrawn')
        ON_HOLD = 'on_hold', _('On Hold')

    # Terminal statuses where application cannot proceed
    TERMINAL_STATUSES = {ApplicationStatus.HIRED, ApplicationStatus.REJECTED,
                         ApplicationStatus.WITHDRAWN}
    # Active statuses (not terminal)
    ACTIVE_STATUSES = {ApplicationStatus.NEW, ApplicationStatus.IN_REVIEW,
                       ApplicationStatus.SHORTLISTED, ApplicationStatus.INTERVIEWING,
                       ApplicationStatus.OFFER_PENDING, ApplicationStatus.OFFER_EXTENDED,
                       ApplicationStatus.ON_HOLD}

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    candidate = models.ForeignKey(
        Candidate,
        on_delete=models.CASCADE,
        related_name='applications'
    )
    job = models.ForeignKey(
        JobPosting,
        on_delete=models.CASCADE,
        related_name='applications'
    )

    # Status & Stage
    status = models.CharField(
        max_length=20,
        choices=ApplicationStatus.choices,
        default=ApplicationStatus.NEW
    )
    current_stage = models.ForeignKey(
        PipelineStage,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='applications'
    )

    # Application Content
    cover_letter = models.TextField(blank=True)
    custom_answers = models.JSONField(default=dict, blank=True)
    additional_documents = models.JSONField(default=list, blank=True)

    # Scores & Ratings
    overall_rating = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(5)]
    )
    ai_match_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )

    # Assignment
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_applications'
    )

    # Rejection
    rejection_reason = models.CharField(max_length=200, blank=True)
    rejection_feedback = models.TextField(blank=True)
    send_rejection_email = models.BooleanField(default=True)

    # Source tracking
    utm_source = models.CharField(max_length=100, blank=True)
    utm_medium = models.CharField(max_length=100, blank=True)
    utm_campaign = models.CharField(max_length=100, blank=True)
    referrer_url = models.URLField(blank=True)

    # Timestamps
    applied_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_stage_change_at = models.DateTimeField(null=True, blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    hired_at = models.DateTimeField(null=True, blank=True)
    rejected_at = models.DateTimeField(null=True, blank=True)

    # Soft delete fields (for cascade soft delete from JobPosting)
    is_deleted = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name=_('Is deleted')
    )
    deleted_at = models.DateTimeField(null=True, blank=True)

    # Optimistic locking version counter
    version = models.PositiveIntegerField(
        default=1,
        verbose_name=_('Version'),
        help_text=_('Record version for optimistic locking.')
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _('Application')
        verbose_name_plural = _('Applications')
        ordering = ['-applied_at']
        indexes = [
            models.Index(fields=['job', 'status']),
            models.Index(fields=['job', 'current_stage']),
            models.Index(fields=['candidate', 'applied_at']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'candidate', 'job'],
                name='ats_application_unique_tenant_candidate_job'
            ),
            # CHECK constraint: 0 <= overall_rating <= 5
            models.CheckConstraint(
                check=(
                    models.Q(overall_rating__isnull=True) |
                    (models.Q(overall_rating__gte=0) & models.Q(overall_rating__lte=5))
                ),
                name='ats_application_overall_rating_range'
            ),
            # CHECK constraint: 0 <= ai_match_score <= 100
            models.CheckConstraint(
                check=(
                    models.Q(ai_match_score__isnull=True) |
                    (models.Q(ai_match_score__gte=0) & models.Q(ai_match_score__lte=100))
                ),
                name='ats_application_ai_match_score_range'
            ),
        ]

    def __str__(self):
        return f"{self.candidate.full_name} -> {self.job.title}"

    def save(self, *args, **kwargs):
        """
        Save with optimistic locking to prevent concurrent modification conflicts.

        Uses atomic version increment with F() expression to prevent race conditions.
        Verifies version hasn't changed since the record was read.

        Raises:
            ConcurrentModificationError: If the record was modified by another
                process since it was read.
        """
        # Auto-populate tenant if not set
        if not self.tenant_id:
            try:
                from django.db import connection
                tenant = getattr(connection, 'tenant', None)
                if tenant:
                    self.tenant = tenant
            except Exception:
                pass

        # Optimistic locking for existing records
        if self.pk:
            expected_version = self.version
            # Check if the record still has the expected version
            current_version = Application.objects.filter(pk=self.pk).values_list(
                'version', flat=True
            ).first()

            if current_version is not None and current_version != expected_version:
                raise ConcurrentModificationError(
                    model_name='Application',
                    object_id=self.pk,
                    expected_version=expected_version,
                    actual_version=current_version
                )

            # Use atomic increment with update() and F() expression
            update_fields = kwargs.get('update_fields')
            if update_fields is None:
                # Full save - use atomic update for version
                Application.objects.filter(pk=self.pk, version=expected_version).update(
                    version=F('version') + 1
                )
                # Update local version number
                self.version = expected_version + 1

        super().save(*args, **kwargs)

    def clean(self):
        """Validate application constraints."""
        super().clean()
        errors = {}

        # Rating range validation
        if self.overall_rating is not None:
            if self.overall_rating < 0 or self.overall_rating > 5:
                errors['overall_rating'] = _('Rating must be between 0 and 5.')

        # AI score range validation
        if self.ai_match_score is not None:
            if self.ai_match_score < 0 or self.ai_match_score > 100:
                errors['ai_match_score'] = _('AI match score must be between 0 and 100.')

        if errors:
            raise ValidationError(errors)

    @property
    def is_active(self) -> bool:
        """Check if application is in an active (non-terminal) status."""
        return self.status in self.ACTIVE_STATUSES

    @property
    def is_terminal(self) -> bool:
        """Check if application has reached a terminal status."""
        return self.status in self.TERMINAL_STATUSES

    @property
    def can_advance(self) -> bool:
        """Check if application can advance to next stage."""
        if self.is_terminal:
            return False
        if not self.current_stage:
            return True
        return not self.current_stage.is_terminal

    @property
    def can_reject(self) -> bool:
        """Check if application can be rejected."""
        return self.status not in {self.ApplicationStatus.REJECTED,
                                   self.ApplicationStatus.HIRED,
                                   self.ApplicationStatus.WITHDRAWN}

    @property
    def can_withdraw(self) -> bool:
        """Check if application can be withdrawn."""
        return self.status not in {self.ApplicationStatus.WITHDRAWN,
                                   self.ApplicationStatus.HIRED,
                                   self.ApplicationStatus.REJECTED}

    @property
    def days_in_pipeline(self) -> int:
        """Return number of days since application was submitted."""
        if not self.applied_at:
            return 0
        end_date = self.hired_at or self.rejected_at or timezone.now()
        return (end_date - self.applied_at).days

    @property
    def days_in_current_stage(self) -> Optional[int]:
        """Return number of days in current stage."""
        if not self.current_stage or not self.last_stage_change_at:
            if self.applied_at:
                return (timezone.now() - self.applied_at).days
            return None
        return (timezone.now() - self.last_stage_change_at).days

    @property
    def time_to_hire(self) -> Optional[timedelta]:
        """Return time from application to hire (if hired)."""
        if self.status != self.ApplicationStatus.HIRED or not self.hired_at:
            return None
        return self.hired_at - self.applied_at

    @property
    def interviews_count(self) -> int:
        """Return number of interviews scheduled."""
        return self.interviews.count()

    @property
    def has_pending_interviews(self) -> bool:
        """Check if there are pending interviews."""
        return self.interviews.filter(
            status__in=['scheduled', 'confirmed']
        ).exists()

    @property
    def average_interview_rating(self) -> Optional[float]:
        """Calculate average rating from all interview feedback."""
        from django.db.models import Avg
        result = InterviewFeedback.objects.filter(
            interview__application=self,
            overall_rating__isnull=False
        ).aggregate(avg=Avg('overall_rating'))
        return result['avg']

    def move_to_stage(self, stage: PipelineStage, user=None, notes: str = ''):
        """
        Move application to a new pipeline stage with transaction protection.

        Uses select_for_update() to prevent race conditions when multiple users
        try to move the same application simultaneously.

        Args:
            stage: The PipelineStage to move the application to.
            user: The user performing the action.
            notes: Optional notes about the stage change.

        Raises:
            ValidationError: If the application is in a terminal state.
        """
        with transaction.atomic():
            # Lock the application row to prevent concurrent modifications
            locked_app = Application.objects.select_for_update().get(pk=self.pk)

            if locked_app.is_terminal:
                raise ValidationError(_('Cannot move a terminal application.'))

            old_stage = locked_app.current_stage
            locked_app.current_stage = stage
            locked_app.last_stage_change_at = timezone.now()
            locked_app.save(update_fields=['current_stage', 'last_stage_change_at', 'updated_at'])

            # Update self to reflect the changes
            self.current_stage = stage
            self.last_stage_change_at = locked_app.last_stage_change_at

            # Log the stage change
            ApplicationActivity.objects.create(
                application=locked_app,
                activity_type=ApplicationActivity.ActivityType.STAGE_CHANGE,
                performed_by=user,
                old_value=old_stage.name if old_stage else '',
                new_value=stage.name,
                notes=notes,
            )

            # Update candidate last activity
            locked_app.candidate.update_last_activity()

    def advance_to_next_stage(self, user=None, notes: str = ''):
        """Advance to the next stage in the pipeline."""
        if not self.can_advance:
            raise ValidationError(_('Cannot advance this application.'))

        if not self.current_stage:
            # Move to first stage
            if self.job.pipeline:
                first_stage = self.job.pipeline.stages.filter(
                    is_active=True
                ).order_by('order').first()
                if first_stage:
                    self.move_to_stage(first_stage, user, notes)
            return

        next_stage = self.current_stage.get_next_stage()
        if next_stage:
            self.move_to_stage(next_stage, user, notes)
        else:
            raise ValidationError(_('No next stage available.'))

    def reject(self, reason: str = '', feedback: str = '', user=None,
               send_email: bool = True):
        """Reject the application."""
        if not self.can_reject:
            raise ValidationError(_('This application cannot be rejected.'))

        old_status = self.status
        self.status = self.ApplicationStatus.REJECTED
        self.rejection_reason = reason
        self.rejection_feedback = feedback
        self.rejected_at = timezone.now()
        self.send_rejection_email = send_email
        self.save()

        ApplicationActivity.objects.create(
            application=self,
            activity_type=ApplicationActivity.ActivityType.STATUS_CHANGE,
            performed_by=user,
            old_value=old_status,
            new_value=self.ApplicationStatus.REJECTED,
            notes=reason,
        )

        # Update candidate last activity
        self.candidate.update_last_activity()

    def withdraw(self, reason: str = '', user=None):
        """Withdraw the application (candidate-initiated)."""
        if not self.can_withdraw:
            raise ValidationError(_('This application cannot be withdrawn.'))

        old_status = self.status
        self.status = self.ApplicationStatus.WITHDRAWN
        self.save(update_fields=['status', 'updated_at'])

        ApplicationActivity.objects.create(
            application=self,
            activity_type=ApplicationActivity.ActivityType.STATUS_CHANGE,
            performed_by=user,
            old_value=old_status,
            new_value=self.ApplicationStatus.WITHDRAWN,
            notes=reason,
        )

    def hire(self, user=None):
        """Mark the application as hired."""
        if self.status == self.ApplicationStatus.HIRED:
            return

        old_status = self.status
        self.status = self.ApplicationStatus.HIRED
        self.hired_at = timezone.now()
        self.save(update_fields=['status', 'hired_at', 'updated_at'])

        ApplicationActivity.objects.create(
            application=self,
            activity_type=ApplicationActivity.ActivityType.STATUS_CHANGE,
            performed_by=user,
            old_value=old_status,
            new_value=self.ApplicationStatus.HIRED,
        )

        # Update candidate last activity
        self.candidate.update_last_activity()

    def put_on_hold(self, reason: str = '', user=None):
        """Put the application on hold."""
        if self.is_terminal:
            raise ValidationError(_('Cannot put a terminal application on hold.'))

        old_status = self.status
        self.status = self.ApplicationStatus.ON_HOLD
        self.save(update_fields=['status', 'updated_at'])

        ApplicationActivity.objects.create(
            application=self,
            activity_type=ApplicationActivity.ActivityType.STATUS_CHANGE,
            performed_by=user,
            old_value=old_status,
            new_value=self.ApplicationStatus.ON_HOLD,
            notes=reason,
        )

    def update_rating(self, rating: float, user=None):
        """Update the overall rating."""
        if rating < 0 or rating > 5:
            raise ValidationError(_('Rating must be between 0 and 5.'))

        old_rating = self.overall_rating
        self.overall_rating = rating
        self.save(update_fields=['overall_rating', 'updated_at'])

        ApplicationActivity.objects.create(
            application=self,
            activity_type=ApplicationActivity.ActivityType.RATING_UPDATED,
            performed_by=user,
            old_value=str(old_rating) if old_rating else '',
            new_value=str(rating),
        )

    def assign_to(self, assignee, user=None):
        """Assign application to a reviewer."""
        old_assignee = self.assigned_to
        self.assigned_to = assignee
        self.save(update_fields=['assigned_to', 'updated_at'])

        ApplicationActivity.objects.create(
            application=self,
            activity_type=ApplicationActivity.ActivityType.ASSIGNED,
            performed_by=user,
            old_value=str(old_assignee) if old_assignee else '',
            new_value=str(assignee) if assignee else 'Unassigned',
        )


class ApplicationActivity(models.Model):
    """
    Activity log for application events.
    Tracks all changes and interactions.
    """

    class ActivityType(models.TextChoices):
        CREATED = 'created', _('Application Created')
        STATUS_CHANGE = 'status_change', _('Status Changed')
        STAGE_CHANGE = 'stage_change', _('Stage Changed')
        NOTE_ADDED = 'note_added', _('Note Added')
        EMAIL_SENT = 'email_sent', _('Email Sent')
        INTERVIEW_SCHEDULED = 'interview_scheduled', _('Interview Scheduled')
        FEEDBACK_SUBMITTED = 'feedback_submitted', _('Feedback Submitted')
        RATING_UPDATED = 'rating_updated', _('Rating Updated')
        DOCUMENT_UPLOADED = 'document_uploaded', _('Document Uploaded')
        ASSIGNED = 'assigned', _('Assigned to Reviewer')
        OFFER_CREATED = 'offer_created', _('Offer Created')
        OFFER_ACCEPTED = 'offer_accepted', _('Offer Accepted')
        OFFER_DECLINED = 'offer_declined', _('Offer Declined')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False)
    application = models.ForeignKey(
        Application,
        on_delete=models.CASCADE,
        related_name='activities'
    )
    activity_type = models.CharField(
        max_length=30,
        choices=ActivityType.choices
    )
    performed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    old_value = models.CharField(max_length=200, blank=True)
    new_value = models.CharField(max_length=200, blank=True)
    notes = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Application Activity')
        verbose_name_plural = _('Application Activities')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.application} - {self.get_activity_type_display()}"


class ApplicationNote(models.Model):
    """Notes and comments on applications."""

    uuid = models.UUIDField(default=uuid.uuid4, editable=False)
    application = models.ForeignKey(
        Application,
        on_delete=models.CASCADE,
        related_name='notes'
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True
    )
    content = models.TextField()
    is_private = models.BooleanField(
        default=False,
        help_text=_('Private notes are only visible to recruiters')
    )
    mentions = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        related_name='mentioned_in_notes'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Application Note')
        verbose_name_plural = _('Application Notes')
        ordering = ['-created_at']

    def __str__(self):
        return f"Note on {self.application} by {self.author}"


class Interview(models.Model):
    """
    Interview scheduling and management.

    Enhanced with video conferencing integration, timezone-aware scheduling,
    reminder tracking, and interview template support.
    """

    class InterviewStatus(models.TextChoices):
        SCHEDULED = 'scheduled', _('Scheduled')
        CONFIRMED = 'confirmed', _('Confirmed')
        IN_PROGRESS = 'in_progress', _('In Progress')
        COMPLETED = 'completed', _('Completed')
        CANCELLED = 'cancelled', _('Cancelled')
        NO_SHOW = 'no_show', _('No Show')
        RESCHEDULED = 'rescheduled', _('Rescheduled')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    application = models.ForeignKey(
        Application,
        on_delete=models.CASCADE,
        related_name='interviews'
    )

    # Type & Status (using global InterviewType)
    interview_type = models.CharField(
        max_length=20,
        choices=InterviewType.choices,
        default=InterviewType.VIDEO
    )
    status = models.CharField(
        max_length=20,
        choices=InterviewStatus.choices,
        default=InterviewStatus.SCHEDULED
    )
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)

    # Interview Template (NEW)
    interview_template = models.ForeignKey(
        InterviewTemplate,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='interviews',
        help_text=_('Template used for this interview')
    )

    # Scheduling
    scheduled_start = models.DateTimeField()
    scheduled_end = models.DateTimeField()
    timezone = models.CharField(max_length=50, default='America/Toronto')
    actual_start = models.DateTimeField(null=True, blank=True)
    actual_end = models.DateTimeField(null=True, blank=True)

    # Candidate Timezone (NEW)
    candidate_timezone = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('Candidate\'s timezone for scheduling convenience')
    )

    # Location/Meeting
    location = models.CharField(max_length=300, blank=True)
    meeting_url = models.URLField(
        blank=True,
        help_text=_('Video conferencing link')
    )
    meeting_id = models.CharField(max_length=100, blank=True)
    meeting_password = models.CharField(max_length=50, blank=True)

    # Video Conferencing Provider (NEW)
    meeting_provider = models.CharField(
        max_length=20,
        choices=MeetingProvider.choices,
        blank=True,
        help_text=_('Video conferencing platform')
    )
    meeting_link = models.URLField(
        blank=True,
        help_text=_('Alternative meeting link field for custom providers')
    )

    # Participants
    interviewers = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='interviews_as_interviewer'
    )
    organizer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='organized_interviews'
    )

    # Calendar Integration (ENHANCED)
    calendar_event_id = models.CharField(
        max_length=255,
        blank=True,
        help_text=_('External calendar event ID (Google, Outlook, etc.)')
    )
    calendar_provider = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('Calendar provider (google, outlook, ical)')
    )
    candidate_calendar_event_id = models.CharField(
        max_length=255,
        blank=True,
        help_text=_('Calendar event ID sent to candidate')
    )

    # Notification Status
    candidate_notified = models.BooleanField(default=False)
    interviewers_notified = models.BooleanField(default=False)

    # Reminder Tracking (NEW)
    reminder_sent_1day = models.BooleanField(
        default=False,
        help_text=_('Whether 1-day reminder was sent')
    )
    reminder_sent_1hour = models.BooleanField(
        default=False,
        help_text=_('Whether 1-hour reminder was sent')
    )
    reminder_sent_15min = models.BooleanField(
        default=False,
        help_text=_('Whether 15-minute reminder was sent')
    )

    # Notes
    preparation_notes = models.TextField(blank=True)
    interview_guide = models.TextField(blank=True)
    cancellation_reason = models.TextField(
        blank=True,
        help_text=_('Reason for cancellation if cancelled')
    )
    reschedule_count = models.PositiveIntegerField(
        default=0,
        help_text=_('Number of times this interview has been rescheduled')
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    confirmed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('When the candidate confirmed attendance')
    )
    cancelled_at = models.DateTimeField(null=True, blank=True)

    # Tenant-aware manager for filtering through application
    objects = InterviewTenantManager()

    class Meta:
        verbose_name = _('Interview')
        verbose_name_plural = _('Interviews')
        ordering = ['scheduled_start']
        indexes = [
            models.Index(fields=['application', 'status']),
            models.Index(fields=['scheduled_start', 'status']),
            models.Index(fields=['interview_type', 'scheduled_start']),
        ]

    def __str__(self):
        return f"{self.title} - {self.application.candidate.full_name}"

    @property
    def tenant(self):
        """Access tenant through parent application."""
        return self.application.tenant if self.application else None

    def validate_tenant_access(self, request_tenant):
        """
        Validate that the requesting tenant has access to this interview.

        Args:
            request_tenant: The tenant making the request

        Returns:
            True if access is valid, False otherwise
        """
        return self.tenant == request_tenant

    def clean(self):
        """Validate interview constraints."""
        super().clean()
        errors = {}

        if self.scheduled_end and self.scheduled_start:
            if self.scheduled_end <= self.scheduled_start:
                errors['scheduled_end'] = _('End time must be after start time.')

        if errors:
            raise ValidationError(errors)

    @property
    def duration_minutes(self) -> int:
        """Return scheduled duration in minutes."""
        if self.scheduled_start and self.scheduled_end:
            delta = self.scheduled_end - self.scheduled_start
            return int(delta.total_seconds() / 60)
        return 0

    @property
    def actual_duration_minutes(self) -> Optional[int]:
        """Return actual duration in minutes if available."""
        if self.actual_start and self.actual_end:
            delta = self.actual_end - self.actual_start
            return int(delta.total_seconds() / 60)
        return None

    @property
    def is_upcoming(self) -> bool:
        """Check if interview is upcoming (not started yet)."""
        return (
            self.status in [self.InterviewStatus.SCHEDULED, self.InterviewStatus.CONFIRMED]
            and self.scheduled_start > timezone.now()
        )

    @property
    def is_past(self) -> bool:
        """Check if interview end time has passed."""
        return self.scheduled_end < timezone.now()

    @property
    def is_today(self) -> bool:
        """Check if interview is scheduled for today."""
        today = timezone.now().date()
        return self.scheduled_start.date() == today

    @property
    def needs_1day_reminder(self) -> bool:
        """Check if 1-day reminder should be sent."""
        if self.reminder_sent_1day or self.status == self.InterviewStatus.CANCELLED:
            return False
        time_until = self.scheduled_start - timezone.now()
        return timedelta(hours=23) <= time_until <= timedelta(hours=25)

    @property
    def needs_1hour_reminder(self) -> bool:
        """Check if 1-hour reminder should be sent."""
        if self.reminder_sent_1hour or self.status == self.InterviewStatus.CANCELLED:
            return False
        time_until = self.scheduled_start - timezone.now()
        return timedelta(minutes=55) <= time_until <= timedelta(minutes=65)

    @property
    def meeting_url_display(self) -> str:
        """Return the best available meeting URL."""
        return self.meeting_link or self.meeting_url or ''

    @property
    def all_feedback_submitted(self) -> bool:
        """Check if all interviewers have submitted feedback."""
        interviewer_count = self.interviewers.count()
        feedback_count = self.feedback.count()
        return interviewer_count > 0 and feedback_count >= interviewer_count

    def confirm(self, confirmed_by_candidate: bool = True) -> None:
        """Mark interview as confirmed."""
        self.status = self.InterviewStatus.CONFIRMED
        self.confirmed_at = timezone.now()
        self.save(update_fields=['status', 'confirmed_at', 'updated_at'])

    def start(self) -> None:
        """Mark interview as in progress."""
        self.status = self.InterviewStatus.IN_PROGRESS
        self.actual_start = timezone.now()
        self.save(update_fields=['status', 'actual_start', 'updated_at'])

    def complete(self) -> None:
        """Mark interview as completed."""
        self.status = self.InterviewStatus.COMPLETED
        self.actual_end = timezone.now()
        self.save(update_fields=['status', 'actual_end', 'updated_at'])

    def cancel(self, reason: str = '') -> None:
        """Cancel the interview."""
        self.status = self.InterviewStatus.CANCELLED
        self.cancellation_reason = reason
        self.cancelled_at = timezone.now()
        self.save(update_fields=['status', 'cancellation_reason', 'cancelled_at', 'updated_at'])

    def reschedule(self, new_start: 'datetime', new_end: 'datetime') -> None:
        """Reschedule the interview to new times."""
        self.scheduled_start = new_start
        self.scheduled_end = new_end
        self.status = self.InterviewStatus.RESCHEDULED
        self.reschedule_count += 1
        # Reset reminder flags for the new time
        self.reminder_sent_1day = False
        self.reminder_sent_1hour = False
        self.reminder_sent_15min = False
        self.save(update_fields=[
            'scheduled_start', 'scheduled_end', 'status', 'reschedule_count',
            'reminder_sent_1day', 'reminder_sent_1hour', 'reminder_sent_15min', 'updated_at'
        ])

    def mark_no_show(self) -> None:
        """Mark interview as no-show."""
        self.status = self.InterviewStatus.NO_SHOW
        self.save(update_fields=['status', 'updated_at'])

    def mark_reminder_sent(self, reminder_type: str) -> None:
        """
        Mark a reminder as sent.

        Args:
            reminder_type: One of '1day', '1hour', or '15min'
        """
        field_map = {
            '1day': 'reminder_sent_1day',
            '1hour': 'reminder_sent_1hour',
            '15min': 'reminder_sent_15min',
        }
        if reminder_type in field_map:
            setattr(self, field_map[reminder_type], True)
            self.save(update_fields=[field_map[reminder_type], 'updated_at'])

    def get_candidate_local_time(self) -> Optional['datetime']:
        """Get the scheduled start time in candidate's timezone."""
        if not self.candidate_timezone:
            return self.scheduled_start
        try:
            import pytz
            candidate_tz = pytz.timezone(self.candidate_timezone)
            return self.scheduled_start.astimezone(candidate_tz)
        except Exception:
            return self.scheduled_start

    def apply_template(self, template: InterviewTemplate) -> None:
        """Apply an interview template to this interview."""
        self.interview_template = template
        self.interview_type = template.interview_type
        self.interview_guide = template.instructions
        self.preparation_notes = template.preparation_guide
        # Calculate end time based on template duration
        if template.default_duration:
            self.scheduled_end = self.scheduled_start + template.default_duration
        self.save()


class InterviewFeedback(models.Model):
    """Feedback from interviewers after interviews."""

    uuid = models.UUIDField(default=uuid.uuid4, editable=False)
    interview = models.ForeignKey(
        Interview,
        on_delete=models.CASCADE,
        related_name='feedback'
    )
    interviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True
    )

    # Ratings
    overall_rating = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    technical_skills = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    communication = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    cultural_fit = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    problem_solving = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )

    # Recommendation
    recommendation = models.CharField(
        max_length=20,
        choices=[
            ('strong_yes', _('Strong Yes')),
            ('yes', _('Yes')),
            ('maybe', _('Maybe')),
            ('no', _('No')),
            ('strong_no', _('Strong No')),
        ]
    )

    # Written Feedback
    strengths = models.TextField(blank=True)
    weaknesses = models.TextField(blank=True)
    notes = models.TextField(blank=True)
    private_notes = models.TextField(
        blank=True,
        help_text=_('Only visible to HR/admins')
    )

    # Custom criteria
    custom_ratings = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    submitted_at = models.DateTimeField(null=True, blank=True)

    # Tenant-aware manager for filtering through interview -> application
    objects = InterviewFeedbackTenantManager()

    class Meta:
        verbose_name = _('Interview Feedback')
        verbose_name_plural = _('Interview Feedback')
        unique_together = ['interview', 'interviewer']

    @property
    def tenant(self):
        """Access tenant through interview's application."""
        if self.interview and self.interview.application:
            return self.interview.application.tenant
        return None

    def validate_tenant_access(self, request_tenant):
        """
        Validate that the requesting tenant has access to this feedback.

        Args:
            request_tenant: The tenant making the request

        Returns:
            True if access is valid, False otherwise
        """
        return self.tenant == request_tenant

    def __str__(self):
        return f"Feedback from {self.interviewer} on {self.interview}"


class Offer(models.Model):
    """
    Job offers extended to candidates.

    Enhanced with approval workflows, e-signature integration,
    and counter-offer chain support.
    """

    class OfferStatus(models.TextChoices):
        DRAFT = 'draft', _('Draft')
        PENDING_APPROVAL = 'pending_approval', _('Pending Approval')
        APPROVED = 'approved', _('Approved')
        SENT = 'sent', _('Sent to Candidate')
        ACCEPTED = 'accepted', _('Accepted')
        DECLINED = 'declined', _('Declined')
        EXPIRED = 'expired', _('Expired')
        WITHDRAWN = 'withdrawn', _('Withdrawn')
        COUNTERED = 'countered', _('Counter-Offered')

    class ApprovalStatusChoices(models.TextChoices):
        NOT_REQUIRED = 'not_required', _('Not Required')
        PENDING_APPROVAL = 'pending_approval', _('Pending Approval')
        APPROVED = 'approved', _('Approved')
        REJECTED = 'rejected', _('Rejected')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    application = models.ForeignKey(
        Application,
        on_delete=models.CASCADE,
        related_name='offers'
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=OfferStatus.choices,
        default=OfferStatus.DRAFT
    )

    # Approval Workflow (NEW)
    approval_status = models.CharField(
        max_length=20,
        choices=ApprovalStatusChoices.choices,
        default=ApprovalStatusChoices.NOT_REQUIRED,
        help_text=_('Current approval workflow status')
    )
    approval_level_required = models.PositiveIntegerField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(4)],
        help_text=_('Highest approval level required (0=none, 1=Manager, 2=Director, 3=VP, 4=C-Level)')
    )
    current_approval_level = models.PositiveIntegerField(
        default=0,
        help_text=_('Current approval level reached')
    )

    # Offer Details
    job_title = models.CharField(max_length=200)
    department = models.CharField(max_length=100, blank=True)
    reports_to = models.CharField(max_length=200, blank=True)
    start_date = models.DateField(null=True, blank=True)
    employment_type = models.CharField(max_length=50, default='full_time')

    # Compensation
    base_salary = models.DecimalField(max_digits=12, decimal_places=2)
    salary_currency = models.CharField(max_length=3, default='CAD')
    salary_period = models.CharField(max_length=20, default='yearly')
    signing_bonus = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True
    )
    annual_bonus_target = models.CharField(max_length=100, blank=True)
    equity = models.TextField(blank=True)
    other_compensation = models.TextField(blank=True)

    # Benefits
    benefits_summary = models.TextField(blank=True)
    pto_days = models.PositiveIntegerField(null=True, blank=True)
    remote_policy = models.CharField(max_length=100, blank=True)

    # Terms
    offer_letter_content = models.TextField(blank=True)
    terms_and_conditions = models.TextField(blank=True)
    expiration_date = models.DateField(null=True, blank=True)

    # E-Signature (ENHANCED)
    requires_signature = models.BooleanField(default=True)
    signature_document_id = models.CharField(max_length=255, blank=True)
    signed_at = models.DateTimeField(null=True, blank=True)

    # E-Sign Provider (NEW)
    esign_provider = models.CharField(
        max_length=20,
        choices=ESignProvider.choices,
        blank=True,
        help_text=_('E-signature provider (docusign, hellosign, etc.)')
    )
    esign_envelope_id = models.CharField(
        max_length=255,
        blank=True,
        help_text=_('E-signature envelope/document ID from provider')
    )
    esign_status = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('E-signature status from provider')
    )
    esign_completed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('When e-signature was completed')
    )

    # Approvals (single approver - legacy support)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='approved_offers'
    )
    approved_at = models.DateTimeField(null=True, blank=True)

    # Counter-offer chain (NEW)
    counter_offer_count = models.PositiveIntegerField(
        default=0,
        help_text=_('Number of counter-offers in this negotiation')
    )
    previous_offer = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='counter_offers',
        help_text=_('Previous offer in the counter-offer chain')
    )
    is_counter_offer = models.BooleanField(
        default=False,
        help_text=_('Whether this is a counter-offer')
    )
    counter_offer_notes = models.TextField(
        blank=True,
        help_text=_('Notes explaining changes from previous offer')
    )

    # Response
    response_notes = models.TextField(blank=True)
    decline_reason = models.CharField(max_length=200, blank=True)

    # Offer Template (NEW)
    offer_template = models.ForeignKey(
        'OfferTemplate',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='offers',
        help_text=_('Template used to create this offer')
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    responded_at = models.DateTimeField(null=True, blank=True)

    # Creator
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_offers'
    )

    # Tenant-aware manager for filtering through application
    objects = OfferTenantManager()

    class Meta:
        verbose_name = _('Offer')
        verbose_name_plural = _('Offers')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['application', 'status']),
            models.Index(fields=['approval_status']),
            models.Index(fields=['status', 'created_at']),
        ]

    @property
    def tenant(self):
        """Access tenant through parent application."""
        return self.application.tenant if self.application else None

    def validate_tenant_access(self, request_tenant):
        """
        Validate that the requesting tenant has access to this offer.

        Args:
            request_tenant: The tenant making the request

        Returns:
            True if access is valid, False otherwise
        """
        return self.tenant == request_tenant

    def __str__(self):
        counter = f" (Counter #{self.counter_offer_count})" if self.is_counter_offer else ""
        return f"Offer to {self.application.candidate.full_name} - {self.job_title}{counter}"

    def clean(self):
        """Validate offer constraints."""
        super().clean()
        errors = {}

        # Check expiration date
        if self.expiration_date and self.status == self.OfferStatus.SENT:
            from datetime import date
            if self.expiration_date < date.today():
                errors['expiration_date'] = _('Expiration date cannot be in the past for sent offers.')

        # Validate counter-offer chain
        if self.previous_offer:
            if self.previous_offer.application != self.application:
                errors['previous_offer'] = _('Counter-offer must be for the same application.')

        if errors:
            raise ValidationError(errors)

    @property
    def is_pending_approval(self) -> bool:
        """Check if offer is waiting for approval."""
        return self.approval_status == self.ApprovalStatusChoices.PENDING_APPROVAL

    @property
    def is_approved(self) -> bool:
        """Check if offer has been fully approved."""
        return (
            self.approval_status == self.ApprovalStatusChoices.APPROVED or
            self.approval_status == self.ApprovalStatusChoices.NOT_REQUIRED
        )

    @property
    def can_be_sent(self) -> bool:
        """Check if offer can be sent to candidate."""
        return (
            self.status in [self.OfferStatus.DRAFT, self.OfferStatus.APPROVED] and
            self.is_approved
        )

    @property
    def is_expired(self) -> bool:
        """Check if offer has expired."""
        if not self.expiration_date:
            return False
        from datetime import date
        return self.expiration_date < date.today() and self.status == self.OfferStatus.SENT

    @property
    def days_until_expiration(self) -> Optional[int]:
        """Return days until expiration (negative if expired)."""
        if not self.expiration_date:
            return None
        from datetime import date
        return (self.expiration_date - date.today()).days

    @property
    def total_compensation(self) -> Decimal:
        """Calculate total annual compensation."""
        total = self.base_salary
        if self.signing_bonus:
            total += self.signing_bonus
        return total

    @property
    def offer_chain(self) -> List['Offer']:
        """Return the full chain of offers in this negotiation."""
        chain = [self]
        current = self
        while current.previous_offer:
            chain.insert(0, current.previous_offer)
            current = current.previous_offer
        return chain

    @property
    def pending_approvals_count(self) -> int:
        """Return count of pending approvals."""
        return self.approvals.filter(status='pending').count()

    def send_to_candidate(self):
        """Send offer to candidate."""
        if not self.can_be_sent:
            raise ValidationError(_('Offer cannot be sent - approval may be required.'))
        self.status = self.OfferStatus.SENT
        self.sent_at = timezone.now()
        self.save(update_fields=['status', 'sent_at', 'updated_at'])

    def accept(self):
        """
        Mark offer as accepted with transaction protection.

        Uses select_for_update() to atomically update both the offer and
        the application status, preventing race conditions where multiple
        offers for the same application could be accepted simultaneously.

        Raises:
            ValidationError: If the offer is not in a state that can be accepted.
        """
        with transaction.atomic():
            # Lock both the offer and the application to prevent race conditions
            locked_offer = Offer.objects.select_for_update().get(pk=self.pk)
            locked_app = Application.objects.select_for_update().get(
                pk=locked_offer.application_id
            )

            # Verify offer can be accepted
            if locked_offer.status != self.OfferStatus.SENT:
                raise ValidationError(
                    _('Only sent offers can be accepted. Current status: %(status)s'),
                    params={'status': locked_offer.status}
                )

            # Update offer status
            locked_offer.status = self.OfferStatus.ACCEPTED
            locked_offer.responded_at = timezone.now()
            locked_offer.save(update_fields=['status', 'responded_at', 'updated_at'])

            # Update application status
            locked_app.status = Application.ApplicationStatus.HIRED
            locked_app.hired_at = timezone.now()
            locked_app.save(update_fields=['status', 'hired_at', 'updated_at'])

            # Update self to reflect the changes
            self.status = locked_offer.status
            self.responded_at = locked_offer.responded_at

            # Log the activity
            ApplicationActivity.objects.create(
                application=locked_app,
                activity_type=ApplicationActivity.ActivityType.OFFER_ACCEPTED,
                new_value=self.OfferStatus.ACCEPTED,
                notes=f'Offer for {locked_offer.job_title} accepted',
            )

    def decline(self, reason=''):
        """Mark offer as declined."""
        self.status = self.OfferStatus.DECLINED
        self.decline_reason = reason
        self.responded_at = timezone.now()
        self.save(update_fields=['status', 'decline_reason', 'responded_at', 'updated_at'])

    def withdraw(self, reason: str = '') -> None:
        """Withdraw the offer."""
        if self.status in [self.OfferStatus.ACCEPTED, self.OfferStatus.DECLINED]:
            raise ValidationError(_('Cannot withdraw an offer that has been responded to.'))
        self.status = self.OfferStatus.WITHDRAWN
        self.response_notes = reason
        self.save(update_fields=['status', 'response_notes', 'updated_at'])

    def expire(self) -> None:
        """Mark offer as expired."""
        if self.status != self.OfferStatus.SENT:
            return
        self.status = self.OfferStatus.EXPIRED
        self.save(update_fields=['status', 'updated_at'])

    def create_counter_offer(
        self,
        base_salary: Decimal,
        created_by=None,
        notes: str = '',
        **kwargs
    ) -> 'Offer':
        """
        Create a counter-offer based on this offer.

        Args:
            base_salary: New base salary for the counter-offer
            created_by: User creating the counter-offer
            notes: Notes explaining the changes
            **kwargs: Additional fields to update

        Returns:
            New Offer instance as a counter-offer
        """
        # Mark this offer as countered
        self.status = self.OfferStatus.COUNTERED
        self.save(update_fields=['status', 'updated_at'])

        # Create new counter-offer
        counter = Offer(
            application=self.application,
            job_title=self.job_title,
            department=self.department,
            reports_to=self.reports_to,
            start_date=self.start_date,
            employment_type=self.employment_type,
            base_salary=base_salary,
            salary_currency=self.salary_currency,
            salary_period=self.salary_period,
            signing_bonus=kwargs.get('signing_bonus', self.signing_bonus),
            annual_bonus_target=kwargs.get('annual_bonus_target', self.annual_bonus_target),
            equity=kwargs.get('equity', self.equity),
            other_compensation=kwargs.get('other_compensation', self.other_compensation),
            benefits_summary=kwargs.get('benefits_summary', self.benefits_summary),
            pto_days=kwargs.get('pto_days', self.pto_days),
            remote_policy=kwargs.get('remote_policy', self.remote_policy),
            offer_letter_content=self.offer_letter_content,
            terms_and_conditions=self.terms_and_conditions,
            expiration_date=kwargs.get('expiration_date', self.expiration_date),
            requires_signature=self.requires_signature,
            esign_provider=self.esign_provider,
            # Counter-offer specific
            previous_offer=self,
            is_counter_offer=True,
            counter_offer_count=self.counter_offer_count + 1,
            counter_offer_notes=notes,
            created_by=created_by,
        )
        counter.save()

        # Log the activity
        ApplicationActivity.objects.create(
            application=self.application,
            activity_type=ApplicationActivity.ActivityType.OFFER_CREATED,
            performed_by=created_by,
            notes=f'Counter-offer #{counter.counter_offer_count} created',
            metadata={'previous_offer_id': self.pk, 'new_salary': str(base_salary)}
        )

        return counter

    def request_approval(self, approvers: List[Dict], requested_by=None) -> List['OfferApproval']:
        """
        Initiate the approval workflow for this offer.

        Args:
            approvers: List of dicts with 'user' and 'level' keys
            requested_by: User requesting approval

        Returns:
            List of created OfferApproval instances
        """
        from .models import OfferApproval  # Import here to avoid circular import

        self.status = self.OfferStatus.PENDING_APPROVAL
        self.approval_status = self.ApprovalStatusChoices.PENDING_APPROVAL
        self.save(update_fields=['status', 'approval_status', 'updated_at'])

        return OfferApproval.create_approval_chain(
            offer=self,
            approvers=approvers,
            requested_by=requested_by
        )

    def apply_template(self, template: 'OfferTemplate', context: Dict[str, Any] = None) -> None:
        """
        Apply an offer template to this offer.

        Args:
            template: The OfferTemplate to apply
            context: Template rendering context
        """
        self.offer_template = template
        template.apply_to_offer(self, context)
        self.save()

    def mark_esign_complete(self, envelope_id: str = None) -> None:
        """Mark the e-signature as complete."""
        self.esign_status = 'completed'
        self.esign_completed_at = timezone.now()
        self.signed_at = timezone.now()
        if envelope_id:
            self.esign_envelope_id = envelope_id
        self.save(update_fields=[
            'esign_status', 'esign_completed_at', 'signed_at',
            'esign_envelope_id', 'updated_at'
        ])

    def get_salary_difference_from_previous(self) -> Optional[Dict[str, Any]]:
        """
        Get salary difference from previous offer in the chain.

        Returns:
            Dict with 'amount', 'percentage', and 'direction' or None
        """
        if not self.previous_offer:
            return None

        prev_salary = self.previous_offer.base_salary
        curr_salary = self.base_salary
        difference = curr_salary - prev_salary
        percentage = (difference / prev_salary * 100) if prev_salary else 0

        return {
            'amount': difference,
            'percentage': round(percentage, 2),
            'direction': 'increase' if difference > 0 else 'decrease' if difference < 0 else 'same'
        }


class SavedSearch(models.Model):
    """Saved candidate searches for quick access."""

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='saved_searches'
    )
    name = models.CharField(max_length=100)
    filters = models.JSONField(default=dict)
    is_alert_enabled = models.BooleanField(
        default=False,
        help_text=_('Get notified when new candidates match')
    )
    alert_frequency = models.CharField(
        max_length=20,
        choices=[
            ('instant', _('Instant')),
            ('daily', _('Daily')),
            ('weekly', _('Weekly')),
        ],
        default='daily'
    )
    last_run_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Saved Search')
        verbose_name_plural = _('Saved Searches')
        ordering = ['-updated_at']

    def __str__(self):
        return f"{self.name} by {self.user.email}"


# =============================================================================
# OFFER TEMPLATE MODEL
# =============================================================================

class OfferTemplate(TenantAwareModel):
    """
    Template for job offers.

    Provides standardized offer structures with salary bands, benefits packages,
    and letter templates. Uses Jinja2-style templating for dynamic content.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(
        max_length=100,
        help_text=_('Name of the offer template')
    )

    # Job level and categorization
    job_level = models.CharField(
        max_length=50,
        help_text=_('Job level (e.g., Junior, Mid, Senior, Lead, Director)')
    )
    department = models.CharField(max_length=100, blank=True)
    job_type = models.CharField(
        max_length=20,
        choices=JobPosting.JobType.choices,
        blank=True
    )

    # Salary bands
    base_salary_min = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text=_('Minimum base salary for this level')
    )
    base_salary_max = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text=_('Maximum base salary for this level')
    )
    salary_currency = models.CharField(max_length=3, default='CAD')
    salary_period = models.CharField(max_length=20, default='yearly')

    # Bonus and equity
    bonus_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Target bonus as percentage of base salary')
    )
    equity_shares = models.PositiveIntegerField(
        default=0,
        help_text=_('Number of equity shares/options')
    )
    equity_vesting_schedule = models.CharField(
        max_length=100,
        blank=True,
        help_text=_('e.g., "4 years with 1-year cliff"')
    )

    # Benefits package
    benefits_package = models.JSONField(
        default=dict,
        blank=True,
        help_text=_(
            'Benefits structure: {"health": "...", "dental": "...", "401k": "...", "pto_days": 20}'
        )
    )
    default_pto_days = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text=_('Default PTO days for this level')
    )

    # Offer letter template (Jinja2 format)
    letter_template = models.TextField(
        help_text=_(
            'Jinja2 template for offer letter. Available variables: '
            '{{ candidate_name }}, {{ job_title }}, {{ salary }}, {{ start_date }}, etc.'
        )
    )
    terms_template = models.TextField(
        blank=True,
        help_text=_('Terms and conditions template')
    )

    # Approval settings
    requires_approval = models.BooleanField(
        default=True,
        help_text=_('Whether offers using this template require approval')
    )
    approval_levels_required = models.PositiveIntegerField(
        default=1,
        validators=[MinValueValidator(0), MaxValueValidator(5)],
        help_text=_('Number of approval levels needed (0-5)')
    )

    # Status
    is_active = models.BooleanField(default=True)
    is_default = models.BooleanField(
        default=False,
        help_text=_('Use as default template for the job level')
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_offer_templates'
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _('Offer Template')
        verbose_name_plural = _('Offer Templates')
        ordering = ['job_level', 'name']
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'name'],
                name='ats_offertemplate_unique_tenant_name'
            ),
            # Salary min must be <= max
            models.CheckConstraint(
                check=Q(base_salary_min__lte=F('base_salary_max')),
                name='ats_offertemplate_salary_min_lte_max'
            ),
        ]

    def __str__(self):
        return f"{self.name} ({self.job_level})"

    def clean(self):
        """Validate template constraints."""
        super().clean()
        errors = {}

        if self.base_salary_min and self.base_salary_max:
            if self.base_salary_min > self.base_salary_max:
                errors['base_salary_min'] = _('Minimum salary cannot exceed maximum.')

        if errors:
            raise ValidationError(errors)

    @property
    def salary_range_display(self) -> str:
        """Return formatted salary range string."""
        return f"{self.salary_currency} {self.base_salary_min:,.0f} - {self.base_salary_max:,.0f}"

    @property
    def salary_midpoint(self) -> Decimal:
        """Calculate the midpoint of the salary range."""
        return (self.base_salary_min + self.base_salary_max) / 2

    def render_letter(self, context: Dict[str, Any]) -> str:
        """
        Render the offer letter with the given context.

        Args:
            context: Dictionary of template variables

        Returns:
            Rendered offer letter content
        """
        try:
            # Use Django's template engine for Jinja2-like rendering
            from django.template import Template, Context
            template = Template(self.letter_template)
            return template.render(Context(context))
        except Exception:
            # Fallback to simple replacement
            result = self.letter_template
            for key, value in context.items():
                result = result.replace('{{ ' + key + ' }}', str(value))
                result = result.replace('{{' + key + '}}', str(value))
            return result

    def is_salary_in_range(self, salary: Decimal) -> bool:
        """Check if a salary falls within the template's range."""
        return self.base_salary_min <= salary <= self.base_salary_max

    def get_benefits_list(self) -> List[str]:
        """Return benefits as a list of strings."""
        if not self.benefits_package:
            return []
        return [f"{k}: {v}" for k, v in self.benefits_package.items()]

    def apply_to_offer(self, offer: 'Offer', context: Dict[str, Any] = None) -> 'Offer':
        """
        Apply this template to an offer.

        Args:
            offer: The Offer instance to update
            context: Template context for rendering

        Returns:
            Updated Offer instance
        """
        context = context or {}

        # Set default values from template
        if not offer.pto_days and self.default_pto_days:
            offer.pto_days = self.default_pto_days

        # Render and apply letter content
        letter_context = {
            'candidate_name': offer.application.candidate.full_name,
            'job_title': offer.job_title,
            'salary': offer.base_salary,
            'start_date': offer.start_date,
            'department': offer.department,
            **context
        }
        offer.offer_letter_content = self.render_letter(letter_context)

        if self.terms_template:
            offer.terms_and_conditions = self.render_letter({**letter_context, 'template': self.terms_template})

        # Set benefits from template
        if self.benefits_package and not offer.benefits_summary:
            offer.benefits_summary = '\n'.join(self.get_benefits_list())

        return offer


# =============================================================================
# OFFER APPROVAL MODEL
# =============================================================================

class OfferApproval(TenantAwareModel):
    """
    Approval workflow for offers.

    Supports multi-level approval chains with different approver levels
    (Manager, Director, VP, C-Level). Each approval level must approve
    before the offer can be sent to the candidate.
    """

    class ApprovalStatus(models.TextChoices):
        PENDING = 'pending', _('Pending')
        APPROVED = 'approved', _('Approved')
        REJECTED = 'rejected', _('Rejected')
        SKIPPED = 'skipped', _('Skipped')
        EXPIRED = 'expired', _('Expired')

    class ApproverLevel(models.IntegerChoices):
        MANAGER = 1, _('Manager')
        DIRECTOR = 2, _('Director')
        VP = 3, _('VP')
        C_LEVEL = 4, _('C-Level')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    offer = models.ForeignKey(
        'Offer',
        on_delete=models.CASCADE,
        related_name='approvals'
    )

    # Approver details
    approver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='offer_approvals'
    )
    level = models.PositiveIntegerField(
        choices=ApproverLevel.choices,
        default=ApproverLevel.MANAGER,
        help_text=_('Approval level: 1=Manager, 2=Director, 3=VP, 4=C-Level')
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=ApprovalStatus.choices,
        default=ApprovalStatus.PENDING
    )

    # Decision details
    decided_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('When the decision was made')
    )
    comments = models.TextField(
        blank=True,
        help_text=_('Comments from the approver')
    )

    # Request tracking
    requested_at = models.DateTimeField(auto_now_add=True)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='requested_offer_approvals'
    )
    due_date = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('Deadline for this approval')
    )

    # Notification tracking
    notification_sent = models.BooleanField(default=False)
    reminder_sent = models.BooleanField(default=False)
    reminder_count = models.PositiveIntegerField(default=0)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _('Offer Approval')
        verbose_name_plural = _('Offer Approvals')
        ordering = ['offer', 'level']
        indexes = [
            models.Index(fields=['offer', 'status']),
            models.Index(fields=['approver', 'status']),
            models.Index(fields=['level', 'status']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['offer', 'approver'],
                name='ats_offerapproval_unique_offer_approver'
            ),
        ]

    def __str__(self):
        return f"L{self.level} approval for {self.offer} by {self.approver}"

    @property
    def is_pending(self) -> bool:
        """Check if approval is still pending."""
        return self.status == self.ApprovalStatus.PENDING

    @property
    def is_overdue(self) -> bool:
        """Check if approval is overdue."""
        if not self.due_date or self.status != self.ApprovalStatus.PENDING:
            return False
        return timezone.now() > self.due_date

    @property
    def days_pending(self) -> int:
        """Return number of days this approval has been pending."""
        if self.status != self.ApprovalStatus.PENDING:
            return 0
        return (timezone.now() - self.requested_at).days

    @property
    def level_display(self) -> str:
        """Return human-readable level name."""
        return self.get_level_display()

    def approve(self, comments: str = '') -> None:
        """
        Approve this approval request.

        If all approvals at required levels are complete, updates offer status.
        """
        self.status = self.ApprovalStatus.APPROVED
        self.decided_at = timezone.now()
        self.comments = comments
        self.save(update_fields=['status', 'decided_at', 'comments', 'updated_at'])

        # Check if all required approvals are complete
        self._update_offer_approval_status()

    def reject(self, reason: str = '') -> None:
        """
        Reject this approval request.

        Updates the offer status to rejected and prevents sending.
        """
        self.status = self.ApprovalStatus.REJECTED
        self.decided_at = timezone.now()
        self.comments = reason
        self.save(update_fields=['status', 'decided_at', 'comments', 'updated_at'])

        # Update offer status to indicate rejection
        self.offer.approval_status = 'rejected'
        self.offer.save(update_fields=['approval_status', 'updated_at'])

    def skip(self, reason: str = '') -> None:
        """Skip this approval (e.g., when approver is unavailable)."""
        self.status = self.ApprovalStatus.SKIPPED
        self.decided_at = timezone.now()
        self.comments = reason
        self.save(update_fields=['status', 'decided_at', 'comments', 'updated_at'])

        self._update_offer_approval_status()

    def _update_offer_approval_status(self) -> None:
        """Update the offer's approval status based on all approvals."""
        # Get all approvals for this offer
        all_approvals = self.offer.approvals.all()

        # Check for any rejections
        if all_approvals.filter(status=self.ApprovalStatus.REJECTED).exists():
            self.offer.approval_status = 'rejected'
            self.offer.save(update_fields=['approval_status', 'updated_at'])
            return

        # Check if all required levels are approved/skipped
        pending = all_approvals.filter(status=self.ApprovalStatus.PENDING)
        if not pending.exists():
            # All approvals complete
            self.offer.approval_status = 'approved'
            self.offer.approved_at = timezone.now()
            self.offer.current_approval_level = self.level
            self.offer.save(update_fields=[
                'approval_status', 'approved_at', 'current_approval_level', 'updated_at'
            ])

    @classmethod
    def create_approval_chain(
        cls,
        offer: 'Offer',
        approvers: List[Dict[str, Any]],
        requested_by=None
    ) -> List['OfferApproval']:
        """
        Create a chain of approvals for an offer.

        Args:
            offer: The Offer requiring approval
            approvers: List of dicts with 'user' and 'level' keys
            requested_by: User requesting the approvals

        Returns:
            List of created OfferApproval instances
        """
        approvals = []
        for approver_info in approvers:
            approval = cls.objects.create(
                tenant=offer.application.tenant,
                offer=offer,
                approver=approver_info['user'],
                level=approver_info['level'],
                requested_by=requested_by,
                due_date=approver_info.get('due_date'),
            )
            approvals.append(approval)

        # Update offer status
        offer.approval_status = 'pending_approval'
        offer.approval_level_required = max(a['level'] for a in approvers)
        offer.save(update_fields=['approval_status', 'approval_level_required', 'updated_at'])

        return approvals
