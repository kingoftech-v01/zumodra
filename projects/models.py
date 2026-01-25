"""
Projects Models - Tenant-level project missions.

This module defines models for project-based work:
- Projects: Specific missions with deliverables and timelines
- Providers: Profiles for offering project services
- Proposals: Provider bids on projects
- Milestones: Payment and delivery checkpoints
- Contracts: Binding agreements
- Reviews: Post-completion feedback

Architecture: Tenant-aware models using TenantAwareModel base class.
Projects are posted by company tenants and fulfilled by FreelancerProfiles.
"""

import uuid
from decimal import Decimal
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.contrib.postgres.fields import ArrayField
from django.conf import settings

from core.models import TenantAwareModel, TimestampedModel


# ============================================================================
# PROJECT CATEGORIES
# ============================================================================

class ProjectCategory(models.Model):
    """
    Hierarchical categorization for projects.

    Examples:
    - Web Development > E-commerce > Shopify Integration
    - Design > UX/UI > Mobile App Design
    - Marketing > Content > Blog Writing
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=100)
    slug = models.SlugField(max_length=120, unique=True)
    description = models.TextField(blank=True)

    # Hierarchy
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='subcategories'
    )

    # Visual representation
    icon = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('Phosphor icon name (e.g., "ph-code", "ph-palette")')
    )
    color = models.CharField(
        max_length=7,
        default='#3B82F6',
        help_text=_('Hex color code for category badge')
    )

    # Stats (denormalized for performance)
    project_count = models.PositiveIntegerField(default=0)

    # Ordering
    display_order = models.PositiveIntegerField(default=0)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Project Category')
        verbose_name_plural = _('Project Categories')
        ordering = ['display_order', 'name']
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['parent', 'display_order']),
        ]

    def __str__(self):
        if self.parent:
            return f"{self.parent.name} > {self.name}"
        return self.name

    def get_full_path(self):
        """Get full category path (e.g., 'Web Development > E-commerce > Shopify')."""
        if self.parent:
            return f"{self.parent.get_full_path()} > {self.name}"
        return self.name


# ============================================================================
# PROJECT PROVIDER PROFILES
# ============================================================================

class ProjectProvider(TenantAwareModel, TimestampedModel):
    """
    Project provider profile for tenants offering project services.

    This represents a company's capability to deliver projects.
    Can link to freelancer profiles for individual contractors.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Provider info
    name = models.CharField(max_length=255)
    description = models.TextField()
    tagline = models.CharField(max_length=200, blank=True)

    # Categories and skills
    categories = models.ManyToManyField(ProjectCategory, related_name='providers')
    skills = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True,
        help_text=_('Array of skill keywords')
    )

    # Portfolio
    portfolio_url = models.URLField(blank=True)
    portfolio_images = models.JSONField(
        default=list,
        blank=True,
        help_text=_('Array of image URLs')
    )

    # Location
    city = models.CharField(max_length=100, blank=True)
    country = models.CharField(max_length=100, blank=True)
    remote_only = models.BooleanField(default=False)

    # Availability
    is_active = models.BooleanField(default=True)
    is_accepting_projects = models.BooleanField(default=True)
    max_concurrent_projects = models.PositiveIntegerField(default=3)

    # Stats (denormalized)
    completed_projects = models.PositiveIntegerField(default=0)
    total_earnings = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00')
    )
    average_rating = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(5)]
    )
    total_reviews = models.PositiveIntegerField(default=0)

    # Verification
    is_verified = models.BooleanField(default=False)
    verification_date = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Project Provider')
        verbose_name_plural = _('Project Providers')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['tenant', 'is_active']),
            models.Index(fields=['is_accepting_projects', '-average_rating']),
        ]

    def __str__(self):
        return f"{self.name} ({self.tenant.name})"

    @property
    def active_projects_count(self):
        """Count currently active projects."""
        return self.assigned_projects.filter(
            status__in=['IN_PROGRESS', 'REVIEW']
        ).count()

    @property
    def can_accept_new_project(self):
        """Check if provider can accept new projects."""
        return (
            self.is_active and
            self.is_accepting_projects and
            self.active_projects_count < self.max_concurrent_projects
        )


# ============================================================================
# PROJECTS
# ============================================================================

class Project(TenantAwareModel, TimestampedModel):
    """
    Specific mission/mandate with deliverables and timeline.

    Different from Service (ongoing offering):
    - Fixed start/end dates
    - Specific deliverables
    - Milestone-based workflow
    - Proposal system (providers bid)
    """

    class BudgetType(models.TextChoices):
        FIXED = 'FIXED', _('Fixed Price')
        MILESTONES = 'MILESTONES', _('Milestone-based')
        TIME_MATERIALS = 'TIME_MATERIALS', _('Time & Materials')
        NEGOTIABLE = 'NEGOTIABLE', _('Negotiable')

    class ExperienceLevel(models.TextChoices):
        JUNIOR = 'JUNIOR', _('Junior (0-2 years)')
        MID = 'MID', _('Mid-level (2-5 years)')
        SENIOR = 'SENIOR', _('Senior (5+ years)')
        EXPERT = 'EXPERT', _('Expert/Lead (10+ years)')

    class LocationType(models.TextChoices):
        REMOTE = 'REMOTE', _('Remote')
        ONSITE = 'ONSITE', _('On-site')
        HYBRID = 'HYBRID', _('Hybrid')

    class Status(models.TextChoices):
        DRAFT = 'DRAFT', _('Draft')
        OPEN = 'OPEN', _('Open for Proposals')
        IN_PROGRESS = 'IN_PROGRESS', _('In Progress')
        REVIEW = 'REVIEW', _('Under Review')
        COMPLETED = 'COMPLETED', _('Completed')
        CANCELLED = 'CANCELLED', _('Cancelled')
        ON_HOLD = 'ON_HOLD', _('On Hold')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Basic info
    title = models.CharField(max_length=255)
    description = models.TextField(
        help_text=_('Detailed project description, goals, and expectations')
    )
    short_description = models.CharField(
        max_length=500,
        blank=True,
        help_text=_('Brief summary for listings')
    )

    # Classification
    category = models.ForeignKey(
        ProjectCategory,
        on_delete=models.PROTECT,
        related_name='projects'
    )
    required_skills = ArrayField(
        models.CharField(max_length=100),
        default=list,
        help_text=_('Array of required skill keywords')
    )
    experience_level = models.CharField(
        max_length=20,
        choices=ExperienceLevel.choices,
        default=ExperienceLevel.MID
    )

    # Timeline
    start_date = models.DateField(
        null=True,
        blank=True,
        help_text=_('Desired start date')
    )
    end_date = models.DateField(
        null=True,
        blank=True,
        help_text=_('Expected completion date')
    )
    estimated_duration_weeks = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text=_('Estimated duration in weeks')
    )
    deadline = models.DateField(
        null=True,
        blank=True,
        help_text=_('Hard deadline (if applicable)')
    )

    # Budget
    budget_type = models.CharField(
        max_length=20,
        choices=BudgetType.choices,
        default=BudgetType.FIXED
    )
    budget_min = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0)]
    )
    budget_max = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0)]
    )
    budget_currency = models.CharField(max_length=3, default='CAD')

    # Deliverables
    deliverables = models.JSONField(
        default=list,
        help_text=_('Array of expected deliverables with descriptions')
    )

    # Location
    location_type = models.CharField(
        max_length=20,
        choices=LocationType.choices,
        default=LocationType.REMOTE
    )
    location_city = models.CharField(max_length=100, blank=True)
    location_country = models.CharField(max_length=100, blank=True)

    # Status and workflow
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.DRAFT
    )

    # Publication
    is_published = models.BooleanField(default=False)
    published_at = models.DateTimeField(null=True, blank=True)
    published_to_catalog = models.BooleanField(
        default=False,
        help_text=_('Synced to public catalog')
    )

    # Assignment
    assigned_provider = models.ForeignKey(
        ProjectProvider,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_projects'
    )
    assigned_at = models.DateTimeField(null=True, blank=True)
    contract = models.OneToOneField(
        'ProjectContract',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='project_assignment'
    )

    # Contact
    contact_email = models.EmailField(blank=True)
    contact_person = models.CharField(max_length=200, blank=True)

    # Application settings
    max_proposals = models.PositiveIntegerField(
        default=20,
        help_text=_('Maximum number of proposals to accept')
    )
    proposal_deadline = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('Deadline for submitting proposals')
    )

    # Completion
    completed_at = models.DateTimeField(null=True, blank=True)
    cancelled_at = models.DateTimeField(null=True, blank=True)
    cancellation_reason = models.TextField(blank=True)

    class Meta:
        verbose_name = _('Project')
        verbose_name_plural = _('Projects')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['tenant', 'status']),
            models.Index(fields=['status', 'published_at']),
            models.Index(fields=['category', 'status']),
            models.Index(fields=['-created_at']),
        ]

    def __str__(self):
        return f"{self.title} ({self.tenant.name})"

    def publish(self):
        """Publish project and make available for proposals."""
        if not self.is_published:
            self.is_published = True
            self.published_at = timezone.now()
            self.status = self.Status.OPEN
            self.save(update_fields=['is_published', 'published_at', 'status'])

    def unpublish(self):
        """Unpublish project (remove from public catalog)."""
        if self.is_published:
            self.is_published = False
            self.published_to_catalog = False
            if self.status == self.Status.OPEN:
                self.status = self.Status.DRAFT
            self.save(update_fields=['is_published', 'published_to_catalog', 'status'])

    @property
    def is_open_for_proposals(self):
        """Check if project is accepting proposals."""
        if self.status != self.Status.OPEN:
            return False
        if self.proposal_deadline and timezone.now() > self.proposal_deadline:
            return False
        if self.proposals.count() >= self.max_proposals:
            return False
        return True

    @property
    def proposal_count(self):
        """Count of submitted proposals."""
        return self.proposals.count()

    @property
    def accepted_proposal(self):
        """Get accepted proposal (if any)."""
        return self.proposals.filter(status='ACCEPTED').first()


# ============================================================================
# PROJECT PROPOSALS
# ============================================================================

class ProjectProposal(TimestampedModel):
    """
    Provider's bid/proposal for a project.

    Providers submit proposals with:
    - Proposed budget and timeline
    - Approach and methodology
    - Portfolio examples
    - Cover letter
    """

    class Status(models.TextChoices):
        DRAFT = 'DRAFT', _('Draft')
        SUBMITTED = 'SUBMITTED', _('Submitted')
        UNDER_REVIEW = 'UNDER_REVIEW', _('Under Review')
        SHORTLISTED = 'SHORTLISTED', _('Shortlisted')
        ACCEPTED = 'ACCEPTED', _('Accepted')
        REJECTED = 'REJECTED', _('Rejected')
        WITHDRAWN = 'WITHDRAWN', _('Withdrawn')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Relationships
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name='proposals'
    )
    provider = models.ForeignKey(
        ProjectProvider,
        on_delete=models.CASCADE,
        related_name='proposals'
    )
    freelancer_profile = models.ForeignKey(
        'tenant_profiles.FreelancerProfile',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='project_proposals',
        help_text=_('If provider is individual freelancer')
    )

    # Proposal content
    cover_letter = models.TextField(
        help_text=_('Why you are perfect for this project')
    )
    approach = models.TextField(
        help_text=_('Your proposed methodology and approach')
    )

    # Pricing
    proposed_budget = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)]
    )
    budget_currency = models.CharField(max_length=3, default='CAD')
    
    # Timeline
    proposed_duration_weeks = models.PositiveIntegerField()
    proposed_start_date = models.DateField(null=True, blank=True)
    proposed_completion_date = models.DateField(null=True, blank=True)

    # Milestones (if applicable)
    proposed_milestones = models.JSONField(
        default=list,
        blank=True,
        help_text=_('Array of proposed milestone objects')
    )

    # Portfolio examples
    portfolio_links = models.JSONField(
        default=list,
        blank=True,
        help_text=_('Array of relevant portfolio URLs')
    )
    attachments = models.JSONField(
        default=list,
        blank=True,
        help_text=_('Array of attachment file URLs')
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.DRAFT
    )
    submitted_at = models.DateTimeField(null=True, blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    accepted_at = models.DateTimeField(null=True, blank=True)
    rejected_at = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(blank=True)

    # Questionnaire responses (if project has custom questions)
    questionnaire_responses = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Answers to project-specific questions')
    )

    class Meta:
        verbose_name = _('Project Proposal')
        verbose_name_plural = _('Project Proposals')
        ordering = ['-created_at']
        unique_together = [['project', 'provider']]
        indexes = [
            models.Index(fields=['project', 'status']),
            models.Index(fields=['provider', 'status']),
            models.Index(fields=['-submitted_at']),
        ]

    def __str__(self):
        return f"Proposal for {self.project.title} by {self.provider.name}"

    def submit(self):
        """Submit proposal for review."""
        if self.status == self.Status.DRAFT:
            self.status = self.Status.SUBMITTED
            self.submitted_at = timezone.now()
            self.save(update_fields=['status', 'submitted_at'])

    def accept(self):
        """Accept proposal and assign project to provider."""
        self.status = self.Status.ACCEPTED
        self.accepted_at = timezone.now()
        self.save(update_fields=['status', 'accepted_at'])

        # Assign provider to project
        self.project.assigned_provider = self.provider
        self.project.assigned_at = timezone.now()
        self.project.status = Project.Status.IN_PROGRESS
        self.project.save(update_fields=['assigned_provider', 'assigned_at', 'status'])

        # Reject all other proposals
        self.project.proposals.exclude(pk=self.pk).update(
            status=self.Status.REJECTED,
            rejected_at=timezone.now(),
            rejection_reason='Another proposal was selected'
        )

    def reject(self, reason=''):
        """Reject proposal."""
        self.status = self.Status.REJECTED
        self.rejected_at = timezone.now()
        self.rejection_reason = reason
        self.save(update_fields=['status', 'rejected_at', 'rejection_reason'])


# ============================================================================
# PROJECT CONTRACTS
# ============================================================================

class ProjectContract(TimestampedModel):
    """
    Binding agreement between project owner and assigned provider.

    Created when proposal is accepted.
    Defines terms, payment schedule, and deliverables.
    """

    class Status(models.TextChoices):
        DRAFT = 'DRAFT', _('Draft')
        PENDING_SIGNATURE = 'PENDING_SIGNATURE', _('Pending Signature')
        ACTIVE = 'ACTIVE', _('Active')
        COMPLETED = 'COMPLETED', _('Completed')
        TERMINATED = 'TERMINATED', _('Terminated')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Relationships
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name='contracts'
    )
    proposal = models.OneToOneField(
        ProjectProposal,
        on_delete=models.CASCADE,
        related_name='contract'
    )
    provider = models.ForeignKey(
        ProjectProvider,
        on_delete=models.CASCADE,
        related_name='contracts'
    )

    # Contract terms
    total_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)]
    )
    currency = models.CharField(max_length=3, default='CAD')
    payment_terms = models.TextField(
        help_text=_('Payment schedule and conditions')
    )

    # Timeline
    start_date = models.DateField()
    end_date = models.DateField()
    
    # Terms and conditions
    terms_and_conditions = models.TextField()
    scope_of_work = models.TextField()
    deliverables = models.JSONField(
        default=list,
        help_text=_('Array of agreed deliverables')
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.DRAFT
    )

    # Signatures
    client_signed_at = models.DateTimeField(null=True, blank=True)
    provider_signed_at = models.DateTimeField(null=True, blank=True)
    fully_executed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('When both parties signed')
    )

    # Termination
    terminated_at = models.DateTimeField(null=True, blank=True)
    termination_reason = models.TextField(blank=True)

    class Meta:
        verbose_name = _('Project Contract')
        verbose_name_plural = _('Project Contracts')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['project', 'status']),
            models.Index(fields=['provider', 'status']),
        ]

    def __str__(self):
        return f"Contract for {self.project.title}"

    @property
    def is_fully_executed(self):
        """Check if both parties have signed."""
        return self.client_signed_at and self.provider_signed_at

    def activate(self):
        """Activate contract after both parties sign."""
        if self.is_fully_executed:
            self.status = self.Status.ACTIVE
            self.fully_executed_at = timezone.now()
            self.save(update_fields=['status', 'fully_executed_at'])


# ============================================================================
# PROJECT MILESTONES
# ============================================================================

class ProjectMilestone(TimestampedModel):
    """
    Payment and delivery checkpoint within a project.

    Milestones define phases of work with:
    - Specific deliverables
    - Payment amount
    - Due date
    - Approval workflow
    """

    class Status(models.TextChoices):
        PENDING = 'PENDING', _('Pending')
        IN_PROGRESS = 'IN_PROGRESS', _('In Progress')
        SUBMITTED = 'SUBMITTED', _('Submitted for Review')
        APPROVED = 'APPROVED', _('Approved')
        REJECTED = 'REJECTED', _('Rejected')
        PAID = 'PAID', _('Paid')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Relationships
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name='milestones'
    )
    contract = models.ForeignKey(
        ProjectContract,
        on_delete=models.CASCADE,
        related_name='milestones',
        null=True,
        blank=True
    )

    # Milestone info
    title = models.CharField(max_length=200)
    description = models.TextField()
    order = models.PositiveIntegerField(
        default=0,
        help_text=_('Sequential order of milestone')
    )

    # Deliverables
    deliverables = models.JSONField(
        default=list,
        help_text=_('Array of deliverable descriptions')
    )

    # Payment
    amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)]
    )
    currency = models.CharField(max_length=3, default='CAD')

    # Timeline
    due_date = models.DateField()
    submitted_at = models.DateTimeField(null=True, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    paid_at = models.DateTimeField(null=True, blank=True)

    # Status
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING
    )

    # Review
    reviewer_notes = models.TextField(blank=True)
    rejection_reason = models.TextField(blank=True)

    class Meta:
        verbose_name = _('Project Milestone')
        verbose_name_plural = _('Project Milestones')
        ordering = ['project', 'order']
        indexes = [
            models.Index(fields=['project', 'order']),
            models.Index(fields=['status', 'due_date']),
        ]

    def __str__(self):
        return f"{self.project.title} - Milestone {self.order}: {self.title}"

    def submit_for_review(self):
        """Mark milestone as submitted for client review."""
        self.status = self.Status.SUBMITTED
        self.submitted_at = timezone.now()
        self.save(update_fields=['status', 'submitted_at'])

    def approve(self, notes=''):
        """Approve milestone and trigger payment."""
        self.status = self.Status.APPROVED
        self.approved_at = timezone.now()
        self.reviewer_notes = notes
        self.save(update_fields=['status', 'approved_at', 'reviewer_notes'])

    def reject(self, reason):
        """Reject milestone with reason."""
        self.status = self.Status.REJECTED
        self.rejection_reason = reason
        self.save(update_fields=['status', 'rejection_reason'])


# ============================================================================
# PROJECT DELIVERABLES
# ============================================================================

class ProjectDeliverable(TimestampedModel):
    """
    Submitted work/files for a project or milestone.

    Providers upload deliverables for client review.
    Can be associated with specific milestones or final project delivery.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Relationships
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name='uploaded_deliverables'
    )
    milestone = models.ForeignKey(
        ProjectMilestone,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='uploaded_deliverables'
    )

    # Deliverable info
    title = models.CharField(max_length=200)
    description = models.TextField()
    file_url = models.URLField(
        help_text=_('URL to uploaded file (S3, etc.)')
    )
    file_name = models.CharField(max_length=255)
    file_size = models.PositiveIntegerField(
        help_text=_('File size in bytes')
    )
    file_type = models.CharField(max_length=100)

    # Submission
    submitted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='submitted_deliverables'
    )
    submitted_at = models.DateTimeField(auto_now_add=True)

    # Review
    is_approved = models.BooleanField(default=False)
    approved_at = models.DateTimeField(null=True, blank=True)
    reviewer_notes = models.TextField(blank=True)

    class Meta:
        verbose_name = _('Project Deliverable')
        verbose_name_plural = _('Project Deliverables')
        ordering = ['-submitted_at']
        indexes = [
            models.Index(fields=['project', '-submitted_at']),
            models.Index(fields=['milestone', 'is_approved']),
        ]

    def __str__(self):
        return f"{self.project.title} - {self.title}"

    def approve(self, notes=''):
        """Approve deliverable."""
        self.is_approved = True
        self.approved_at = timezone.now()
        self.reviewer_notes = notes
        self.save(update_fields=['is_approved', 'approved_at', 'reviewer_notes'])


# ============================================================================
# PROJECT REVIEWS
# ============================================================================

class ProjectReview(TimestampedModel):
    """
    Post-completion review and rating.

    Both client and provider can review each other after project completion.
    Reviews are public and affect reputation scores.
    """

    class ReviewerType(models.TextChoices):
        CLIENT = 'CLIENT', _('Client reviewing Provider')
        PROVIDER = 'PROVIDER', _('Provider reviewing Client')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Relationships
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name='reviews'
    )
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='project_reviews_given'
    )
    reviewer_type = models.CharField(
        max_length=20,
        choices=ReviewerType.choices
    )

    # Rating (1-5 stars)
    rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    
    # Detailed ratings
    communication_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True,
        blank=True
    )
    quality_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True,
        blank=True
    )
    timeliness_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True,
        blank=True
    )
    professionalism_rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        null=True,
        blank=True
    )

    # Review content
    title = models.CharField(max_length=200)
    review = models.TextField()

    # Publication
    is_public = models.BooleanField(default=True)
    is_featured = models.BooleanField(default=False)

    # Response (reviewed party can respond)
    response = models.TextField(blank=True)
    responded_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Project Review')
        verbose_name_plural = _('Project Reviews')
        ordering = ['-created_at']
        unique_together = [['project', 'reviewer', 'reviewer_type']]
        indexes = [
            models.Index(fields=['project', 'reviewer_type']),
            models.Index(fields=['rating', '-created_at']),
        ]

    def __str__(self):
        return f"{self.reviewer_type} review for {self.project.title}"

    @property
    def average_detailed_rating(self):
        """Calculate average of detailed ratings."""
        ratings = [
            r for r in [
                self.communication_rating,
                self.quality_rating,
                self.timeliness_rating,
                self.professionalism_rating
            ] if r is not None
        ]
        if ratings:
            return sum(ratings) / len(ratings)
        return self.rating
