"""
HR Core Models - Human Resources Operations

This module implements:
- Employee records and onboarding
- Time-off/absence management
- Document management with e-signatures
- Performance reviews
- Employee offboarding
- Compensation history
- Skills and certifications
- Work authorization tracking
"""

import uuid
from datetime import timedelta
from decimal import Decimal
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinValueValidator, MaxValueValidator, FileExtensionValidator
from django.core.exceptions import ValidationError
from django.contrib.postgres.fields import ArrayField
from core.db.models import TenantAwareModel


class Employee(TenantAwareModel):
    """
    Employee record linking user to HR data.
    Distinct from TenantUser which handles access/permissions.

    Inherits from TenantAwareModel for proper multi-tenant isolation.
    Provides: tenant FK, UUID primary key, timestamps, is_active flag.
    """

    class EmploymentStatus(models.TextChoices):
        PENDING = 'pending', _('Pending Start')
        PROBATION = 'probation', _('Probationary')
        ACTIVE = 'active', _('Active')
        ON_LEAVE = 'on_leave', _('On Leave')
        SUSPENDED = 'suspended', _('Suspended')
        NOTICE_PERIOD = 'notice_period', _('Notice Period')
        TERMINATED = 'terminated', _('Terminated')
        RESIGNED = 'resigned', _('Resigned')

    class EmploymentType(models.TextChoices):
        FULL_TIME = 'full_time', _('Full-time')
        PART_TIME = 'part_time', _('Part-time')
        CONTRACT = 'contract', _('Contract')
        INTERN = 'intern', _('Intern')
        TEMPORARY = 'temporary', _('Temporary')

    # Note: id (UUID), tenant, created_at, updated_at, is_active inherited from TenantAwareModel

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='employee_record'
    )

    # Employment Details
    employee_id = models.CharField(
        max_length=50,
        unique=True,
        help_text=_('Internal employee ID')
    )
    status = models.CharField(
        max_length=20,
        choices=EmploymentStatus.choices,
        default=EmploymentStatus.PENDING
    )
    employment_type = models.CharField(
        max_length=20,
        choices=EmploymentType.choices,
        default=EmploymentType.FULL_TIME
    )

    # Position
    job_title = models.CharField(max_length=200)
    department = models.ForeignKey(
        'configurations.Department',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='employees'
    )
    manager = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='direct_reports'
    )
    team = models.CharField(max_length=100, blank=True)
    work_location = models.CharField(max_length=200, blank=True)

    # Dates
    hire_date = models.DateField()
    start_date = models.DateField(null=True, blank=True)
    probation_end_date = models.DateField(null=True, blank=True)
    termination_date = models.DateField(null=True, blank=True)
    last_working_day = models.DateField(null=True, blank=True)

    # Compensation (encrypted in production)
    base_salary = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True
    )
    salary_currency = models.CharField(max_length=3, default='CAD')
    pay_frequency = models.CharField(
        max_length=20,
        choices=[
            ('weekly', _('Weekly')),
            ('bi_weekly', _('Bi-weekly')),
            ('semi_monthly', _('Semi-monthly')),
            ('monthly', _('Monthly')),
        ],
        default='bi_weekly'
    )
    bank_account_info = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Encrypted bank account details')
    )

    # Benefits & PTO
    pto_balance = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00')
    )
    sick_leave_balance = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00')
    )
    benefits_enrolled = models.JSONField(default=list, blank=True)

    # Emergency Contact
    emergency_contact_name = models.CharField(max_length=200, blank=True)
    emergency_contact_phone = models.CharField(max_length=30, blank=True)
    emergency_contact_relationship = models.CharField(max_length=50, blank=True)

    # Sensitive Data (encrypted)
    sin_number_encrypted = models.CharField(
        max_length=500,
        blank=True,
        help_text=_('Encrypted SIN/SSN')
    )
    tax_info = models.JSONField(default=dict, blank=True)

    # Extended Emergency Contacts (multiple contacts)
    emergency_contacts = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of emergency contacts with name, phone, relationship, is_primary')
    )

    # Work Authorization
    work_authorization_status = models.CharField(
        max_length=50,
        choices=[
            ('citizen', _('Citizen')),
            ('permanent_resident', _('Permanent Resident')),
            ('work_permit', _('Work Permit')),
            ('visa', _('Work Visa')),
            ('other', _('Other')),
        ],
        blank=True
    )
    visa_type = models.CharField(max_length=50, blank=True)
    visa_expiry = models.DateField(null=True, blank=True)
    work_permit_number = models.CharField(max_length=100, blank=True)
    work_permit_expiry = models.DateField(null=True, blank=True)
    right_to_work_verified = models.BooleanField(default=False)
    right_to_work_verified_date = models.DateField(null=True, blank=True)
    right_to_work_verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='work_verifications'
    )

    # Skills and Certifications (using ArrayField for PostgreSQL)
    skills = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True,
        help_text=_('List of skills')
    )
    certifications = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of certifications with name, issuer, date, expiry')
    )

    # Performance Review Schedule
    next_review_date = models.DateField(null=True, blank=True)
    review_frequency_months = models.PositiveIntegerField(
        default=12,
        help_text=_('Months between performance reviews')
    )

    # Linked to ATS
    from_application = models.ForeignKey(
        'ats.Application',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='employee_records'
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Employee')
        verbose_name_plural = _('Employees')
        ordering = ['user__last_name', 'user__first_name']

    def __str__(self):
        return f"{self.user.get_full_name()} ({self.employee_id})"

    @property
    def first_name(self):
        return self.user.first_name

    @property
    def last_name(self):
        return self.user.last_name

    @property
    def full_name(self):
        return self.user.get_full_name()

    @property
    def is_active_employee(self):
        return self.status in [
            self.EmploymentStatus.ACTIVE,
            self.EmploymentStatus.PROBATION,
            self.EmploymentStatus.ON_LEAVE,
        ]

    @property
    def years_of_service(self):
        if not self.start_date:
            return 0
        delta = timezone.now().date() - self.start_date
        return delta.days / 365.25


class TimeOffType(TenantAwareModel):
    """
    Types of time off (vacation, sick, personal, etc.)

    Note: Inherits from TenantAwareModel because each company/tenant
    has its own time-off policies (e.g., Company A: 15 days PTO,
    Company B: unlimited PTO).
    """

    name = models.CharField(max_length=100)
    code = models.CharField(max_length=20, unique=True)
    description = models.TextField(blank=True)
    color = models.CharField(max_length=7, default='#3B82F6')

    # Accrual settings
    is_accrued = models.BooleanField(default=True)
    accrual_rate = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Days accrued per pay period')
    )
    max_balance = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Maximum balance allowed')
    )
    max_carryover = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Max days to carry over to next year')
    )

    # Policy
    requires_approval = models.BooleanField(default=True)
    requires_documentation = models.BooleanField(default=False)
    min_notice_days = models.PositiveIntegerField(default=0)
    is_paid = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = _('Time Off Type')
        verbose_name_plural = _('Time Off Types')
        ordering = ['name']

    def __str__(self):
        return self.name


class TimeOffRequest(TenantAwareModel):
    """
    Employee time off/absence requests.

    Note: Inherits from TenantAwareModel because time-off requests
    are specific to a company/tenant's employee.
    """

    class RequestStatus(models.TextChoices):
        DRAFT = 'draft', _('Draft')
        PENDING = 'pending', _('Pending Approval')
        APPROVED = 'approved', _('Approved')
        REJECTED = 'rejected', _('Rejected')
        CANCELLED = 'cancelled', _('Cancelled')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    employee = models.ForeignKey(
        Employee,
        on_delete=models.CASCADE,
        related_name='time_off_requests'
    )
    time_off_type = models.ForeignKey(
        TimeOffType,
        on_delete=models.PROTECT,
        related_name='requests'
    )

    # Dates
    start_date = models.DateField()
    end_date = models.DateField()
    is_half_day = models.BooleanField(default=False)
    half_day_period = models.CharField(
        max_length=10,
        choices=[('am', 'Morning'), ('pm', 'Afternoon')],
        blank=True
    )

    # Details
    total_days = models.DecimalField(max_digits=5, decimal_places=2)
    reason = models.TextField(blank=True)
    notes = models.TextField(blank=True)

    # Status
    status = models.CharField(
        max_length=20,
        choices=RequestStatus.choices,
        default=RequestStatus.PENDING
    )

    # Approval workflow
    approver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='time_off_approvals'
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(blank=True)

    # Documents
    supporting_document = models.FileField(
        upload_to='time_off_docs/',
        blank=True,
        null=True,
        validators=[
            FileExtensionValidator(allowed_extensions=['pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'])
        ],
        help_text=_("Allowed formats: PDF, DOC, DOCX, JPG, PNG. Max size: 10MB")
    )

    def clean(self):
        super().clean()
        if self.supporting_document and hasattr(self.supporting_document, 'size'):
            if self.supporting_document.size > 10 * 1024 * 1024:  # 10MB
                raise ValidationError({'supporting_document': _("File size must be less than 10MB.")})

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Time Off Request')
        verbose_name_plural = _('Time Off Requests')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.employee.full_name} - {self.time_off_type.name} ({self.start_date} to {self.end_date})"

    def approve(self, approver):
        """Approve the request with atomic transaction and balance validation."""
        from django.db import transaction

        with transaction.atomic():
            # Lock and fetch the employee to ensure concurrent safety
            employee = Employee.objects.select_for_update().get(id=self.employee_id)

            # Deduct from balance first (before approving) with validation
            if self.time_off_type.is_accrued:
                # Check if sufficient balance exists
                if employee.pto_balance < self.total_days:
                    from django.core.exceptions import ValidationError
                    raise ValidationError(
                        f'Insufficient PTO balance. Available: {employee.pto_balance}, Requested: {self.total_days}'
                    )

                # Use F() expression for safe concurrent deduction
                from django.db.models import F
                Employee.objects.filter(id=employee.id).update(
                    pto_balance=F('pto_balance') - self.total_days
                )

            # Update request status
            self.status = self.RequestStatus.APPROVED
            self.approver = approver
            self.approved_at = timezone.now()
            self.save()

    def reject(self, approver, reason=''):
        """Reject the request."""
        self.status = self.RequestStatus.REJECTED
        self.approver = approver
        self.rejection_reason = reason
        self.save()


class OnboardingChecklist(models.Model):
    """Template for onboarding checklists."""

    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    employment_type = models.CharField(
        max_length=20,
        choices=Employee.EmploymentType.choices,
        blank=True,
        help_text=_('Apply to specific employment type or leave blank for all')
    )
    department = models.ForeignKey(
        'configurations.Department',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Onboarding Checklist')
        verbose_name_plural = _('Onboarding Checklists')

    def __str__(self):
        return self.name


class OnboardingTask(models.Model):
    """Individual tasks in an onboarding checklist."""

    class TaskCategory(models.TextChoices):
        DOCUMENTATION = 'documentation', _('Documentation')
        IT_SETUP = 'it_setup', _('IT Setup')
        TRAINING = 'training', _('Training')
        INTRODUCTIONS = 'introductions', _('Introductions')
        COMPLIANCE = 'compliance', _('Compliance')
        BENEFITS = 'benefits', _('Benefits Enrollment')
        OTHER = 'other', _('Other')

    checklist = models.ForeignKey(
        OnboardingChecklist,
        on_delete=models.CASCADE,
        related_name='tasks'
    )
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    category = models.CharField(
        max_length=20,
        choices=TaskCategory.choices,
        default=TaskCategory.OTHER
    )
    order = models.PositiveIntegerField(default=0)

    # Assignment
    assigned_to_role = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('Role responsible (HR, Manager, IT, etc.)')
    )
    due_days = models.PositiveIntegerField(
        default=0,
        help_text=_('Days after start date')
    )

    # Requirements
    is_required = models.BooleanField(default=True)
    requires_signature = models.BooleanField(default=False)
    document_template = models.ForeignKey(
        'DocumentTemplate',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    class Meta:
        verbose_name = _('Onboarding Task')
        verbose_name_plural = _('Onboarding Tasks')
        ordering = ['checklist', 'order']

    def __str__(self):
        return f"{self.checklist.name} - {self.title}"


class EmployeeOnboarding(models.Model):
    """Employee-specific onboarding progress."""

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    employee = models.OneToOneField(
        Employee,
        on_delete=models.CASCADE,
        related_name='onboarding'
    )
    checklist = models.ForeignKey(
        OnboardingChecklist,
        on_delete=models.SET_NULL,
        null=True
    )
    start_date = models.DateField()
    target_completion_date = models.DateField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        verbose_name = _('Employee Onboarding')
        verbose_name_plural = _('Employee Onboardings')

    def __str__(self):
        return f"Onboarding: {self.employee.full_name}"

    @property
    def completion_percentage(self):
        total = self.task_progress.count()
        if total == 0:
            return 0
        completed = self.task_progress.filter(is_completed=True).count()
        return int((completed / total) * 100)


class OnboardingTaskProgress(models.Model):
    """Track completion of individual onboarding tasks."""

    onboarding = models.ForeignKey(
        EmployeeOnboarding,
        on_delete=models.CASCADE,
        related_name='task_progress'
    )
    task = models.ForeignKey(
        OnboardingTask,
        on_delete=models.CASCADE
    )
    is_completed = models.BooleanField(default=False)
    completed_at = models.DateTimeField(null=True, blank=True)
    completed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='completed_onboarding_tasks'
    )
    notes = models.TextField(blank=True)
    due_date = models.DateField(null=True, blank=True)

    # Task assignment fields
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_onboarding_tasks',
        help_text=_('User currently assigned to complete this task')
    )
    reassignment_history = models.JSONField(
        default=list,
        blank=True,
        help_text=_('History of task reassignments')
    )

    class Meta:
        verbose_name = _('Onboarding Task Progress')
        verbose_name_plural = _('Onboarding Task Progress')
        unique_together = ['onboarding', 'task']

    def __str__(self):
        status = "Done" if self.is_completed else "Pending"
        return f"{self.task.title} - {status}"

    def complete(self, user=None):
        """Mark task as completed."""
        self.is_completed = True
        self.completed_at = timezone.now()
        self.completed_by = user
        self.save()

    def reassign(self, new_assignee, reassigned_by=None, reason=''):
        """
        Reassign task to a new user.

        Args:
            new_assignee: User to assign the task to
            reassigned_by: User performing the reassignment
            reason: Reason for reassignment
        """
        if self.is_completed:
            raise ValueError("Cannot reassign a completed task")

        old_assignee = self.assigned_to

        # Track reassignment history
        history_entry = {
            'timestamp': timezone.now().isoformat(),
            'from_user_id': old_assignee.id if old_assignee else None,
            'from_user_name': str(old_assignee) if old_assignee else None,
            'to_user_id': new_assignee.id,
            'to_user_name': str(new_assignee),
            'reassigned_by_id': reassigned_by.id if reassigned_by else None,
            'reassigned_by_name': str(reassigned_by) if reassigned_by else None,
            'reason': reason,
        }

        if not self.reassignment_history:
            self.reassignment_history = []
        self.reassignment_history.append(history_entry)

        self.assigned_to = new_assignee
        self.save(update_fields=['assigned_to', 'reassignment_history'])


class DocumentTemplate(models.Model):
    """Templates for HR documents (offer letters, contracts, etc.)."""

    class DocumentCategory(models.TextChoices):
        OFFER_LETTER = 'offer_letter', _('Offer Letter')
        CONTRACT = 'contract', _('Employment Contract')
        NDA = 'nda', _('Non-Disclosure Agreement')
        POLICY = 'policy', _('Policy Document')
        FORM = 'form', _('Form')
        OTHER = 'other', _('Other')

    name = models.CharField(max_length=200)
    category = models.CharField(
        max_length=20,
        choices=DocumentCategory.choices,
        default=DocumentCategory.OTHER
    )
    description = models.TextField(blank=True)
    content = models.TextField(help_text=_('HTML template with placeholders'))
    placeholders = models.JSONField(
        default=list,
        help_text=_('List of available placeholders')
    )
    requires_signature = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    version = models.CharField(max_length=20, default='1.0')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Document Template')
        verbose_name_plural = _('Document Templates')

    def __str__(self):
        return f"{self.name} (v{self.version})"


class EmployeeDocument(models.Model):
    """Documents uploaded or generated for employees."""

    class DocumentStatus(models.TextChoices):
        DRAFT = 'draft', _('Draft')
        PENDING_SIGNATURE = 'pending_signature', _('Pending Signature')
        SIGNED = 'signed', _('Signed')
        EXPIRED = 'expired', _('Expired')
        ARCHIVED = 'archived', _('Archived')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    employee = models.ForeignKey(
        Employee,
        on_delete=models.CASCADE,
        related_name='documents'
    )
    template = models.ForeignKey(
        DocumentTemplate,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    # Document Info
    title = models.CharField(max_length=200)
    category = models.CharField(
        max_length=20,
        choices=DocumentTemplate.DocumentCategory.choices,
        default=DocumentTemplate.DocumentCategory.OTHER
    )
    description = models.TextField(blank=True)
    file = models.FileField(
        upload_to='employee_documents/',
        validators=[
            FileExtensionValidator(allowed_extensions=['pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpeg', 'png'])
        ],
        help_text=_("Allowed formats: PDF, DOC, DOCX, XLS, XLSX, JPG, PNG. Max size: 10MB")
    )
    file_type = models.CharField(max_length=50, blank=True)
    file_size = models.PositiveIntegerField(null=True, blank=True)

    # Status
    status = models.CharField(
        max_length=20,
        choices=DocumentStatus.choices,
        default=DocumentStatus.DRAFT
    )

    # E-Signature (DocuSign integration)
    requires_signature = models.BooleanField(default=False)
    signature_provider = models.CharField(max_length=50, blank=True)
    signature_envelope_id = models.CharField(max_length=255, blank=True)
    signed_at = models.DateTimeField(null=True, blank=True)
    signed_document_url = models.URLField(blank=True)

    # Expiration
    expires_at = models.DateField(null=True, blank=True)

    # Audit
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='uploaded_documents'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Employee Document')
        verbose_name_plural = _('Employee Documents')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} - {self.employee.full_name}"

    def clean(self):
        super().clean()
        if self.file and hasattr(self.file, 'size'):
            if self.file.size > 10 * 1024 * 1024:  # 10MB
                raise ValidationError({'file': _("File size must be less than 10MB.")})


class Offboarding(models.Model):
    """Employee offboarding/separation process."""

    class SeparationType(models.TextChoices):
        RESIGNATION = 'resignation', _('Resignation')
        TERMINATION = 'termination', _('Termination')
        LAYOFF = 'layoff', _('Layoff')
        RETIREMENT = 'retirement', _('Retirement')
        CONTRACT_END = 'contract_end', _('Contract End')
        MUTUAL = 'mutual', _('Mutual Agreement')
        OTHER = 'other', _('Other')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    employee = models.OneToOneField(
        Employee,
        on_delete=models.CASCADE,
        related_name='offboarding'
    )

    # Separation Details
    separation_type = models.CharField(
        max_length=20,
        choices=SeparationType.choices
    )
    reason = models.TextField(blank=True)
    notice_date = models.DateField()
    last_working_day = models.DateField()
    exit_interview_date = models.DateField(null=True, blank=True)
    exit_interview_notes = models.TextField(blank=True)

    # Checklist Status
    knowledge_transfer_complete = models.BooleanField(default=False)
    equipment_returned = models.BooleanField(default=False)
    access_revoked = models.BooleanField(default=False)
    final_paycheck_processed = models.BooleanField(default=False)
    benefits_terminated = models.BooleanField(default=False)
    exit_interview_completed = models.BooleanField(default=False)

    # Final Details
    severance_offered = models.BooleanField(default=False)
    severance_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True
    )
    pto_payout_days = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True
    )

    # Eligibility
    eligible_for_rehire = models.BooleanField(default=True)
    rehire_notes = models.TextField(blank=True)

    # Audit
    processed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Offboarding')
        verbose_name_plural = _('Offboardings')

    def __str__(self):
        return f"Offboarding: {self.employee.full_name}"

    @property
    def is_complete(self):
        return all([
            self.knowledge_transfer_complete,
            self.equipment_returned,
            self.access_revoked,
            self.final_paycheck_processed,
        ])


class PerformanceReview(models.Model):
    """Performance review records."""

    class ReviewType(models.TextChoices):
        PROBATION = 'probation', _('Probation Review')
        ANNUAL = 'annual', _('Annual Review')
        MID_YEAR = 'mid_year', _('Mid-Year Review')
        PROJECT = 'project', _('Project-Based')
        PROMOTION = 'promotion', _('Promotion Review')

    class ReviewStatus(models.TextChoices):
        DRAFT = 'draft', _('Draft')
        PENDING_SELF = 'pending_self', _('Pending Self-Assessment')
        PENDING_MANAGER = 'pending_manager', _('Pending Manager Review')
        PENDING_APPROVAL = 'pending_approval', _('Pending HR Approval')
        COMPLETED = 'completed', _('Completed')
        CANCELLED = 'cancelled', _('Cancelled')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    employee = models.ForeignKey(
        Employee,
        on_delete=models.CASCADE,
        related_name='performance_reviews'
    )
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='hr_performance_reviews_given'
    )

    # Review Details
    review_type = models.CharField(
        max_length=20,
        choices=ReviewType.choices,
        default=ReviewType.ANNUAL
    )
    review_period_start = models.DateField()
    review_period_end = models.DateField()
    status = models.CharField(
        max_length=20,
        choices=ReviewStatus.choices,
        default=ReviewStatus.DRAFT
    )

    # Ratings
    overall_rating = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    goals_met_percentage = models.PositiveIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    competency_ratings = models.JSONField(default=dict, blank=True)

    # Written Feedback
    self_assessment = models.TextField(blank=True)
    manager_feedback = models.TextField(blank=True)
    accomplishments = models.TextField(blank=True)
    areas_for_improvement = models.TextField(blank=True)
    goals_for_next_period = models.TextField(blank=True)

    # Outcome
    promotion_recommended = models.BooleanField(default=False)
    salary_increase_recommended = models.BooleanField(default=False)
    salary_increase_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True
    )
    pip_recommended = models.BooleanField(
        default=False,
        help_text=_('Performance Improvement Plan')
    )

    # Signatures
    employee_signed_at = models.DateTimeField(null=True, blank=True)
    manager_signed_at = models.DateTimeField(null=True, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Performance Review')
        verbose_name_plural = _('Performance Reviews')
        ordering = ['-review_period_end']

    def __str__(self):
        return f"{self.employee.full_name} - {self.get_review_type_display()} ({self.review_period_end})"


# =============================================================================
# COMPENSATION MODELS
# =============================================================================

class EmployeeCompensation(models.Model):
    """
    Historical compensation records for employees.
    Tracks salary changes, bonuses, and equity over time.
    """

    class ChangeReason(models.TextChoices):
        HIRE = 'hire', _('Initial Hire')
        PROMOTION = 'promotion', _('Promotion')
        MERIT_INCREASE = 'merit_increase', _('Merit Increase')
        MARKET_ADJUSTMENT = 'market_adjustment', _('Market Adjustment')
        ROLE_CHANGE = 'role_change', _('Role Change')
        TRANSFER = 'transfer', _('Transfer')
        COST_OF_LIVING = 'cost_of_living', _('Cost of Living Adjustment')
        CORRECTION = 'correction', _('Correction')
        OTHER = 'other', _('Other')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    employee = models.ForeignKey(
        Employee,
        on_delete=models.CASCADE,
        related_name='compensation_history'
    )

    # Effective Date
    effective_date = models.DateField()
    end_date = models.DateField(null=True, blank=True, help_text=_('When this compensation ended'))

    # Base Compensation
    base_salary = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text=_('Annual base salary')
    )
    currency = models.CharField(max_length=3, default='CAD')
    pay_frequency = models.CharField(
        max_length=20,
        choices=[
            ('weekly', _('Weekly')),
            ('bi_weekly', _('Bi-weekly')),
            ('semi_monthly', _('Semi-monthly')),
            ('monthly', _('Monthly')),
            ('annually', _('Annually')),
        ],
        default='bi_weekly'
    )

    # Variable Compensation
    bonus_target_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Target bonus as percentage of base salary')
    )
    bonus_type = models.CharField(
        max_length=50,
        choices=[
            ('none', _('None')),
            ('annual', _('Annual Bonus')),
            ('quarterly', _('Quarterly Bonus')),
            ('discretionary', _('Discretionary')),
            ('performance', _('Performance-Based')),
        ],
        default='none'
    )
    commission_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Commission percentage if applicable')
    )

    # Equity
    equity_shares = models.IntegerField(
        null=True,
        blank=True,
        help_text=_('Number of stock options/shares granted')
    )
    equity_vest_start = models.DateField(null=True, blank=True)
    equity_vest_end = models.DateField(null=True, blank=True)
    equity_cliff_months = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text=_('Cliff period in months')
    )

    # Change Details
    change_reason = models.CharField(
        max_length=30,
        choices=ChangeReason.choices,
        default=ChangeReason.HIRE
    )
    change_notes = models.TextField(blank=True)
    previous_salary = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True
    )

    # Approval
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='compensation_approvals'
    )
    approved_at = models.DateTimeField(null=True, blank=True)

    # Audit
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='compensation_created'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Employee Compensation')
        verbose_name_plural = _('Employee Compensation Records')
        ordering = ['-effective_date']
        indexes = [
            models.Index(fields=['employee', 'effective_date']),
            models.Index(fields=['effective_date']),
        ]

    def __str__(self):
        return f"{self.employee.full_name} - {self.currency} {self.base_salary} ({self.effective_date})"

    @property
    def salary_change_percentage(self):
        """Calculate percentage change from previous salary."""
        if self.previous_salary and self.previous_salary > 0:
            change = ((self.base_salary - self.previous_salary) / self.previous_salary) * 100
            return round(change, 2)
        return None

    @property
    def total_target_compensation(self):
        """Calculate total target compensation including bonus."""
        total = self.base_salary
        if self.bonus_target_percentage:
            total += self.base_salary * (self.bonus_target_percentage / 100)
        return total


class TimeOffBalance(models.Model):
    """
    Track time-off balances by type for each employee.
    Separate from the basic pto_balance field on Employee for more detail.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    employee = models.ForeignKey(
        Employee,
        on_delete=models.CASCADE,
        related_name='time_off_balances'
    )
    time_off_type = models.ForeignKey(
        'TimeOffType',
        on_delete=models.CASCADE,
        related_name='balances'
    )

    # Balances
    balance = models.DecimalField(
        max_digits=6,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Current available balance')
    )
    accrued_this_year = models.DecimalField(
        max_digits=6,
        decimal_places=2,
        default=Decimal('0.00')
    )
    used_this_year = models.DecimalField(
        max_digits=6,
        decimal_places=2,
        default=Decimal('0.00')
    )
    carried_over = models.DecimalField(
        max_digits=6,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Amount carried over from previous year')
    )
    pending = models.DecimalField(
        max_digits=6,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Amount in pending requests')
    )

    # Accrual Tracking
    last_accrual_date = models.DateField(null=True, blank=True)
    accrual_rate_override = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Override default accrual rate for this employee')
    )

    # Year Tracking
    year = models.PositiveIntegerField(default=timezone.now().year)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Time Off Balance')
        verbose_name_plural = _('Time Off Balances')
        unique_together = ['employee', 'time_off_type', 'year']
        ordering = ['employee', 'time_off_type']

    def __str__(self):
        return f"{self.employee.full_name} - {self.time_off_type.name}: {self.balance} days"

    def accrue(self, amount: Decimal):
        """Add accrued time off."""
        self.balance += amount
        self.accrued_this_year += amount

        # Check max balance cap
        if self.time_off_type.max_balance:
            if self.balance > self.time_off_type.max_balance:
                self.balance = self.time_off_type.max_balance

        self.last_accrual_date = timezone.now().date()
        self.save()

    def deduct(self, amount: Decimal):
        """Deduct time off from balance."""
        self.balance -= amount
        self.used_this_year += amount
        self.save()

    def reset_for_new_year(self, carryover: bool = True):
        """Reset balance for new year with optional carryover."""
        if carryover and self.time_off_type.max_carryover:
            self.carried_over = min(self.balance, self.time_off_type.max_carryover)
        else:
            self.carried_over = Decimal('0.00')

        self.balance = self.carried_over
        self.accrued_this_year = Decimal('0.00')
        self.used_this_year = Decimal('0.00')
        self.year = timezone.now().year
        self.save()


class TimeOffAccrualLog(models.Model):
    """
    Log of time-off accruals for audit purposes.
    """

    balance = models.ForeignKey(
        TimeOffBalance,
        on_delete=models.CASCADE,
        related_name='accrual_logs'
    )
    accrual_date = models.DateField()
    amount = models.DecimalField(max_digits=5, decimal_places=2)
    balance_after = models.DecimalField(max_digits=6, decimal_places=2)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Time Off Accrual Log')
        verbose_name_plural = _('Time Off Accrual Logs')
        ordering = ['-accrual_date', '-created_at']

    def __str__(self):
        return f"{self.balance.employee.full_name} - +{self.amount} on {self.accrual_date}"


class TimeOffBlackoutDate(models.Model):
    """
    Dates when time off requests are restricted or blocked.
    """

    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    start_date = models.DateField()
    end_date = models.DateField()

    # Scope
    applies_to_all = models.BooleanField(
        default=True,
        help_text=_('Applies to all employees')
    )
    departments = models.ManyToManyField(
        'configurations.Department',
        blank=True,
        help_text=_('Specific departments this applies to')
    )

    # Restriction Level
    restriction_type = models.CharField(
        max_length=20,
        choices=[
            ('blocked', _('Completely Blocked')),
            ('restricted', _('Restricted - Requires Manager Approval')),
            ('limited', _('Limited - Max 20% Team Capacity')),
        ],
        default='restricted'
    )

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Time Off Blackout Date')
        verbose_name_plural = _('Time Off Blackout Dates')
        ordering = ['start_date']

    def __str__(self):
        return f"{self.name}: {self.start_date} - {self.end_date}"


# =============================================================================
# SKILL MODELS
# =============================================================================

class SkillCategory(models.Model):
    """Categories for organizing skills."""

    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = _('Skill Category')
        verbose_name_plural = _('Skill Categories')
        ordering = ['order', 'name']

    def __str__(self):
        return self.name


class Skill(models.Model):
    """
    Master list of skills that can be assigned to employees.
    """

    name = models.CharField(max_length=100, unique=True)
    category = models.ForeignKey(
        SkillCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='skills'
    )
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = _('Skill')
        verbose_name_plural = _('Skills')
        ordering = ['category', 'name']

    def __str__(self):
        return self.name


class EmployeeSkill(models.Model):
    """
    Association between employee and skills with proficiency level.
    """

    class ProficiencyLevel(models.TextChoices):
        BEGINNER = 'beginner', _('Beginner')
        INTERMEDIATE = 'intermediate', _('Intermediate')
        ADVANCED = 'advanced', _('Advanced')
        EXPERT = 'expert', _('Expert')

    employee = models.ForeignKey(
        Employee,
        on_delete=models.CASCADE,
        related_name='employee_skills'
    )
    skill = models.ForeignKey(
        Skill,
        on_delete=models.CASCADE,
        related_name='employee_skills'
    )
    proficiency = models.CharField(
        max_length=20,
        choices=ProficiencyLevel.choices,
        default=ProficiencyLevel.INTERMEDIATE
    )
    years_of_experience = models.DecimalField(
        max_digits=4,
        decimal_places=1,
        null=True,
        blank=True
    )
    last_used_date = models.DateField(null=True, blank=True)
    is_primary = models.BooleanField(
        default=False,
        help_text=_('Primary/featured skill')
    )
    verified = models.BooleanField(default=False)
    verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='skill_verifications'
    )
    verified_date = models.DateField(null=True, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Employee Skill')
        verbose_name_plural = _('Employee Skills')
        unique_together = ['employee', 'skill']
        ordering = ['-is_primary', 'skill__name']

    def __str__(self):
        return f"{self.employee.full_name} - {self.skill.name} ({self.get_proficiency_display()})"


class Certification(models.Model):
    """
    Employee certifications and credentials.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    employee = models.ForeignKey(
        Employee,
        on_delete=models.CASCADE,
        related_name='certification_records'
    )

    # Certification Details
    name = models.CharField(max_length=200)
    issuing_organization = models.CharField(max_length=200)
    credential_id = models.CharField(max_length=100, blank=True)
    credential_url = models.URLField(blank=True)

    # Dates
    issue_date = models.DateField()
    expiry_date = models.DateField(null=True, blank=True)

    # Verification
    is_verified = models.BooleanField(default=False)
    verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='certification_verifications'
    )
    verified_date = models.DateField(null=True, blank=True)

    # Document
    certificate_file = models.FileField(
        upload_to='certifications/',
        blank=True,
        null=True
    )

    # Status
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Certification')
        verbose_name_plural = _('Certifications')
        ordering = ['-issue_date']

    def __str__(self):
        return f"{self.employee.full_name} - {self.name}"

    @property
    def is_expired(self):
        if not self.expiry_date:
            return False
        return timezone.now().date() > self.expiry_date

    @property
    def days_until_expiry(self):
        if not self.expiry_date:
            return None
        delta = self.expiry_date - timezone.now().date()
        return delta.days


# =============================================================================
# EMPLOYEE ACTIVITY LOG
# =============================================================================

class EmployeeActivityLog(models.Model):
    """
    Audit log for employee record changes.
    """

    class ActivityType(models.TextChoices):
        CREATED = 'created', _('Employee Created')
        UPDATED = 'updated', _('Information Updated')
        STATUS_CHANGE = 'status_change', _('Status Changed')
        POSITION_CHANGE = 'position_change', _('Position Changed')
        DEPARTMENT_CHANGE = 'department_change', _('Department Changed')
        MANAGER_CHANGE = 'manager_change', _('Manager Changed')
        SALARY_CHANGE = 'salary_change', _('Salary Changed')
        ONBOARDING_STARTED = 'onboarding_started', _('Onboarding Started')
        ONBOARDING_COMPLETED = 'onboarding_completed', _('Onboarding Completed')
        TERMINATION_INITIATED = 'termination_initiated', _('Termination Initiated')
        TERMINATED = 'terminated', _('Terminated')
        OTHER = 'other', _('Other')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    employee = models.ForeignKey(
        Employee,
        on_delete=models.CASCADE,
        related_name='activity_logs'
    )
    activity_type = models.CharField(
        max_length=30,
        choices=ActivityType.choices
    )
    description = models.TextField()
    old_value = models.TextField(blank=True)
    new_value = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    performed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Employee Activity Log')
        verbose_name_plural = _('Employee Activity Logs')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['employee', '-created_at']),
            models.Index(fields=['activity_type', '-created_at']),
        ]

    def __str__(self):
        return f"{self.employee.employee_id} - {self.get_activity_type_display()}"


# =============================================================================
# EMPLOYEE GOALS
# =============================================================================

class EmployeeGoal(models.Model):
    """
    Track employee goals for performance management.
    """

    class GoalStatus(models.TextChoices):
        DRAFT = 'draft', _('Draft')
        ACTIVE = 'active', _('Active')
        COMPLETED = 'completed', _('Completed')
        CANCELLED = 'cancelled', _('Cancelled')
        ON_HOLD = 'on_hold', _('On Hold')

    class GoalPriority(models.TextChoices):
        LOW = 'low', _('Low')
        MEDIUM = 'medium', _('Medium')
        HIGH = 'high', _('High')
        CRITICAL = 'critical', _('Critical')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    employee = models.ForeignKey(
        Employee,
        on_delete=models.CASCADE,
        related_name='goals'
    )

    # Goal Details
    title = models.CharField(max_length=200)
    description = models.TextField()
    key_results = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of key results with title, target, and current value')
    )

    # Categorization
    category = models.CharField(
        max_length=50,
        choices=[
            ('performance', _('Performance')),
            ('development', _('Development')),
            ('project', _('Project')),
            ('team', _('Team')),
            ('personal', _('Personal')),
        ],
        default='performance'
    )
    priority = models.CharField(
        max_length=20,
        choices=GoalPriority.choices,
        default=GoalPriority.MEDIUM
    )

    # Timeline
    start_date = models.DateField()
    target_date = models.DateField()
    completed_date = models.DateField(null=True, blank=True)

    # Progress
    status = models.CharField(
        max_length=20,
        choices=GoalStatus.choices,
        default=GoalStatus.DRAFT
    )
    progress_percentage = models.PositiveIntegerField(
        default=0,
        validators=[MaxValueValidator(100)]
    )

    # Weight for performance review
    weight = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('1.00'),
        help_text=_('Weight of this goal in overall performance')
    )

    # Linked to Review
    performance_review = models.ForeignKey(
        PerformanceReview,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='goals'
    )

    # Approval
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='approved_goals'
    )
    approved_at = models.DateTimeField(null=True, blank=True)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Employee Goal')
        verbose_name_plural = _('Employee Goals')
        ordering = ['-priority', 'target_date']

    def __str__(self):
        return f"{self.employee.full_name} - {self.title}"

    @property
    def is_overdue(self):
        if self.status == self.GoalStatus.COMPLETED:
            return False
        return timezone.now().date() > self.target_date

    @property
    def days_remaining(self):
        if self.status == self.GoalStatus.COMPLETED:
            return 0
        delta = self.target_date - timezone.now().date()
        return max(0, delta.days)


# =============================================================================
# PERFORMANCE IMPROVEMENT PLAN (PIP) MODELS
# =============================================================================

class PerformanceImprovementPlan(models.Model):
    """
    Performance Improvement Plan (PIP) tracking.

    Formal documentation for employees who need performance improvement.
    Tracks goals, milestones, check-ins, and outcomes.
    """

    class PIPStatus(models.TextChoices):
        DRAFT = 'draft', _('Draft')
        ACTIVE = 'active', _('Active')
        EXTENDED = 'extended', _('Extended')
        COMPLETED_SUCCESS = 'completed_success', _('Completed Successfully')
        COMPLETED_FAIL = 'completed_fail', _('Completed Unsuccessfully')
        TERMINATED = 'terminated', _('Terminated')
        CANCELLED = 'cancelled', _('Cancelled')

    class PIPOutcome(models.TextChoices):
        PENDING = 'pending', _('Pending')
        IMPROVED = 'improved', _('Improved - PIP Closed')
        TERMINATED = 'terminated', _('Terminated')
        DEMOTED = 'demoted', _('Demoted')
        TRANSFERRED = 'transferred', _('Transferred')
        EXTENDED = 'extended', _('Extended')
        RESIGNED = 'resigned', _('Resigned During PIP')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    employee = models.ForeignKey(
        Employee,
        on_delete=models.CASCADE,
        related_name='pips'
    )
    initiated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='initiated_pips'
    )
    hr_representative = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='hr_pips'
    )

    # PIP Details
    status = models.CharField(
        max_length=20,
        choices=PIPStatus.choices,
        default=PIPStatus.DRAFT
    )
    reason = models.TextField(
        help_text=_('Detailed reason for placing employee on PIP')
    )
    performance_concerns = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of specific performance concerns')
    )
    goals = models.JSONField(
        default=list,
        blank=True,
        help_text=_('Improvement goals with measurable targets')
    )
    support_provided = models.TextField(
        blank=True,
        help_text=_('Resources and support provided to employee')
    )
    expectations = models.TextField(
        blank=True,
        help_text=_('Clear expectations for improvement')
    )

    # Timeline
    start_date = models.DateField()
    target_end_date = models.DateField()
    actual_end_date = models.DateField(null=True, blank=True)

    # Check-in Schedule
    check_in_frequency_days = models.PositiveIntegerField(
        default=7,
        help_text=_('Days between check-in meetings')
    )
    next_check_in = models.DateField(null=True, blank=True)

    # Outcome
    outcome = models.CharField(
        max_length=20,
        choices=PIPOutcome.choices,
        default=PIPOutcome.PENDING
    )
    final_assessment = models.TextField(blank=True)
    final_rating = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )

    # Linked to Performance Review (if initiated from a review)
    source_review = models.ForeignKey(
        PerformanceReview,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resulting_pips'
    )

    # Signatures & Acknowledgement
    employee_acknowledged_at = models.DateTimeField(null=True, blank=True)
    manager_signed_at = models.DateTimeField(null=True, blank=True)
    hr_signed_at = models.DateTimeField(null=True, blank=True)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Performance Improvement Plan')
        verbose_name_plural = _('Performance Improvement Plans')
        ordering = ['-created_at']

    def __str__(self):
        return f"PIP - {self.employee.full_name} ({self.get_status_display()})"

    @property
    def duration_days(self):
        """Calculate total PIP duration in days."""
        end = self.actual_end_date or self.target_end_date
        return (end - self.start_date).days

    @property
    def days_remaining(self):
        """Days remaining until target end date."""
        if self.status in [
            self.PIPStatus.COMPLETED_SUCCESS,
            self.PIPStatus.COMPLETED_FAIL,
            self.PIPStatus.TERMINATED,
            self.PIPStatus.CANCELLED
        ]:
            return 0
        delta = self.target_end_date - timezone.now().date()
        return max(0, delta.days)

    @property
    def is_overdue(self):
        """Check if PIP has passed target end date without resolution."""
        if self.status in [
            self.PIPStatus.COMPLETED_SUCCESS,
            self.PIPStatus.COMPLETED_FAIL,
            self.PIPStatus.TERMINATED,
            self.PIPStatus.CANCELLED
        ]:
            return False
        return timezone.now().date() > self.target_end_date

    @property
    def progress_percentage(self):
        """Calculate progress through PIP timeline."""
        if self.status == self.PIPStatus.DRAFT:
            return 0
        total_days = (self.target_end_date - self.start_date).days
        if total_days <= 0:
            return 100
        elapsed = (timezone.now().date() - self.start_date).days
        return min(100, max(0, int((elapsed / total_days) * 100)))

    def activate(self):
        """Activate a draft PIP."""
        if self.status == self.PIPStatus.DRAFT:
            self.status = self.PIPStatus.ACTIVE
            self.next_check_in = self.start_date + timedelta(
                days=self.check_in_frequency_days
            )
            self.save()

    def extend(self, new_end_date, reason=''):
        """Extend the PIP deadline."""
        self.status = self.PIPStatus.EXTENDED
        self.target_end_date = new_end_date
        # Log the extension
        PIPProgressNote.objects.create(
            pip=self,
            note_type='extension',
            content=f"PIP extended to {new_end_date}. Reason: {reason}",
        )
        self.save()

    def complete(self, outcome, final_assessment=''):
        """Complete the PIP with an outcome."""
        self.outcome = outcome
        self.final_assessment = final_assessment
        self.actual_end_date = timezone.now().date()

        if outcome == self.PIPOutcome.IMPROVED:
            self.status = self.PIPStatus.COMPLETED_SUCCESS
        elif outcome in [self.PIPOutcome.TERMINATED, self.PIPOutcome.DEMOTED]:
            self.status = self.PIPStatus.COMPLETED_FAIL
        else:
            self.status = self.PIPStatus.COMPLETED_SUCCESS

        self.save()


class PIPMilestone(models.Model):
    """
    Milestones within a Performance Improvement Plan.

    Specific, measurable goals that must be achieved during the PIP.
    """

    class MilestoneStatus(models.TextChoices):
        PENDING = 'pending', _('Pending')
        IN_PROGRESS = 'in_progress', _('In Progress')
        ACHIEVED = 'achieved', _('Achieved')
        NOT_ACHIEVED = 'not_achieved', _('Not Achieved')
        DEFERRED = 'deferred', _('Deferred')

    pip = models.ForeignKey(
        PerformanceImprovementPlan,
        on_delete=models.CASCADE,
        related_name='milestones'
    )

    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    success_criteria = models.TextField(
        blank=True,
        help_text=_('How success will be measured')
    )

    # Timeline
    due_date = models.DateField()
    completed_date = models.DateField(null=True, blank=True)

    # Status & Progress
    status = models.CharField(
        max_length=20,
        choices=MilestoneStatus.choices,
        default=MilestoneStatus.PENDING
    )
    progress_notes = models.TextField(blank=True)

    # Weight for overall PIP completion
    weight = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('1.00')
    )

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('PIP Milestone')
        verbose_name_plural = _('PIP Milestones')
        ordering = ['due_date']

    def __str__(self):
        return f"{self.pip.employee.full_name} - {self.title}"

    @property
    def is_overdue(self):
        if self.status in [self.MilestoneStatus.ACHIEVED, self.MilestoneStatus.DEFERRED]:
            return False
        return timezone.now().date() > self.due_date

    def mark_achieved(self, notes=''):
        """Mark milestone as achieved."""
        self.status = self.MilestoneStatus.ACHIEVED
        self.completed_date = timezone.now().date()
        if notes:
            self.progress_notes += f"\n{timezone.now().date()}: {notes}"
        self.save()


class PIPProgressNote(models.Model):
    """
    Progress notes and check-in records for a PIP.

    Tracks meetings, progress updates, and any documentation.
    """

    class NoteType(models.TextChoices):
        CHECK_IN = 'check_in', _('Check-in Meeting')
        PROGRESS_UPDATE = 'progress_update', _('Progress Update')
        CONCERN = 'concern', _('Concern Raised')
        ACHIEVEMENT = 'achievement', _('Achievement')
        EXTENSION = 'extension', _('Extension')
        FORMAL_WARNING = 'formal_warning', _('Formal Warning')
        OTHER = 'other', _('Other')

    pip = models.ForeignKey(
        PerformanceImprovementPlan,
        on_delete=models.CASCADE,
        related_name='progress_notes'
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='pip_notes_authored'
    )

    note_type = models.CharField(
        max_length=20,
        choices=NoteType.choices,
        default=NoteType.PROGRESS_UPDATE
    )
    content = models.TextField()

    # For check-in meetings
    meeting_date = models.DateField(null=True, blank=True)
    attendees = models.JSONField(default=list, blank=True)
    action_items = models.JSONField(default=list, blank=True)

    # Employee Response (for acknowledgements)
    employee_response = models.TextField(blank=True)
    employee_responded_at = models.DateTimeField(null=True, blank=True)

    # Attachments
    attachments = models.JSONField(default=list, blank=True)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('PIP Progress Note')
        verbose_name_plural = _('PIP Progress Notes')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.pip.employee.full_name} - {self.get_note_type_display()} ({self.created_at.date()})"
