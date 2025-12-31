"""
Configurations Models - Zumodra Core Taxonomy & HR

This module provides core organizational and HR models:
- Skill taxonomy (shared across services and ATS)
- Company/Organization structure (Company, Site, Department, Role)
- Basic HR operations (Employee records, leave, timesheets)
- Lightweight job board models (for internal hiring, separate from ATS)
- Website content models (FAQ, testimonials, partners)

Note: For enterprise ATS features (pipelines, advanced scoring, automation),
use the `ats` app instead. This module provides simpler HR/job functionality.
"""

from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import Group, Permission

from core.db.models import TenantAwareModel
from core.db.managers import TenantAwareManager


# =============================================================================
# SKILL TAXONOMY (Shared across services, ATS, HR)
# =============================================================================

class Skill(TenantAwareModel):
    """
    Represents a skill or competency.
    Used to tag service providers, candidates, and filter matching.

    This is the canonical skill model - used by:
    - services.ProviderSkill
    - ats.CandidateProfile
    - hr_core.EmployeeSkill
    """
    name = models.CharField(max_length=100)
    slug = models.SlugField(max_length=100, blank=True)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=50, blank=True, help_text=_("Skill category (e.g., 'Technical', 'Soft Skills')"))
    is_verified = models.BooleanField(default=False, help_text=_("Admin-verified skill"))

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Skill")
        verbose_name_plural = _("Skills")
        ordering = ['name']
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'slug'],
                name='configurations_skill_unique_tenant_slug'
            )
        ]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            from django.utils.text import slugify
            self.slug = slugify(self.name)[:100]
        super().save(*args, **kwargs)


# =============================================================================
# COMPANY & ORGANIZATION STRUCTURE
# =============================================================================

class Company(TenantAwareModel):
    """
    Represents a company/organization within a tenant.
    Can be the tenant's own company or a client/partner company.
    """
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    domain = models.CharField(max_length=255, blank=True, null=True)
    industry = models.CharField(max_length=120, blank=True)
    logo = models.ImageField(upload_to='company_logos/', blank=True, null=True)
    website = models.URLField(blank=True)
    employee_count = models.PositiveIntegerField(null=True, blank=True)
    founded_year = models.PositiveSmallIntegerField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Company")
        verbose_name_plural = _("Companies")
        ordering = ['name']

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            from django.utils.text import slugify
            self.slug = slugify(self.name)[:255]
        super().save(*args, **kwargs)


class Site(TenantAwareModel):
    """
    Site or branch location of a company.
    """
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='sites')
    name = models.CharField(max_length=255)
    address = models.CharField(max_length=512, blank=True)
    city = models.CharField(max_length=128, blank=True)
    state = models.CharField(max_length=100, blank=True)
    postal_code = models.CharField(max_length=20, blank=True)
    country = models.CharField(max_length=64, blank=True, default='CA')
    phone = models.CharField(max_length=30, blank=True)
    email = models.EmailField(blank=True)
    established_date = models.DateField(null=True, blank=True)
    number_of_employees = models.PositiveIntegerField(default=1)
    is_main_office = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Site")
        verbose_name_plural = _("Sites")
        constraints = [
            models.UniqueConstraint(
                fields=['company', 'name'],
                name='configurations_site_unique_company_name'
            )
        ]

    def __str__(self):
        return f"{self.name} ({self.company.name})"


class CompanyProfile(TenantAwareModel):
    """
    Extended profile information for a company.
    """
    company = models.OneToOneField(Company, on_delete=models.CASCADE, related_name='profile')
    site = models.ForeignKey(Site, on_delete=models.SET_NULL, null=True, blank=True, related_name='profiles')
    description = models.TextField(blank=True)
    website = models.URLField(blank=True, null=True)
    linkedin_url = models.URLField(blank=True)
    twitter_url = models.URLField(blank=True)
    facebook_url = models.URLField(blank=True)
    instagram_url = models.URLField(blank=True)
    culture_description = models.TextField(blank=True)
    benefits_description = models.TextField(blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Company Profile")
        verbose_name_plural = _("Company Profiles")

    def __str__(self):
        return f"Profile: {self.company.name}"


class Department(TenantAwareModel):
    """
    Department within a company.
    """
    company = models.ForeignKey(CompanyProfile, on_delete=models.CASCADE, related_name='departments')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    manager = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='managed_departments'
    )
    parent = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='sub_departments'
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Department")
        verbose_name_plural = _("Departments")
        constraints = [
            models.UniqueConstraint(
                fields=['company', 'name'],
                name='configurations_department_unique_company_name'
            )
        ]

    def __str__(self):
        return f"{self.name} - {self.company.company.name}"


class Role(TenantAwareModel):
    """
    Business role within a company (e.g., Manager, Accountant, HR).
    Can be linked to Django Groups for permission inheritance.
    """
    company = models.ForeignKey(CompanyProfile, on_delete=models.CASCADE, related_name='roles')
    name = models.CharField(max_length=64)
    description = models.TextField(blank=True)
    group = models.OneToOneField(Group, on_delete=models.SET_NULL, null=True, blank=True)
    permissions = models.ManyToManyField(
        Permission,
        blank=True,
        related_name='org_role_permissions'
    )
    is_default = models.BooleanField(default=False, help_text=_("Default role for new members"))

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Role")
        verbose_name_plural = _("Roles")
        constraints = [
            models.UniqueConstraint(
                fields=['company', 'name'],
                name='configurations_role_unique_company_name'
            )
        ]

    def __str__(self):
        return f"{self.name} - {self.company.company.name}"


class Membership(TenantAwareModel):
    """
    Links a user to a company with department and role assignments.
    Manages local permissions within the organization context.
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='company_memberships'
    )
    company = models.ForeignKey(CompanyProfile, on_delete=models.CASCADE, related_name='memberships')
    department = models.ForeignKey(
        Department,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='memberships'
    )
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True, related_name='memberships')
    job_title = models.CharField(max_length=100, blank=True)
    is_active = models.BooleanField(default=True)
    joined_at = models.DateTimeField(auto_now_add=True)
    user_permissions = models.ManyToManyField(
        Permission,
        blank=True,
        related_name='org_membership_permissions'
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Membership")
        verbose_name_plural = _("Memberships")
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'company'],
                name='configurations_membership_unique_user_company'
            )
        ]

    def __str__(self):
        role_name = self.role.name if self.role else 'No Role'
        return f"{self.user.email} @ {self.company.company.name} ({role_name})"

    def get_all_permissions(self):
        """Get all permissions from role and direct assignments."""
        perms = set()
        if self.role and self.role.group:
            perms |= set(self.role.group.permissions.values_list('codename', flat=True))
        if self.role:
            perms |= set(self.role.permissions.values_list('codename', flat=True))
        perms |= set(self.user_permissions.values_list('codename', flat=True))
        return perms

    def has_perm(self, codename):
        """Check if membership has a specific permission."""
        return codename in self.get_all_permissions()


# =============================================================================
# SIMPLE JOB BOARD (for internal hiring - separate from ATS)
# =============================================================================

class CandidateProfile(TenantAwareModel):
    """
    Simple candidate profile for job applications.
    For advanced ATS features, use ats.Candidate instead.
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='basic_candidate_profile'
    )
    resume = models.FileField(upload_to='resumes/', blank=True, null=True)
    bio = models.TextField(blank=True)
    phone = models.CharField(max_length=30, blank=True)
    linkedin_url = models.URLField(blank=True)
    github_url = models.URLField(blank=True)
    portfolio_url = models.URLField(blank=True)
    skills = models.ManyToManyField(Skill, blank=True, related_name='basic_candidates')

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Candidate Profile")
        verbose_name_plural = _("Candidate Profiles")

    def __str__(self):
        return f"Candidate: {self.user.email}"


class JobPosition(TenantAwareModel):
    """
    Job position template within a company.
    """
    company = models.ForeignKey(CompanyProfile, on_delete=models.CASCADE, related_name='positions')
    site = models.ForeignKey(Site, on_delete=models.SET_NULL, null=True, blank=True, related_name='positions')
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True, related_name='positions')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    is_open = models.BooleanField(default=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Job Position")
        verbose_name_plural = _("Job Positions")

    def __str__(self):
        site_name = self.site.name if self.site else "No Site"
        return f"{self.title} ({site_name}) - {self.company.company.name}"


class Job(TenantAwareModel):
    """
    Job posting/listing.
    For enterprise ATS, use ats.JobPosting instead.
    """
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='job_listings')
    position = models.ForeignKey(JobPosition, on_delete=models.CASCADE, related_name='jobs')
    title = models.CharField(max_length=255)
    description = models.TextField()
    requirements = models.TextField(blank=True)
    salary_from = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    salary_to = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    currency = models.CharField(max_length=3, default='CAD')
    is_active = models.BooleanField(default=True)
    posted_at = models.DateTimeField(auto_now_add=True)
    closes_at = models.DateTimeField(null=True, blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Job Listing")
        verbose_name_plural = _("Job Listings")
        ordering = ['-posted_at']

    def __str__(self):
        return f"{self.title} ({self.company.name})"


class JobApplication(TenantAwareModel):
    """
    Simple job application.
    For advanced ATS features, use ats.Application instead.
    """
    class ApplicationStatus(models.TextChoices):
        PENDING = 'pending', _('Pending')
        REVIEWED = 'reviewed', _('Reviewed')
        INTERVIEW = 'interview', _('Interview')
        OFFERED = 'offered', _('Offered')
        ACCEPTED = 'accepted', _('Accepted')
        REJECTED = 'rejected', _('Rejected')
        WITHDRAWN = 'withdrawn', _('Withdrawn')

    candidate = models.ForeignKey(CandidateProfile, on_delete=models.CASCADE, related_name='job_applications')
    job = models.ForeignKey(Job, on_delete=models.CASCADE, related_name='applications')
    cover_letter = models.TextField(blank=True)
    status = models.CharField(
        max_length=20,
        choices=ApplicationStatus.choices,
        default=ApplicationStatus.PENDING
    )
    applied_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_applications'
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Job Application")
        verbose_name_plural = _("Job Applications")
        ordering = ['-applied_at']
        constraints = [
            models.UniqueConstraint(
                fields=['candidate', 'job'],
                name='configurations_application_unique_candidate_job'
            )
        ]

    def __str__(self):
        return f"{self.candidate.user.email} -> {self.job.title} ({self.status})"


# =============================================================================
# EMPLOYEE RECORDS & HR OPERATIONS
# =============================================================================

class EmployeeRecord(TenantAwareModel):
    """
    Employee record linked to a membership.
    """
    class ContractType(models.TextChoices):
        PERMANENT = 'permanent', _('Permanent')
        CONTRACT = 'contract', _('Contract')
        TEMPORARY = 'temporary', _('Temporary')
        INTERN = 'intern', _('Intern')
        FREELANCE = 'freelance', _('Freelance')

    class EmploymentStatus(models.TextChoices):
        ACTIVE = 'active', _('Active')
        ON_LEAVE = 'on_leave', _('On Leave')
        TERMINATED = 'terminated', _('Terminated')
        RESIGNED = 'resigned', _('Resigned')

    membership = models.OneToOneField(Membership, on_delete=models.CASCADE, related_name='employee_record')
    employee_id = models.CharField(max_length=50, blank=True)
    hire_date = models.DateField()
    contract_type = models.CharField(
        max_length=15,
        choices=ContractType.choices,
        default=ContractType.PERMANENT
    )
    salary = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    currency = models.CharField(max_length=3, default='CAD')
    status = models.CharField(
        max_length=15,
        choices=EmploymentStatus.choices,
        default=EmploymentStatus.ACTIVE
    )
    termination_date = models.DateField(null=True, blank=True)
    termination_reason = models.TextField(blank=True)
    notes = models.TextField(blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Employee Record")
        verbose_name_plural = _("Employee Records")

    def __str__(self):
        return f"Employee: {self.membership.user.email}"


class ContractDocument(TenantAwareModel):
    """
    Employment contract documents.
    """
    employee_record = models.ForeignKey(EmployeeRecord, on_delete=models.CASCADE, related_name='contracts')
    title = models.CharField(max_length=200)
    document = models.FileField(upload_to='contracts/')
    description = models.TextField(blank=True)
    signed_at = models.DateField(null=True, blank=True)
    expires_at = models.DateField(null=True, blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Contract Document")
        verbose_name_plural = _("Contract Documents")

    def __str__(self):
        return f"{self.title} - {self.employee_record.membership.user.email}"


class Interview(TenantAwareModel):
    """
    Interview for a job application.
    """
    class InterviewMode(models.TextChoices):
        IN_PERSON = 'in_person', _('In Person')
        REMOTE = 'remote', _('Remote/Video')
        PHONE = 'phone', _('Phone')

    class InterviewStatus(models.TextChoices):
        SCHEDULED = 'scheduled', _('Scheduled')
        COMPLETED = 'completed', _('Completed')
        CANCELLED = 'cancelled', _('Cancelled')
        NO_SHOW = 'no_show', _('No Show')

    application = models.ForeignKey(JobApplication, on_delete=models.CASCADE, related_name='interviews')
    interviewer = models.ForeignKey(Membership, on_delete=models.SET_NULL, null=True, related_name='conducted_interviews')
    scheduled_at = models.DateTimeField()
    duration_minutes = models.PositiveIntegerField(default=30)
    location = models.CharField(max_length=255, blank=True)
    meeting_url = models.URLField(blank=True)
    mode = models.CharField(
        max_length=12,
        choices=InterviewMode.choices,
        default=InterviewMode.REMOTE
    )
    status = models.CharField(
        max_length=12,
        choices=InterviewStatus.choices,
        default=InterviewStatus.SCHEDULED
    )
    summary = models.TextField(blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Interview")
        verbose_name_plural = _("Interviews")
        ordering = ['scheduled_at']

    def __str__(self):
        return f"Interview: {self.application.candidate.user.email} - {self.scheduled_at}"


class InterviewNote(TenantAwareModel):
    """
    Notes from an interview.
    """
    interview = models.ForeignKey(Interview, on_delete=models.CASCADE, related_name='notes')
    author = models.ForeignKey(Membership, on_delete=models.SET_NULL, null=True)
    note = models.TextField()
    rating = models.PositiveSmallIntegerField(null=True, blank=True, help_text=_("1-5 rating"))

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Interview Note")
        verbose_name_plural = _("Interview Notes")

    def __str__(self):
        return f"Note for {self.interview}"


class OnboardingChecklist(TenantAwareModel):
    """
    Onboarding checklist item for new employees.
    """
    employee_record = models.ForeignKey(EmployeeRecord, on_delete=models.CASCADE, related_name='onboarding_items')
    item = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    completed = models.BooleanField(default=False)
    completed_at = models.DateTimeField(null=True, blank=True)
    due_date = models.DateField(null=True, blank=True)
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Onboarding Item")
        verbose_name_plural = _("Onboarding Checklist")

    def __str__(self):
        status = "Done" if self.completed else "Pending"
        return f"{self.item} ({status})"


class LeaveRequest(TenantAwareModel):
    """
    Employee leave/time-off request.
    """
    class LeaveType(models.TextChoices):
        VACATION = 'vacation', _('Vacation')
        SICK = 'sick', _('Sick Leave')
        PERSONAL = 'personal', _('Personal')
        MATERNITY = 'maternity', _('Maternity/Paternity')
        UNPAID = 'unpaid', _('Unpaid Leave')
        OTHER = 'other', _('Other')

    class LeaveStatus(models.TextChoices):
        PENDING = 'pending', _('Pending')
        APPROVED = 'approved', _('Approved')
        REJECTED = 'rejected', _('Rejected')
        CANCELLED = 'cancelled', _('Cancelled')

    employee_record = models.ForeignKey(EmployeeRecord, on_delete=models.CASCADE, related_name='leave_requests')
    leave_type = models.CharField(max_length=15, choices=LeaveType.choices)
    start_date = models.DateField()
    end_date = models.DateField()
    reason = models.TextField(blank=True)
    status = models.CharField(
        max_length=12,
        choices=LeaveStatus.choices,
        default=LeaveStatus.PENDING
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_leave_requests'
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_notes = models.TextField(blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Leave Request")
        verbose_name_plural = _("Leave Requests")
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.get_leave_type_display()}: {self.start_date} - {self.end_date}"

    @property
    def duration_days(self):
        """Calculate leave duration in days."""
        return (self.end_date - self.start_date).days + 1


class Timesheet(TenantAwareModel):
    """
    Weekly timesheet for an employee.
    """
    employee_record = models.ForeignKey(EmployeeRecord, on_delete=models.CASCADE, related_name='timesheets')
    week_start = models.DateField()
    hours_worked = models.DecimalField(max_digits=5, decimal_places=2)
    notes = models.TextField(blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)
    approved = models.BooleanField(default=False)
    approved_at = models.DateTimeField(null=True, blank=True)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='approved_timesheets'
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Timesheet")
        verbose_name_plural = _("Timesheets")
        ordering = ['-week_start']
        constraints = [
            models.UniqueConstraint(
                fields=['employee_record', 'week_start'],
                name='configurations_timesheet_unique_employee_week'
            )
        ]

    def __str__(self):
        return f"Timesheet: {self.employee_record.membership.user.email} - {self.week_start}"


class EmployeeDocument(TenantAwareModel):
    """
    Documents associated with an employee.
    """
    employee_record = models.ForeignKey(EmployeeRecord, on_delete=models.CASCADE, related_name='documents')
    title = models.CharField(max_length=200)
    document = models.FileField(upload_to='employee_docs/')
    description = models.TextField(blank=True)
    document_type = models.CharField(max_length=50, blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Employee Document")
        verbose_name_plural = _("Employee Documents")

    def __str__(self):
        return f"{self.title} - {self.employee_record.membership.user.email}"


class InternalNotification(TenantAwareModel):
    """
    Internal company notifications.
    """
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='internal_notifications')
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    title = models.CharField(max_length=200, blank=True)
    message = models.TextField()
    target_roles = models.ManyToManyField(Role, blank=True)
    is_urgent = models.BooleanField(default=False)
    is_published = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Internal Notification")
        verbose_name_plural = _("Internal Notifications")
        ordering = ['-created_at']

    def __str__(self):
        return self.title or self.message[:50]


# =============================================================================
# CANDIDATE DETAILS (for job board)
# =============================================================================

class WorkExperience(TenantAwareModel):
    """
    Candidate work experience history.
    """
    candidate = models.ForeignKey(CandidateProfile, on_delete=models.CASCADE, related_name='work_experiences')
    job_title = models.CharField(max_length=255)
    company_name = models.CharField(max_length=255)
    location = models.CharField(max_length=255, blank=True)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    is_current = models.BooleanField(default=False)
    description = models.TextField(blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Work Experience")
        verbose_name_plural = _("Work Experiences")
        ordering = ['-start_date']

    def __str__(self):
        return f"{self.job_title} at {self.company_name}"


class Education(TenantAwareModel):
    """
    Candidate education history.
    """
    candidate = models.ForeignKey(CandidateProfile, on_delete=models.CASCADE, related_name='educations')
    school_name = models.CharField(max_length=255)
    degree = models.CharField(max_length=255, blank=True)
    field_of_study = models.CharField(max_length=255, blank=True)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    description = models.TextField(blank=True)
    gpa = models.DecimalField(max_digits=3, decimal_places=2, null=True, blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Education")
        verbose_name_plural = _("Education")
        ordering = ['-start_date']

    def __str__(self):
        return f"{self.degree} - {self.school_name}"


class Certification(TenantAwareModel):
    """
    Candidate certifications.
    """
    candidate = models.ForeignKey(CandidateProfile, on_delete=models.CASCADE, related_name='certifications')
    name = models.CharField(max_length=255)
    issuing_authority = models.CharField(max_length=255, blank=True)
    credential_id = models.CharField(max_length=255, blank=True)
    credential_url = models.URLField(blank=True)
    issue_date = models.DateField()
    expiry_date = models.DateField(null=True, blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Certification")
        verbose_name_plural = _("Certifications")
        ordering = ['-issue_date']

    def __str__(self):
        return f"{self.name}"

    @property
    def is_valid(self):
        """Check if certification is still valid."""
        if not self.expiry_date:
            return True
        return self.expiry_date >= timezone.now().date()


class CandidateDocument(TenantAwareModel):
    """
    Documents uploaded by candidates.
    """
    class DocumentType(models.TextChoices):
        CV = 'cv', _('CV/Resume')
        COVER_LETTER = 'cover_letter', _('Cover Letter')
        PORTFOLIO = 'portfolio', _('Portfolio')
        CERTIFICATE = 'certificate', _('Certificate')
        OTHER = 'other', _('Other')

    candidate = models.ForeignKey(CandidateProfile, on_delete=models.CASCADE, related_name='documents')
    document_type = models.CharField(max_length=20, choices=DocumentType.choices)
    title = models.CharField(max_length=200, blank=True)
    file = models.FileField(upload_to='candidate_documents/')
    description = models.TextField(blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Candidate Document")
        verbose_name_plural = _("Candidate Documents")

    def __str__(self):
        return f"{self.get_document_type_display()} - {self.candidate.user.email}"


class ApplicationNote(TenantAwareModel):
    """
    Internal notes on a job application.
    """
    application = models.ForeignKey(JobApplication, on_delete=models.CASCADE, related_name='notes')
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='config_applicationnote_set')
    note = models.TextField()
    is_private = models.BooleanField(default=True, help_text=_("Private notes visible only to hiring team"))

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Application Note")
        verbose_name_plural = _("Application Notes")
        ordering = ['-created_at']

    def __str__(self):
        return f"Note on {self.application} by {self.author}"


class ApplicationMessage(TenantAwareModel):
    """
    Messages between recruiter and candidate.
    """
    application = models.ForeignKey(JobApplication, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    message = models.TextField()
    is_from_candidate = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True, blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Application Message")
        verbose_name_plural = _("Application Messages")
        ordering = ['created_at']

    def __str__(self):
        return f"Message: {self.application} - {self.sender}"


# =============================================================================
# WEBSITE CONTENT
# =============================================================================

class FAQEntry(TenantAwareModel):
    """
    Frequently Asked Questions.
    """
    question = models.CharField(max_length=500)
    answer = models.TextField()
    category = models.CharField(max_length=100, blank=True)
    sort_order = models.PositiveIntegerField(default=0)
    is_published = models.BooleanField(default=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("FAQ")
        verbose_name_plural = _("FAQs")
        ordering = ['sort_order', 'question']

    def __str__(self):
        return self.question


class Partnership(TenantAwareModel):
    """
    Partner organizations.
    """
    name = models.CharField(max_length=255)
    logo = models.ImageField(upload_to='partners_logos/')
    website = models.URLField(blank=True)
    description = models.TextField(blank=True)
    is_featured = models.BooleanField(default=False)
    sort_order = models.PositiveIntegerField(default=0)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Partnership")
        verbose_name_plural = _("Partnerships")
        ordering = ['sort_order', 'name']

    def __str__(self):
        return self.name


class Testimonial(TenantAwareModel):
    """
    Customer/user testimonials.
    """
    author_name = models.CharField(max_length=255)
    author_title = models.CharField(max_length=255, blank=True)
    author_company = models.CharField(max_length=255, blank=True)
    content = models.TextField()
    author_photo = models.ImageField(upload_to='testimonials/', blank=True, null=True)
    rating = models.PositiveSmallIntegerField(default=5, help_text=_("1-5 rating"))
    is_featured = models.BooleanField(default=False)
    is_published = models.BooleanField(default=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Testimonial")
        verbose_name_plural = _("Testimonials")
        ordering = ['-created_at']

    def __str__(self):
        return f"Testimonial by {self.author_name}"


class TrustedCompany(TenantAwareModel):
    """
    Trusted/client companies (for logos display).
    """
    name = models.CharField(max_length=255)
    logo = models.ImageField(upload_to='trusted_companies/')
    website = models.URLField(blank=True)
    sort_order = models.PositiveIntegerField(default=0)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _("Trusted Company")
        verbose_name_plural = _("Trusted Companies")
        ordering = ['sort_order', 'name']

    def __str__(self):
        return self.name


# =============================================================================
# BACKWARDS COMPATIBILITY
# =============================================================================

# Alias for old typo in model name
Patnership = Partnership
