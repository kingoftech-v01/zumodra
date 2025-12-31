"""
Accounts Models - KYC, Progressive Revelation, RBAC

This module implements:
- Bidirectional KYC verification (candidates AND recruiters)
- Progressive data revelation with consent management
- Role-Based Access Control (RBAC) per tenant
- User profiles with encryption for sensitive data
"""

import uuid
from decimal import Decimal
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.validators import MinValueValidator, MaxValueValidator, FileExtensionValidator, MaxLengthValidator
from phonenumber_field.modelfields import PhoneNumberField


class TenantUser(models.Model):
    """
    Links a user to a tenant with role and permissions.
    A user can belong to multiple tenants with different roles.
    """

    class UserRole(models.TextChoices):
        OWNER = 'owner', _('Owner/PDG')
        ADMIN = 'admin', _('Administrator')
        HR_MANAGER = 'hr_manager', _('HR Manager')
        RECRUITER = 'recruiter', _('Recruiter')
        HIRING_MANAGER = 'hiring_manager', _('Hiring Manager')
        EMPLOYEE = 'employee', _('Employee')
        VIEWER = 'viewer', _('Viewer (Read-only)')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='tenant_memberships'
    )
    tenant = models.ForeignKey(
        'tenants.Tenant',
        on_delete=models.CASCADE,
        related_name='members'
    )

    # Role & Permissions
    role = models.CharField(
        max_length=20,
        choices=UserRole.choices,
        default=UserRole.EMPLOYEE
    )
    custom_permissions = models.ManyToManyField(
        Permission,
        blank=True,
        related_name='tenant_users'
    )

    # Department/Team assignment
    department = models.ForeignKey(
        'configurations.Department',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='tenant_users'
    )
    job_title = models.CharField(max_length=100, blank=True)
    reports_to = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='direct_reports'
    )

    # Status
    is_active = models.BooleanField(default=True)
    is_primary_tenant = models.BooleanField(
        default=False,
        help_text=_('Is this the user\'s primary tenant?')
    )

    # Timestamps
    joined_at = models.DateTimeField(auto_now_add=True)
    last_active_at = models.DateTimeField(null=True, blank=True)
    deactivated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Tenant User')
        verbose_name_plural = _('Tenant Users')
        unique_together = ['user', 'tenant']
        ordering = ['-joined_at']

    def __str__(self):
        return f"{self.user.email} @ {self.tenant.name} ({self.get_role_display()})"

    @property
    def is_admin(self):
        return self.role in [self.UserRole.OWNER, self.UserRole.ADMIN]

    @property
    def can_hire(self):
        return self.role in [
            self.UserRole.OWNER, self.UserRole.ADMIN,
            self.UserRole.HR_MANAGER, self.UserRole.RECRUITER,
            self.UserRole.HIRING_MANAGER
        ]

    def get_all_permissions(self):
        """Get all permissions for this tenant user."""
        # Role-based permissions
        role_perms = ROLE_PERMISSIONS.get(self.role, set())
        # Custom permissions
        custom_perms = set(self.custom_permissions.values_list('codename', flat=True))
        return role_perms | custom_perms

    def has_permission(self, perm):
        """Check if user has a specific permission."""
        return perm in self.get_all_permissions()


# Role-based permission mapping
ROLE_PERMISSIONS = {
    TenantUser.UserRole.OWNER: {
        'view_all', 'edit_all', 'delete_all', 'manage_users', 'manage_billing',
        'manage_settings', 'view_analytics', 'export_data', 'manage_integrations',
        'view_candidates', 'edit_candidates', 'view_jobs', 'edit_jobs', 'publish_jobs',
        'view_employees', 'edit_employees', 'manage_hr', 'view_reports',
    },
    TenantUser.UserRole.ADMIN: {
        'view_all', 'edit_all', 'manage_users', 'manage_settings', 'view_analytics',
        'export_data', 'view_candidates', 'edit_candidates', 'view_jobs', 'edit_jobs',
        'publish_jobs', 'view_employees', 'edit_employees', 'manage_hr', 'view_reports',
    },
    TenantUser.UserRole.HR_MANAGER: {
        'view_candidates', 'edit_candidates', 'view_jobs', 'edit_jobs', 'publish_jobs',
        'view_employees', 'edit_employees', 'manage_hr', 'view_reports', 'view_analytics',
        'export_data',
    },
    TenantUser.UserRole.RECRUITER: {
        'view_candidates', 'edit_candidates', 'view_jobs', 'edit_jobs',
        'schedule_interviews', 'send_messages', 'view_reports',
    },
    TenantUser.UserRole.HIRING_MANAGER: {
        'view_candidates', 'view_jobs', 'schedule_interviews', 'leave_feedback',
        'approve_offers', 'view_reports',
    },
    TenantUser.UserRole.EMPLOYEE: {
        'view_profile', 'edit_profile', 'view_directory', 'request_time_off',
        'view_payslips', 'view_announcements',
    },
    TenantUser.UserRole.VIEWER: {
        'view_jobs', 'view_candidates', 'view_reports',
    },
}


class UserProfile(models.Model):
    """
    Extended user profile with KYC status and personal information.
    Supports both candidates and internal users.
    """

    class ProfileType(models.TextChoices):
        CANDIDATE = 'candidate', _('Candidate')
        RECRUITER = 'recruiter', _('Recruiter')
        EMPLOYEE = 'employee', _('Employee')
        ADMIN = 'admin', _('Administrator')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='profile'
    )
    profile_type = models.CharField(
        max_length=20,
        choices=ProfileType.choices,
        default=ProfileType.CANDIDATE
    )

    # Personal Information
    phone = PhoneNumberField(blank=True, null=True)
    phone_verified = models.BooleanField(default=False)
    date_of_birth = models.DateField(null=True, blank=True)
    nationality = models.CharField(max_length=100, blank=True)
    languages = models.JSONField(default=list, blank=True)

    # Address
    address_line1 = models.CharField(max_length=255, blank=True)
    address_line2 = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    postal_code = models.CharField(max_length=20, blank=True)
    country = models.CharField(max_length=100, blank=True, default='CA')

    # Profile Media
    avatar = models.ImageField(
        upload_to='avatars/',
        blank=True,
        null=True,
        validators=[
            FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'gif', 'webp'])
        ],
        help_text=_("Allowed formats: JPG, PNG, GIF, WebP. Max size: 5MB")
    )
    bio = models.TextField(blank=True, validators=[MaxLengthValidator(2000)])

    # Social Links
    linkedin_url = models.URLField(blank=True)
    github_url = models.URLField(blank=True)
    portfolio_url = models.URLField(blank=True)
    twitter_url = models.URLField(blank=True)

    # Preferences
    preferred_language = models.CharField(max_length=10, default='en')
    timezone = models.CharField(max_length=50, default='America/Toronto')
    notification_preferences = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    profile_completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('User Profile')
        verbose_name_plural = _('User Profiles')

    def __str__(self):
        return f"Profile: {self.user.email}"

    @property
    def is_complete(self):
        """Check if profile has minimum required fields."""
        required = [self.phone, self.city, self.country]
        return all(required)

    @property
    def completion_percentage(self):
        """Calculate profile completion percentage."""
        fields = [
            self.phone, self.date_of_birth, self.address_line1,
            self.city, self.country, self.bio, self.avatar
        ]
        filled = sum(1 for f in fields if f)
        return int((filled / len(fields)) * 100)


class KYCVerification(models.Model):
    """
    KYC (Know Your Customer) verification for bidirectional trust.
    Both candidates AND recruiters must be verified.
    """

    class VerificationStatus(models.TextChoices):
        PENDING = 'pending', _('Pending')
        IN_PROGRESS = 'in_progress', _('In Progress')
        VERIFIED = 'verified', _('Verified')
        REJECTED = 'rejected', _('Rejected')
        EXPIRED = 'expired', _('Expired')
        REQUIRES_UPDATE = 'requires_update', _('Requires Update')

    class VerificationType(models.TextChoices):
        IDENTITY = 'identity', _('Identity Verification')
        ADDRESS = 'address', _('Address Verification')
        EMPLOYMENT = 'employment', _('Employment Verification')
        EDUCATION = 'education', _('Education Verification')
        BACKGROUND = 'background', _('Background Check')
        BUSINESS = 'business', _('Business Verification')

    class VerificationLevel(models.TextChoices):
        BASIC = 'basic', _('Basic (Email + Phone)')
        STANDARD = 'standard', _('Standard (ID Verification)')
        ENHANCED = 'enhanced', _('Enhanced (Background Check)')
        COMPLETE = 'complete', _('Complete (Full Verification)')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='kyc_verifications'
    )

    # Verification Details
    verification_type = models.CharField(
        max_length=20,
        choices=VerificationType.choices
    )
    status = models.CharField(
        max_length=20,
        choices=VerificationStatus.choices,
        default=VerificationStatus.PENDING
    )
    level = models.CharField(
        max_length=20,
        choices=VerificationLevel.choices,
        default=VerificationLevel.BASIC
    )

    # Provider Information
    provider = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('KYC provider (e.g., Onfido, Jumio)')
    )
    provider_reference_id = models.CharField(max_length=255, blank=True)
    provider_response = models.JSONField(default=dict, blank=True)

    # Documents (encrypted storage recommended)
    document_type = models.CharField(max_length=50, blank=True)
    document_number_hash = models.CharField(
        max_length=255,
        blank=True,
        help_text=_('Hashed document number for security')
    )
    document_country = models.CharField(max_length=100, blank=True)
    document_expiry = models.DateField(null=True, blank=True)

    # Verification Results
    confidence_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    verified_data = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Verified information from KYC provider')
    )
    rejection_reason = models.TextField(blank=True)

    # Audit
    verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='kyc_verifications_performed'
    )
    notes = models.TextField(blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    submitted_at = models.DateTimeField(null=True, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('KYC Verification')
        verbose_name_plural = _('KYC Verifications')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'verification_type']),
            models.Index(fields=['status', 'created_at']),
        ]

    def __str__(self):
        return f"KYC {self.get_verification_type_display()} for {self.user.email}: {self.get_status_display()}"

    @property
    def is_valid(self):
        """Check if verification is currently valid."""
        if self.status != self.VerificationStatus.VERIFIED:
            return False
        if self.expires_at and timezone.now() > self.expires_at:
            return False
        return True

    def mark_verified(self, verified_by=None, confidence_score=None):
        """Mark verification as successful."""
        self.status = self.VerificationStatus.VERIFIED
        self.verified_at = timezone.now()
        self.verified_by = verified_by
        if confidence_score:
            self.confidence_score = confidence_score
        # Set expiry (1 year by default)
        self.expires_at = timezone.now() + timezone.timedelta(days=365)
        self.save()

    def mark_rejected(self, reason=''):
        """Mark verification as rejected."""
        self.status = self.VerificationStatus.REJECTED
        self.rejection_reason = reason
        self.save()


class ProgressiveConsent(models.Model):
    """
    Progressive data revelation with explicit consent tracking.
    Controls what data is visible at each stage of the hiring process.
    """

    class DataCategory(models.TextChoices):
        BASIC = 'basic', _('Basic Info (Name, Title)')
        CONTACT = 'contact', _('Contact Info (Email, Phone)')
        RESUME = 'resume', _('Resume/CV')
        DETAILED = 'detailed', _('Detailed Profile')
        PERSONAL = 'personal', _('Personal Info (DOB, Address)')
        SENSITIVE = 'sensitive', _('Sensitive Data (NAS, Medical)')
        REFERENCES = 'references', _('References')
        SALARY = 'salary', _('Salary Expectations')
        BACKGROUND = 'background', _('Background Check Results')

    class ConsentStatus(models.TextChoices):
        NOT_REQUESTED = 'not_requested', _('Not Requested')
        PENDING = 'pending', _('Pending')
        GRANTED = 'granted', _('Granted')
        DENIED = 'denied', _('Denied')
        REVOKED = 'revoked', _('Revoked')
        EXPIRED = 'expired', _('Expired')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Who is granting consent (candidate/user)
    grantor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='consents_given'
    )

    # Who is receiving access (recruiter/company)
    grantee_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='consents_received'
    )
    grantee_tenant = models.ForeignKey(
        'tenants.Tenant',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='consents_received'
    )

    # What data category
    data_category = models.CharField(
        max_length=20,
        choices=DataCategory.choices
    )

    # Consent status
    status = models.CharField(
        max_length=20,
        choices=ConsentStatus.choices,
        default=ConsentStatus.NOT_REQUESTED
    )

    # Context (e.g., job application)
    context_type = models.CharField(max_length=50, blank=True)
    context_id = models.PositiveIntegerField(null=True, blank=True)
    purpose = models.TextField(blank=True, help_text=_('Purpose for data access'))

    # Timestamps
    requested_at = models.DateTimeField(null=True, blank=True)
    responded_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    # Audit
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    class Meta:
        verbose_name = _('Progressive Consent')
        verbose_name_plural = _('Progressive Consents')
        unique_together = ['grantor', 'grantee_user', 'grantee_tenant', 'data_category', 'context_type', 'context_id']
        ordering = ['-requested_at']

    def __str__(self):
        grantee = self.grantee_user or self.grantee_tenant
        return f"{self.grantor.email} -> {grantee}: {self.get_data_category_display()}"

    @property
    def is_active(self):
        """Check if consent is currently active."""
        if self.status != self.ConsentStatus.GRANTED:
            return False
        if self.expires_at and timezone.now() > self.expires_at:
            return False
        return True

    def grant(self):
        """Grant consent."""
        self.status = self.ConsentStatus.GRANTED
        self.responded_at = timezone.now()
        # Default expiry: 90 days
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(days=90)
        self.save()

    def deny(self):
        """Deny consent."""
        self.status = self.ConsentStatus.DENIED
        self.responded_at = timezone.now()
        self.save()

    def revoke(self):
        """Revoke previously granted consent."""
        self.status = self.ConsentStatus.REVOKED
        self.revoked_at = timezone.now()
        self.save()


class DataAccessLog(models.Model):
    """
    Audit log for tracking data access under progressive revelation.
    Records who accessed what data and when.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False)

    # Who accessed
    accessor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='data_access_logs'
    )
    accessor_tenant = models.ForeignKey(
        'tenants.Tenant',
        on_delete=models.SET_NULL,
        null=True
    )

    # Whose data
    data_subject = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='data_accessed_logs'
    )

    # What was accessed
    data_category = models.CharField(max_length=20)
    data_fields = models.JSONField(default=list, help_text=_('List of specific fields accessed'))

    # Context
    consent = models.ForeignKey(
        ProgressiveConsent,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    access_reason = models.TextField(blank=True)

    # Request details
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    endpoint = models.CharField(max_length=255, blank=True)

    # Timestamp
    accessed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Data Access Log')
        verbose_name_plural = _('Data Access Logs')
        ordering = ['-accessed_at']
        indexes = [
            models.Index(fields=['data_subject', 'accessed_at']),
            models.Index(fields=['accessor', 'accessed_at']),
        ]

    def __str__(self):
        return f"{self.accessor} accessed {self.data_category} of {self.data_subject}"


class SecurityQuestion(models.Model):
    """
    Security questions for account recovery.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='security_questions'
    )
    question = models.CharField(max_length=255)
    answer_hash = models.CharField(max_length=255, help_text=_('Hashed answer'))
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Security Question')
        verbose_name_plural = _('Security Questions')

    def __str__(self):
        return f"Security Q for {self.user.email}"


class LoginHistory(models.Model):
    """
    Track user login history for security monitoring.
    """

    class LoginResult(models.TextChoices):
        SUCCESS = 'success', _('Success')
        FAILED = 'failed', _('Failed')
        BLOCKED = 'blocked', _('Blocked')
        MFA_REQUIRED = 'mfa_required', _('MFA Required')

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='login_history'
    )
    result = models.CharField(max_length=20, choices=LoginResult.choices)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    location = models.JSONField(default=dict, blank=True)
    device_fingerprint = models.CharField(max_length=255, blank=True)
    failure_reason = models.CharField(max_length=100, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Login History')
        verbose_name_plural = _('Login Histories')
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.user.email} login {self.result} at {self.timestamp}"


# =============================================================================
# TRUST SYSTEM MODELS (Phase 1 - features.md Section 5)
# =============================================================================

class TrustScore(models.Model):
    """
    Multi-dimensional trust score for candidates, freelancers, and employers.

    Implements features.md Section 5.1 - Trust Levels:
    - Identity verification status (Level 1 KYC)
    - Career verification status (Level 2 - Employment + Education)
    - Completed contracts/jobs count and quality
    - Dispute/resolution history
    - Review history and average rating
    """

    class EntityType(models.TextChoices):
        CANDIDATE = 'candidate', _('Candidate/Freelancer')
        EMPLOYER = 'employer', _('Employer/Client')
        INSTITUTION = 'institution', _('School/Institution')

    class TrustLevel(models.TextChoices):
        NEW = 'new', _('New to Platform')
        BASIC = 'basic', _('Basic Trust')
        VERIFIED = 'verified', _('Verified')
        HIGH = 'high', _('High Trust')
        PREMIUM = 'premium', _('Premium Trust')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='trust_score'
    )
    entity_type = models.CharField(
        max_length=20,
        choices=EntityType.choices,
        default=EntityType.CANDIDATE
    )

    # Overall Trust Level
    trust_level = models.CharField(
        max_length=20,
        choices=TrustLevel.choices,
        default=TrustLevel.NEW
    )

    # Composite Scores (0-100)
    overall_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Overall trust score 0-100')
    )

    # Component Scores
    identity_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('KYC/Identity verification score')
    )
    career_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Employment + Education verification score')
    )
    activity_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Platform activity and engagement score')
    )
    review_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Average review rating score')
    )
    dispute_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('100.00'),
        help_text=_('Dispute history score (starts at 100, decreases with disputes)')
    )
    payment_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Payment reliability score (for employers)')
    )

    # Verification Flags
    is_id_verified = models.BooleanField(default=False, help_text=_('Level 1: KYC verified'))
    is_career_verified = models.BooleanField(default=False, help_text=_('Level 2: 80%+ career verified'))
    verified_employment_count = models.PositiveIntegerField(default=0)
    verified_education_count = models.PositiveIntegerField(default=0)
    total_employment_count = models.PositiveIntegerField(default=0)
    total_education_count = models.PositiveIntegerField(default=0)

    # Activity Metrics
    completed_jobs = models.PositiveIntegerField(default=0)
    total_contracts = models.PositiveIntegerField(default=0)
    successful_hires = models.PositiveIntegerField(default=0)  # For employers
    on_time_deliveries = models.PositiveIntegerField(default=0)

    # Review Metrics
    total_reviews = models.PositiveIntegerField(default=0)
    positive_reviews = models.PositiveIntegerField(default=0)
    negative_reviews = models.PositiveIntegerField(default=0)
    average_rating = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        default=Decimal('0.00')
    )

    # Dispute Metrics
    total_disputes = models.PositiveIntegerField(default=0)
    disputes_won = models.PositiveIntegerField(default=0)
    disputes_lost = models.PositiveIntegerField(default=0)
    disputes_pending = models.PositiveIntegerField(default=0)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_calculated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Trust Score')
        verbose_name_plural = _('Trust Scores')
        indexes = [
            models.Index(fields=['trust_level', 'overall_score']),
            models.Index(fields=['entity_type', 'trust_level']),
        ]

    def __str__(self):
        return f"{self.user.email}: {self.get_trust_level_display()} ({self.overall_score})"

    def calculate_overall_score(self):
        """Calculate overall trust score from components."""
        weights = {
            'identity': 0.25,
            'career': 0.25,
            'activity': 0.15,
            'review': 0.20,
            'dispute': 0.15,
        }

        self.overall_score = (
            self.identity_score * Decimal(str(weights['identity'])) +
            self.career_score * Decimal(str(weights['career'])) +
            self.activity_score * Decimal(str(weights['activity'])) +
            self.review_score * Decimal(str(weights['review'])) +
            self.dispute_score * Decimal(str(weights['dispute']))
        )

        # Determine trust level based on score
        if self.overall_score >= 85:
            self.trust_level = self.TrustLevel.PREMIUM
        elif self.overall_score >= 70:
            self.trust_level = self.TrustLevel.HIGH
        elif self.overall_score >= 50:
            self.trust_level = self.TrustLevel.VERIFIED
        elif self.overall_score >= 25:
            self.trust_level = self.TrustLevel.BASIC
        else:
            self.trust_level = self.TrustLevel.NEW

        self.last_calculated_at = timezone.now()
        self.save()

    def update_identity_score(self):
        """Update identity score based on KYC verification."""
        kyc = self.user.kyc_verifications.filter(
            status=KYCVerification.VerificationStatus.VERIFIED
        ).order_by('-level').first()

        if kyc:
            self.is_id_verified = True
            level_scores = {
                KYCVerification.VerificationLevel.BASIC: 40,
                KYCVerification.VerificationLevel.STANDARD: 70,
                KYCVerification.VerificationLevel.ENHANCED: 90,
                KYCVerification.VerificationLevel.COMPLETE: 100,
            }
            self.identity_score = Decimal(str(level_scores.get(kyc.level, 0)))
        else:
            self.is_id_verified = False
            self.identity_score = Decimal('0.00')

        self.save()

    def update_career_score(self):
        """Update career score based on employment/education verification."""
        if self.total_employment_count > 0:
            emp_ratio = self.verified_employment_count / self.total_employment_count
        else:
            emp_ratio = 0

        if self.total_education_count > 0:
            edu_ratio = self.verified_education_count / self.total_education_count
        else:
            edu_ratio = 0

        # Career verified if 80%+ of both are verified
        combined_ratio = (emp_ratio + edu_ratio) / 2 if (self.total_employment_count + self.total_education_count) > 0 else 0
        self.is_career_verified = combined_ratio >= 0.8

        self.career_score = Decimal(str(combined_ratio * 100))
        self.save()

    def update_review_score(self):
        """Update review score based on ratings."""
        if self.total_reviews > 0:
            # Convert 5-star rating to 100-point scale
            self.review_score = self.average_rating * Decimal('20')
        else:
            # Neutral score for new users (not penalized)
            self.review_score = Decimal('50.00')
        self.save()

    def update_dispute_score(self):
        """Update dispute score based on dispute history."""
        if self.total_disputes == 0:
            self.dispute_score = Decimal('100.00')
        else:
            # Each lost dispute reduces score
            lost_penalty = self.disputes_lost * 15
            pending_penalty = self.disputes_pending * 5
            self.dispute_score = max(Decimal('0.00'), Decimal('100.00') - Decimal(str(lost_penalty + pending_penalty)))
        self.save()

    @property
    def trust_explanation(self) -> str:
        """Generate human-readable trust explanation."""
        parts = []
        if self.is_id_verified:
            parts.append("verified identity")
        if self.is_career_verified:
            parts.append(f"{self.verified_employment_count} verified employers")
        if self.completed_jobs > 0:
            parts.append(f"{self.completed_jobs} successful contracts")
        if self.total_disputes == 0:
            parts.append("0 disputes")
        elif self.disputes_lost == 0:
            parts.append(f"{self.disputes_won} disputes resolved in favor")

        return f"{self.get_trust_level_display()} because: " + ", ".join(parts) if parts else "New to platform"


class EmploymentVerification(models.Model):
    """
    Employment verification workflow for Level 2 career verification.

    Implements features.md Section 3.2 - Employment verification:
    - Automated emails to HR contacts
    - Structured questionnaire responses
    - Status tracking per employment entry
    """

    class VerificationStatus(models.TextChoices):
        UNVERIFIED = 'unverified', _('Unverified')
        PENDING = 'pending', _('Verification Pending')
        IN_PROGRESS = 'in_progress', _('In Progress')
        VERIFIED = 'verified', _('Verified')
        DISPUTED = 'disputed', _('Disputed')
        UNABLE_TO_VERIFY = 'unable', _('Unable to Verify')
        EXPIRED = 'expired', _('Verification Expired')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='employment_verifications'
    )

    # Employment Details
    company_name = models.CharField(max_length=255)
    job_title = models.CharField(max_length=255)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True, help_text=_('Leave blank if current'))
    is_current = models.BooleanField(default=False)
    employment_type = models.CharField(
        max_length=20,
        choices=[
            ('full_time', _('Full-time')),
            ('part_time', _('Part-time')),
            ('contract', _('Contract')),
            ('intern', _('Internship')),
            ('freelance', _('Freelance')),
        ],
        default='full_time'
    )
    description = models.TextField(blank=True)

    # Verification Contact
    hr_contact_email = models.EmailField(
        blank=True,
        help_text=_('Official HR or manager email for verification')
    )
    hr_contact_name = models.CharField(max_length=255, blank=True)
    hr_contact_phone = models.CharField(max_length=30, blank=True)
    company_domain = models.CharField(
        max_length=255,
        blank=True,
        help_text=_('Company email domain for validation')
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=VerificationStatus.choices,
        default=VerificationStatus.UNVERIFIED
    )

    # Verification Token (for email links)
    verification_token = models.CharField(max_length=255, unique=True, blank=True)
    token_expires_at = models.DateTimeField(null=True, blank=True)

    # Verification Response
    verified_by_email = models.EmailField(blank=True)
    verified_by_name = models.CharField(max_length=255, blank=True)
    verification_response = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Structured questionnaire response')
    )
    response_notes = models.TextField(blank=True)

    # Verification Details
    dates_confirmed = models.BooleanField(null=True, blank=True)
    title_confirmed = models.BooleanField(null=True, blank=True)
    eligible_for_rehire = models.BooleanField(null=True, blank=True)
    performance_rating = models.CharField(max_length=50, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    request_sent_at = models.DateTimeField(null=True, blank=True)
    reminder_sent_at = models.DateTimeField(null=True, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('Verification expiry (typically 2 years)')
    )

    class Meta:
        verbose_name = _('Employment Verification')
        verbose_name_plural = _('Employment Verifications')
        ordering = ['-start_date']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['verification_token']),
        ]

    def __str__(self):
        return f"{self.user.email}: {self.job_title} at {self.company_name} ({self.get_status_display()})"

    def save(self, *args, **kwargs):
        if not self.verification_token:
            import secrets
            self.verification_token = secrets.token_urlsafe(32)
            self.token_expires_at = timezone.now() + timezone.timedelta(days=30)
        super().save(*args, **kwargs)

    def send_verification_request(self):
        """Send verification email to HR contact."""
        if not self.hr_contact_email:
            return False

        self.status = self.VerificationStatus.PENDING
        self.request_sent_at = timezone.now()
        self.save()
        # Email sending logic would be handled by Celery task
        return True

    def mark_verified(self, response_data: dict):
        """Mark employment as verified with response data."""
        self.status = self.VerificationStatus.VERIFIED
        self.verified_at = timezone.now()
        self.verification_response = response_data
        self.dates_confirmed = response_data.get('dates_confirmed')
        self.title_confirmed = response_data.get('title_confirmed')
        self.eligible_for_rehire = response_data.get('eligible_for_rehire')
        self.expires_at = timezone.now() + timezone.timedelta(days=730)  # 2 years
        self.save()

        # Update user's trust score
        if hasattr(self.user, 'trust_score'):
            trust = self.user.trust_score
            trust.verified_employment_count += 1
            trust.update_career_score()
            trust.calculate_overall_score()


class EducationVerification(models.Model):
    """
    Education verification workflow for Level 2 career verification.

    Implements features.md Section 3.2 - Education verification:
    - University portal/API integration
    - Email-based verification to registrar
    - Transcript upload and validation
    """

    class VerificationStatus(models.TextChoices):
        UNVERIFIED = 'unverified', _('Unverified')
        PENDING = 'pending', _('Verification Pending')
        IN_PROGRESS = 'in_progress', _('In Progress')
        VERIFIED = 'verified', _('Verified')
        DISPUTED = 'disputed', _('Disputed')
        UNABLE_TO_VERIFY = 'unable', _('Unable to Verify')
        EXPIRED = 'expired', _('Verification Expired')

    class VerificationMethod(models.TextChoices):
        EMAIL = 'email', _('Email to Registrar')
        API = 'api', _('Academic API/Partner')
        PORTAL = 'portal', _('Student Portal Login')
        TRANSCRIPT = 'transcript', _('Transcript Upload')
        MANUAL = 'manual', _('Manual Verification')

    class DegreeType(models.TextChoices):
        HIGH_SCHOOL = 'high_school', _('High School Diploma')
        CERTIFICATE = 'certificate', _('Certificate')
        DIPLOMA = 'diploma', _('Diploma')
        ASSOCIATE = 'associate', _('Associate Degree')
        BACHELOR = 'bachelor', _('Bachelor\'s Degree')
        MASTER = 'master', _('Master\'s Degree')
        DOCTORATE = 'doctorate', _('Doctorate/PhD')
        PROFESSIONAL = 'professional', _('Professional Degree')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='education_verifications'
    )

    # Education Details
    institution_name = models.CharField(max_length=255)
    institution_type = models.CharField(
        max_length=20,
        choices=[
            ('university', _('University')),
            ('college', _('College')),
            ('high_school', _('High School')),
            ('vocational', _('Vocational School')),
            ('online', _('Online Institution')),
            ('other', _('Other')),
        ],
        default='university'
    )
    degree_type = models.CharField(
        max_length=20,
        choices=DegreeType.choices,
        default=DegreeType.BACHELOR
    )
    field_of_study = models.CharField(max_length=255)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    is_current = models.BooleanField(default=False)
    graduated = models.BooleanField(default=True)
    gpa = models.DecimalField(max_digits=4, decimal_places=2, null=True, blank=True)
    honors = models.CharField(max_length=100, blank=True)

    # Institution Contact
    registrar_email = models.EmailField(blank=True)
    institution_domain = models.CharField(max_length=255, blank=True)
    student_id = models.CharField(max_length=50, blank=True)

    # Verification Method
    verification_method = models.CharField(
        max_length=20,
        choices=VerificationMethod.choices,
        blank=True
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=VerificationStatus.choices,
        default=VerificationStatus.UNVERIFIED
    )

    # Verification Token
    verification_token = models.CharField(max_length=255, unique=True, blank=True)
    token_expires_at = models.DateTimeField(null=True, blank=True)

    # Documents
    transcript_file = models.FileField(
        upload_to='education_transcripts/',
        blank=True,
        null=True
    )
    diploma_file = models.FileField(
        upload_to='education_diplomas/',
        blank=True,
        null=True
    )

    # Verification Response
    verified_by = models.CharField(max_length=255, blank=True)
    verification_response = models.JSONField(default=dict, blank=True)
    degree_confirmed = models.BooleanField(null=True, blank=True)
    dates_confirmed = models.BooleanField(null=True, blank=True)
    graduation_confirmed = models.BooleanField(null=True, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    request_sent_at = models.DateTimeField(null=True, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Education Verification')
        verbose_name_plural = _('Education Verifications')
        ordering = ['-end_date', '-start_date']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['verification_token']),
        ]

    def __str__(self):
        return f"{self.user.email}: {self.get_degree_type_display()} at {self.institution_name} ({self.get_status_display()})"

    def save(self, *args, **kwargs):
        if not self.verification_token:
            import secrets
            self.verification_token = secrets.token_urlsafe(32)
            self.token_expires_at = timezone.now() + timezone.timedelta(days=30)
        super().save(*args, **kwargs)

    def mark_verified(self, response_data: dict = None):
        """Mark education as verified."""
        self.status = self.VerificationStatus.VERIFIED
        self.verified_at = timezone.now()
        if response_data:
            self.verification_response = response_data
            self.degree_confirmed = response_data.get('degree_confirmed')
            self.dates_confirmed = response_data.get('dates_confirmed')
            self.graduation_confirmed = response_data.get('graduation_confirmed')
        self.expires_at = timezone.now() + timezone.timedelta(days=1825)  # 5 years
        self.save()

        # Update user's trust score
        if hasattr(self.user, 'trust_score'):
            trust = self.user.trust_score
            trust.verified_education_count += 1
            trust.update_career_score()
            trust.calculate_overall_score()


class Review(models.Model):
    """
    Review system with AI-assisted verification for negative reviews.

    Implements features.md Section 5.2-5.3:
    - Structured reviews after job/contract completion
    - AI-assisted fact-checking for negative reviews
    - Anonymous mediation process
    """

    class ReviewType(models.TextChoices):
        EMPLOYER_TO_CANDIDATE = 'emp_to_cand', _('Employer reviewing Candidate')
        CANDIDATE_TO_EMPLOYER = 'cand_to_emp', _('Candidate reviewing Employer')
        CLIENT_TO_FREELANCER = 'cli_to_free', _('Client reviewing Freelancer')
        FREELANCER_TO_CLIENT = 'free_to_cli', _('Freelancer reviewing Client')

    class ReviewStatus(models.TextChoices):
        PENDING = 'pending', _('Pending')
        PUBLISHED = 'published', _('Published')
        UNDER_REVIEW = 'under_review', _('Under Review')
        DISPUTED = 'disputed', _('Disputed')
        VALIDATED = 'validated', _('Validated')
        REJECTED = 'rejected', _('Rejected')
        HIDDEN = 'hidden', _('Hidden')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Reviewer and Reviewee
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='reviews_given'
    )
    reviewee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='reviews_received'
    )

    # Review Type
    review_type = models.CharField(
        max_length=20,
        choices=ReviewType.choices
    )

    # Context (link to job/contract)
    context_type = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('e.g., job_application, contract, project')
    )
    context_id = models.PositiveIntegerField(null=True, blank=True)

    # Rating
    overall_rating = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )

    # Structured ratings
    communication_rating = models.PositiveSmallIntegerField(
        null=True, blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    professionalism_rating = models.PositiveSmallIntegerField(
        null=True, blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    quality_rating = models.PositiveSmallIntegerField(
        null=True, blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    timeliness_rating = models.PositiveSmallIntegerField(
        null=True, blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    would_recommend = models.BooleanField(null=True, blank=True)
    would_work_again = models.BooleanField(null=True, blank=True)

    # Review Content
    title = models.CharField(max_length=255, blank=True)
    content = models.TextField()
    pros = models.TextField(blank=True)
    cons = models.TextField(blank=True)

    # Status
    status = models.CharField(
        max_length=20,
        choices=ReviewStatus.choices,
        default=ReviewStatus.PENDING
    )

    # AI Analysis (for negative reviews)
    is_negative = models.BooleanField(default=False)
    ai_analysis = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('AI analysis of review content')
    )
    ai_flagged = models.BooleanField(
        default=False,
        help_text=_('AI flagged for policy violation')
    )
    ai_confidence_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True
    )

    # Verification/Mediation
    requires_verification = models.BooleanField(default=False)
    evidence_submitted = models.JSONField(default=list, blank=True)
    reviewee_response = models.TextField(blank=True)
    reviewee_evidence = models.JSONField(default=list, blank=True)
    mediation_notes = models.TextField(blank=True)
    mediation_outcome = models.CharField(max_length=50, blank=True)

    # Trust Impact
    trust_impact_applied = models.BooleanField(default=False)
    trust_impact_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    published_at = models.DateTimeField(null=True, blank=True)
    disputed_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Review')
        verbose_name_plural = _('Reviews')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['reviewee', 'status', '-created_at']),
            models.Index(fields=['reviewer', '-created_at']),
            models.Index(fields=['overall_rating', 'status']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['reviewer', 'reviewee', 'context_type', 'context_id'],
                name='accounts_review_unique_per_context'
            )
        ]

    def __str__(self):
        return f"{self.reviewer.email} -> {self.reviewee.email}: {self.overall_rating}/5"

    def save(self, *args, **kwargs):
        # Mark as negative if rating <= 2
        self.is_negative = self.overall_rating <= 2

        # Auto-flag negative reviews for verification
        if self.is_negative and not self.pk:
            self.requires_verification = True
            self.status = self.ReviewStatus.UNDER_REVIEW

        super().save(*args, **kwargs)

    def publish(self):
        """Publish the review."""
        self.status = self.ReviewStatus.PUBLISHED
        self.published_at = timezone.now()
        self.save()
        self._apply_trust_impact()

    def _apply_trust_impact(self):
        """Apply trust score impact from this review."""
        if self.trust_impact_applied:
            return

        if hasattr(self.reviewee, 'trust_score'):
            trust = self.reviewee.trust_score
            trust.total_reviews += 1

            if self.overall_rating >= 4:
                trust.positive_reviews += 1
            elif self.overall_rating <= 2 and self.status == self.ReviewStatus.VALIDATED:
                trust.negative_reviews += 1

            # Recalculate average rating
            all_reviews = Review.objects.filter(
                reviewee=self.reviewee,
                status__in=[self.ReviewStatus.PUBLISHED, self.ReviewStatus.VALIDATED]
            )
            if all_reviews.exists():
                from django.db.models import Avg
                avg = all_reviews.aggregate(Avg('overall_rating'))['overall_rating__avg']
                trust.average_rating = Decimal(str(avg or 0))

            trust.update_review_score()
            trust.calculate_overall_score()

            self.trust_impact_applied = True
            self.save()

    def dispute(self, response: str, evidence: list = None):
        """Dispute this review."""
        self.status = self.ReviewStatus.DISPUTED
        self.reviewee_response = response
        self.reviewee_evidence = evidence or []
        self.disputed_at = timezone.now()
        self.save()

    def validate_after_mediation(self, notes: str, outcome: str):
        """Validate review after mediation process."""
        self.status = self.ReviewStatus.VALIDATED
        self.mediation_notes = notes
        self.mediation_outcome = outcome
        self.resolved_at = timezone.now()
        self.save()
        self._apply_trust_impact()

    def reject_after_mediation(self, notes: str, outcome: str):
        """Reject review after mediation (frivolous/abusive)."""
        self.status = self.ReviewStatus.REJECTED
        self.mediation_notes = notes
        self.mediation_outcome = outcome
        self.resolved_at = timezone.now()
        self.save()


# =============================================================================
# MULTI-CV SYSTEM (Phase 3 - features.md Section 8)
# =============================================================================

class CandidateCV(models.Model):
    """
    Multi-CV system allowing candidates to maintain multiple CV versions.

    Implements features.md Section 8.1:
    - Multiple CV profiles per candidate
    - Targeted to different job types
    - AI-powered selection recommendations
    """

    class CVStatus(models.TextChoices):
        DRAFT = 'draft', _('Draft')
        ACTIVE = 'active', _('Active')
        ARCHIVED = 'archived', _('Archived')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='cvs'
    )

    # CV Identity
    name = models.CharField(
        max_length=100,
        help_text=_('e.g., "Software Engineer", "Data Analyst"')
    )
    slug = models.SlugField(max_length=100)
    is_primary = models.BooleanField(
        default=False,
        help_text=_('Primary/default CV')
    )
    status = models.CharField(
        max_length=20,
        choices=CVStatus.choices,
        default=CVStatus.DRAFT
    )

    # Target
    target_job_types = models.JSONField(
        default=list,
        blank=True,
        help_text=_('Job types this CV is optimized for')
    )
    target_industries = models.JSONField(default=list, blank=True)
    target_keywords = models.JSONField(default=list, blank=True)

    # CV Content
    summary = models.TextField(blank=True, help_text=_('Professional summary'))
    headline = models.CharField(max_length=255, blank=True)

    # Skills (can vary per CV)
    skills = models.JSONField(
        default=list,
        blank=True,
        help_text=_('Skills emphasized in this CV version')
    )
    highlighted_skills = models.JSONField(
        default=list,
        blank=True,
        help_text=_('Top skills to highlight')
    )

    # Experience Selection (which experiences to include)
    included_experiences = models.JSONField(
        default=list,
        blank=True,
        help_text=_('IDs of EmploymentVerification to include')
    )
    experience_order = models.JSONField(
        default=list,
        blank=True,
        help_text=_('Custom ordering of experiences')
    )

    # Education Selection
    included_education = models.JSONField(
        default=list,
        blank=True,
        help_text=_('IDs of EducationVerification to include')
    )

    # Projects/Portfolio
    projects = models.JSONField(
        default=list,
        blank=True,
        help_text=_('Project entries for this CV')
    )

    # Certifications
    certifications = models.JSONField(default=list, blank=True)

    # File Uploads
    cv_file = models.FileField(
        upload_to='candidate_cvs/',
        blank=True,
        null=True,
        validators=[
            FileExtensionValidator(allowed_extensions=['pdf', 'doc', 'docx', 'rtf', 'txt'])
        ],
        help_text=_("Uploaded CV file. Allowed formats: PDF, DOC, DOCX, RTF, TXT. Max size: 10MB")
    )
    cv_file_parsed = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Parsed content from uploaded file')
    )

    # AI Analysis
    ai_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('AI quality score')
    )
    ai_feedback = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('AI-generated feedback')
    )
    ats_compatibility_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('ATS-safe formatting score')
    )
    last_analyzed_at = models.DateTimeField(null=True, blank=True)

    # Usage Stats
    times_used = models.PositiveIntegerField(default=0)
    last_used_at = models.DateTimeField(null=True, blank=True)
    applications_count = models.PositiveIntegerField(default=0)
    interview_rate = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Percentage of applications that led to interviews')
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Candidate CV')
        verbose_name_plural = _('Candidate CVs')
        ordering = ['-is_primary', '-updated_at']
        unique_together = ['user', 'slug']

    def __str__(self):
        return f"{self.user.email}: {self.name}"

    def save(self, *args, **kwargs):
        if not self.slug:
            from django.utils.text import slugify
            self.slug = slugify(self.name)[:90]

        # Ensure only one primary CV
        if self.is_primary:
            CandidateCV.objects.filter(
                user=self.user,
                is_primary=True
            ).exclude(pk=self.pk).update(is_primary=False)

        super().save(*args, **kwargs)

    def record_usage(self):
        """Record that this CV was used for an application."""
        self.times_used += 1
        self.applications_count += 1
        self.last_used_at = timezone.now()
        self.save()

    def calculate_interview_rate(self):
        """Calculate interview rate based on applications."""
        # This would query related applications
        # Placeholder for actual implementation
        pass

    @classmethod
    def get_best_match_for_job(cls, user, job_description: str, job_keywords: list = None):
        """
        Get the best matching CV for a job description.
        Uses AI/keyword matching to recommend the best CV.
        """
        cvs = cls.objects.filter(user=user, status=cls.CVStatus.ACTIVE)
        if not cvs.exists():
            return cls.objects.filter(user=user, is_primary=True).first()

        # Simple keyword matching (AI matching would be more sophisticated)
        if job_keywords:
            best_match = None
            best_score = 0
            for cv in cvs:
                cv_keywords = set(cv.target_keywords + cv.highlighted_skills)
                job_kw_set = set(job_keywords)
                overlap = len(cv_keywords.intersection(job_kw_set))
                if overlap > best_score:
                    best_score = overlap
                    best_match = cv
            if best_match:
                return best_match

        return cvs.filter(is_primary=True).first() or cvs.first()


# =============================================================================
# CO-OP / STUDENT ECOSYSTEM (Phase 3 - features.md Section 7)
# =============================================================================

class StudentProfile(models.Model):
    """
    Student profile for co-op and internship ecosystem.

    Implements features.md Section 7:
    - Distinct student cohorts (university, college, junior)
    - Academic integration
    - School-employer-student triad
    """

    class StudentType(models.TextChoices):
        UNIVERSITY = 'university', _('University Student')
        COLLEGE = 'college', _('College Student')
        HIGH_SCHOOL = 'high_school', _('High School Student')
        VOCATIONAL = 'vocational', _('Vocational/Trade Student')
        BOOTCAMP = 'bootcamp', _('Bootcamp Student')

    class ProgramType(models.TextChoices):
        COOP = 'coop', _('Co-op Program')
        INTERNSHIP = 'internship', _('Internship')
        APPRENTICESHIP = 'apprenticeship', _('Apprenticeship')
        WORK_STUDY = 'work_study', _('Work Study')
        CAPSTONE = 'capstone', _('Capstone Project')

    class EnrollmentStatus(models.TextChoices):
        ACTIVE = 'active', _('Currently Enrolled')
        ON_COOP = 'on_coop', _('On Co-op Term')
        GRADUATED = 'graduated', _('Graduated')
        WITHDRAWN = 'withdrawn', _('Withdrawn')
        SUSPENDED = 'suspended', _('Suspended')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='student_profile'
    )

    # Student Type
    student_type = models.CharField(
        max_length=20,
        choices=StudentType.choices,
        default=StudentType.UNIVERSITY
    )
    program_type = models.CharField(
        max_length=20,
        choices=ProgramType.choices,
        default=ProgramType.COOP
    )

    # Institution
    institution_name = models.CharField(max_length=255)
    institution_type = models.CharField(max_length=50, blank=True)
    institution_email_domain = models.CharField(
        max_length=255,
        blank=True,
        help_text=_('e.g., uwaterloo.ca')
    )
    student_email = models.EmailField(
        blank=True,
        help_text=_('Institutional email for verification')
    )
    student_id = models.CharField(max_length=50, blank=True)

    # Program Details
    program_name = models.CharField(max_length=255)
    faculty = models.CharField(max_length=255, blank=True)
    major = models.CharField(max_length=255)
    minor = models.CharField(max_length=255, blank=True)
    expected_graduation = models.DateField(null=True, blank=True)
    current_year = models.PositiveSmallIntegerField(
        null=True, blank=True,
        help_text=_('Current year of study (1-6)')
    )
    current_term = models.CharField(max_length=20, blank=True)

    # Enrollment Status
    enrollment_status = models.CharField(
        max_length=20,
        choices=EnrollmentStatus.choices,
        default=EnrollmentStatus.ACTIVE
    )
    enrollment_verified = models.BooleanField(default=False)
    enrollment_verified_at = models.DateTimeField(null=True, blank=True)

    # Co-op Program Details
    coop_sequence = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('Co-op sequence (e.g., "4-stream", "8-month")')
    )
    work_terms_completed = models.PositiveSmallIntegerField(default=0)
    work_terms_required = models.PositiveSmallIntegerField(default=0)
    next_work_term_start = models.DateField(null=True, blank=True)
    next_work_term_end = models.DateField(null=True, blank=True)

    # GPA (optional, verified)
    gpa = models.DecimalField(max_digits=4, decimal_places=2, null=True, blank=True)
    gpa_scale = models.DecimalField(
        max_digits=3,
        decimal_places=1,
        default=Decimal('4.0')
    )
    gpa_verified = models.BooleanField(default=False)

    # Skills and Interests
    skills = models.JSONField(default=list, blank=True)
    interests = models.JSONField(default=list, blank=True)
    preferred_industries = models.JSONField(default=list, blank=True)
    preferred_locations = models.JSONField(default=list, blank=True)
    remote_preference = models.CharField(
        max_length=20,
        choices=[
            ('on_site', _('On-site only')),
            ('remote', _('Remote only')),
            ('hybrid', _('Hybrid')),
            ('flexible', _('Flexible')),
        ],
        default='flexible'
    )

    # Work Authorization
    work_authorization = models.CharField(
        max_length=50,
        choices=[
            ('citizen', _('Citizen')),
            ('permanent_resident', _('Permanent Resident')),
            ('study_permit', _('Study Permit with Work Authorization')),
            ('no_authorization', _('No Work Authorization')),
        ],
        blank=True
    )
    work_permit_expiry = models.DateField(null=True, blank=True)

    # Co-op Coordinator Contact
    coordinator_name = models.CharField(max_length=255, blank=True)
    coordinator_email = models.EmailField(blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Student Profile')
        verbose_name_plural = _('Student Profiles')

    def __str__(self):
        return f"{self.user.email}: {self.program_name} at {self.institution_name}"

    @property
    def is_eligible_for_work(self):
        """Check if student is eligible for work placements."""
        if self.enrollment_status not in [
            self.EnrollmentStatus.ACTIVE,
            self.EnrollmentStatus.ON_COOP
        ]:
            return False
        if self.work_authorization == 'no_authorization':
            return False
        return True


class CoopTerm(models.Model):
    """
    Individual co-op/internship work term tracking.
    """

    class TermStatus(models.TextChoices):
        SEARCHING = 'searching', _('Searching')
        MATCHED = 'matched', _('Matched with Employer')
        CONFIRMED = 'confirmed', _('Confirmed')
        IN_PROGRESS = 'in_progress', _('In Progress')
        COMPLETED = 'completed', _('Completed')
        CANCELLED = 'cancelled', _('Cancelled')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    student = models.ForeignKey(
        StudentProfile,
        on_delete=models.CASCADE,
        related_name='coop_terms'
    )

    # Term Details
    term_number = models.PositiveSmallIntegerField()
    term_name = models.CharField(max_length=50, blank=True)  # e.g., "Fall 2024"
    start_date = models.DateField()
    end_date = models.DateField()
    status = models.CharField(
        max_length=20,
        choices=TermStatus.choices,
        default=TermStatus.SEARCHING
    )

    # Employer/Position
    employer_name = models.CharField(max_length=255, blank=True)
    employer_tenant = models.ForeignKey(
        'tenants.Tenant',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='coop_terms'
    )
    job_title = models.CharField(max_length=255, blank=True)
    job_description = models.TextField(blank=True)
    location = models.CharField(max_length=255, blank=True)
    is_remote = models.BooleanField(default=False)

    # Compensation
    hourly_rate = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True
    )
    currency = models.CharField(max_length=3, default='CAD')

    # Evaluation
    employer_evaluation = models.JSONField(default=dict, blank=True)
    employer_rating = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        null=True,
        blank=True
    )
    student_evaluation = models.JSONField(default=dict, blank=True)
    student_rating = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        null=True,
        blank=True
    )
    work_term_report = models.FileField(
        upload_to='coop_reports/',
        blank=True,
        null=True
    )

    # School Approval
    school_approved = models.BooleanField(default=False)
    school_approved_by = models.CharField(max_length=255, blank=True)
    school_approved_at = models.DateTimeField(null=True, blank=True)
    school_notes = models.TextField(blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Co-op Term')
        verbose_name_plural = _('Co-op Terms')
        ordering = ['student', 'term_number']
        unique_together = ['student', 'term_number']

    def __str__(self):
        return f"{self.student.user.email}: Term {self.term_number} - {self.employer_name or 'Searching'}"
