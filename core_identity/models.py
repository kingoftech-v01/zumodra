"""
Core Identity Models - PUBLIC Schema

These models live in the PUBLIC schema and are shared across all tenants.
They represent global user identity, verification, and cross-tenant data.

Models:
- CustomUser: Core user model (extends AbstractUser)
- UserIdentity: Global personal identity (ONE per user, always created)
- MarketplaceProfile: OPTIONAL freelancer/marketplace identity
- StudentProfile: Student-specific data for co-op education
- CoopSupervisor: Academic/workplace supervisor for co-op students
- TenantInvitation: Email-based invitation system (created BEFORE user joins tenant)

Author: Zumodra Team
Date: 2026-01-17
"""

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from phonenumber_field.modelfields import PhoneNumberField
import uuid


class CustomUser(AbstractUser):
    """
    Core user model - PUBLIC schema.

    Global user account that can belong to multiple tenants.
    Verification flags removed - now in KYCVerification model.
    """

    # Unique identifier
    uuid = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        unique=True,
        db_index=True,
        help_text=_('Global unique identifier for this user')
    )

    # Email is the username
    email = models.EmailField(
        unique=True,
        db_index=True,
        help_text=_('Email address (used for login)')
    )

    # MFA Configuration
    mfa_enabled = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('Whether user has MFA enabled via allauth.mfa')
    )
    mfa_grace_period_end = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('End of 30-day grace period for MFA setup')
    )

    # Privacy
    anonymous_mode = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('Whether user is browsing anonymously')
    )

    # Waitlist System
    is_waitlisted = models.BooleanField(
        default=True,
        db_index=True,
        help_text=_('User is on waitlist and cannot access platform yet')
    )
    waitlist_joined_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('When user joined waitlist')
    )
    waitlist_position = models.PositiveIntegerField(
        null=True,
        blank=True,
        db_index=True,
        help_text=_('Position in waitlist (for gamification)')
    )

    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True
    )
    updated_at = models.DateTimeField(auto_now=True)

    # Use email as username
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')
        db_table = 'core_identity_customuser'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['uuid']),
            models.Index(fields=['mfa_enabled']),
            models.Index(fields=['is_waitlisted']),
            models.Index(fields=['waitlist_position']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return self.email

    @property
    def display_name(self):
        """Return display name from UserIdentity if available."""
        try:
            return self.identity.display_name
        except UserIdentity.DoesNotExist:
            return self.get_full_name() or self.email

    def save(self, *args, **kwargs):
        """Set MFA grace period end on creation."""
        if not self.pk and not self.mfa_grace_period_end:
            from datetime import timedelta
            self.mfa_grace_period_end = timezone.now() + timedelta(days=30)
        super().save(*args, **kwargs)


class UserIdentity(models.Model):
    """
    Global personal identity - ONE per user (always created).

    Contains personal data that doesn't change based on tenant context.
    This is the user's core identity across the entire platform.

    Created automatically via signal when CustomUser is created.
    """

    user = models.OneToOneField(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='identity',
        db_index=True
    )

    # Basic Info
    display_name = models.CharField(
        max_length=100,
        help_text=_('Display name shown across platform')
    )
    avatar = models.ImageField(
        upload_to='avatars/',
        blank=True,
        null=True,
        help_text=_('Profile picture')
    )
    bio = models.TextField(
        max_length=1000,
        blank=True,
        help_text=_('Short bio or introduction')
    )

    # Contact Information
    phone = PhoneNumberField(
        blank=True,
        null=True,
        help_text=_('Primary phone number')
    )
    location_city = models.CharField(
        max_length=100,
        blank=True,
        help_text=_('City of residence')
    )
    location_state = models.CharField(
        max_length=100,
        blank=True,
        help_text=_('State/Province')
    )
    location_country = models.CharField(
        max_length=100,
        blank=True,
        default='CA',
        help_text=_('Country code (ISO 3166-1 alpha-2)')
    )
    timezone = models.CharField(
        max_length=50,
        default='America/Toronto',
        help_text=_('IANA timezone identifier')
    )

    # Professional Links
    linkedin_url = models.URLField(
        blank=True,
        help_text=_('LinkedIn profile URL')
    )
    github_url = models.URLField(
        blank=True,
        help_text=_('GitHub profile URL')
    )
    twitter_handle = models.CharField(
        max_length=100,
        blank=True,
        help_text=_('Twitter/X handle (without @)')
    )
    website_url = models.URLField(
        blank=True,
        help_text=_('Personal website URL')
    )

    # Languages
    languages = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of languages spoken with proficiency levels')
    )

    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('User Identity')
        verbose_name_plural = _('User Identities')
        db_table = 'core_identity_useridentity'
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['location_country']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.display_name} ({self.user.email})"


class MarketplaceProfile(models.Model):
    """
    OPTIONAL freelancer/marketplace identity.

    Only created when user opts into freelance marketplace.
    Has is_active flag - user must explicitly activate their profile.

    Replaces marketplace-specific fields from old PublicProfile model.
    """

    user = models.OneToOneField(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='marketplace_profile',
        db_index=True
    )

    # Activation Status (IMPORTANT: defaults to False)
    is_active = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('Whether user has activated their marketplace profile')
    )

    # Professional Information
    professional_title = models.CharField(
        max_length=150,
        help_text=_('Professional title or headline')
    )
    skills = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of professional skills')
    )

    # Service Categories
    # Note: ManyToMany relationship to ServiceCategory will be added when services app exists

    # Availability
    available_for_work = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('Currently available for new projects')
    )
    availability_hours_per_week = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text=_('Available hours per week')
    )

    # Pricing
    hourly_rate_min = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Minimum hourly rate')
    )
    hourly_rate_max = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Maximum hourly rate')
    )
    rate_currency = models.CharField(
        max_length=3,
        default='CAD',
        help_text=_('Currency code (ISO 4217)')
    )

    # Portfolio
    portfolio_url = models.URLField(
        blank=True,
        help_text=_('Portfolio website URL')
    )
    cv_file = models.FileField(
        upload_to='cvs/',
        blank=True,
        null=True,
        help_text=_('Latest CV/resume file')
    )

    # Privacy & Visibility
    VISIBILITY_PUBLIC = 'public'
    VISIBILITY_TENANTS_ONLY = 'tenants_only'
    VISIBILITY_PRIVATE = 'private'

    VISIBILITY_CHOICES = [
        (VISIBILITY_PUBLIC, _('Public - Anyone can view')),
        (VISIBILITY_TENANTS_ONLY, _('Tenants Only - Only organizations I joined')),
        (VISIBILITY_PRIVATE, _('Private - Hidden')),
    ]

    profile_visibility = models.CharField(
        max_length=20,
        choices=VISIBILITY_CHOICES,
        default=VISIBILITY_PRIVATE,
        db_index=True,
        help_text=_('Who can view this marketplace profile')
    )

    # Statistics (calculated/cached)
    completed_projects = models.PositiveIntegerField(
        default=0,
        help_text=_('Total completed projects')
    )
    total_earnings = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=0,
        help_text=_('Total earnings across all projects')
    )
    average_rating = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Average rating from clients (0-5)')
    )

    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True
    )
    updated_at = models.DateTimeField(auto_now=True)
    activated_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('When profile was first activated')
    )

    class Meta:
        verbose_name = _('Marketplace Profile')
        verbose_name_plural = _('Marketplace Profiles')
        db_table = 'core_identity_marketplaceprofile'
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['is_active', 'available_for_work']),
            models.Index(fields=['profile_visibility']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        status = "Active" if self.is_active else "Inactive"
        return f"{self.user.email} - Marketplace ({status})"

    def activate(self):
        """Activate the marketplace profile."""
        if not self.is_active:
            self.is_active = True
            if not self.activated_at:
                self.activated_at = timezone.now()
            self.save(update_fields=['is_active', 'activated_at', 'updated_at'])

    def deactivate(self):
        """Deactivate the marketplace profile."""
        if self.is_active:
            self.is_active = False
            self.available_for_work = False
            self.save(update_fields=['is_active', 'available_for_work', 'updated_at'])


class StudentProfile(models.Model):
    """
    Student-specific data for co-op education programs.

    Lives in PUBLIC schema - student identity doesn't change per tenant.
    Links to CoopPlacement models in TENANT schema for specific placements.
    """

    user = models.OneToOneField(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='student_profile',
        db_index=True
    )

    # Student Identification
    student_id = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text=_('Student ID from educational institution')
    )

    # Educational Institution
    institution_name = models.CharField(
        max_length=200,
        help_text=_('Name of educational institution')
    )
    program_name = models.CharField(
        max_length=200,
        help_text=_('Program/degree name')
    )
    program_level = models.CharField(
        max_length=50,
        choices=[
            ('diploma', _('Diploma')),
            ('bachelor', _('Bachelor')),
            ('master', _('Master')),
            ('doctorate', _('Doctorate')),
        ],
        help_text=_('Level of study')
    )

    # Program Dates
    program_start_date = models.DateField(
        help_text=_('When student started the program')
    )
    expected_graduation_date = models.DateField(
        help_text=_('Expected graduation date')
    )

    # Co-op Program Details
    total_coop_terms_required = models.PositiveIntegerField(
        default=3,
        help_text=_('Total co-op terms required for graduation')
    )
    total_hours_required = models.PositiveIntegerField(
        default=1800,
        help_text=_('Total hours required across all co-op terms')
    )

    # Academic Advisor/Coordinator
    academic_advisor_email = models.EmailField(
        help_text=_('Email of academic advisor or co-op coordinator')
    )
    academic_advisor_name = models.CharField(
        max_length=200,
        help_text=_('Name of academic advisor or co-op coordinator')
    )

    # Status
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text=_('Whether student is currently enrolled')
    )

    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Student Profile')
        verbose_name_plural = _('Student Profiles')
        db_table = 'core_identity_studentprofile'
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['student_id']),
            models.Index(fields=['institution_name']),
            models.Index(fields=['is_active']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.student_id} ({self.institution_name})"


class CoopSupervisor(models.Model):
    """
    Academic or workplace supervisor for co-op students.

    Lives in PUBLIC schema - supervisors can oversee students across tenants.
    Can be linked to a CustomUser if they have a platform account.
    """

    # Link to user account (optional - supervisor might not be a platform user)
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='coop_supervisor_profiles',
        help_text=_('Platform account if supervisor is also a user')
    )

    # Supervisor Type
    SUPERVISOR_TYPE_ACADEMIC = 'academic'
    SUPERVISOR_TYPE_WORKPLACE = 'workplace'

    SUPERVISOR_TYPE_CHOICES = [
        (SUPERVISOR_TYPE_ACADEMIC, _('Academic Supervisor (Professor/Teacher)')),
        (SUPERVISOR_TYPE_WORKPLACE, _('Workplace Supervisor (Company Manager)')),
    ]

    supervisor_type = models.CharField(
        max_length=20,
        choices=SUPERVISOR_TYPE_CHOICES,
        db_index=True,
        help_text=_('Type of supervisor')
    )

    # Contact Information
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(
        unique=True,
        db_index=True,
        help_text=_('Contact email')
    )
    phone = PhoneNumberField(
        blank=True,
        null=True,
        help_text=_('Contact phone number')
    )

    # Organization (for academic supervisors)
    institution_name = models.CharField(
        max_length=200,
        blank=True,
        help_text=_('Educational institution name (for academic supervisors)')
    )
    department = models.CharField(
        max_length=200,
        blank=True,
        help_text=_('Department or faculty')
    )

    # Workplace (for workplace supervisors - tenant link in CoopPlacement model)
    job_title = models.CharField(
        max_length=150,
        blank=True,
        help_text=_('Job title at company (for workplace supervisors)')
    )

    # Credentials
    credentials = models.CharField(
        max_length=200,
        blank=True,
        help_text=_('Professional credentials or certifications')
    )

    # Status
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text=_('Whether supervisor is currently active')
    )

    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Co-op Supervisor')
        verbose_name_plural = _('Co-op Supervisors')
        db_table = 'core_identity_coopsupervisor'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['supervisor_type']),
            models.Index(fields=['is_active']),
        ]

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.get_supervisor_type_display()})"

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"


class TenantInvitation(models.Model):
    """
    Email-based invitation system for joining tenants.

    Lives in PUBLIC schema - invitations created BEFORE user account exists.
    Ensures user account is created in PUBLIC schema BEFORE tenant integration.

    Workflow:
    1. Manager invites "jean@email.com" → TenantInvitation created
    2. Jean receives email with unique token
    3. Jean MUST create account first (if doesn't exist)
    4. Jean accepts invitation → TenantMember created in tenant
    5. Jean can access the tenant
    """

    # Invitation Details
    uuid = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        unique=True,
        db_index=True,
        help_text=_('Unique invitation token')
    )
    email = models.EmailField(
        db_index=True,
        help_text=_('Email address being invited')
    )

    # Tenant Information (stored as UUID to avoid cross-schema FK)
    tenant_uuid = models.UUIDField(
        db_index=True,
        help_text=_('UUID of the tenant inviting this user')
    )
    tenant_name = models.CharField(
        max_length=200,
        help_text=_('Cached name of tenant for display')
    )

    # Role & Invitation Details
    invited_role = models.CharField(
        max_length=20,
        help_text=_('Role user will have when they join')
    )
    invited_by_email = models.EmailField(
        help_text=_('Email of user who sent the invitation')
    )
    invited_by_name = models.CharField(
        max_length=200,
        help_text=_('Name of user who sent the invitation')
    )

    # Custom Message
    custom_message = models.TextField(
        blank=True,
        max_length=500,
        help_text=_('Optional personal message from inviter')
    )

    # Status
    STATUS_PENDING = 'pending'
    STATUS_ACCEPTED = 'accepted'
    STATUS_REJECTED = 'rejected'
    STATUS_EXPIRED = 'expired'
    STATUS_CANCELLED = 'cancelled'

    STATUS_CHOICES = [
        (STATUS_PENDING, _('Pending')),
        (STATUS_ACCEPTED, _('Accepted')),
        (STATUS_REJECTED, _('Rejected')),
        (STATUS_EXPIRED, _('Expired')),
        (STATUS_CANCELLED, _('Cancelled')),
    ]

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
        db_index=True,
        help_text=_('Current status of invitation')
    )

    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True
    )
    expires_at = models.DateTimeField(
        help_text=_('When invitation expires (default: 7 days)')
    )
    accepted_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('When invitation was accepted')
    )

    # Linked User (set when invitation is accepted)
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='tenant_invitations',
        help_text=_('User who accepted this invitation')
    )

    class Meta:
        verbose_name = _('Tenant Invitation')
        verbose_name_plural = _('Tenant Invitations')
        db_table = 'core_identity_tenantinvitation'
        indexes = [
            models.Index(fields=['uuid']),
            models.Index(fields=['email', 'status']),
            models.Index(fields=['tenant_uuid', 'status']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['created_at']),
        ]
        unique_together = [
            ('email', 'tenant_uuid', 'status'),  # One pending invitation per email per tenant
        ]

    def __str__(self):
        return f"Invitation for {self.email} to {self.tenant_name} ({self.status})"

    def is_expired(self):
        """Check if invitation has expired."""
        return timezone.now() > self.expires_at and self.status == self.STATUS_PENDING

    def accept(self, user):
        """Accept the invitation and link to user."""
        if self.status != self.STATUS_PENDING:
            raise ValueError(f"Cannot accept invitation with status: {self.status}")

        if self.is_expired():
            self.status = self.STATUS_EXPIRED
            self.save(update_fields=['status', 'updated_at'])
            raise ValueError("Invitation has expired")

        self.user = user
        self.status = self.STATUS_ACCEPTED
        self.accepted_at = timezone.now()
        self.save(update_fields=['user', 'status', 'accepted_at'])

    def reject(self):
        """Reject the invitation."""
        if self.status != self.STATUS_PENDING:
            raise ValueError(f"Cannot reject invitation with status: {self.status}")

        self.status = self.STATUS_REJECTED
        self.save(update_fields=['status'])

    def cancel(self):
        """Cancel the invitation (by inviter)."""
        if self.status not in [self.STATUS_PENDING, self.STATUS_EXPIRED]:
            raise ValueError(f"Cannot cancel invitation with status: {self.status}")

        self.status = self.STATUS_CANCELLED
        self.save(update_fields=['status'])

    def save(self, *args, **kwargs):
        """Set expiration date on creation (7 days from now)."""
        if not self.pk and not self.expires_at:
            from datetime import timedelta
            self.expires_at = timezone.now() + timedelta(days=7)
        super().save(*args, **kwargs)


class PlatformLaunch(models.Model):
    """
    Global platform launch configuration - SINGLETON MODEL.

    Controls the waitlist system and platform launch date.
    Only one record should exist in the database.

    Features:
    - Set platform launch date
    - Enable/disable waitlist system
    - Manual launch override
    - Customizable waitlist message
    """

    launch_date = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        help_text=_('When platform becomes publicly accessible')
    )
    is_launched = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('Manual override to launch immediately')
    )
    waitlist_enabled = models.BooleanField(
        default=True,
        db_index=True,
        help_text=_('Enable waitlist system')
    )
    waitlist_message = models.TextField(
        default='Thank you for your interest! The platform will launch soon.',
        help_text=_('Message shown to waitlisted users')
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Platform Launch Configuration')
        verbose_name_plural = _('Platform Launch Configuration')
        db_table = 'core_identity_platformlaunch'

    def __str__(self):
        if self.is_launched:
            return "Platform: LAUNCHED"
        elif self.launch_date:
            return f"Platform Launch: {self.launch_date.strftime('%Y-%m-%d %H:%M')}"
        else:
            return "Platform Launch: Date Not Set"

    @classmethod
    def get_config(cls):
        """
        Get or create singleton configuration.

        Returns:
            PlatformLaunch: The singleton configuration instance
        """
        config, created = cls.objects.get_or_create(pk=1)
        if created:
            # Set default launch date to 30 days from now if not specified
            from datetime import timedelta
            config.launch_date = timezone.now() + timedelta(days=30)
            config.save()
        return config

    @property
    def is_platform_launched(self):
        """
        Check if platform has launched.

        Returns:
            bool: True if platform is accessible, False if waitlisted
        """
        # Manual override
        if self.is_launched:
            return True

        # Check if launch date has passed
        if self.launch_date and timezone.now() >= self.launch_date:
            return True

        return False

    @property
    def days_until_launch(self):
        """
        Calculate days remaining until launch.

        Returns:
            int: Number of days until launch (0 if launched), or None if no date set
        """
        if self.is_platform_launched:
            return 0

        if not self.launch_date:
            return None

        delta = self.launch_date - timezone.now()
        return max(0, delta.days)

    @property
    def time_until_launch(self):
        """
        Get detailed time remaining (days, hours, minutes).

        Returns:
            dict: {'days': int, 'hours': int, 'minutes': int} or None
        """
        if self.is_platform_launched:
            return {'days': 0, 'hours': 0, 'minutes': 0}

        if not self.launch_date:
            return None

        delta = self.launch_date - timezone.now()

        # Handle negative delta (launch date in past but not manually launched)
        if delta.total_seconds() < 0:
            return {'days': 0, 'hours': 0, 'minutes': 0}

        days = delta.days
        seconds = delta.seconds
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60

        return {
            'days': max(0, days),
            'hours': max(0, hours),
            'minutes': max(0, minutes)
        }

    def save(self, *args, **kwargs):
        """Ensure singleton pattern - only one instance allowed."""
        self.pk = 1
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Prevent deletion of singleton instance."""
        pass
