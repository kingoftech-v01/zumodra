"""
Tenants Models - Multi-tenant ATS/HR SaaS Platform

This module defines the core multi-tenancy models for Zumodra:
- Plan: Subscription tiers with feature flags
- Tenant: Enterprise/organization with schema isolation
- TenantSettings: Tenant-specific configuration
- Domain: Custom domain mapping for tenants
- TenantInvitation: Invite users to join tenant
"""

import uuid
from decimal import Decimal
from django.db import models
from django.contrib.gis.db import models as gis_models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.postgres.fields import ArrayField
from django_tenants.models import TenantMixin, DomainMixin
from django.conf import settings
from django.core.validators import FileExtensionValidator
from django.core.exceptions import ValidationError


class Plan(models.Model):
    """
    Subscription plans with feature flags and limits.
    Defines what features each tenant tier has access to.
    """

    class PlanType(models.TextChoices):
        FREE = 'free', _('Free')
        STARTER = 'starter', _('Starter')
        PROFESSIONAL = 'professional', _('Professional')
        ENTERPRISE = 'enterprise', _('Enterprise')

    # Basic Info
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True)
    plan_type = models.CharField(
        max_length=20,
        choices=PlanType.choices,
        default=PlanType.FREE
    )
    description = models.TextField(blank=True)

    # Pricing
    price_monthly = models.DecimalField(
        max_digits=10, decimal_places=2, default=Decimal('0.00')
    )
    price_yearly = models.DecimalField(
        max_digits=10, decimal_places=2, default=Decimal('0.00')
    )
    currency = models.CharField(max_length=3, default='USD')
    stripe_price_id_monthly = models.CharField(max_length=255, blank=True)
    stripe_price_id_yearly = models.CharField(max_length=255, blank=True)
    stripe_product_id = models.CharField(max_length=255, blank=True)

    # Limits
    max_users = models.PositiveIntegerField(default=5, help_text=_('Maximum users allowed'))
    max_job_postings = models.PositiveIntegerField(default=10, help_text=_('Maximum active job postings'))
    max_candidates_per_month = models.PositiveIntegerField(default=100, help_text=_('Max candidate applications per month'))
    max_circusales = models.PositiveIntegerField(default=1, help_text=_('Maximum business locations/branches'))
    storage_limit_gb = models.PositiveIntegerField(default=5, help_text=_('Storage limit in GB'))

    # Feature Flags - Core ATS/HR
    feature_ats = models.BooleanField(default=True, help_text=_('ATS (Applicant Tracking System)'))
    feature_hr_core = models.BooleanField(default=False, help_text=_('HR Core (Time-off, Onboarding)'))
    feature_analytics = models.BooleanField(default=False, help_text=_('Advanced Analytics'))
    feature_api_access = models.BooleanField(default=False, help_text=_('REST API Access'))
    feature_custom_pipelines = models.BooleanField(default=False, help_text=_('Custom Recruitment Pipelines'))
    feature_ai_matching = models.BooleanField(default=False, help_text=_('AI Candidate Matching'))
    feature_video_interviews = models.BooleanField(default=False, help_text=_('Video Interview Integration'))
    feature_esignature = models.BooleanField(default=False, help_text=_('E-Signature (DocuSign)'))
    feature_sso = models.BooleanField(default=False, help_text=_('Single Sign-On (SAML/OIDC)'))
    feature_audit_logs = models.BooleanField(default=False, help_text=_('Detailed Audit Logs'))
    feature_custom_branding = models.BooleanField(default=False, help_text=_('Custom Branding/White-label'))
    feature_priority_support = models.BooleanField(default=False, help_text=_('Priority Support'))
    feature_data_export = models.BooleanField(default=True, help_text=_('Data Export (CSV/Excel)'))
    feature_bulk_actions = models.BooleanField(default=False, help_text=_('Bulk Actions'))
    feature_advanced_filters = models.BooleanField(default=False, help_text=_('Advanced ATS Filters (30+)'))
    feature_diversity_analytics = models.BooleanField(default=False, help_text=_('Diversity & Inclusion Analytics'))
    feature_compliance_tools = models.BooleanField(default=False, help_text=_('Compliance Management Tools'))

    # Feature Flags - Marketplace & Services (Zumodra-specific)
    feature_marketplace = models.BooleanField(default=False, help_text=_('Freelance Services Marketplace'))
    feature_escrow_payments = models.BooleanField(default=False, help_text=_('Escrow Payment System'))
    feature_real_time_messaging = models.BooleanField(default=True, help_text=_('Real-time WebSocket Messaging'))
    feature_appointments = models.BooleanField(default=True, help_text=_('Appointment Booking System'))
    feature_newsletter = models.BooleanField(default=False, help_text=_('Email Newsletter/Marketing'))
    feature_crm = models.BooleanField(default=False, help_text=_('CRM Pipeline Management'))
    feature_geospatial = models.BooleanField(default=False, help_text=_('PostGIS Geospatial Features'))

    # Feature Flags - Multi-Tenant & Enterprise
    feature_multi_circusale = models.BooleanField(default=False, help_text=_('Multiple Business Locations'))
    feature_custom_domains = models.BooleanField(default=False, help_text=_('Custom Domain Mapping'))
    feature_webhooks = models.BooleanField(default=False, help_text=_('Outbound Webhooks'))
    feature_2fa_required = models.BooleanField(default=False, help_text=_('Enforce 2FA for All Users'))
    feature_ip_whitelist = models.BooleanField(default=False, help_text=_('IP Whitelist Access Control'))

    # Feature Flags - Content & Marketing
    feature_wagtail_cms = models.BooleanField(default=False, help_text=_('Wagtail CMS for Content'))
    feature_career_pages = models.BooleanField(default=True, help_text=_('Public Career Pages'))
    feature_events = models.BooleanField(default=False, help_text=_('Event Management & RSVPs'))

    # Feature Flags - Integrations
    feature_slack_integration = models.BooleanField(default=False, help_text=_('Slack Notifications'))
    feature_calendar_sync = models.BooleanField(default=False, help_text=_('Calendar Integration (Google/Outlook)'))
    feature_linkedin_import = models.BooleanField(default=False, help_text=_('LinkedIn Profile Import'))
    feature_background_checks = models.BooleanField(default=False, help_text=_('Background Check Integration'))

    # Metadata
    is_active = models.BooleanField(default=True)
    is_popular = models.BooleanField(default=False, help_text=_('Highlight as popular plan'))
    sort_order = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['sort_order', 'price_monthly']
        verbose_name = _('Subscription Plan')
        verbose_name_plural = _('Subscription Plans')

    def __str__(self):
        return f"{self.name} ({self.get_plan_type_display()})"

    def get_features_list(self):
        """Return list of enabled features for display."""
        features = []
        feature_fields = [f for f in self._meta.get_fields() if f.name.startswith('feature_')]
        for field in feature_fields:
            if getattr(self, field.name):
                features.append(field.verbose_name or field.name.replace('feature_', '').replace('_', ' ').title())
        return features


class Tenant(TenantMixin):
    """
    Multi-tenant organization with schema-per-tenant isolation.
    Each tenant represents an enterprise/company using the platform.
    """

    class TenantStatus(models.TextChoices):
        PENDING = 'pending', _('Pending Setup')
        ACTIVE = 'active', _('Active')
        SUSPENDED = 'suspended', _('Suspended')
        CANCELLED = 'cancelled', _('Cancelled')
        TRIAL = 'trial', _('Trial')

    class TenantType(models.TextChoices):
        COMPANY = 'company', _('Company')
        FREELANCER = 'freelancer', _('Freelancer')

    # Identity
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=255, help_text=_('Organization name'))
    slug = models.SlugField(max_length=100, unique=True)

    # Status & Plan
    status = models.CharField(
        max_length=20,
        choices=TenantStatus.choices,
        default=TenantStatus.TRIAL
    )
    plan = models.ForeignKey(
        Plan,
        on_delete=models.PROTECT,
        related_name='tenants',
        null=True,
        blank=True
    )

    # Trial & Subscription
    trial_ends_at = models.DateTimeField(null=True, blank=True)
    paid_until = models.DateTimeField(null=True, blank=True)
    on_trial = models.BooleanField(default=True)

    # Stripe Integration
    stripe_customer_id = models.CharField(max_length=255, blank=True)
    stripe_subscription_id = models.CharField(max_length=255, blank=True)

    # Owner (first admin user)
    owner_email = models.EmailField(help_text=_('Primary contact email'))

    # Company Info
    industry = models.CharField(max_length=100, blank=True)
    company_size = models.CharField(
        max_length=20,
        choices=[
            ('1-10', '1-10'),
            ('11-50', '11-50'),
            ('51-200', '51-200'),
            ('201-500', '201-500'),
            ('501-1000', '501-1000'),
            ('1000+', '1000+'),
        ],
        blank=True
    )
    website = models.URLField(blank=True)
    logo = models.ImageField(
        upload_to='tenant_logos/',
        blank=True,
        null=True,
        validators=[
            FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp'])
        ],
        help_text=_("Allowed formats: JPG, PNG, GIF, SVG, WebP. Max size: 5MB")
    )

    # Address
    address_line1 = models.CharField(max_length=255, blank=True)
    address_line2 = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    postal_code = models.CharField(max_length=20, blank=True)
    country = models.CharField(max_length=100, blank=True, default='CA')

    # Geolocation (for map markers)
    # See TODO-CAREERS-001 in careers/TODO.md
    location = gis_models.PointField(
        geography=True,
        srid=4326,  # WGS84 (latitude/longitude)
        null=True,
        blank=True,
        help_text=_('Geographic coordinates for company location')
    )

    # Tenant Type & Verification
    tenant_type = models.CharField(
        max_length=20,
        choices=TenantType.choices,
        default=TenantType.COMPANY,
        db_index=True,
        help_text=_('Company (jobs+services, employees) or Freelancer (services only, solo)')
    )
    ein_number = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('EIN/Business registration number')
    )
    ein_verified = models.BooleanField(
        default=False,
        help_text=_('Business number verified via API')
    )
    ein_verified_at = models.DateTimeField(null=True, blank=True)

    # Settings Flags
    auto_create_schema = True
    auto_drop_schema = False  # Safety: don't auto-delete tenant data

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    activated_at = models.DateTimeField(null=True, blank=True)
    suspended_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Tenant')
        verbose_name_plural = _('Tenants')
        ordering = ['-created_at']

    def __str__(self):
        return self.name

    def clean(self):
        super().clean()
        if self.logo and hasattr(self.logo, 'size'):
            if self.logo.size > 5 * 1024 * 1024:  # 5MB
                raise ValidationError({'logo': _("Logo file size must be less than 5MB.")})

    @property
    def is_active(self):
        return self.status == self.TenantStatus.ACTIVE

    @property
    def is_on_trial(self):
        if not self.on_trial:
            return False
        if self.trial_ends_at and timezone.now() > self.trial_ends_at:
            return False
        return True

    @property
    def trial_days_remaining(self):
        if not self.trial_ends_at:
            return 0
        delta = self.trial_ends_at - timezone.now()
        return max(0, delta.days)

    @property
    def latitude(self):
        """Get latitude from location PointField."""
        if self.location:
            return self.location.y
        return None

    @property
    def longitude(self):
        """Get longitude from location PointField."""
        if self.location:
            return self.location.x
        return None

    @property
    def has_location(self):
        """Check if tenant has geocoded location."""
        return self.location is not None

    def activate(self):
        """Activate tenant after successful payment or approval."""
        self.status = self.TenantStatus.ACTIVE
        self.on_trial = False
        self.activated_at = timezone.now()
        self.save(update_fields=['status', 'on_trial', 'activated_at'])

    def suspend(self, reason=''):
        """Suspend tenant (e.g., payment failure)."""
        self.status = self.TenantStatus.SUSPENDED
        self.suspended_at = timezone.now()
        self.save(update_fields=['status', 'suspended_at'])

    def cancel(self):
        """Cancel tenant subscription."""
        self.status = self.TenantStatus.CANCELLED
        self.save(update_fields=['status'])

    def reactivate(self, plan=None):
        """
        Reactivate a suspended or cancelled tenant.

        Args:
            plan: Optional new plan to assign.
        """
        if plan:
            self.plan = plan
        self.status = self.TenantStatus.ACTIVE
        self.suspended_at = None
        self.save(update_fields=['status', 'plan', 'suspended_at'])

    def extend_trial(self, days: int = 14):
        """
        Extend the trial period by specified days.

        Args:
            days: Number of days to extend trial (default 14).
        """
        if self.trial_ends_at:
            self.trial_ends_at = self.trial_ends_at + timezone.timedelta(days=days)
        else:
            self.trial_ends_at = timezone.now() + timezone.timedelta(days=days)

        self.on_trial = True
        self.status = self.TenantStatus.TRIAL
        self.save(update_fields=['trial_ends_at', 'on_trial', 'status'])

    def convert_from_trial(self, plan=None):
        """
        Convert from trial to paid subscription.

        Args:
            plan: Plan to subscribe to (optional, uses current plan if not provided).
        """
        if plan:
            self.plan = plan
        self.on_trial = False
        self.status = self.TenantStatus.ACTIVE
        self.activated_at = timezone.now()
        # Set default paid_until to 30 days from now if not set
        if not self.paid_until:
            self.paid_until = timezone.now() + timezone.timedelta(days=30)
        self.save(update_fields=['plan', 'on_trial', 'status', 'activated_at', 'paid_until'])

    def update_subscription(self, stripe_subscription_id: str, paid_until):
        """
        Update subscription details from Stripe.

        Args:
            stripe_subscription_id: Stripe subscription ID.
            paid_until: Datetime until which subscription is paid.
        """
        self.stripe_subscription_id = stripe_subscription_id
        self.paid_until = paid_until
        self.save(update_fields=['stripe_subscription_id', 'paid_until'])

    def check_subscription_status(self) -> str:
        """
        Check and return current subscription status.

        Returns:
            Status string: 'active', 'trial', 'expired', 'suspended', 'cancelled'
        """
        if self.status == self.TenantStatus.CANCELLED:
            return 'cancelled'

        if self.status == self.TenantStatus.SUSPENDED:
            return 'suspended'

        if self.on_trial:
            if self.trial_ends_at and timezone.now() > self.trial_ends_at:
                return 'expired'
            return 'trial'

        if self.paid_until and timezone.now() > self.paid_until:
            return 'expired'

        return 'active'

    def has_feature(self, feature_name: str) -> bool:
        """
        Check if tenant's plan has a specific feature.

        Args:
            feature_name: Feature name without 'feature_' prefix.

        Returns:
            True if feature is enabled, False otherwise.
        """
        if not self.plan:
            return False

        feature_attr = f'feature_{feature_name}'
        return getattr(self.plan, feature_attr, False)

    def get_usage_percentage(self, resource: str) -> float:
        """
        Get usage percentage for a resource against plan limits.

        Args:
            resource: Resource name ('users', 'jobs', 'storage', etc.)

        Returns:
            Percentage of limit used (0-100+).
        """
        usage = getattr(self, 'usage', None)
        if not usage or not self.plan:
            return 0.0

        mappings = {
            'users': (usage.user_count, self.plan.max_users),
            'jobs': (usage.active_job_count, self.plan.max_job_postings),
            'candidates': (usage.candidate_count_this_month, self.plan.max_candidates_per_month),
            'circusales': (usage.circusale_count, self.plan.max_circusales),
            'storage': (usage.storage_used_gb, self.plan.storage_limit_gb),
        }

        if resource not in mappings:
            return 0.0

        current, limit = mappings[resource]
        if limit == 0:
            return 0.0

        return (current / limit) * 100

    def is_approaching_limit(self, resource: str, threshold: float = 80.0) -> bool:
        """
        Check if tenant is approaching a resource limit.

        Args:
            resource: Resource name.
            threshold: Warning threshold percentage (default 80%).

        Returns:
            True if usage >= threshold percentage.
        """
        return self.get_usage_percentage(resource) >= threshold

    @property
    def is_subscription_active(self) -> bool:
        """Check if subscription is currently active (not expired)."""
        status = self.check_subscription_status()
        return status in ('active', 'trial')

    @property
    def days_until_expiry(self) -> int:
        """
        Get days until trial or subscription expires.

        Returns:
            Number of days, or -1 if no expiry set.
        """
        if self.on_trial and self.trial_ends_at:
            delta = self.trial_ends_at - timezone.now()
            return max(0, delta.days)
        elif self.paid_until:
            delta = self.paid_until - timezone.now()
            return max(0, delta.days)
        return -1

    def get_primary_domain(self):
        """Get the primary domain for this tenant."""
        return self.domains.filter(is_primary=True).first()

    def get_careers_domain(self):
        """Get the careers page domain if configured."""
        return self.domains.filter(is_careers_domain=True).first()

    def can_create_jobs(self):
        """Only COMPANY tenants can create job postings."""
        return self.tenant_type == self.TenantType.COMPANY

    def can_have_employees(self):
        """Only COMPANY tenants can have multiple employees."""
        return self.tenant_type == self.TenantType.COMPANY

    def switch_to_freelancer(self):
        """
        Convert company to freelancer (must have ≤1 member).

        Raises:
            ValidationError: If tenant has more than 1 active member.
        """
        if self.members.filter(is_active=True).count() > 1:
            raise ValidationError(
                _("Cannot switch to freelancer with multiple members.")
            )
        self.tenant_type = self.TenantType.FREELANCER
        self.save(update_fields=['tenant_type'])

    def switch_to_company(self):
        """Convert freelancer to company."""
        self.tenant_type = self.TenantType.COMPANY
        self.save(update_fields=['tenant_type'])


class TenantSettings(models.Model):
    """
    Tenant-specific configuration and customization settings.
    One-to-one relationship with Tenant.
    """

    tenant = models.OneToOneField(
        Tenant,
        on_delete=models.CASCADE,
        related_name='settings'
    )

    # Branding
    primary_color = models.CharField(max_length=7, default='#3B82F6', help_text=_('Primary brand color (hex)'))
    secondary_color = models.CharField(max_length=7, default='#1E40AF', help_text=_('Secondary brand color (hex)'))
    accent_color = models.CharField(max_length=7, default='#10B981', help_text=_('Accent color (hex)'))
    favicon = models.ImageField(
        upload_to='tenant_favicons/',
        blank=True,
        null=True,
        validators=[
            FileExtensionValidator(allowed_extensions=['ico', 'png', 'svg'])
        ],
        help_text=_("Allowed formats: ICO, PNG, SVG. Max size: 1MB")
    )

    # Localization
    default_language = models.CharField(max_length=10, default='en')
    default_timezone = models.CharField(max_length=50, default='America/Toronto')
    date_format = models.CharField(max_length=20, default='YYYY-MM-DD')
    time_format = models.CharField(max_length=10, default='24h', choices=[('12h', '12-hour'), ('24h', '24-hour')])
    currency = models.CharField(max_length=3, default='CAD')

    # ATS Settings
    default_pipeline_stages = ArrayField(
        models.CharField(max_length=50),
        default=list,
        blank=True,
        help_text=_('Default pipeline stages for new job postings')
    )
    require_cover_letter = models.BooleanField(default=False)
    auto_reject_after_days = models.PositiveIntegerField(default=0, help_text=_('Auto-reject inactive applications after X days (0=disabled)'))
    send_rejection_email = models.BooleanField(default=True)

    # HR Settings
    fiscal_year_start_month = models.PositiveSmallIntegerField(default=1, help_text=_('Fiscal year start month (1-12)'))
    default_pto_days = models.PositiveIntegerField(default=15, help_text=_('Default PTO days for new employees'))
    approval_workflow_enabled = models.BooleanField(default=True)

    # Security Settings
    require_2fa = models.BooleanField(default=False, help_text=_('Require 2FA for all users'))
    session_timeout_minutes = models.PositiveIntegerField(default=480, help_text=_('Session timeout in minutes'))
    password_expiry_days = models.PositiveIntegerField(default=0, help_text=_('Force password change after X days (0=disabled)'))
    allowed_email_domains = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True,
        help_text=_('Restrict signups to specific email domains')
    )
    ip_whitelist = ArrayField(
        models.GenericIPAddressField(),
        default=list,
        blank=True,
        help_text=_('IP whitelist for admin access')
    )

    # Notifications
    notify_new_application = models.BooleanField(default=True)
    notify_interview_scheduled = models.BooleanField(default=True)
    notify_offer_accepted = models.BooleanField(default=True)
    daily_digest_enabled = models.BooleanField(default=False)

    # Career Page
    career_page_enabled = models.BooleanField(default=True)
    career_page_title = models.CharField(max_length=200, default='Careers')
    career_page_description = models.TextField(blank=True)
    career_page_custom_css = models.TextField(blank=True, help_text=_('Custom CSS for career page'))
    show_salary_range = models.BooleanField(default=False)

    # Integrations (enabled/disabled)
    integration_slack_enabled = models.BooleanField(default=False)
    integration_slack_webhook = models.URLField(blank=True)
    integration_calendar_enabled = models.BooleanField(default=False)
    integration_calendar_provider = models.CharField(max_length=20, blank=True, choices=[
        ('google', 'Google Calendar'),
        ('outlook', 'Outlook Calendar'),
    ])

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Tenant Settings')
        verbose_name_plural = _('Tenant Settings')

    def __str__(self):
        return f"Settings for {self.tenant.name}"

    def clean(self):
        super().clean()
        if self.favicon and hasattr(self.favicon, 'size'):
            if self.favicon.size > 1 * 1024 * 1024:  # 1MB
                raise ValidationError({'favicon': _("Favicon file size must be less than 1MB.")})

    def get_default_pipeline_stages(self):
        """Return default pipeline stages or fallback defaults."""
        if self.default_pipeline_stages:
            return self.default_pipeline_stages
        return [
            'New',
            'Screening',
            'Phone Interview',
            'Technical Interview',
            'Final Interview',
            'Offer',
            'Hired',
            'Rejected'
        ]


class Domain(DomainMixin):
    """
    Custom domain mapping for tenants.
    Supports multiple domains per tenant (e.g., careers.company.com).
    """

    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='domains'
    )

    # Domain Type
    is_careers_domain = models.BooleanField(
        default=False,
        help_text=_('Is this domain for the public careers page?')
    )

    # SSL
    ssl_enabled = models.BooleanField(default=True)
    ssl_certificate = models.TextField(blank=True, help_text=_('Custom SSL certificate (PEM)'))
    ssl_private_key = models.TextField(blank=True, help_text=_('SSL private key (PEM)'))

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    verified_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Domain')
        verbose_name_plural = _('Domains')

    def __str__(self):
        return self.domain


class TenantInvitation(models.Model):
    """
    Invitations to join a tenant organization.
    Used for onboarding new team members.

    IMPORTANT: Only COMPANY tenants can send invitations.
    FREELANCER tenants cannot invite employees (single-user only).
    """

    class InvitationStatus(models.TextChoices):
        PENDING = 'pending', _('Pending')
        ACCEPTED = 'accepted', _('Accepted')
        EXPIRED = 'expired', _('Expired')
        REVOKED = 'revoked', _('Revoked')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='invitations'
    )
    email = models.EmailField()
    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='sent_invitations'
    )

    # Role assignment (uses TenantUser.UserRole choices)
    assigned_role = models.CharField(
        max_length=20,
        default='employee',
        help_text=_('Role assigned to user upon accepting invitation')
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=InvitationStatus.choices,
        default=InvitationStatus.PENDING
    )

    # Token for secure acceptance
    token = models.CharField(max_length=100, unique=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Tenant Invitation')
        verbose_name_plural = _('Tenant Invitations')
        unique_together = ['tenant', 'email']

    def __str__(self):
        return f"Invitation to {self.email} for {self.tenant.name}"

    def clean(self):
        """Validate invitation rules."""
        super().clean()
        # Import validators here to avoid circular imports
        from .validators import validate_company_can_receive_invitations

        # Freelancers cannot send invitations
        validate_company_can_receive_invitations(self.tenant)

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    def accept(self, user):
        """Accept invitation and create TenantUser with assigned role."""
        from accounts.models import TenantUser

        # Create TenantUser with the assigned role
        TenantUser.objects.get_or_create(
            user=user,
            tenant=self.tenant,
            defaults={
                'role': self.assigned_role,
                'is_active': True,
            }
        )

        # Mark invitation as accepted
        self.status = self.InvitationStatus.ACCEPTED
        self.accepted_at = timezone.now()
        self.save(update_fields=['status', 'accepted_at'])


class TenantUsage(models.Model):
    """
    Track tenant resource usage for billing and limits enforcement.
    Updated periodically by background tasks.
    """

    tenant = models.OneToOneField(
        Tenant,
        on_delete=models.CASCADE,
        related_name='usage'
    )

    # Counts
    user_count = models.PositiveIntegerField(default=0)
    active_job_count = models.PositiveIntegerField(default=0)
    total_job_count = models.PositiveIntegerField(default=0)
    candidate_count_this_month = models.PositiveIntegerField(default=0)
    total_candidate_count = models.PositiveIntegerField(default=0)
    circusale_count = models.PositiveIntegerField(default=0)
    employee_count = models.PositiveIntegerField(default=0)

    # Storage
    storage_used_bytes = models.BigIntegerField(default=0)

    # API Usage
    api_calls_this_month = models.PositiveIntegerField(default=0)

    # Timestamps
    last_calculated_at = models.DateTimeField(auto_now=True)
    month_reset_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Tenant Usage')
        verbose_name_plural = _('Tenant Usage')

    def __str__(self):
        return f"Usage for {self.tenant.name}"

    @property
    def storage_used_gb(self):
        return round(self.storage_used_bytes / (1024 ** 3), 2)

    def is_within_limits(self):
        """Check if tenant is within plan limits."""
        plan = self.tenant.plan
        if not plan:
            return False

        return (
            self.user_count <= plan.max_users and
            self.active_job_count <= plan.max_job_postings and
            self.candidate_count_this_month <= plan.max_candidates_per_month and
            self.circusale_count <= plan.max_circusales and
            self.storage_used_gb <= plan.storage_limit_gb
        )


class AuditLog(models.Model):
    """
    Tenant-scoped audit log for compliance and security.
    Records significant actions within each tenant.
    """

    class ActionType(models.TextChoices):
        CREATE = 'create', _('Create')
        UPDATE = 'update', _('Update')
        DELETE = 'delete', _('Delete')
        LOGIN = 'login', _('Login')
        LOGOUT = 'logout', _('Logout')
        EXPORT = 'export', _('Export')
        PERMISSION_CHANGE = 'permission_change', _('Permission Change')
        SETTING_CHANGE = 'setting_change', _('Setting Change')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='audit_logs'
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='tenant_audit_logs'
    )

    # Action Details
    action = models.CharField(max_length=30, choices=ActionType.choices)
    resource_type = models.CharField(max_length=100, help_text=_('Model/resource type'))
    resource_id = models.CharField(max_length=100, blank=True)
    description = models.TextField(blank=True)

    # Change Data
    old_values = models.JSONField(default=dict, blank=True)
    new_values = models.JSONField(default=dict, blank=True)

    # Request Context
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    # Timestamp
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        verbose_name = _('Audit Log')
        verbose_name_plural = _('Audit Logs')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['tenant', 'created_at']),
            models.Index(fields=['tenant', 'action']),
            models.Index(fields=['tenant', 'resource_type']),
        ]

    def __str__(self):
        return f"{self.action} on {self.resource_type} by {self.user}"


class Circusale(models.Model):
    """
    Business unit/division within a tenant organization.

    Each tenant (enterprise) can have multiple circusales representing
    different locations, branches, or business units. Users are assigned
    to specific circusales for data scoping and organizational hierarchy.

    Features:
    - PostGIS-enabled location for geospatial queries
    - Budget tracking per division
    - Hierarchical parent-child relationships
    - Contact information and settings
    """

    class CircusaleStatus(models.TextChoices):
        ACTIVE = 'active', _('Active')
        INACTIVE = 'inactive', _('Inactive')
        PENDING = 'pending', _('Pending Setup')

    # Identity
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='circusales'
    )
    name = models.CharField(max_length=100, help_text=_('Division/branch name'))
    slug = models.SlugField(max_length=100)
    code = models.CharField(
        max_length=20,
        blank=True,
        help_text=_('Internal code (e.g., MTL-001)')
    )

    # Hierarchy
    parent = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='children',
        help_text=_('Parent circusale for hierarchy')
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=CircusaleStatus.choices,
        default=CircusaleStatus.ACTIVE
    )

    # Location - Using nullable fields; PostGIS PointField added when PostGIS is enabled
    address_line1 = models.CharField(max_length=255, blank=True)
    address_line2 = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    postal_code = models.CharField(max_length=20, blank=True)
    country = models.CharField(max_length=100, blank=True, default='CA')

    # Geospatial coordinates (latitude/longitude for basic geo queries)
    # For full PostGIS support, use: from django.contrib.gis.db import models as gis_models
    # location = gis_models.PointField(null=True, blank=True, srid=4326)
    latitude = models.DecimalField(
        max_digits=9,
        decimal_places=6,
        null=True,
        blank=True,
        help_text=_('Latitude coordinate')
    )
    longitude = models.DecimalField(
        max_digits=9,
        decimal_places=6,
        null=True,
        blank=True,
        help_text=_('Longitude coordinate')
    )

    # Budget & Finance
    budget = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Annual budget allocation')
    )
    currency = models.CharField(max_length=3, default='CAD')
    cost_center = models.CharField(max_length=50, blank=True, help_text=_('Cost center code'))

    # Contact Information
    phone = models.CharField(max_length=20, blank=True)
    email = models.EmailField(blank=True)
    manager_name = models.CharField(max_length=100, blank=True)

    # Settings
    timezone = models.CharField(max_length=50, default='America/Toronto')
    is_headquarters = models.BooleanField(
        default=False,
        help_text=_('Is this the main headquarters?')
    )
    accepts_applications = models.BooleanField(
        default=True,
        help_text=_('Can receive job applications')
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Circusale')
        verbose_name_plural = _('Circusales')
        ordering = ['name']
        unique_together = ['tenant', 'slug']
        indexes = [
            models.Index(fields=['tenant', 'status']),
            models.Index(fields=['tenant', 'is_headquarters']),
        ]

    def __str__(self):
        return f"{self.name} ({self.tenant.name})"

    def save(self, *args, **kwargs):
        """Auto-generate slug if not provided."""
        if not self.slug:
            from django.utils.text import slugify
            base_slug = slugify(self.name)[:90]
            slug = base_slug
            counter = 1
            while Circusale.objects.filter(tenant=self.tenant, slug=slug).exclude(pk=self.pk).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1
            self.slug = slug
        super().save(*args, **kwargs)

    @property
    def full_address(self) -> str:
        """Return formatted full address."""
        parts = filter(None, [
            self.address_line1,
            self.address_line2,
            self.city,
            self.state,
            self.postal_code,
            self.country
        ])
        return ', '.join(parts)

    @property
    def coordinates(self):
        """Return coordinates as tuple if available."""
        if self.latitude and self.longitude:
            return (float(self.latitude), float(self.longitude))
        return None

    def get_descendants(self, include_self=False):
        """Get all descendant circusales in hierarchy."""
        descendants = []
        if include_self:
            descendants.append(self)

        children = list(self.children.all())
        for child in children:
            descendants.append(child)
            descendants.extend(child.get_descendants())

        return descendants

    def get_ancestors(self, include_self=False):
        """Get all ancestor circusales in hierarchy."""
        ancestors = []
        if include_self:
            ancestors.append(self)

        current = self.parent
        while current:
            ancestors.append(current)
            current = current.parent

        return ancestors

    @property
    def depth(self) -> int:
        """Return depth in hierarchy (0 for root)."""
        return len(self.get_ancestors())

    @classmethod
    def get_headquarters(cls, tenant):
        """Get the headquarters circusale for a tenant."""
        return cls.objects.filter(
            tenant=tenant,
            is_headquarters=True
        ).first()


class CircusaleUser(models.Model):
    """
    Links users to circusales with specific roles.
    A user can belong to multiple circusales within a tenant.
    """

    class CircusaleRole(models.TextChoices):
        MANAGER = 'manager', _('Manager')
        SUPERVISOR = 'supervisor', _('Supervisor')
        MEMBER = 'member', _('Member')
        VIEWER = 'viewer', _('Viewer')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='circusale_memberships'
    )
    circusale = models.ForeignKey(
        Circusale,
        on_delete=models.CASCADE,
        related_name='members'
    )
    role = models.CharField(
        max_length=20,
        choices=CircusaleRole.choices,
        default=CircusaleRole.MEMBER
    )
    is_primary = models.BooleanField(
        default=False,
        help_text=_('Is this the user\'s primary circusale?')
    )

    # Timestamps
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Circusale User')
        verbose_name_plural = _('Circusale Users')
        unique_together = ['user', 'circusale']

    def __str__(self):
        return f"{self.user} @ {self.circusale.name} ({self.get_role_display()})"


# =============================================================================
# PUBLIC MARKETPLACE CATALOG
# =============================================================================

class PublicServiceCatalog(models.Model):
    """
    Read-only public catalog of services published by tenants.
    Denormalized for performance - synced via signals from tenant schemas.

    This model lives in the PUBLIC schema and aggregates services marked as
    `is_public=True` from all tenant schemas. It enables the public homepage
    and marketplace browsing without requiring cross-schema queries.

    Synchronization:
    - Triggered by Service.post_save signal in tenant schemas
    - Only services with is_public=True and provider.marketplace_enabled=True
    - Denormalized data (name, price, category, etc.) for fast reads
    - Auto-updated when source service changes
    """

    # Identity
    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(unique=True, db_index=True, help_text=_('Service UUID (same as source service)'))
    tenant = models.ForeignKey(
        'Tenant',
        on_delete=models.CASCADE,
        related_name='published_services',
        help_text=_('Tenant/company offering this service')
    )

    # Service Reference (for sync tracking)
    service_uuid = models.UUIDField(
        db_index=True,
        help_text=_('UUID of service in tenant schema')
    )
    tenant_schema_name = models.CharField(
        max_length=63,
        help_text=_('Schema name of tenant (for sync reference)')
    )

    # Denormalized Service Data
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=255)
    description = models.TextField()
    short_description = models.CharField(max_length=300, blank=True)

    # Category (denormalized)
    category_name = models.CharField(max_length=100, db_index=True, blank=True)
    category_slug = models.SlugField(max_length=100, db_index=True, blank=True)

    # Provider (denormalized)
    provider_name = models.CharField(max_length=255)
    provider_uuid = models.UUIDField()

    # Pricing
    service_type = models.CharField(
        max_length=20,
        help_text=_('fixed, hourly, or custom')
    )
    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Fixed price (for fixed/hourly types)')
    )
    price_min = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Minimum price (for custom quotes)')
    )
    price_max = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Maximum price (for custom quotes)')
    )
    currency = models.CharField(max_length=3, default='CAD')

    # Media
    thumbnail_url = models.CharField(
        max_length=500,
        blank=True,
        help_text=_('URL to service thumbnail image')
    )

    # Stats (denormalized from provider)
    rating_avg = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Average provider rating')
    )
    review_count = models.PositiveIntegerField(
        default=0,
        help_text=_('Total provider reviews')
    )
    order_count = models.PositiveIntegerField(
        default=0,
        help_text=_('Total service orders/contracts')
    )

    # Status & Visibility
    is_active = models.BooleanField(default=True, db_index=True)
    is_featured = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('Featured services appear prominently on homepage')
    )

    # Sync Tracking
    published_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_('When service was first published to catalog')
    )
    synced_at = models.DateTimeField(
        auto_now=True,
        help_text=_('Last sync timestamp from tenant schema')
    )

    class Meta:
        verbose_name = _('Public Service Catalog Entry')
        verbose_name_plural = _('Public Service Catalog')
        ordering = ['-is_featured', '-published_at']
        indexes = [
            models.Index(fields=['tenant', 'is_active'], name='catalog_tenant_active'),
            models.Index(fields=['category_slug', 'is_active'], name='catalog_category_active'),
            models.Index(fields=['-rating_avg', '-order_count'], name='catalog_rating_orders'),
            models.Index(fields=['tenant_schema_name', 'service_uuid'], name='catalog_sync_ref'),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['tenant_schema_name', 'service_uuid'],
                name='unique_service_per_tenant_schema'
            )
        ]

    def __str__(self):
        return f"{self.name} by {self.tenant.name}"

    def get_tenant_service_url(self):
        """
        Generate URL to view service in tenant context.
        Returns absolute URL to service detail page on tenant subdomain.
        """
        domain = self.tenant.get_primary_domain()
        if domain:
            return f"https://{domain.domain}/services/service/{self.uuid}/"
        return None

    def get_public_request_url(self):
        """
        Generate URL for creating a cross-tenant service request.
        Used by users browsing public marketplace to request this service.
        """
        from django.urls import reverse
        return reverse('services:request_cross_tenant', kwargs={'catalog_service_uuid': self.uuid})


class PublicJobCatalog(models.Model):
    """
    Read-only public catalog of job postings published by tenants.
    Denormalized for performance - synced via signals from tenant schemas.

    This model lives in the PUBLIC schema and aggregates jobs marked as
    `published_on_career_page=True` from all tenant schemas. It enables the
    public careers page browsing without requiring cross-schema queries.

    Synchronization:
    - Triggered by JobPosting.post_save signal in tenant schemas
    - Only jobs with published_on_career_page=True and is_internal_only=False
    - Denormalized data (title, location, salary, etc.) for fast reads
    - Auto-updated when source job changes

    Security:
    - Salary only included if show_salary=True
    - Internal-only jobs excluded
    - Sensitive fields (hiring manager, internal notes) never synced
    """

    # Identity
    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(
        unique=True,
        db_index=True,
        help_text=_('Job UUID (same as source JobPosting)')
    )
    tenant = models.ForeignKey(
        'Tenant',
        on_delete=models.CASCADE,
        related_name='published_jobs',
        help_text=_('Tenant/company offering this job')
    )

    # Job Reference (for sync tracking)
    job_uuid = models.UUIDField(
        db_index=True,
        help_text=_('UUID of job in tenant schema')
    )
    tenant_schema_name = models.CharField(
        max_length=63,
        help_text=_('Schema name of tenant (for sync reference)')
    )

    # Denormalized Job Data
    title = models.CharField(max_length=200)
    slug = models.SlugField(max_length=220, blank=True)
    reference_code = models.CharField(max_length=50, blank=True)

    # Category (denormalized)
    category_name = models.CharField(max_length=100, db_index=True, blank=True)
    category_slug = models.SlugField(max_length=100, db_index=True, blank=True)

    # Job Classification
    job_type = models.CharField(
        max_length=20,
        db_index=True,
        help_text=_('full_time, part_time, contract, internship, temporary, freelance')
    )
    experience_level = models.CharField(
        max_length=20,
        db_index=True,
        help_text=_('entry, junior, mid, senior, lead, executive')
    )
    remote_policy = models.CharField(
        max_length=20,
        db_index=True,
        help_text=_('on_site, remote, hybrid, flexible')
    )

    # Location (denormalized)
    location_city = models.CharField(max_length=100, blank=True, db_index=True)
    location_state = models.CharField(max_length=100, blank=True)
    location_country = models.CharField(max_length=100, blank=True, db_index=True)
    location_coordinates = gis_models.PointField(null=True, blank=True, srid=4326)

    # Description Fields (sanitized HTML)
    description = models.TextField(blank=True, help_text=_('Sanitized HTML'))
    responsibilities = models.TextField(blank=True)
    requirements = models.TextField(blank=True)
    nice_to_have = models.TextField(blank=True)
    benefits = models.TextField(blank=True)

    # Compensation (conditional - only if show_salary=True)
    salary_min = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Only included if job.show_salary=True')
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
        default='yearly',
        help_text=_('hourly, daily, weekly, monthly, yearly')
    )
    show_salary = models.BooleanField(default=False)

    # Skills (PostgreSQL arrays)
    required_skills = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of required skills')
    )
    preferred_skills = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of preferred skills')
    )

    # Hiring Details
    positions_count = models.PositiveIntegerField(default=1)
    team = models.CharField(max_length=100, blank=True)

    # Company Info (denormalized from tenant)
    company_name = models.CharField(max_length=255, db_index=True)
    company_logo_url = models.CharField(max_length=500, blank=True)

    # Status & Visibility
    is_featured = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('Featured jobs appear prominently on careers page')
    )

    # Deadlines & Metadata
    application_deadline = models.DateTimeField(null=True, blank=True)
    published_at = models.DateTimeField(
        db_index=True,
        help_text=_('When job was first published to catalog')
    )

    # Sync Tracking
    synced_at = models.DateTimeField(
        auto_now=True,
        help_text=_('Last sync timestamp from tenant schema')
    )

    # SEO
    meta_title = models.CharField(max_length=200, blank=True)
    meta_description = models.TextField(max_length=500, blank=True)

    class Meta:
        verbose_name = _('Public Job Catalog Entry')
        verbose_name_plural = _('Public Job Catalog')
        ordering = ['-is_featured', '-published_at']
        indexes = [
            models.Index(fields=['tenant', 'is_featured'], name='job_catalog_tenant_featured'),
            models.Index(fields=['job_type', 'experience_level'], name='job_catalog_type_level'),
            models.Index(fields=['location_country', 'location_city'], name='job_catalog_location'),
            models.Index(fields=['tenant_schema_name', 'job_uuid'], name='job_catalog_sync_ref'),
            models.Index(fields=['-published_at'], name='job_catalog_published'),
            models.Index(fields=['remote_policy'], name='job_catalog_remote'),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['tenant_schema_name', 'job_uuid'],
                name='unique_job_per_tenant_schema'
            )
        ]

    def __str__(self):
        return f"{self.title} at {self.company_name}"

    def get_tenant_job_url(self):
        """
        Generate URL to view job in tenant context.
        Returns absolute URL to job detail page on tenant subdomain.
        """
        domain = self.tenant.get_primary_domain()
        if domain:
            return f"https://{domain.domain}/jobs/{self.uuid}/"
        return None

    def get_apply_url(self):
        """
        Generate URL for applying to this job.
        Points to the tenant's application page.
        """
        domain = self.tenant.get_primary_domain()
        if domain:
            return f"https://{domain.domain}/jobs/{self.uuid}/apply/"
        return None


class PublicProviderCatalog(models.Model):
    """
    Read-only public catalog of service providers (freelancers) published by tenants.
    Denormalized for performance - synced via signals from tenant schemas.

    This model lives in the PUBLIC schema and aggregates providers with
    `marketplace_enabled=True` from all tenant schemas. It enables public
    browsing of freelancers without cross-schema queries.

    Synchronization:
    - Triggered by ServiceProvider.post_save signal in tenant schemas
    - Only providers with marketplace_enabled=True and is_active=True
    - Denormalized profile data (bio, skills, ratings) for fast reads
    - Auto-updated when source provider changes

    Security:
    - Sensitive data (email, phone, bank details) never synced
    - Only public profile information included
    - Location limited to city/country (no full addresses)
    """

    # Identity
    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(
        unique=True,
        db_index=True,
        help_text=_('Provider UUID (same as source ServiceProvider)')
    )
    tenant = models.ForeignKey(
        'Tenant',
        on_delete=models.CASCADE,
        related_name='published_providers',
        help_text=_('Tenant/company where provider operates')
    )

    # Provider Reference (for sync tracking)
    provider_uuid = models.UUIDField(
        db_index=True,
        help_text=_('UUID of provider in tenant schema')
    )
    tenant_schema_name = models.CharField(
        max_length=63,
        help_text=_('Schema name of tenant (for sync reference)')
    )

    # Profile Information
    display_name = models.CharField(max_length=255, db_index=True)
    provider_type = models.CharField(
        max_length=20,
        db_index=True,
        help_text=_('individual, agency, company')
    )
    bio = models.TextField(
        max_length=2000,
        blank=True,
        help_text=_('Sanitized bio (max 2000 chars)')
    )
    tagline = models.CharField(max_length=200, blank=True)

    # Media URLs (stored as strings, not FileFields)
    avatar_url = models.CharField(max_length=500, blank=True)
    cover_image_url = models.CharField(max_length=500, blank=True)

    # Location (city/country only, no full addresses)
    city = models.CharField(max_length=100, blank=True, db_index=True)
    state = models.CharField(max_length=100, blank=True)
    country = models.CharField(max_length=100, blank=True, db_index=True)
    location = gis_models.PointField(null=True, blank=True, srid=4326)

    # Categories (denormalized as JSON arrays)
    category_names = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of category names')
    )
    category_slugs = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of category slugs for filtering')
    )

    # Skills (denormalized with metadata)
    skills_data = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of {name, level, years_experience} dicts')
    )

    # Pricing
    hourly_rate = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Hourly rate if applicable')
    )
    minimum_budget = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Minimum project budget')
    )
    currency = models.CharField(max_length=3, default='CAD')

    # Stats & Reputation (denormalized)
    rating_avg = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        default=Decimal('0.00'),
        db_index=True,
        help_text=_('Average rating across all reviews')
    )
    total_reviews = models.PositiveIntegerField(
        default=0,
        help_text=_('Total number of reviews received')
    )
    completed_jobs_count = models.PositiveIntegerField(
        default=0,
        help_text=_('Number of completed projects/jobs')
    )
    response_rate = models.PositiveSmallIntegerField(
        default=0,
        help_text=_('Percentage of messages responded to (0-100)')
    )
    avg_response_time_hours = models.PositiveSmallIntegerField(
        default=0,
        help_text=_('Average response time in hours')
    )

    # Availability & Status
    availability_status = models.CharField(
        max_length=20,
        default='available',
        db_index=True,
        help_text=_('available, busy, unavailable')
    )
    is_verified = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('KYC verified provider')
    )
    is_featured = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('Featured providers shown prominently')
    )
    is_accepting_projects = models.BooleanField(default=True, db_index=True)
    can_work_remotely = models.BooleanField(default=True)
    can_work_onsite = models.BooleanField(default=False)

    # Sync Tracking
    published_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_('When provider was first published to catalog')
    )
    synced_at = models.DateTimeField(
        auto_now=True,
        help_text=_('Last sync timestamp from tenant schema')
    )

    class Meta:
        verbose_name = _('Public Provider Catalog Entry')
        verbose_name_plural = _('Public Provider Catalog')
        ordering = ['-is_featured', '-rating_avg', '-published_at']
        indexes = [
            models.Index(fields=['tenant', 'is_verified'], name='pcat_ten_verified'),
            models.Index(fields=['provider_type', 'is_accepting_projects'], name='pcat_type_accept'),
            models.Index(fields=['country', 'city'], name='pcat_location'),
            models.Index(fields=['tenant_schema_name', 'provider_uuid'], name='pcat_sync_ref'),
            models.Index(fields=['-rating_avg', '-total_reviews'], name='pcat_rating'),
            models.Index(fields=['availability_status'], name='pcat_availability'),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['tenant_schema_name', 'provider_uuid'],
                name='unique_provider_per_tenant_schema'
            )
        ]

    def __str__(self):
        return f"{self.display_name} ({self.provider_type})"

    def get_tenant_provider_url(self):
        """
        Generate URL to view provider profile in tenant context.
        Returns absolute URL to provider detail page on tenant subdomain.
        """
        domain = self.tenant.get_primary_domain()
        if domain:
            return f"https://{domain.domain}/providers/{self.uuid}/"
        return None

    def get_skills_list(self):
        """Extract skill names from skills_data JSON."""
        if not self.skills_data:
            return []
        return [skill.get('name', '') for skill in self.skills_data if skill.get('name')]

# =============================================================================
# PUBLIC JOB CATALOG
# =============================================================================

