"""
Tenants Serializers - DRF serializers for tenant management API.

This module provides serializers for:
- Plan: Public pricing info
- Tenant: Admin view with full tenant details
- TenantSettings: Tenant configuration
- Domain: Custom domain management
- TenantInvitation: Invite users to tenant
- TenantUsage: Usage statistics vs limits
- AuditLog: Read-only audit logs
- TenantOnboarding: Setup wizard data
"""

from rest_framework import serializers
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from django.utils import timezone
from django.contrib.auth import get_user_model

from .models import (
    Plan, Tenant, TenantSettings, Domain,
    TenantInvitation, TenantUsage, AuditLog
)

User = get_user_model()


# ==================== USER SERIALIZERS ====================

class BasicUserSerializer(serializers.ModelSerializer):
    """Minimal user info for nested relationships."""

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name']
        read_only_fields = fields


# ==================== PLAN SERIALIZERS ====================

class PlanSerializer(serializers.ModelSerializer):
    """
    Public plan information for pricing pages.
    Excludes Stripe IDs and internal fields.
    """

    features = serializers.SerializerMethodField()
    savings_yearly = serializers.SerializerMethodField()

    class Meta:
        model = Plan
        fields = [
            'id', 'name', 'slug', 'plan_type', 'description',
            'price_monthly', 'price_yearly', 'currency',
            'max_users', 'max_job_postings', 'max_candidates_per_month',
            'max_circusales', 'storage_limit_gb',
            'features', 'savings_yearly',
            'is_active', 'is_popular', 'sort_order'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_features(self, obj):
        """Return list of enabled feature names."""
        features = []
        feature_mapping = {
            'feature_ats': 'Applicant Tracking System',
            'feature_hr_core': 'HR Core (Time-off, Onboarding)',
            'feature_analytics': 'Advanced Analytics',
            'feature_api_access': 'REST API Access',
            'feature_custom_pipelines': 'Custom Recruitment Pipelines',
            'feature_ai_matching': 'AI Candidate Matching',
            'feature_video_interviews': 'Video Interview Integration',
            'feature_esignature': 'E-Signature (DocuSign)',
            'feature_sso': 'Single Sign-On (SAML/OIDC)',
            'feature_audit_logs': 'Detailed Audit Logs',
            'feature_custom_branding': 'Custom Branding/White-label',
            'feature_priority_support': 'Priority Support',
            'feature_data_export': 'Data Export (CSV/Excel)',
            'feature_bulk_actions': 'Bulk Actions',
            'feature_advanced_filters': 'Advanced ATS Filters (30+)',
            'feature_diversity_analytics': 'Diversity & Inclusion Analytics',
            'feature_compliance_tools': 'Compliance Management Tools',
        }

        for field_name, display_name in feature_mapping.items():
            if getattr(obj, field_name, False):
                features.append({
                    'key': field_name.replace('feature_', ''),
                    'name': display_name,
                    'enabled': True
                })

        return features

    @extend_schema_field(OpenApiTypes.STR)
    def get_savings_yearly(self, obj):
        """Calculate yearly savings compared to monthly billing."""
        if obj.price_monthly and obj.price_yearly:
            monthly_total = obj.price_monthly * 12
            savings = monthly_total - obj.price_yearly
            return {
                'amount': float(savings),
                'percentage': round((savings / monthly_total) * 100, 1) if monthly_total > 0 else 0
            }
        return {'amount': 0, 'percentage': 0}


class PlanDetailSerializer(PlanSerializer):
    """
    Detailed plan information including Stripe IDs (admin only).
    """

    class Meta(PlanSerializer.Meta):
        fields = PlanSerializer.Meta.fields + [
            'stripe_product_id', 'stripe_price_id_monthly', 'stripe_price_id_yearly',
            'created_at', 'updated_at'
        ]


# ==================== TENANT SERIALIZERS ====================

class TenantSerializer(serializers.ModelSerializer):
    """
    Full tenant information for admin/owner view.
    """

    plan = PlanSerializer(read_only=True)
    plan_id = serializers.PrimaryKeyRelatedField(
        queryset=Plan.objects.filter(is_active=True),
        source='plan',
        write_only=True,
        required=False
    )
    trial_days_remaining = serializers.ReadOnlyField()
    is_on_trial = serializers.ReadOnlyField()
    primary_domain = serializers.SerializerMethodField()
    can_create_jobs = serializers.SerializerMethodField()
    can_have_employees = serializers.SerializerMethodField()
    ein_verified = serializers.ReadOnlyField()

    class Meta:
        model = Tenant
        fields = [
            'id', 'uuid', 'name', 'slug', 'status',
            'tenant_type', 'can_create_jobs', 'can_have_employees',
            'plan', 'plan_id',
            'trial_ends_at', 'paid_until', 'on_trial',
            'trial_days_remaining', 'is_on_trial',
            'owner_email',
            'industry', 'company_size', 'website', 'logo',
            'address_line1', 'address_line2', 'city', 'state',
            'postal_code', 'country',
            'ein_number', 'ein_verified',
            'primary_domain',
            'created_at', 'updated_at', 'activated_at'
        ]
        read_only_fields = [
            'id', 'uuid', 'slug', 'status', 'tenant_type',
            'can_create_jobs', 'can_have_employees',
            'trial_ends_at', 'paid_until', 'on_trial',
            'trial_days_remaining', 'is_on_trial',
            'ein_verified',
            'created_at', 'updated_at', 'activated_at'
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_primary_domain(self, obj):
        """Get the primary domain for this tenant."""
        primary = obj.domains.filter(is_primary=True).first()
        return primary.domain if primary else None

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_create_jobs(self, obj):
        """Check if tenant can create job postings (COMPANY only)."""
        return obj.can_create_jobs()

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_have_employees(self, obj):
        """Check if tenant can have multiple employees (COMPANY only)."""
        return obj.can_have_employees()


class TenantUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating tenant details (non-sensitive fields).
    """

    class Meta:
        model = Tenant
        fields = [
            'name', 'industry', 'company_size', 'website', 'logo',
            'address_line1', 'address_line2', 'city', 'state',
            'postal_code', 'country', 'ein_number'
        ]


class TenantPublicSerializer(serializers.ModelSerializer):
    """
    Public tenant information (for career pages, public profiles).
    """

    can_create_jobs = serializers.SerializerMethodField()

    class Meta:
        model = Tenant
        fields = [
            'uuid', 'name', 'tenant_type', 'logo', 'industry', 'company_size',
            'website', 'city', 'country', 'can_create_jobs', 'ein_verified'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_create_jobs(self, obj):
        """Check if tenant can create job postings (COMPANY only)."""
        return obj.can_create_jobs()


# ==================== TENANT SETTINGS SERIALIZERS ====================

class TenantSettingsSerializer(serializers.ModelSerializer):
    """
    Tenant settings/configuration serializer.
    """

    class Meta:
        model = TenantSettings
        fields = [
            'id',
            # Branding
            'primary_color', 'secondary_color', 'accent_color', 'favicon',
            # Localization
            'default_language', 'default_timezone', 'date_format',
            'time_format', 'currency',
            # ATS Settings
            'default_pipeline_stages', 'require_cover_letter',
            'auto_reject_after_days', 'send_rejection_email',
            # HR Settings
            'fiscal_year_start_month', 'default_pto_days',
            'approval_workflow_enabled',
            # Security Settings
            'require_2fa', 'session_timeout_minutes', 'password_expiry_days',
            'allowed_email_domains', 'ip_whitelist',
            # Notifications
            'notify_new_application', 'notify_interview_scheduled',
            'notify_offer_accepted', 'daily_digest_enabled',
            # Career Page
            'career_page_enabled', 'career_page_title',
            'career_page_description', 'career_page_custom_css',
            'show_salary_range',
            # Integrations
            'integration_slack_enabled', 'integration_slack_webhook',
            'integration_calendar_enabled', 'integration_calendar_provider',
            # Timestamps
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class TenantSettingsUpdateSerializer(serializers.ModelSerializer):
    """
    Partial update serializer for tenant settings.
    Excludes sensitive fields that require special handling.
    """

    class Meta:
        model = TenantSettings
        fields = [
            # Branding
            'primary_color', 'secondary_color', 'accent_color', 'favicon',
            # Localization
            'default_language', 'default_timezone', 'date_format',
            'time_format', 'currency',
            # ATS Settings
            'default_pipeline_stages', 'require_cover_letter',
            'auto_reject_after_days', 'send_rejection_email',
            # HR Settings
            'fiscal_year_start_month', 'default_pto_days',
            'approval_workflow_enabled',
            # Notifications
            'notify_new_application', 'notify_interview_scheduled',
            'notify_offer_accepted', 'daily_digest_enabled',
            # Career Page
            'career_page_enabled', 'career_page_title',
            'career_page_description', 'career_page_custom_css',
            'show_salary_range',
        ]


class TenantSecuritySettingsSerializer(serializers.ModelSerializer):
    """
    Security-specific settings (requires admin permission).
    """

    class Meta:
        model = TenantSettings
        fields = [
            'require_2fa', 'session_timeout_minutes', 'password_expiry_days',
            'allowed_email_domains', 'ip_whitelist'
        ]


class TenantIntegrationSettingsSerializer(serializers.ModelSerializer):
    """
    Integration settings serializer.
    """

    class Meta:
        model = TenantSettings
        fields = [
            'integration_slack_enabled', 'integration_slack_webhook',
            'integration_calendar_enabled', 'integration_calendar_provider'
        ]


# ==================== DOMAIN SERIALIZERS ====================

class DomainSerializer(serializers.ModelSerializer):
    """
    Domain management serializer.
    """

    is_verified = serializers.SerializerMethodField()

    class Meta:
        model = Domain
        fields = [
            'id', 'domain', 'is_primary', 'is_careers_domain',
            'ssl_enabled', 'is_verified', 'created_at', 'verified_at'
        ]
        read_only_fields = ['id', 'is_verified', 'created_at', 'verified_at']

    @extend_schema_field(OpenApiTypes.STR)
    def get_is_verified(self, obj):
        """Check if domain is verified."""
        return obj.verified_at is not None


class DomainCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating new domains.
    """

    class Meta:
        model = Domain
        fields = ['domain', 'is_primary', 'is_careers_domain']

    def validate_domain(self, value):
        """Validate domain format and uniqueness."""
        import re

        # Basic domain validation
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, value):
            raise serializers.ValidationError("Invalid domain format.")

        # Check uniqueness across all tenants
        if Domain.objects.filter(domain=value).exists():
            raise serializers.ValidationError("This domain is already in use.")

        return value.lower()


# ==================== INVITATION SERIALIZERS ====================

class TenantInvitationSerializer(serializers.ModelSerializer):
    """
    Tenant invitation serializer.
    """

    invited_by = BasicUserSerializer(read_only=True)
    is_expired = serializers.ReadOnlyField()
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)

    class Meta:
        model = TenantInvitation
        fields = [
            'id', 'uuid', 'email', 'assigned_role', 'status',
            'invited_by', 'tenant_name',
            'is_expired', 'created_at', 'expires_at', 'accepted_at'
        ]
        read_only_fields = [
            'id', 'uuid', 'status', 'invited_by', 'tenant_name',
            'is_expired', 'created_at', 'expires_at', 'accepted_at'
        ]


class TenantInvitationCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating new invitations.
    """

    VALID_ROLES = ['member', 'admin', 'hr_manager', 'recruiter', 'hiring_manager', 'employee', 'viewer']

    class Meta:
        model = TenantInvitation
        fields = ['email', 'assigned_role']

    def validate_email(self, value):
        """Validate email format and check for existing user/invitation."""
        email = value.lower().strip()

        # Check if already a member
        tenant = self.context.get('tenant')
        if tenant:
            from tenant_profiles.models import TenantUser
            if TenantUser.objects.filter(
                tenant=tenant,
                user__email=email,
                is_active=True
            ).exists():
                raise serializers.ValidationError("This user is already a member of the tenant.")

        return email

    def validate_role(self, value):
        """Validate role is allowed."""
        if value not in self.VALID_ROLES:
            raise serializers.ValidationError(f"Role must be one of: {', '.join(self.VALID_ROLES)}")
        return value


class TenantInvitationAcceptSerializer(serializers.Serializer):
    """
    Serializer for accepting an invitation.
    """

    token = serializers.CharField(max_length=100)


# ==================== USAGE SERIALIZERS ====================

class TenantUsageSerializer(serializers.ModelSerializer):
    """
    Tenant usage statistics with plan limits comparison.
    """

    storage_used_gb = serializers.ReadOnlyField()
    limits = serializers.SerializerMethodField()
    usage_percentages = serializers.SerializerMethodField()
    is_within_limits = serializers.SerializerMethodField()

    class Meta:
        model = TenantUsage
        fields = [
            'id',
            'user_count', 'active_job_count', 'total_job_count',
            'candidate_count_this_month', 'total_candidate_count',
            'circusale_count', 'employee_count',
            'storage_used_bytes', 'storage_used_gb',
            'api_calls_this_month',
            'limits', 'usage_percentages', 'is_within_limits',
            'last_calculated_at', 'month_reset_at'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_limits(self, obj):
        """Get plan limits for comparison."""
        plan = obj.tenant.plan
        if not plan:
            return None

        return {
            'max_users': plan.max_users,
            'max_job_postings': plan.max_job_postings,
            'max_candidates_per_month': plan.max_candidates_per_month,
            'max_circusales': plan.max_circusales,
            'storage_limit_gb': plan.storage_limit_gb
        }

    @extend_schema_field(OpenApiTypes.STR)
    def get_usage_percentages(self, obj):
        """Calculate usage as percentage of limits."""
        plan = obj.tenant.plan
        if not plan:
            return None

        def calc_percentage(used, limit):
            if limit <= 0:
                return 0
            return min(100, round((used / limit) * 100, 1))

        return {
            'users': calc_percentage(obj.user_count, plan.max_users),
            'jobs': calc_percentage(obj.active_job_count, plan.max_job_postings),
            'candidates': calc_percentage(obj.candidate_count_this_month, plan.max_candidates_per_month),
            'circusales': calc_percentage(obj.circusale_count, plan.max_circusales),
            'storage': calc_percentage(obj.storage_used_gb, plan.storage_limit_gb)
        }

    @extend_schema_field(OpenApiTypes.STR)
    def get_is_within_limits(self, obj):
        """Check if tenant is within all limits."""
        return obj.is_within_limits()


# ==================== AUDIT LOG SERIALIZERS ====================

class AuditLogSerializer(serializers.ModelSerializer):
    """
    Read-only audit log serializer.
    """

    user = BasicUserSerializer(read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)

    class Meta:
        model = AuditLog
        fields = [
            'id', 'uuid', 'user', 'action', 'action_display',
            'resource_type', 'resource_id', 'description',
            'old_values', 'new_values',
            'ip_address', 'user_agent',
            'created_at'
        ]
        read_only_fields = fields


class AuditLogListSerializer(serializers.ModelSerializer):
    """
    Simplified audit log for list views.
    """

    user_email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = AuditLog
        fields = [
            'id', 'uuid', 'user_email', 'action',
            'resource_type', 'resource_id', 'description',
            'ip_address', 'created_at'
        ]
        read_only_fields = fields


# ==================== ONBOARDING SERIALIZERS ====================

class TenantOnboardingSerializer(serializers.Serializer):
    """
    Serializer for tenant onboarding wizard.
    Tracks completion of setup steps.
    """

    # Step 1: Company Info
    company_name = serializers.CharField(max_length=255)
    industry = serializers.CharField(max_length=100, required=False, allow_blank=True)
    company_size = serializers.ChoiceField(
        choices=[
            ('1-10', '1-10'),
            ('11-50', '11-50'),
            ('51-200', '51-200'),
            ('201-500', '201-500'),
            ('501-1000', '501-1000'),
            ('1000+', '1000+'),
        ],
        required=False
    )
    website = serializers.URLField(required=False, allow_blank=True)

    # Step 2: Branding
    logo = serializers.ImageField(required=False)
    primary_color = serializers.CharField(max_length=7, required=False, default='#3B82F6')

    # Step 3: Settings
    default_timezone = serializers.CharField(max_length=50, required=False, default='America/Toronto')
    default_language = serializers.CharField(max_length=10, required=False, default='en')

    # Step 4: Team Invitations
    invitations = serializers.ListField(
        child=serializers.DictField(),
        required=False,
        allow_empty=True
    )


class TenantOnboardingStatusSerializer(serializers.Serializer):
    """
    Serializer for onboarding progress status.
    """

    is_complete = serializers.BooleanField()
    current_step = serializers.IntegerField()
    total_steps = serializers.IntegerField()
    steps = serializers.ListField(child=serializers.DictField())
    completion_percentage = serializers.IntegerField()


# ==================== SUBSCRIPTION SERIALIZERS ====================

class SubscriptionSerializer(serializers.Serializer):
    """
    Serializer for subscription management.
    """

    plan_id = serializers.IntegerField()
    billing_cycle = serializers.ChoiceField(
        choices=[('monthly', 'Monthly'), ('yearly', 'Yearly')],
        default='monthly'
    )


class SubscriptionStatusSerializer(serializers.Serializer):
    """
    Serializer for subscription status response.
    """

    status = serializers.CharField()
    plan = PlanSerializer()
    billing_cycle = serializers.CharField()
    current_period_start = serializers.DateTimeField()
    current_period_end = serializers.DateTimeField()
    cancel_at_period_end = serializers.BooleanField()
    stripe_subscription_id = serializers.CharField()


class SubscriptionUpgradeSerializer(serializers.Serializer):
    """
    Serializer for subscription upgrade/downgrade.
    """

    plan_id = serializers.IntegerField()
    prorate = serializers.BooleanField(default=True)


class SubscriptionCancelSerializer(serializers.Serializer):
    """
    Serializer for subscription cancellation.
    """

    cancel_immediately = serializers.BooleanField(default=False)
    feedback = serializers.CharField(required=False, allow_blank=True)


# ==================== STRIPE WEBHOOK SERIALIZERS ====================

class StripeWebhookSerializer(serializers.Serializer):
    """
    Serializer for Stripe webhook payload validation.
    """

    type = serializers.CharField()
    data = serializers.DictField()
    livemode = serializers.BooleanField()


class StripeCheckoutSessionSerializer(serializers.Serializer):
    """
    Serializer for creating Stripe checkout session.
    """

    plan_id = serializers.IntegerField()
    billing_cycle = serializers.ChoiceField(
        choices=[('monthly', 'Monthly'), ('yearly', 'Yearly')],
        default='monthly'
    )
    success_url = serializers.URLField()
    cancel_url = serializers.URLField()


class StripeBillingPortalSerializer(serializers.Serializer):
    """
    Serializer for creating Stripe billing portal session.
    """

    return_url = serializers.URLField()


# ==================== VERIFICATION SERIALIZERS ====================

class EINVerificationSerializer(serializers.Serializer):
    """
    Serializer for EIN/business number verification.
    Validates EIN format (US: XX-XXXXXXX).
    """
    ein_number = serializers.CharField(max_length=50)

    def validate_ein_number(self, value):
        """Validate EIN format (US format)."""
        import re

        # US EIN format: XX-XXXXXXX
        us_ein_pattern = r'^\d{2}-\d{7}$'
        if not re.match(us_ein_pattern, value):
            raise serializers.ValidationError(
                _("Invalid EIN format. Expected format: XX-XXXXXXX (e.g., 12-3456789)")
            )

        return value
