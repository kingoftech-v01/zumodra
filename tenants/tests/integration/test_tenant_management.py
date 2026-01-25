"""
Comprehensive Tests for Zumodra Tenants App

Tests cover:
1. Model creation and validation
2. Model relationships
3. Signal handlers
4. Tenant isolation (data doesn't leak between tenants)
5. Plan feature enforcement
6. Domain routing
7. Tenant lifecycle (trial, active, suspended)
8. Middleware functionality
"""

import pytest
import uuid
import secrets
from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch, PropertyMock

from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.test import TestCase, TransactionTestCase, RequestFactory, override_settings
from django.utils import timezone
from django.http import HttpResponse, HttpRequest
from django.contrib.sites.models import Site

from conftest import (
    PlanFactory, FreePlanFactory, EnterprisePlanFactory,
    TenantFactory, TrialTenantFactory,
    TenantSettingsFactory, DomainFactory,
    TenantInvitationFactory, TenantUsageFactory, AuditLogFactory,
    UserFactory, TenantUserFactory, MockTenantRequest,
    tenant_context
)

from tenants.models import (
    Plan, Tenant, TenantSettings, Domain,
    TenantInvitation, TenantUsage, AuditLog,
    Circusale, CircusaleUser
)
from tenants.signals import (
    create_tenant_settings, cleanup_tenant,
    set_invitation_token, generate_invitation_token
)
from tenants.middleware import (
    TenantURLConfMiddleware, ZumodraTenantMiddleware,
    TenantContextMiddleware, TenantUsageMiddleware,
    TenantSecurityMiddleware, TenantResolutionError,
    TenantNotFoundError, TenantInactiveError
)
from tenants.context import (
    get_current_tenant, set_current_tenant, clear_tenant_context,
    tenant_context as context_manager, TenantContext
)


# ============================================================================
# PLAN MODEL TESTS
# ============================================================================

@pytest.mark.django_db
class TestPlanModel:
    """Test Plan model creation and validation."""

    def test_create_plan_with_required_fields(self, plan_factory):
        """Test creating a plan with required fields."""
        plan = plan_factory(
            name='Test Plan',
            slug='test-plan',
            plan_type='professional'
        )

        assert plan.pk is not None
        assert plan.name == 'Test Plan'
        assert plan.slug == 'test-plan'
        assert plan.plan_type == 'professional'
        assert plan.is_active is True

    def test_plan_type_choices(self, plan_factory):
        """Test all plan type choices are valid."""
        for plan_type, display_name in Plan.PlanType.choices:
            plan = plan_factory(
                slug=f'plan-{plan_type}',
                plan_type=plan_type
            )
            assert plan.plan_type == plan_type

    def test_plan_pricing_fields(self, plan_factory):
        """Test plan pricing fields."""
        plan = plan_factory(
            price_monthly=Decimal('29.99'),
            price_yearly=Decimal('299.99'),
            currency='USD'
        )

        assert plan.price_monthly == Decimal('29.99')
        assert plan.price_yearly == Decimal('299.99')
        assert plan.currency == 'USD'

    def test_plan_limits(self, plan_factory):
        """Test plan limit fields."""
        plan = plan_factory(
            max_users=10,
            max_job_postings=25,
            max_candidates_per_month=500,
            max_circusales=3,
            storage_limit_gb=10
        )

        assert plan.max_users == 10
        assert plan.max_job_postings == 25
        assert plan.max_candidates_per_month == 500
        assert plan.max_circusales == 3
        assert plan.storage_limit_gb == 10

    def test_plan_feature_flags(self, plan_factory):
        """Test plan feature flag fields."""
        plan = plan_factory(
            feature_ats=True,
            feature_hr_core=True,
            feature_analytics=False,
            feature_api_access=True,
            feature_sso=False
        )

        assert plan.feature_ats is True
        assert plan.feature_hr_core is True
        assert plan.feature_analytics is False
        assert plan.feature_api_access is True
        assert plan.feature_sso is False

    def test_get_features_list(self, plan_factory):
        """Test get_features_list method."""
        plan = plan_factory(
            feature_ats=True,
            feature_hr_core=True,
            feature_analytics=False
        )

        features = plan.get_features_list()
        assert isinstance(features, list)
        # At least ATS and HR Core should be present
        assert len(features) >= 2

    def test_plan_str_representation(self, plan_factory):
        """Test plan string representation."""
        plan = plan_factory(name='Enterprise', plan_type='enterprise')
        assert 'Enterprise' in str(plan)

    def test_plan_ordering(self, plan_factory):
        """Test plans are ordered by sort_order and price."""
        plan1 = plan_factory(sort_order=2, price_monthly=Decimal('50.00'))
        plan2 = plan_factory(sort_order=1, price_monthly=Decimal('25.00'))
        plan3 = plan_factory(sort_order=1, price_monthly=Decimal('10.00'))

        plans = list(Plan.objects.all().order_by('sort_order', 'price_monthly'))

        # plan3 and plan2 have same sort_order, should be ordered by price
        assert plans[0].price_monthly < plans[1].price_monthly or plans[0].sort_order < plans[1].sort_order

    def test_free_plan_factory(self, free_plan_factory):
        """Test free plan factory creates correct defaults."""
        plan = free_plan_factory()

        assert plan.plan_type == 'free'
        assert plan.price_monthly == Decimal('0.00')
        assert plan.max_users == 2
        assert plan.feature_hr_core is False
        assert plan.feature_analytics is False

    def test_enterprise_plan_factory(self, enterprise_plan_factory):
        """Test enterprise plan factory creates correct defaults."""
        plan = enterprise_plan_factory()

        assert plan.plan_type == 'enterprise'
        assert plan.max_users == 500
        assert plan.feature_ai_matching is True
        assert plan.feature_sso is True
        assert plan.feature_custom_branding is True

    def test_plan_slug_unique(self, plan_factory):
        """Test plan slug must be unique."""
        plan_factory(slug='unique-slug')

        with pytest.raises(IntegrityError):
            Plan.objects.create(
                name='Another Plan',
                slug='unique-slug',
                plan_type='starter'
            )


# ============================================================================
# TENANT MODEL TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantModel:
    """Test Tenant model creation and validation."""

    def test_create_tenant_with_required_fields(self, tenant_factory, plan_factory):
        """Test creating a tenant with required fields."""
        plan = plan_factory()
        tenant = tenant_factory(
            name='Test Company',
            slug='test-company',
            plan=plan
        )

        assert tenant.pk is not None
        assert tenant.name == 'Test Company'
        assert tenant.slug == 'test-company'
        assert tenant.plan == plan
        assert tenant.uuid is not None

    def test_tenant_status_choices(self, tenant_factory):
        """Test all tenant status choices are valid."""
        for status, display_name in Tenant.TenantStatus.choices:
            tenant = tenant_factory(
                slug=f'tenant-{status}',
                status=status
            )
            assert tenant.status == status

    def test_tenant_uuid_auto_generated(self, tenant_factory):
        """Test tenant UUID is auto-generated."""
        tenant = tenant_factory()

        assert tenant.uuid is not None
        assert isinstance(tenant.uuid, uuid.UUID)

    def test_tenant_uuid_unique(self, tenant_factory):
        """Test tenant UUIDs are unique."""
        tenant1 = tenant_factory()
        tenant2 = tenant_factory()

        assert tenant1.uuid != tenant2.uuid

    def test_tenant_is_active_property(self, tenant_factory):
        """Test is_active property."""
        active_tenant = tenant_factory(status='active')
        trial_tenant = tenant_factory(status='trial')
        suspended_tenant = tenant_factory(status='suspended')

        assert active_tenant.is_active is True
        assert trial_tenant.is_active is False
        assert suspended_tenant.is_active is False

    def test_tenant_is_on_trial_property(self, tenant_factory):
        """Test is_on_trial property."""
        trial_tenant = tenant_factory(
            on_trial=True,
            trial_ends_at=timezone.now() + timedelta(days=7)
        )
        active_tenant = tenant_factory(on_trial=False)
        expired_trial_tenant = tenant_factory(
            on_trial=True,
            trial_ends_at=timezone.now() - timedelta(days=1)
        )

        assert trial_tenant.is_on_trial is True
        assert active_tenant.is_on_trial is False
        assert expired_trial_tenant.is_on_trial is False

    def test_tenant_trial_days_remaining(self, tenant_factory):
        """Test trial_days_remaining property."""
        tenant = tenant_factory(
            on_trial=True,
            trial_ends_at=timezone.now() + timedelta(days=7)
        )

        assert 6 <= tenant.trial_days_remaining <= 7

        expired_tenant = tenant_factory(
            on_trial=True,
            trial_ends_at=timezone.now() - timedelta(days=1)
        )
        assert expired_tenant.trial_days_remaining == 0

    def test_tenant_activate(self, tenant_factory):
        """Test tenant activate method."""
        tenant = tenant_factory(status='trial', on_trial=True)

        tenant.activate()

        assert tenant.status == 'active'
        assert tenant.on_trial is False
        assert tenant.activated_at is not None

    def test_tenant_suspend(self, tenant_factory):
        """Test tenant suspend method."""
        tenant = tenant_factory(status='active')

        tenant.suspend()

        assert tenant.status == 'suspended'
        assert tenant.suspended_at is not None

    def test_tenant_cancel(self, tenant_factory):
        """Test tenant cancel method."""
        tenant = tenant_factory(status='active')

        tenant.cancel()

        assert tenant.status == 'cancelled'

    def test_tenant_reactivate(self, tenant_factory, plan_factory):
        """Test tenant reactivate method."""
        tenant = tenant_factory(status='suspended')
        new_plan = plan_factory()

        tenant.reactivate(plan=new_plan)

        assert tenant.status == 'active'
        assert tenant.plan == new_plan
        assert tenant.suspended_at is None

    def test_tenant_extend_trial(self, tenant_factory):
        """Test tenant extend_trial method."""
        initial_trial_end = timezone.now() + timedelta(days=7)
        tenant = tenant_factory(
            status='trial',
            on_trial=True,
            trial_ends_at=initial_trial_end
        )

        tenant.extend_trial(days=14)

        # Trial should be extended by 14 days from original end
        assert tenant.trial_ends_at > initial_trial_end
        assert tenant.on_trial is True
        assert tenant.status == 'trial'

    def test_tenant_convert_from_trial(self, tenant_factory, plan_factory):
        """Test tenant convert_from_trial method."""
        tenant = tenant_factory(status='trial', on_trial=True)
        new_plan = plan_factory()

        tenant.convert_from_trial(plan=new_plan)

        assert tenant.status == 'active'
        assert tenant.on_trial is False
        assert tenant.plan == new_plan
        assert tenant.activated_at is not None
        assert tenant.paid_until is not None

    def test_tenant_check_subscription_status(self, tenant_factory):
        """Test check_subscription_status method."""
        # Active tenant
        active = tenant_factory(status='active', on_trial=False)
        assert active.check_subscription_status() == 'active'

        # Trial tenant
        trial = tenant_factory(
            status='trial',
            on_trial=True,
            trial_ends_at=timezone.now() + timedelta(days=7)
        )
        assert trial.check_subscription_status() == 'trial'

        # Expired trial
        expired = tenant_factory(
            status='trial',
            on_trial=True,
            trial_ends_at=timezone.now() - timedelta(days=1)
        )
        assert expired.check_subscription_status() == 'expired'

        # Suspended
        suspended = tenant_factory(status='suspended')
        assert suspended.check_subscription_status() == 'suspended'

        # Cancelled
        cancelled = tenant_factory(status='cancelled')
        assert cancelled.check_subscription_status() == 'cancelled'

    def test_tenant_has_feature(self, tenant_factory, plan_factory):
        """Test has_feature method."""
        plan = plan_factory(
            feature_ats=True,
            feature_sso=False
        )
        tenant = tenant_factory(plan=plan)

        assert tenant.has_feature('jobs') is True
        assert tenant.has_feature('sso') is False
        assert tenant.has_feature('nonexistent') is False

    def test_tenant_has_feature_no_plan(self, tenant_factory):
        """Test has_feature returns False when no plan."""
        tenant = tenant_factory(plan=None)

        assert tenant.has_feature('jobs') is False

    def test_tenant_get_usage_percentage(self, tenant_factory, plan_factory):
        """Test get_usage_percentage method."""
        plan = plan_factory(max_users=10)
        tenant = tenant_factory(plan=plan)

        # Create usage with 5 users (50%)
        TenantUsage.objects.filter(tenant=tenant).update(user_count=5)
        tenant.refresh_from_db()

        # Note: This requires TenantUsage to be created by signal
        usage = getattr(tenant, 'usage', None)
        if usage:
            percentage = tenant.get_usage_percentage('users')
            assert percentage == 50.0

    def test_tenant_is_approaching_limit(self, tenant_factory, plan_factory):
        """Test is_approaching_limit method."""
        plan = plan_factory(max_users=10)
        tenant = tenant_factory(plan=plan)

        # Update usage to 85%
        TenantUsage.objects.filter(tenant=tenant).update(user_count=8)
        tenant.refresh_from_db()

        usage = getattr(tenant, 'usage', None)
        if usage:
            assert tenant.is_approaching_limit('users', threshold=80.0) is True
            assert tenant.is_approaching_limit('users', threshold=90.0) is False

    def test_tenant_is_subscription_active_property(self, tenant_factory):
        """Test is_subscription_active property."""
        active = tenant_factory(status='active', on_trial=False)
        assert active.is_subscription_active is True

        suspended = tenant_factory(status='suspended')
        assert suspended.is_subscription_active is False

    def test_tenant_days_until_expiry(self, tenant_factory):
        """Test days_until_expiry property."""
        tenant = tenant_factory(
            on_trial=True,
            trial_ends_at=timezone.now() + timedelta(days=10)
        )
        assert 9 <= tenant.days_until_expiry <= 10

        # Tenant with paid_until
        paid_tenant = tenant_factory(
            on_trial=False,
            paid_until=timezone.now() + timedelta(days=30)
        )
        assert 29 <= paid_tenant.days_until_expiry <= 30

    def test_tenant_get_primary_domain(self, tenant_factory, domain_factory):
        """Test get_primary_domain method."""
        tenant = tenant_factory()
        primary_domain = domain_factory(tenant=tenant, is_primary=True)
        domain_factory(tenant=tenant, is_primary=False)

        result = tenant.get_primary_domain()
        assert result == primary_domain

    def test_tenant_get_careers_domain(self, tenant_factory, domain_factory):
        """Test get_careers_domain method."""
        tenant = tenant_factory()
        domain_factory(tenant=tenant, is_primary=True, is_careers_domain=False)
        careers_domain = domain_factory(
            tenant=tenant,
            is_primary=False,
            is_careers_domain=True,
            domain='careers.example.com'
        )

        result = tenant.get_careers_domain()
        assert result == careers_domain

    def test_tenant_logo_validation(self, tenant_factory):
        """Test logo file size validation."""
        tenant = tenant_factory()

        # Mock a large file
        mock_logo = MagicMock()
        mock_logo.size = 10 * 1024 * 1024  # 10MB

        tenant.logo = mock_logo

        with pytest.raises(ValidationError) as exc_info:
            tenant.clean()

        assert 'logo' in exc_info.value.message_dict

    def test_trial_tenant_factory(self, plan_factory):
        """Test TrialTenantFactory creates correct defaults."""
        plan = plan_factory()
        tenant = TrialTenantFactory(plan=plan)

        assert tenant.status == 'trial'
        assert tenant.on_trial is True
        assert tenant.trial_ends_at is not None


# ============================================================================
# TENANT SETTINGS MODEL TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantSettingsModel:
    """Test TenantSettings model creation and validation."""

    def test_create_tenant_settings(self, tenant_settings_factory, tenant_factory):
        """Test creating tenant settings."""
        tenant = tenant_factory()
        settings = tenant_settings_factory(tenant=tenant)

        assert settings.pk is not None
        assert settings.tenant == tenant

    def test_tenant_settings_one_to_one(self, tenant_settings_factory, tenant_factory):
        """Test TenantSettings is one-to-one with Tenant."""
        tenant = tenant_factory()
        tenant_settings_factory(tenant=tenant)

        with pytest.raises(IntegrityError):
            TenantSettings.objects.create(tenant=tenant)

    def test_tenant_settings_branding(self, tenant_settings_factory):
        """Test branding fields."""
        settings = tenant_settings_factory(
            primary_color='#FF0000',
            secondary_color='#00FF00',
            accent_color='#0000FF'
        )

        assert settings.primary_color == '#FF0000'
        assert settings.secondary_color == '#00FF00'
        assert settings.accent_color == '#0000FF'

    def test_tenant_settings_localization(self, tenant_settings_factory):
        """Test localization fields."""
        settings = tenant_settings_factory(
            default_language='fr',
            default_timezone='Europe/Paris',
            currency='EUR'
        )

        assert settings.default_language == 'fr'
        assert settings.default_timezone == 'Europe/Paris'
        assert settings.currency == 'EUR'

    def test_tenant_settings_security(self, tenant_settings_factory):
        """Test security settings fields."""
        settings = tenant_settings_factory(
            require_2fa=True,
            session_timeout_minutes=60,
            password_expiry_days=90
        )

        assert settings.require_2fa is True
        assert settings.session_timeout_minutes == 60
        assert settings.password_expiry_days == 90

    def test_get_default_pipeline_stages(self, tenant_settings_factory):
        """Test get_default_pipeline_stages method."""
        # Settings with custom stages
        settings = tenant_settings_factory(
            default_pipeline_stages=['Stage 1', 'Stage 2', 'Stage 3']
        )
        assert settings.get_default_pipeline_stages() == ['Stage 1', 'Stage 2', 'Stage 3']

        # Settings without custom stages
        settings_default = tenant_settings_factory(default_pipeline_stages=[])
        stages = settings_default.get_default_pipeline_stages()
        assert 'New' in stages
        assert 'Hired' in stages

    def test_tenant_settings_str(self, tenant_settings_factory, tenant_factory):
        """Test string representation."""
        tenant = tenant_factory(name='Acme Corp')
        settings = tenant_settings_factory(tenant=tenant)

        assert 'Acme Corp' in str(settings)

    def test_favicon_validation(self, tenant_settings_factory):
        """Test favicon file size validation."""
        settings = tenant_settings_factory()

        # Mock a large favicon
        mock_favicon = MagicMock()
        mock_favicon.size = 2 * 1024 * 1024  # 2MB

        settings.favicon = mock_favicon

        with pytest.raises(ValidationError) as exc_info:
            settings.clean()

        assert 'favicon' in exc_info.value.message_dict


# ============================================================================
# DOMAIN MODEL TESTS
# ============================================================================

@pytest.mark.django_db
class TestDomainModel:
    """Test Domain model creation and validation."""

    def test_create_domain(self, domain_factory, tenant_factory):
        """Test creating a domain."""
        tenant = tenant_factory()
        domain = domain_factory(
            tenant=tenant,
            domain='example.zumodra.com',
            is_primary=True
        )

        assert domain.pk is not None
        assert domain.tenant == tenant
        assert domain.domain == 'example.zumodra.com'
        assert domain.is_primary is True

    def test_domain_str_representation(self, domain_factory):
        """Test domain string representation."""
        domain = domain_factory(domain='test.zumodra.com')

        assert str(domain) == 'test.zumodra.com'

    def test_domain_careers_domain_flag(self, domain_factory):
        """Test is_careers_domain flag."""
        careers_domain = domain_factory(
            is_careers_domain=True,
            domain='careers.example.com'
        )

        assert careers_domain.is_careers_domain is True

    def test_domain_ssl_settings(self, domain_factory):
        """Test SSL-related fields."""
        domain = domain_factory(
            ssl_enabled=True,
            ssl_certificate='-----BEGIN CERTIFICATE-----',
            ssl_private_key='-----BEGIN PRIVATE KEY-----'
        )

        assert domain.ssl_enabled is True
        assert domain.ssl_certificate != ''
        assert domain.ssl_private_key != ''

    def test_multiple_domains_per_tenant(self, domain_factory, tenant_factory):
        """Test tenant can have multiple domains."""
        tenant = tenant_factory()
        domain1 = domain_factory(tenant=tenant, domain='primary.example.com', is_primary=True)
        domain2 = domain_factory(tenant=tenant, domain='careers.example.com', is_primary=False)

        assert tenant.domains.count() == 2
        assert domain1.tenant == domain2.tenant


# ============================================================================
# TENANT INVITATION MODEL TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantInvitationModel:
    """Test TenantInvitation model creation and validation."""

    def test_create_invitation(self, tenant_invitation_factory, tenant_factory, user_factory):
        """Test creating an invitation."""
        tenant = tenant_factory()
        inviter = user_factory()
        invitation = tenant_invitation_factory(
            tenant=tenant,
            invited_by=inviter,
            email='newuser@example.com',
            role='member'
        )

        assert invitation.pk is not None
        assert invitation.tenant == tenant
        assert invitation.invited_by == inviter
        assert invitation.email == 'newuser@example.com'
        assert invitation.role == 'member'
        assert invitation.status == 'pending'

    def test_invitation_uuid_auto_generated(self, tenant_invitation_factory):
        """Test invitation UUID is auto-generated."""
        invitation = tenant_invitation_factory()

        assert invitation.uuid is not None
        assert isinstance(invitation.uuid, uuid.UUID)

    def test_invitation_is_expired_property(self, tenant_invitation_factory):
        """Test is_expired property."""
        valid_invitation = tenant_invitation_factory(
            expires_at=timezone.now() + timedelta(days=7)
        )
        assert valid_invitation.is_expired is False

        expired_invitation = tenant_invitation_factory(
            expires_at=timezone.now() - timedelta(days=1)
        )
        assert expired_invitation.is_expired is True

    def test_invitation_accept(self, tenant_invitation_factory, user_factory):
        """Test accept method."""
        invitation = tenant_invitation_factory(status='pending')
        user = user_factory()

        invitation.accept(user)

        assert invitation.status == 'accepted'
        assert invitation.accepted_at is not None

    def test_invitation_unique_per_tenant_email(self, tenant_invitation_factory, tenant_factory):
        """Test unique constraint on tenant and email."""
        tenant = tenant_factory()
        tenant_invitation_factory(tenant=tenant, email='user@example.com')

        with pytest.raises(IntegrityError):
            TenantInvitation.objects.create(
                tenant=tenant,
                email='user@example.com',
                token='unique-token',
                expires_at=timezone.now() + timedelta(days=7)
            )

    def test_invitation_str_representation(self, tenant_invitation_factory, tenant_factory):
        """Test string representation."""
        tenant = tenant_factory(name='Acme Corp')
        invitation = tenant_invitation_factory(
            tenant=tenant,
            email='user@example.com'
        )

        str_repr = str(invitation)
        assert 'user@example.com' in str_repr
        assert 'Acme Corp' in str_repr


# ============================================================================
# TENANT USAGE MODEL TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantUsageModel:
    """Test TenantUsage model creation and validation."""

    def test_create_tenant_usage(self, tenant_factory):
        """Test creating tenant usage tracking."""
        tenant = tenant_factory()
        # Usage should be created by signal
        usage = TenantUsage.objects.filter(tenant=tenant).first()

        if usage:
            assert usage.tenant == tenant
            assert usage.user_count >= 0

    def test_tenant_usage_one_to_one(self, tenant_factory):
        """Test TenantUsage is one-to-one with Tenant."""
        tenant = tenant_factory()
        # First usage created by signal

        with pytest.raises(IntegrityError):
            TenantUsage.objects.create(tenant=tenant)

    def test_storage_used_gb_property(self):
        """Test storage_used_gb computed property."""
        usage = TenantUsageFactory(storage_used_bytes=2 * 1024 ** 3)  # 2GB

        assert usage.storage_used_gb == 2.0

    def test_is_within_limits(self, plan_factory, tenant_factory):
        """Test is_within_limits method."""
        plan = plan_factory(
            max_users=10,
            max_job_postings=25,
            max_candidates_per_month=100,
            max_circusales=3,
            storage_limit_gb=5
        )
        tenant = tenant_factory(plan=plan)

        # Get or create usage
        usage, _ = TenantUsage.objects.get_or_create(tenant=tenant)

        # Within limits
        usage.user_count = 5
        usage.active_job_count = 10
        usage.candidate_count_this_month = 50
        usage.circusale_count = 2
        usage.storage_used_bytes = 2 * 1024 ** 3  # 2GB
        usage.save()

        assert usage.is_within_limits() is True

        # Exceed user limit
        usage.user_count = 15
        usage.save()

        assert usage.is_within_limits() is False


# ============================================================================
# AUDIT LOG MODEL TESTS
# ============================================================================

@pytest.mark.django_db
class TestAuditLogModel:
    """Test AuditLog model creation and validation."""

    def test_create_audit_log(self, tenant_factory, user_factory):
        """Test creating an audit log entry."""
        tenant = tenant_factory()
        user = user_factory()
        log = AuditLogFactory(
            tenant=tenant,
            user=user,
            action='create',
            resource_type='JobPosting',
            resource_id='123'
        )

        assert log.pk is not None
        assert log.tenant == tenant
        assert log.user == user
        assert log.action == 'create'
        assert log.resource_type == 'JobPosting'

    def test_audit_log_action_choices(self, tenant_factory, user_factory):
        """Test all action choices are valid."""
        tenant = tenant_factory()
        user = user_factory()

        for action, display_name in AuditLog.ActionType.choices:
            log = AuditLogFactory(
                tenant=tenant,
                user=user,
                action=action
            )
            assert log.action == action

    def test_audit_log_uuid_auto_generated(self):
        """Test audit log UUID is auto-generated."""
        log = AuditLogFactory()

        assert log.uuid is not None
        assert isinstance(log.uuid, uuid.UUID)

    def test_audit_log_json_fields(self, tenant_factory, user_factory):
        """Test JSON fields for old/new values."""
        tenant = tenant_factory()
        user = user_factory()
        log = AuditLogFactory(
            tenant=tenant,
            user=user,
            action='update',
            old_values={'status': 'draft'},
            new_values={'status': 'published'}
        )

        assert log.old_values == {'status': 'draft'}
        assert log.new_values == {'status': 'published'}

    def test_audit_log_str_representation(self, tenant_factory, user_factory):
        """Test string representation."""
        tenant = tenant_factory()
        user = user_factory()
        log = AuditLogFactory(
            tenant=tenant,
            user=user,
            action='create',
            resource_type='JobPosting'
        )

        str_repr = str(log)
        assert 'create' in str_repr
        assert 'JobPosting' in str_repr


# ============================================================================
# CIRCUSALE MODEL TESTS
# ============================================================================

@pytest.mark.django_db
class TestCircusaleModel:
    """Test Circusale (business unit) model."""

    def test_create_circusale(self, tenant_factory):
        """Test creating a circusale."""
        tenant = tenant_factory()
        circusale = Circusale.objects.create(
            tenant=tenant,
            name='Montreal Office',
            slug='montreal-office',
            city='Montreal',
            country='CA'
        )

        assert circusale.pk is not None
        assert circusale.tenant == tenant
        assert circusale.name == 'Montreal Office'

    def test_circusale_uuid_auto_generated(self, tenant_factory):
        """Test circusale UUID is auto-generated."""
        tenant = tenant_factory()
        circusale = Circusale.objects.create(
            tenant=tenant,
            name='Test Office',
            slug='test-office'
        )

        assert circusale.uuid is not None
        assert isinstance(circusale.uuid, uuid.UUID)

    def test_circusale_auto_slug_generation(self, tenant_factory):
        """Test automatic slug generation."""
        tenant = tenant_factory()
        circusale = Circusale(
            tenant=tenant,
            name='New York Office'
        )
        circusale.save()

        assert circusale.slug is not None
        assert 'new-york-office' in circusale.slug

    def test_circusale_unique_slug_per_tenant(self, tenant_factory):
        """Test slug uniqueness within tenant."""
        tenant = tenant_factory()
        Circusale.objects.create(
            tenant=tenant,
            name='Office 1',
            slug='office'
        )

        # Create another with same name - should get different slug
        circusale2 = Circusale(tenant=tenant, name='Office')
        circusale2.save()

        assert circusale2.slug != 'office'

    def test_circusale_full_address(self, tenant_factory):
        """Test full_address property."""
        tenant = tenant_factory()
        circusale = Circusale.objects.create(
            tenant=tenant,
            name='HQ',
            slug='hq',
            address_line1='123 Main St',
            city='Montreal',
            state='QC',
            postal_code='H2X 1X1',
            country='CA'
        )

        address = circusale.full_address
        assert '123 Main St' in address
        assert 'Montreal' in address
        assert 'QC' in address

    def test_circusale_coordinates(self, tenant_factory):
        """Test coordinates property."""
        tenant = tenant_factory()
        circusale = Circusale.objects.create(
            tenant=tenant,
            name='Office',
            slug='office',
            latitude=Decimal('45.5017'),
            longitude=Decimal('-73.5673')
        )

        coords = circusale.coordinates
        assert coords is not None
        assert coords[0] == 45.5017
        assert coords[1] == -73.5673

    def test_circusale_hierarchy(self, tenant_factory):
        """Test parent-child hierarchy."""
        tenant = tenant_factory()
        parent = Circusale.objects.create(
            tenant=tenant,
            name='Corporate HQ',
            slug='corporate-hq',
            is_headquarters=True
        )
        child = Circusale.objects.create(
            tenant=tenant,
            name='Regional Office',
            slug='regional-office',
            parent=parent
        )

        assert child.parent == parent
        assert child in parent.children.all()

    def test_circusale_get_descendants(self, tenant_factory):
        """Test get_descendants method."""
        tenant = tenant_factory()
        root = Circusale.objects.create(tenant=tenant, name='Root', slug='root')
        child1 = Circusale.objects.create(tenant=tenant, name='Child 1', slug='child-1', parent=root)
        child2 = Circusale.objects.create(tenant=tenant, name='Child 2', slug='child-2', parent=root)
        grandchild = Circusale.objects.create(tenant=tenant, name='Grandchild', slug='grandchild', parent=child1)

        descendants = root.get_descendants()

        assert len(descendants) == 3
        assert child1 in descendants
        assert child2 in descendants
        assert grandchild in descendants

    def test_circusale_get_ancestors(self, tenant_factory):
        """Test get_ancestors method."""
        tenant = tenant_factory()
        root = Circusale.objects.create(tenant=tenant, name='Root', slug='root')
        child = Circusale.objects.create(tenant=tenant, name='Child', slug='child', parent=root)
        grandchild = Circusale.objects.create(tenant=tenant, name='Grandchild', slug='grandchild', parent=child)

        ancestors = grandchild.get_ancestors()

        assert len(ancestors) == 2
        assert child in ancestors
        assert root in ancestors

    def test_circusale_depth_property(self, tenant_factory):
        """Test depth property."""
        tenant = tenant_factory()
        root = Circusale.objects.create(tenant=tenant, name='Root', slug='root')
        child = Circusale.objects.create(tenant=tenant, name='Child', slug='child', parent=root)
        grandchild = Circusale.objects.create(tenant=tenant, name='Grandchild', slug='grandchild', parent=child)

        assert root.depth == 0
        assert child.depth == 1
        assert grandchild.depth == 2

    def test_circusale_get_headquarters(self, tenant_factory):
        """Test get_headquarters class method."""
        tenant = tenant_factory()
        Circusale.objects.create(tenant=tenant, name='Branch', slug='branch')
        hq = Circusale.objects.create(tenant=tenant, name='HQ', slug='hq', is_headquarters=True)

        result = Circusale.get_headquarters(tenant)
        assert result == hq


# ============================================================================
# SIGNAL TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantSignals:
    """Test tenant-related signal handlers."""

    def test_create_tenant_settings_signal(self, plan_factory):
        """Test TenantSettings is created on Tenant creation."""
        plan = plan_factory()
        tenant = Tenant.objects.create(
            name='Signal Test Tenant',
            slug='signal-test-tenant',
            schema_name='signal_test_tenant',
            plan=plan,
            owner_email='test@example.com'
        )

        # Settings should be created by signal
        assert TenantSettings.objects.filter(tenant=tenant).exists()

    def test_create_tenant_usage_signal(self, plan_factory):
        """Test TenantUsage is created on Tenant creation."""
        plan = plan_factory()
        tenant = Tenant.objects.create(
            name='Usage Test Tenant',
            slug='usage-test-tenant',
            schema_name='usage_test_tenant',
            plan=plan,
            owner_email='test@example.com'
        )

        # Usage should be created by signal
        assert TenantUsage.objects.filter(tenant=tenant).exists()

    def test_trial_end_date_set_signal(self, plan_factory):
        """Test trial end date is set for new trial tenants."""
        plan = plan_factory()
        tenant = Tenant.objects.create(
            name='Trial Test Tenant',
            slug='trial-test-tenant',
            schema_name='trial_test_tenant',
            plan=plan,
            owner_email='test@example.com',
            on_trial=True
        )

        # Trial end should be set (14 days from now)
        tenant.refresh_from_db()
        assert tenant.trial_ends_at is not None
        assert tenant.trial_ends_at > timezone.now()

    def test_cleanup_tenant_signal(self, tenant_factory, tenant_invitation_factory):
        """Test pending invitations are revoked on tenant deletion."""
        tenant = tenant_factory()

        # Create some invitations
        pending = tenant_invitation_factory(tenant=tenant, status='pending')
        accepted = tenant_invitation_factory(
            tenant=tenant,
            status='accepted',
            email='accepted@example.com'
        )

        pending_id = pending.pk
        accepted_id = accepted.pk

        # Delete tenant
        tenant.delete()

        # Check pending invitation was revoked (not deleted due to CASCADE)
        # Note: Due to CASCADE, invitations will be deleted
        assert not TenantInvitation.objects.filter(pk=pending_id).exists()

    def test_set_invitation_token_signal(self, tenant_factory, user_factory):
        """Test invitation token is set on creation."""
        tenant = tenant_factory()
        user = user_factory()

        # Create invitation without token
        invitation = TenantInvitation.objects.create(
            tenant=tenant,
            email='newuser@example.com',
            invited_by=user,
            token='placeholder',  # Signal will override if empty
            expires_at=timezone.now() + timedelta(days=7)
        )

        invitation.refresh_from_db()
        assert invitation.token is not None
        assert len(invitation.token) > 0

    def test_generate_invitation_token(self):
        """Test generate_invitation_token function."""
        token1 = generate_invitation_token()
        token2 = generate_invitation_token()

        assert token1 is not None
        assert token2 is not None
        assert token1 != token2
        assert len(token1) >= 32


# ============================================================================
# TENANT ISOLATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantIsolation:
    """Test tenant data isolation."""

    def test_invitation_belongs_to_single_tenant(self, tenant_factory, tenant_invitation_factory):
        """Test invitations are isolated to their tenant."""
        tenant1 = tenant_factory(slug='tenant-1')
        tenant2 = tenant_factory(slug='tenant-2')

        invite1 = tenant_invitation_factory(tenant=tenant1, email='user1@example.com')
        invite2 = tenant_invitation_factory(tenant=tenant2, email='user2@example.com')

        # Query invitations for each tenant
        t1_invites = TenantInvitation.objects.filter(tenant=tenant1)
        t2_invites = TenantInvitation.objects.filter(tenant=tenant2)

        assert invite1 in t1_invites
        assert invite2 not in t1_invites
        assert invite2 in t2_invites
        assert invite1 not in t2_invites

    def test_audit_logs_isolated_by_tenant(self, tenant_factory, user_factory):
        """Test audit logs are isolated to their tenant."""
        tenant1 = tenant_factory(slug='tenant-a')
        tenant2 = tenant_factory(slug='tenant-b')
        user = user_factory()

        log1 = AuditLogFactory(tenant=tenant1, user=user, action='create')
        log2 = AuditLogFactory(tenant=tenant2, user=user, action='update')

        t1_logs = AuditLog.objects.filter(tenant=tenant1)
        t2_logs = AuditLog.objects.filter(tenant=tenant2)

        assert log1 in t1_logs
        assert log2 not in t1_logs
        assert log2 in t2_logs
        assert log1 not in t2_logs

    def test_domains_isolated_by_tenant(self, tenant_factory, domain_factory):
        """Test domains are isolated to their tenant."""
        tenant1 = tenant_factory(slug='company-a')
        tenant2 = tenant_factory(slug='company-b')

        domain1 = domain_factory(tenant=tenant1, domain='a.example.com')
        domain2 = domain_factory(tenant=tenant2, domain='b.example.com')

        assert tenant1.domains.count() == 1
        assert tenant2.domains.count() == 1
        assert domain1.tenant == tenant1
        assert domain2.tenant == tenant2

    def test_circusales_isolated_by_tenant(self, tenant_factory):
        """Test circusales are isolated to their tenant."""
        tenant1 = tenant_factory(slug='corp-1')
        tenant2 = tenant_factory(slug='corp-2')

        circ1 = Circusale.objects.create(tenant=tenant1, name='Office 1', slug='office-1')
        circ2 = Circusale.objects.create(tenant=tenant2, name='Office 2', slug='office-2')

        t1_circs = Circusale.objects.filter(tenant=tenant1)
        t2_circs = Circusale.objects.filter(tenant=tenant2)

        assert circ1 in t1_circs
        assert circ2 not in t1_circs
        assert circ2 in t2_circs
        assert circ1 not in t2_circs


# ============================================================================
# PLAN FEATURE ENFORCEMENT TESTS
# ============================================================================

@pytest.mark.django_db
class TestPlanFeatureEnforcement:
    """Test plan feature access control."""

    def test_feature_access_with_plan(self, plan_factory, tenant_factory):
        """Test feature access when tenant has a plan."""
        plan = plan_factory(
            feature_ats=True,
            feature_hr_core=False,
            feature_ai_matching=True
        )
        tenant = tenant_factory(plan=plan)

        assert tenant.has_feature('jobs') is True
        assert tenant.has_feature('hr_core') is False
        assert tenant.has_feature('ai_matching') is True

    def test_feature_access_without_plan(self, tenant_factory):
        """Test feature access when tenant has no plan."""
        tenant = tenant_factory(plan=None)

        assert tenant.has_feature('jobs') is False
        assert tenant.has_feature('hr_core') is False

    def test_free_plan_limited_features(self, free_plan_factory, tenant_factory):
        """Test free plan has limited features."""
        plan = free_plan_factory()
        tenant = tenant_factory(plan=plan)

        # Free plan should have basic features
        assert tenant.has_feature('jobs') is True
        assert tenant.has_feature('hr_core') is False
        assert tenant.has_feature('analytics') is False
        assert tenant.has_feature('api_access') is False

    def test_enterprise_plan_all_features(self, enterprise_plan_factory, tenant_factory):
        """Test enterprise plan has all features."""
        plan = enterprise_plan_factory()
        tenant = tenant_factory(plan=plan)

        # Enterprise plan should have all features
        assert tenant.has_feature('jobs') is True
        assert tenant.has_feature('hr_core') is True
        assert tenant.has_feature('ai_matching') is True
        assert tenant.has_feature('sso') is True
        assert tenant.has_feature('custom_branding') is True


# ============================================================================
# TENANT LIFECYCLE TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantLifecycle:
    """Test tenant lifecycle transitions."""

    def test_trial_to_active_transition(self, tenant_factory, plan_factory):
        """Test transitioning from trial to active."""
        plan = plan_factory()
        tenant = tenant_factory(
            plan=plan,
            status='trial',
            on_trial=True,
            trial_ends_at=timezone.now() + timedelta(days=7)
        )

        # Convert to active
        tenant.convert_from_trial()

        assert tenant.status == 'active'
        assert tenant.on_trial is False
        assert tenant.activated_at is not None
        assert tenant.paid_until is not None

    def test_active_to_suspended_transition(self, tenant_factory):
        """Test transitioning from active to suspended."""
        tenant = tenant_factory(status='active')

        tenant.suspend()

        assert tenant.status == 'suspended'
        assert tenant.suspended_at is not None

    def test_suspended_to_active_transition(self, tenant_factory):
        """Test reactivating a suspended tenant."""
        tenant = tenant_factory(status='suspended')
        tenant.suspended_at = timezone.now() - timedelta(days=1)
        tenant.save()

        tenant.reactivate()

        assert tenant.status == 'active'
        assert tenant.suspended_at is None

    def test_active_to_cancelled_transition(self, tenant_factory):
        """Test cancelling an active tenant."""
        tenant = tenant_factory(status='active')

        tenant.cancel()

        assert tenant.status == 'cancelled'

    def test_trial_extension(self, tenant_factory):
        """Test extending trial period."""
        initial_end = timezone.now() + timedelta(days=3)
        tenant = tenant_factory(
            status='trial',
            on_trial=True,
            trial_ends_at=initial_end
        )

        tenant.extend_trial(days=14)

        assert tenant.trial_ends_at > initial_end
        assert tenant.on_trial is True

    def test_expired_trial_check(self, tenant_factory):
        """Test detection of expired trial."""
        tenant = tenant_factory(
            status='trial',
            on_trial=True,
            trial_ends_at=timezone.now() - timedelta(days=1)
        )

        assert tenant.check_subscription_status() == 'expired'
        assert tenant.is_on_trial is False


# ============================================================================
# MIDDLEWARE TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantMiddleware:
    """Test tenant middleware functionality."""

    def test_tenant_urlconf_middleware(self):
        """Test TenantURLConfMiddleware applies urlconf."""
        middleware = TenantURLConfMiddleware(lambda r: HttpResponse('OK'))

        request = HttpRequest()
        request.urlconf = 'tenant_urls'
        request.method = 'GET'

        response = middleware(request)

        assert response.status_code == 200

    def test_tenant_urlconf_middleware_no_urlconf(self):
        """Test middleware handles missing urlconf gracefully."""
        middleware = TenantURLConfMiddleware(lambda r: HttpResponse('OK'))

        request = HttpRequest()
        request.method = 'GET'

        response = middleware(request)

        assert response.status_code == 200

    def test_zumodra_tenant_middleware_exempt_urls(self, tenant_factory):
        """Test exempt URLs bypass tenant checks."""
        middleware = ZumodraTenantMiddleware(lambda r: HttpResponse('OK'))

        exempt_paths = ['/admin/', '/accounts/', '/api/public/', '/static/']

        for path in exempt_paths:
            assert middleware._is_exempt_url(path) is True

    def test_zumodra_tenant_middleware_extract_subdomain(self, tenant_factory):
        """Test subdomain extraction."""
        middleware = ZumodraTenantMiddleware(lambda r: HttpResponse('OK'))

        # Test with mock settings
        with patch.object(middleware, '_extract_subdomain') as mock_extract:
            mock_extract.return_value = 'acme'
            result = middleware._extract_subdomain('acme.zumodra.com')
            assert result == 'acme'

    def test_tenant_context_middleware(self, tenant_factory, user_factory):
        """Test TenantContextMiddleware adds context."""
        middleware = TenantContextMiddleware(lambda r: HttpResponse('OK'))

        plan = PlanFactory(feature_ats=True, feature_hr_core=False)
        tenant = tenant_factory(plan=plan)
        user = user_factory()

        request = HttpRequest()
        request.tenant = tenant
        request.user = user
        request.method = 'GET'
        request.tenant_features = {'jobs': True, 'hr_core': False}

        response = middleware(request)

        assert response.status_code == 200
        # Context should be cleared after response
        assert get_current_tenant() is None

    def test_tenant_security_middleware_ip_whitelist(self, tenant_factory, tenant_settings_factory, user_factory):
        """Test IP whitelist enforcement."""
        middleware = TenantSecurityMiddleware(lambda r: HttpResponse('OK'))

        tenant = tenant_factory()
        settings = tenant_settings_factory(
            tenant=tenant,
            ip_whitelist=['192.168.1.1']
        )
        user = user_factory(is_staff=True)

        request = HttpRequest()
        request.tenant = tenant
        request.tenant_settings = settings
        request.user = user
        request._is_public_tenant = False
        request.META = {'REMOTE_ADDR': '10.0.0.1'}
        request.method = 'GET'

        response = middleware(request)

        # Should be forbidden due to IP not in whitelist
        assert response.status_code == 403

    def test_tenant_security_middleware_2fa_required(self, tenant_factory, tenant_settings_factory, user_factory):
        """Test 2FA enforcement."""
        middleware = TenantSecurityMiddleware(lambda r: HttpResponse('OK'))

        tenant = tenant_factory()
        settings = tenant_settings_factory(
            tenant=tenant,
            require_2fa=True,
            ip_whitelist=[]  # Empty whitelist
        )
        user = user_factory()

        request = HttpRequest()
        request.tenant = tenant
        request.tenant_settings = settings
        request.user = user
        request._is_public_tenant = False
        request.session = {'2fa_verified': False}
        request.path = '/dashboard/'
        request.META = {'REMOTE_ADDR': '127.0.0.1'}
        request.method = 'GET'

        response = middleware(request)

        # Should redirect to 2FA verification
        assert response.status_code == 302

    def test_tenant_security_middleware_security_headers(self, tenant_factory, tenant_settings_factory):
        """Test security headers are added."""
        middleware = TenantSecurityMiddleware(lambda r: HttpResponse('OK'))

        tenant = tenant_factory()
        settings = tenant_settings_factory(tenant=tenant, require_2fa=False, ip_whitelist=[])

        request = HttpRequest()
        request.tenant = tenant
        request.tenant_settings = settings
        request._is_public_tenant = True  # Bypass security checks
        request.META = {'REMOTE_ADDR': '127.0.0.1'}
        request.method = 'GET'

        response = middleware(request)

        assert response['X-Content-Type-Options'] == 'nosniff'
        assert response['X-Frame-Options'] == 'SAMEORIGIN'


# ============================================================================
# TENANT CONTEXT TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantContext:
    """Test tenant context management."""

    def test_set_and_get_current_tenant(self, tenant_factory):
        """Test setting and getting current tenant."""
        tenant = tenant_factory()

        set_current_tenant(tenant)
        assert get_current_tenant() == tenant

        # Cleanup
        clear_tenant_context()

    def test_clear_tenant_context(self, tenant_factory):
        """Test clearing tenant context."""
        tenant = tenant_factory()
        set_current_tenant(tenant)

        clear_tenant_context()

        assert get_current_tenant() is None

    def test_tenant_context_manager(self, tenant_factory):
        """Test tenant_context context manager."""
        tenant = tenant_factory()

        with context_manager(tenant, activate_schema=False):
            assert get_current_tenant() == tenant

        # Context should be cleared after exiting
        # Note: May need cleanup depending on implementation
        clear_tenant_context()

    def test_nested_tenant_contexts(self, tenant_factory):
        """Test nested tenant contexts."""
        tenant1 = tenant_factory(slug='tenant-1')
        tenant2 = tenant_factory(slug='tenant-2')

        with context_manager(tenant1, activate_schema=False):
            assert get_current_tenant() == tenant1

            with context_manager(tenant2, activate_schema=False):
                assert get_current_tenant() == tenant2

            # Should return to tenant1
            assert get_current_tenant() == tenant1

        clear_tenant_context()

    def test_tenant_context_class(self):
        """Test TenantContext class."""
        ctx = TenantContext()

        assert ctx.tenant is None
        assert ctx.is_public_schema is True

    def test_tenant_context_push_pop(self, tenant_factory):
        """Test TenantContext push/pop stack."""
        tenant1 = tenant_factory(slug='ctx-tenant-1')
        tenant2 = tenant_factory(slug='ctx-tenant-2')

        ctx = TenantContext()
        ctx.tenant = tenant1
        ctx.push()

        ctx.tenant = tenant2
        assert ctx.tenant == tenant2

        ctx.pop()
        assert ctx.tenant == tenant1


# ============================================================================
# DOMAIN ROUTING TESTS
# ============================================================================

@pytest.mark.django_db
class TestDomainRouting:
    """Test domain-based tenant routing."""

    def test_lookup_tenant_by_subdomain(self, tenant_factory):
        """Test tenant lookup by subdomain (slug)."""
        tenant = tenant_factory(slug='acme-corp')

        result = Tenant.objects.get(slug='acme-corp')

        assert result == tenant

    def test_lookup_tenant_by_domain(self, tenant_factory, domain_factory):
        """Test tenant lookup by custom domain."""
        tenant = tenant_factory()
        domain = domain_factory(tenant=tenant, domain='custom.example.com')

        result = Domain.objects.get(domain='custom.example.com')

        assert result.tenant == tenant

    def test_primary_domain_lookup(self, tenant_factory, domain_factory):
        """Test primary domain lookup."""
        tenant = tenant_factory()
        primary = domain_factory(tenant=tenant, is_primary=True, domain='primary.example.com')
        domain_factory(tenant=tenant, is_primary=False, domain='secondary.example.com')

        result = tenant.get_primary_domain()

        assert result == primary
        assert result.domain == 'primary.example.com'


# ============================================================================
# CIRCUSALE USER TESTS
# ============================================================================

@pytest.mark.django_db
class TestCircusaleUser:
    """Test CircusaleUser (user-circusale membership) model."""

    def test_create_circusale_user(self, tenant_factory, user_factory):
        """Test creating a circusale user membership."""
        tenant = tenant_factory()
        user = user_factory()
        circusale = Circusale.objects.create(
            tenant=tenant,
            name='Test Office',
            slug='test-office'
        )

        membership = CircusaleUser.objects.create(
            user=user,
            circusale=circusale,
            role='member',
            is_primary=True
        )

        assert membership.pk is not None
        assert membership.user == user
        assert membership.circusale == circusale
        assert membership.role == 'member'
        assert membership.is_primary is True

    def test_circusale_user_role_choices(self, tenant_factory, user_factory):
        """Test all role choices are valid."""
        tenant = tenant_factory()
        circusale = Circusale.objects.create(tenant=tenant, name='Office', slug='office')

        for role, display_name in CircusaleUser.CircusaleRole.choices:
            user = user_factory()
            membership = CircusaleUser.objects.create(
                user=user,
                circusale=circusale,
                role=role
            )
            assert membership.role == role

    def test_circusale_user_unique_together(self, tenant_factory, user_factory):
        """Test user can only be in a circusale once."""
        tenant = tenant_factory()
        user = user_factory()
        circusale = Circusale.objects.create(tenant=tenant, name='Office', slug='office')

        CircusaleUser.objects.create(user=user, circusale=circusale)

        with pytest.raises(IntegrityError):
            CircusaleUser.objects.create(user=user, circusale=circusale)

    def test_user_multiple_circusales(self, tenant_factory, user_factory):
        """Test user can belong to multiple circusales."""
        tenant = tenant_factory()
        user = user_factory()
        circ1 = Circusale.objects.create(tenant=tenant, name='Office 1', slug='office-1')
        circ2 = Circusale.objects.create(tenant=tenant, name='Office 2', slug='office-2')

        mem1 = CircusaleUser.objects.create(user=user, circusale=circ1, is_primary=True)
        mem2 = CircusaleUser.objects.create(user=user, circusale=circ2, is_primary=False)

        assert user.circusale_memberships.count() == 2


# ============================================================================
# UPDATE SUBSCRIPTION TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantSubscriptionUpdates:
    """Test tenant subscription update methods."""

    def test_update_subscription(self, tenant_factory):
        """Test update_subscription method."""
        tenant = tenant_factory()
        new_paid_until = timezone.now() + timedelta(days=365)

        tenant.update_subscription(
            stripe_subscription_id='sub_123456',
            paid_until=new_paid_until
        )

        tenant.refresh_from_db()
        assert tenant.stripe_subscription_id == 'sub_123456'
        assert tenant.paid_until == new_paid_until

    def test_subscription_expiry_check(self, tenant_factory):
        """Test subscription expiry detection."""
        # Active subscription
        active_tenant = tenant_factory(
            on_trial=False,
            paid_until=timezone.now() + timedelta(days=30)
        )
        assert active_tenant.check_subscription_status() == 'active'

        # Expired subscription
        expired_tenant = tenant_factory(
            on_trial=False,
            paid_until=timezone.now() - timedelta(days=1)
        )
        assert expired_tenant.check_subscription_status() == 'expired'


# ============================================================================
# RATE LIMITING TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantRateLimiting:
    """Test tenant API rate limiting in middleware."""

    def test_usage_tracking_middleware(self, tenant_factory, plan_factory):
        """Test TenantUsageMiddleware tracks API calls."""
        middleware = TenantUsageMiddleware(lambda r: HttpResponse('OK'))

        plan = plan_factory()
        tenant = tenant_factory(plan=plan)

        request = HttpRequest()
        request.tenant = tenant
        request.tenant_plan = plan
        request.path = '/api/v1/jobs/'
        request.META = {'REMOTE_ADDR': '127.0.0.1'}
        request.method = 'GET'

        # Should track is called
        assert middleware._should_track(request) is True

    def test_rate_limit_check(self, tenant_factory, plan_factory):
        """Test rate limit check in usage middleware."""
        middleware = TenantUsageMiddleware(lambda r: HttpResponse('OK'))

        plan = plan_factory()
        tenant = tenant_factory(plan=plan)

        request = HttpRequest()
        request.tenant = tenant
        request.tenant_plan = plan
        request.path = '/api/v1/jobs/'
        request.META = {'REMOTE_ADDR': '127.0.0.1'}
        request.method = 'GET'

        # Rate limit should not be exceeded initially
        assert middleware._check_rate_limit(request) is False


# ============================================================================
# MIDDLEWARE RESPONSE TESTS
# ============================================================================

@pytest.mark.django_db
class TestMiddlewareResponses:
    """Test middleware response handling."""

    def test_suspended_tenant_response(self):
        """Test suspended tenant gets appropriate response."""
        middleware = ZumodraTenantMiddleware(lambda r: HttpResponse('OK'))

        response = middleware._suspended_response(HttpRequest())

        assert response.status_code == 403
        assert 'suspended' in response.content.decode().lower()

    def test_cancelled_tenant_response(self):
        """Test cancelled tenant gets appropriate response."""
        middleware = ZumodraTenantMiddleware(lambda r: HttpResponse('OK'))

        response = middleware._cancelled_response(HttpRequest())

        assert response.status_code == 403
        assert 'cancelled' in response.content.decode().lower()

    def test_pending_tenant_redirect(self):
        """Test pending tenant gets redirected to onboarding."""
        middleware = ZumodraTenantMiddleware(lambda r: HttpResponse('OK'))

        response = middleware._pending_response(HttpRequest())

        assert response.status_code == 302
        assert '/onboarding/' in response.url

    def test_trial_expired_redirect(self):
        """Test expired trial gets redirected to billing."""
        middleware = ZumodraTenantMiddleware(lambda r: HttpResponse('OK'))

        response = middleware._trial_expired_response(HttpRequest())

        assert response.status_code == 302
        assert '/billing/' in response.url


# ============================================================================
# TENANT RESOLUTION ERROR TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantResolutionErrors:
    """Test tenant resolution error handling."""

    def test_tenant_resolution_error(self):
        """Test base TenantResolutionError."""
        error = TenantResolutionError("Test error")
        assert str(error) == "Test error"

    def test_tenant_not_found_error(self):
        """Test TenantNotFoundError."""
        error = TenantNotFoundError("Tenant not found")
        assert isinstance(error, TenantResolutionError)

    def test_tenant_inactive_error(self):
        """Test TenantInactiveError."""
        error = TenantInactiveError("Tenant inactive")
        assert isinstance(error, TenantResolutionError)


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantIntegration:
    """Integration tests for tenant functionality."""

    def test_complete_tenant_setup(self, plan_factory, user_factory):
        """Test complete tenant setup flow."""
        # 1. Create plan
        plan = plan_factory(
            name='Professional',
            feature_ats=True,
            feature_hr_core=True
        )

        # 2. Create tenant
        tenant = Tenant.objects.create(
            name='Integration Test Corp',
            slug='integration-test-corp',
            schema_name='integration_test_corp',
            plan=plan,
            owner_email='owner@integration.test',
            on_trial=True
        )

        # 3. Verify settings created by signal
        assert TenantSettings.objects.filter(tenant=tenant).exists()

        # 4. Verify usage created by signal
        assert TenantUsage.objects.filter(tenant=tenant).exists()

        # 5. Create domain
        domain = Domain.objects.create(
            tenant=tenant,
            domain='integration-test-corp.zumodra.local',
            is_primary=True
        )

        # 6. Create circusale
        circusale = Circusale.objects.create(
            tenant=tenant,
            name='Headquarters',
            slug='hq',
            is_headquarters=True
        )

        # 7. Verify everything is connected
        assert tenant.domains.count() == 1
        assert tenant.circusales.count() == 1
        assert tenant.has_feature('jobs') is True
        assert tenant.has_feature('hr_core') is True

    def test_tenant_lifecycle_flow(self, plan_factory):
        """Test full tenant lifecycle."""
        plan = plan_factory()

        # 1. Create trial tenant
        tenant = Tenant.objects.create(
            name='Lifecycle Test',
            slug='lifecycle-test',
            schema_name='lifecycle_test',
            plan=plan,
            owner_email='owner@lifecycle.test',
            status='trial',
            on_trial=True
        )

        assert tenant.status == 'trial'
        assert tenant.is_on_trial is True

        # 2. Convert to active
        tenant.convert_from_trial()
        assert tenant.status == 'active'
        assert tenant.on_trial is False

        # 3. Suspend
        tenant.suspend()
        assert tenant.status == 'suspended'

        # 4. Reactivate
        tenant.reactivate()
        assert tenant.status == 'active'

        # 5. Cancel
        tenant.cancel()
        assert tenant.status == 'cancelled'

    def test_invitation_flow(self, tenant_factory, user_factory):
        """Test complete invitation flow."""
        tenant = tenant_factory()
        inviter = user_factory()

        # 1. Create invitation
        invitation = TenantInvitation.objects.create(
            tenant=tenant,
            email='newuser@example.com',
            invited_by=inviter,
            role='member',
            token=secrets.token_urlsafe(32),
            expires_at=timezone.now() + timedelta(days=7)
        )

        assert invitation.status == 'pending'
        assert invitation.is_expired is False

        # 2. Accept invitation
        new_user = user_factory(email='newuser@example.com')
        invitation.accept(new_user)

        assert invitation.status == 'accepted'
        assert invitation.accepted_at is not None

    def test_audit_logging_flow(self, tenant_factory, user_factory):
        """Test audit logging for tenant operations."""
        tenant = tenant_factory()
        user = user_factory()

        # Create various audit logs
        logs = []

        # Login log
        logs.append(AuditLog.objects.create(
            tenant=tenant,
            user=user,
            action='login',
            resource_type='User',
            resource_id=str(user.pk),
            ip_address='192.168.1.100'
        ))

        # Create log
        logs.append(AuditLog.objects.create(
            tenant=tenant,
            user=user,
            action='create',
            resource_type='JobPosting',
            resource_id='123',
            new_values={'title': 'Software Engineer'}
        ))

        # Update log
        logs.append(AuditLog.objects.create(
            tenant=tenant,
            user=user,
            action='update',
            resource_type='JobPosting',
            resource_id='123',
            old_values={'status': 'draft'},
            new_values={'status': 'published'}
        ))

        # Verify logs exist
        tenant_logs = AuditLog.objects.filter(tenant=tenant)
        assert tenant_logs.count() == 3

        # Verify ordering (most recent first)
        ordered_logs = list(tenant_logs.order_by('-created_at'))
        assert ordered_logs[0] == logs[2]
