"""
Tenant Models Tests

Tests for:
- Plan model and feature flags
- Tenant model CRUD and status management
- TenantSettings model
- Domain model
- TenantInvitation model
- TenantUsage tracking
- AuditLog functionality
"""

import pytest
from decimal import Decimal
from datetime import timedelta
from django.utils import timezone
from django.db import IntegrityError
from django.core.exceptions import ValidationError

from tenants.models import (
    Plan, Tenant, TenantSettings, Domain,
    TenantInvitation, TenantUsage, AuditLog
)


# ============================================================================
# PLAN MODEL TESTS
# ============================================================================

@pytest.mark.django_db
class TestPlanModel:
    """Tests for the Plan model."""

    def test_create_plan(self, plan_factory):
        """Test basic plan creation."""
        plan = plan_factory()
        assert plan.pk is not None
        assert plan.name is not None
        assert plan.slug is not None
        assert plan.is_active is True

    def test_plan_types(self, plan_factory):
        """Test different plan types."""
        for plan_type, label in Plan.PlanType.choices:
            plan = plan_factory(plan_type=plan_type)
            assert plan.plan_type == plan_type
            assert plan.get_plan_type_display() == label

    def test_free_plan_defaults(self, free_plan_factory):
        """Test free plan has correct defaults."""
        plan = free_plan_factory()
        assert plan.plan_type == 'free'
        assert plan.price_monthly == Decimal('0.00')
        assert plan.price_yearly == Decimal('0.00')
        assert plan.max_users == 2
        assert plan.feature_hr_core is False
        assert plan.feature_analytics is False

    def test_enterprise_plan_features(self, enterprise_plan_factory):
        """Test enterprise plan has all features enabled."""
        plan = enterprise_plan_factory()
        assert plan.plan_type == 'enterprise'
        assert plan.feature_ai_matching is True
        assert plan.feature_video_interviews is True
        assert plan.feature_esignature is True
        assert plan.feature_sso is True
        assert plan.feature_custom_branding is True
        assert plan.feature_priority_support is True

    def test_plan_string_representation(self, plan_factory):
        """Test plan string representation."""
        plan = plan_factory(name='Professional', plan_type='professional')
        assert str(plan) == 'Professional (Professional)'

    def test_get_features_list(self, plan_factory):
        """Test getting list of enabled features."""
        plan = plan_factory(
            feature_ats=True,
            feature_hr_core=True,
            feature_analytics=False
        )
        features = plan.get_features_list()
        assert isinstance(features, list)
        # ATS and HR Core should be in the list, Analytics should not
        assert any('ATS' in f.upper() or 'APPLICANT' in f.upper() for f in features)

    def test_plan_unique_slug(self, plan_factory):
        """Test that plan slug must be unique."""
        plan_factory(slug='unique-plan')
        with pytest.raises(IntegrityError):
            plan_factory(slug='unique-plan')

    def test_plan_ordering(self, plan_factory):
        """Test plan ordering by sort_order and price."""
        plan3 = plan_factory(sort_order=3, price_monthly=Decimal('99.99'))
        plan1 = plan_factory(sort_order=1, price_monthly=Decimal('29.99'))
        plan2 = plan_factory(sort_order=2, price_monthly=Decimal('59.99'))

        plans = list(Plan.objects.all())
        assert plans[0].sort_order <= plans[1].sort_order


# ============================================================================
# TENANT MODEL TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantModel:
    """Tests for the Tenant model."""

    def test_create_tenant(self, tenant_factory):
        """Test basic tenant creation."""
        tenant = tenant_factory()
        assert tenant.pk is not None
        assert tenant.uuid is not None
        assert tenant.name is not None
        assert tenant.slug is not None

    def test_tenant_statuses(self, tenant_factory):
        """Test different tenant statuses."""
        for status, label in Tenant.TenantStatus.choices:
            tenant = tenant_factory(status=status)
            assert tenant.status == status
            assert tenant.get_status_display() == label

    def test_tenant_is_active_property(self, tenant_factory):
        """Test is_active property."""
        active_tenant = tenant_factory(status='active')
        trial_tenant = tenant_factory(status='trial')
        suspended_tenant = tenant_factory(status='suspended')

        assert active_tenant.is_active is True
        assert trial_tenant.is_active is False
        assert suspended_tenant.is_active is False

    def test_tenant_trial_status(self, tenant_factory):
        """Test trial status properties."""
        tenant = tenant_factory(
            on_trial=True,
            trial_ends_at=timezone.now() + timedelta(days=7)
        )
        assert tenant.is_on_trial is True
        assert tenant.trial_days_remaining > 0
        assert tenant.trial_days_remaining <= 7

    def test_tenant_trial_expired(self, tenant_factory):
        """Test expired trial detection."""
        tenant = tenant_factory(
            on_trial=True,
            trial_ends_at=timezone.now() - timedelta(days=1)
        )
        assert tenant.is_on_trial is False
        assert tenant.trial_days_remaining == 0

    def test_tenant_activate(self, tenant_factory):
        """Test tenant activation."""
        tenant = tenant_factory(status='trial', on_trial=True)
        tenant.activate()

        assert tenant.status == 'active'
        assert tenant.on_trial is False
        assert tenant.activated_at is not None

    def test_tenant_suspend(self, tenant_factory):
        """Test tenant suspension."""
        tenant = tenant_factory(status='active')
        tenant.suspend(reason='Payment failure')

        assert tenant.status == 'suspended'
        assert tenant.suspended_at is not None

    def test_tenant_cancel(self, tenant_factory):
        """Test tenant cancellation."""
        tenant = tenant_factory(status='active')
        tenant.cancel()

        assert tenant.status == 'cancelled'

    def test_tenant_string_representation(self, tenant_factory):
        """Test tenant string representation."""
        tenant = tenant_factory(name='Acme Corp')
        assert str(tenant) == 'Acme Corp'

    def test_tenant_unique_slug(self, tenant_factory):
        """Test that tenant slug must be unique."""
        tenant_factory(slug='acme-corp')
        with pytest.raises(IntegrityError):
            tenant_factory(slug='acme-corp')

    def test_tenant_with_plan(self, tenant_factory, enterprise_plan_factory):
        """Test tenant with associated plan."""
        plan = enterprise_plan_factory()
        tenant = tenant_factory(plan=plan)

        assert tenant.plan == plan
        assert tenant.plan.plan_type == 'enterprise'

    def test_tenant_company_sizes(self, tenant_factory):
        """Test different company size options."""
        sizes = ['1-10', '11-50', '51-200', '201-500', '501-1000', '1000+']
        for size in sizes:
            tenant = tenant_factory(company_size=size)
            assert tenant.company_size == size


# ============================================================================
# TENANT SETTINGS TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantSettingsModel:
    """Tests for the TenantSettings model."""

    def test_create_tenant_settings(self, tenant_settings_factory):
        """Test basic tenant settings creation."""
        settings = tenant_settings_factory()
        assert settings.pk is not None
        assert settings.tenant is not None

    def test_default_branding_colors(self, tenant_settings_factory):
        """Test default branding colors."""
        settings = tenant_settings_factory()
        assert settings.primary_color == '#3B82F6'
        assert settings.secondary_color == '#1E40AF'
        assert settings.accent_color == '#10B981'

    def test_localization_settings(self, tenant_settings_factory):
        """Test localization settings."""
        settings = tenant_settings_factory(
            default_language='fr',
            default_timezone='Europe/Paris',
            currency='EUR'
        )
        assert settings.default_language == 'fr'
        assert settings.default_timezone == 'Europe/Paris'
        assert settings.currency == 'EUR'

    def test_ats_settings(self, tenant_settings_factory):
        """Test ATS-specific settings."""
        settings = tenant_settings_factory(
            require_cover_letter=True,
            auto_reject_after_days=60,
            send_rejection_email=False
        )
        assert settings.require_cover_letter is True
        assert settings.auto_reject_after_days == 60
        assert settings.send_rejection_email is False

    def test_get_default_pipeline_stages(self, tenant_settings_factory):
        """Test getting default pipeline stages."""
        settings = tenant_settings_factory(default_pipeline_stages=[])
        stages = settings.get_default_pipeline_stages()

        assert isinstance(stages, list)
        assert len(stages) > 0
        assert 'New' in stages
        assert 'Hired' in stages
        assert 'Rejected' in stages

    def test_custom_pipeline_stages(self, tenant_settings_factory):
        """Test custom pipeline stages."""
        custom_stages = ['Applied', 'Phone Screen', 'Onsite', 'Decision']
        settings = tenant_settings_factory(default_pipeline_stages=custom_stages)

        assert settings.get_default_pipeline_stages() == custom_stages

    def test_security_settings(self, tenant_settings_factory):
        """Test security settings."""
        settings = tenant_settings_factory(
            require_2fa=True,
            session_timeout_minutes=60,
            password_expiry_days=90
        )
        assert settings.require_2fa is True
        assert settings.session_timeout_minutes == 60
        assert settings.password_expiry_days == 90

    def test_notification_settings(self, tenant_settings_factory):
        """Test notification settings."""
        settings = tenant_settings_factory(
            notify_new_application=False,
            daily_digest_enabled=True
        )
        assert settings.notify_new_application is False
        assert settings.daily_digest_enabled is True

    def test_settings_string_representation(self, tenant_settings_factory):
        """Test settings string representation."""
        settings = tenant_settings_factory()
        assert 'Settings for' in str(settings)


# ============================================================================
# DOMAIN MODEL TESTS
# ============================================================================

@pytest.mark.django_db
class TestDomainModel:
    """Tests for the Domain model."""

    def test_create_domain(self, domain_factory):
        """Test basic domain creation."""
        domain = domain_factory()
        assert domain.pk is not None
        assert domain.domain is not None
        assert domain.tenant is not None

    def test_primary_domain(self, domain_factory, tenant_factory):
        """Test primary domain flag."""
        tenant = tenant_factory()
        primary_domain = domain_factory(tenant=tenant, is_primary=True)

        assert primary_domain.is_primary is True

    def test_careers_domain(self, domain_factory, tenant_factory):
        """Test careers domain flag."""
        tenant = tenant_factory()
        careers_domain = domain_factory(
            tenant=tenant,
            domain=f'careers.{tenant.slug}.com',
            is_careers_domain=True
        )

        assert careers_domain.is_careers_domain is True

    def test_ssl_settings(self, domain_factory):
        """Test SSL settings."""
        domain = domain_factory(ssl_enabled=True)
        assert domain.ssl_enabled is True

    def test_domain_string_representation(self, domain_factory):
        """Test domain string representation."""
        domain = domain_factory()
        assert str(domain) == domain.domain


# ============================================================================
# TENANT INVITATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantInvitationModel:
    """Tests for the TenantInvitation model."""

    def test_create_invitation(self, tenant_invitation_factory):
        """Test basic invitation creation."""
        invitation = tenant_invitation_factory()
        assert invitation.pk is not None
        assert invitation.uuid is not None
        assert invitation.token is not None
        assert invitation.email is not None

    def test_invitation_statuses(self, tenant_invitation_factory):
        """Test invitation status choices."""
        for status, label in TenantInvitation.InvitationStatus.choices:
            invitation = tenant_invitation_factory(status=status)
            assert invitation.status == status

    def test_invitation_is_expired(self, tenant_invitation_factory):
        """Test invitation expiration detection."""
        # Not expired
        active_invitation = tenant_invitation_factory(
            expires_at=timezone.now() + timedelta(days=7)
        )
        assert active_invitation.is_expired is False

        # Expired
        expired_invitation = tenant_invitation_factory(
            expires_at=timezone.now() - timedelta(days=1)
        )
        assert expired_invitation.is_expired is True

    def test_invitation_accept(self, tenant_invitation_factory, user_factory):
        """Test accepting an invitation."""
        invitation = tenant_invitation_factory(status='pending')
        user = user_factory()

        invitation.accept(user)

        assert invitation.status == 'accepted'
        assert invitation.accepted_at is not None

    def test_invitation_string_representation(self, tenant_invitation_factory):
        """Test invitation string representation."""
        invitation = tenant_invitation_factory(email='test@example.com')
        assert 'test@example.com' in str(invitation)

    def test_invitation_unique_constraint(self, tenant_invitation_factory, tenant_factory):
        """Test unique constraint on tenant + email."""
        tenant = tenant_factory()
        tenant_invitation_factory(tenant=tenant, email='duplicate@example.com')

        with pytest.raises(IntegrityError):
            tenant_invitation_factory(tenant=tenant, email='duplicate@example.com')


# ============================================================================
# TENANT USAGE TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantUsageModel:
    """Tests for the TenantUsage model."""

    def test_create_usage(self, tenant_factory):
        """Test basic usage record creation."""
        from conftest import TenantUsageFactory
        tenant = tenant_factory()
        usage = TenantUsageFactory(tenant=tenant)

        assert usage.pk is not None
        assert usage.tenant == tenant

    def test_storage_used_gb_property(self, tenant_factory):
        """Test storage GB conversion property."""
        from conftest import TenantUsageFactory
        tenant = tenant_factory()
        # 2.5 GB in bytes
        usage = TenantUsageFactory(
            tenant=tenant,
            storage_used_bytes=int(2.5 * 1024 * 1024 * 1024)
        )

        assert usage.storage_used_gb == 2.5

    def test_is_within_limits_true(self, tenant_factory, plan_factory):
        """Test is_within_limits when within limits."""
        from conftest import TenantUsageFactory
        plan = plan_factory(
            max_users=10,
            max_job_postings=25,
            max_candidates_per_month=500,
            max_circusales=3,
            storage_limit_gb=10
        )
        tenant = tenant_factory(plan=plan)
        usage = TenantUsageFactory(
            tenant=tenant,
            user_count=5,
            active_job_count=10,
            candidate_count_this_month=200,
            circusale_count=2,
            storage_used_bytes=int(5 * 1024 * 1024 * 1024)
        )

        assert usage.is_within_limits() is True

    def test_is_within_limits_exceeded_users(self, tenant_factory, plan_factory):
        """Test is_within_limits when user limit exceeded."""
        from conftest import TenantUsageFactory
        plan = plan_factory(max_users=5)
        tenant = tenant_factory(plan=plan)
        usage = TenantUsageFactory(tenant=tenant, user_count=10)

        assert usage.is_within_limits() is False

    def test_is_within_limits_exceeded_storage(self, tenant_factory, plan_factory):
        """Test is_within_limits when storage limit exceeded."""
        from conftest import TenantUsageFactory
        plan = plan_factory(storage_limit_gb=5)
        tenant = tenant_factory(plan=plan)
        usage = TenantUsageFactory(
            tenant=tenant,
            storage_used_bytes=int(10 * 1024 * 1024 * 1024)
        )

        assert usage.is_within_limits() is False

    def test_is_within_limits_no_plan(self, tenant_factory):
        """Test is_within_limits when no plan assigned."""
        from conftest import TenantUsageFactory
        tenant = tenant_factory(plan=None)
        usage = TenantUsageFactory(tenant=tenant)

        assert usage.is_within_limits() is False


# ============================================================================
# AUDIT LOG TESTS
# ============================================================================

@pytest.mark.django_db
class TestAuditLogModel:
    """Tests for the AuditLog model."""

    def test_create_audit_log(self, tenant_factory, user_factory):
        """Test basic audit log creation."""
        from conftest import AuditLogFactory
        tenant = tenant_factory()
        user = user_factory()
        log = AuditLogFactory(tenant=tenant, user=user)

        assert log.pk is not None
        assert log.uuid is not None
        assert log.tenant == tenant
        assert log.user == user

    def test_audit_log_action_types(self, tenant_factory, user_factory):
        """Test different audit log action types."""
        from conftest import AuditLogFactory
        tenant = tenant_factory()
        user = user_factory()

        for action, label in AuditLog.ActionType.choices:
            log = AuditLogFactory(tenant=tenant, user=user, action=action)
            assert log.action == action

    def test_audit_log_with_values(self, tenant_factory, user_factory):
        """Test audit log with old and new values."""
        from conftest import AuditLogFactory
        tenant = tenant_factory()
        user = user_factory()
        log = AuditLogFactory(
            tenant=tenant,
            user=user,
            action='update',
            resource_type='JobPosting',
            old_values={'status': 'draft'},
            new_values={'status': 'open'}
        )

        assert log.old_values == {'status': 'draft'}
        assert log.new_values == {'status': 'open'}

    def test_audit_log_string_representation(self, tenant_factory, user_factory):
        """Test audit log string representation."""
        from conftest import AuditLogFactory
        tenant = tenant_factory()
        user = user_factory()
        log = AuditLogFactory(
            tenant=tenant,
            user=user,
            action='create',
            resource_type='JobPosting'
        )

        assert 'create' in str(log)
        assert 'JobPosting' in str(log)

    def test_audit_log_ordering(self, tenant_factory, user_factory):
        """Test audit logs are ordered by created_at descending."""
        from conftest import AuditLogFactory
        tenant = tenant_factory()
        user = user_factory()

        log1 = AuditLogFactory(tenant=tenant, user=user)
        log2 = AuditLogFactory(tenant=tenant, user=user)
        log3 = AuditLogFactory(tenant=tenant, user=user)

        logs = list(AuditLog.objects.filter(tenant=tenant))
        # Most recent should be first
        assert logs[0].pk == log3.pk


# ============================================================================
# TENANT ISOLATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantIsolation:
    """Tests for tenant data isolation."""

    def test_tenants_have_unique_schemas(self, tenant_factory):
        """Test that tenants have unique schema names."""
        tenant1 = tenant_factory(slug='company-one')
        tenant2 = tenant_factory(slug='company-two')

        assert tenant1.schema_name != tenant2.schema_name

    def test_audit_logs_scoped_to_tenant(self, tenant_factory, user_factory):
        """Test audit logs are scoped to their tenant."""
        from conftest import AuditLogFactory
        tenant1 = tenant_factory()
        tenant2 = tenant_factory()
        user = user_factory()

        AuditLogFactory(tenant=tenant1, user=user)
        AuditLogFactory(tenant=tenant1, user=user)
        AuditLogFactory(tenant=tenant2, user=user)

        tenant1_logs = AuditLog.objects.filter(tenant=tenant1)
        tenant2_logs = AuditLog.objects.filter(tenant=tenant2)

        assert tenant1_logs.count() == 2
        assert tenant2_logs.count() == 1

    def test_invitations_scoped_to_tenant(self, tenant_invitation_factory, tenant_factory):
        """Test invitations are scoped to their tenant."""
        tenant1 = tenant_factory()
        tenant2 = tenant_factory()

        tenant_invitation_factory(tenant=tenant1)
        tenant_invitation_factory(tenant=tenant1)
        tenant_invitation_factory(tenant=tenant2)

        tenant1_invitations = TenantInvitation.objects.filter(tenant=tenant1)
        tenant2_invitations = TenantInvitation.objects.filter(tenant=tenant2)

        assert tenant1_invitations.count() == 2
        assert tenant2_invitations.count() == 1
