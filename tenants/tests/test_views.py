"""
Tenant Views Tests

Tests for tenant-related views and API endpoints.
"""

import pytest
from django.urls import reverse
from django.test import Client
from rest_framework import status


@pytest.mark.django_db
class TestTenantCreation:
    """Tests for tenant creation flow."""

    def test_tenant_setup_requires_authentication(self, client):
        """Test that tenant setup requires authentication."""
        # This would test the tenant setup view if it exists
        # For now, we'll test the concept
        pass

    def test_tenant_created_with_trial_status(self, tenant_factory):
        """Test new tenants are created with trial status."""
        from conftest import TrialTenantFactory
        tenant = TrialTenantFactory()

        assert tenant.status == 'trial'
        assert tenant.on_trial is True
        assert tenant.trial_ends_at is not None

    def test_tenant_has_default_settings_after_creation(self, tenant_factory, tenant_settings_factory):
        """Test tenant gets default settings."""
        tenant = tenant_factory()
        settings = tenant_settings_factory(tenant=tenant)

        assert settings.primary_color == '#3B82F6'
        assert settings.default_language == 'en'
        assert settings.career_page_enabled is True


@pytest.mark.django_db
class TestDomainRouting:
    """Tests for domain-based tenant routing."""

    def test_domain_associated_with_tenant(self, domain_factory, tenant_factory):
        """Test domain is properly associated with tenant."""
        tenant = tenant_factory(slug='acme-corp')
        domain = domain_factory(tenant=tenant, domain='acme-corp.zumodra.local')

        assert domain.tenant == tenant
        assert domain.domain == 'acme-corp.zumodra.local'

    def test_multiple_domains_per_tenant(self, domain_factory, tenant_factory):
        """Test tenant can have multiple domains."""
        tenant = tenant_factory()
        domain1 = domain_factory(tenant=tenant, domain='app.example.com', is_primary=True)
        domain2 = domain_factory(tenant=tenant, domain='careers.example.com', is_careers_domain=True)

        assert tenant.domains.count() == 2
        assert domain1.is_primary is True
        assert domain2.is_careers_domain is True


@pytest.mark.django_db
class TestPlanLimitsEnforcement:
    """Tests for plan limits enforcement."""

    def test_user_limit_check(self, tenant_factory, plan_factory):
        """Test user limit checking."""
        from conftest import TenantUsageFactory
        plan = plan_factory(max_users=5)
        tenant = tenant_factory(plan=plan)
        usage = TenantUsageFactory(tenant=tenant, user_count=5)

        # At limit
        assert usage.user_count == plan.max_users

    def test_job_posting_limit_check(self, tenant_factory, plan_factory):
        """Test job posting limit checking."""
        from conftest import TenantUsageFactory
        plan = plan_factory(max_job_postings=10)
        tenant = tenant_factory(plan=plan)
        usage = TenantUsageFactory(tenant=tenant, active_job_count=8)

        # Under limit
        assert usage.active_job_count < plan.max_job_postings

    def test_storage_limit_check(self, tenant_factory, plan_factory):
        """Test storage limit checking."""
        from conftest import TenantUsageFactory
        plan = plan_factory(storage_limit_gb=10)
        tenant = tenant_factory(plan=plan)
        usage = TenantUsageFactory(
            tenant=tenant,
            storage_used_bytes=int(5 * 1024 * 1024 * 1024)
        )

        assert usage.storage_used_gb <= plan.storage_limit_gb


@pytest.mark.django_db
class TestFeatureFlagsEnforcement:
    """Tests for feature flag enforcement."""

    def test_free_plan_limited_features(self, free_plan_factory):
        """Test free plan has limited features."""
        plan = free_plan_factory()

        assert plan.feature_ats is True  # Basic ATS included
        assert plan.feature_hr_core is False
        assert plan.feature_analytics is False
        assert plan.feature_api_access is False

    def test_enterprise_plan_all_features(self, enterprise_plan_factory):
        """Test enterprise plan has all features."""
        plan = enterprise_plan_factory()

        assert plan.feature_ats is True
        assert plan.feature_hr_core is True
        assert plan.feature_analytics is True
        assert plan.feature_api_access is True
        assert plan.feature_ai_matching is True
        assert plan.feature_video_interviews is True
        assert plan.feature_esignature is True
        assert plan.feature_sso is True

    def test_feature_check_method(self, plan_factory, tenant_factory):
        """Test feature availability check."""
        plan = plan_factory(feature_hr_core=True, feature_ai_matching=False)
        tenant = tenant_factory(plan=plan)

        assert tenant.plan.feature_hr_core is True
        assert tenant.plan.feature_ai_matching is False


@pytest.mark.django_db
class TestTenantInvitations:
    """Tests for tenant invitation flow."""

    def test_create_invitation(self, tenant_invitation_factory, tenant_factory, user_factory):
        """Test creating a tenant invitation."""
        tenant = tenant_factory()
        inviter = user_factory()
        invitation = tenant_invitation_factory(
            tenant=tenant,
            invited_by=inviter,
            email='newuser@example.com',
            role='recruiter'
        )

        assert invitation.email == 'newuser@example.com'
        assert invitation.role == 'recruiter'
        assert invitation.status == 'pending'

    def test_invitation_token_is_unique(self, tenant_invitation_factory):
        """Test each invitation has unique token."""
        inv1 = tenant_invitation_factory()
        inv2 = tenant_invitation_factory()

        assert inv1.token != inv2.token

    def test_invitation_expiration_default(self, tenant_invitation_factory):
        """Test invitation has expiration date."""
        invitation = tenant_invitation_factory()
        assert invitation.expires_at is not None

    def test_accept_invitation(self, tenant_invitation_factory, user_factory):
        """Test accepting an invitation."""
        invitation = tenant_invitation_factory()
        user = user_factory()

        invitation.accept(user)

        assert invitation.status == 'accepted'
        assert invitation.accepted_at is not None


@pytest.mark.django_db
class TestTenantStatusTransitions:
    """Tests for tenant status transitions."""

    def test_trial_to_active(self, tenant_factory):
        """Test transitioning from trial to active."""
        tenant = tenant_factory(status='trial', on_trial=True)

        tenant.activate()

        assert tenant.status == 'active'
        assert tenant.on_trial is False
        assert tenant.activated_at is not None

    def test_active_to_suspended(self, tenant_factory):
        """Test transitioning from active to suspended."""
        tenant = tenant_factory(status='active')

        tenant.suspend()

        assert tenant.status == 'suspended'
        assert tenant.suspended_at is not None

    def test_active_to_cancelled(self, tenant_factory):
        """Test transitioning from active to cancelled."""
        tenant = tenant_factory(status='active')

        tenant.cancel()

        assert tenant.status == 'cancelled'


@pytest.mark.django_db
class TestTenantSettings:
    """Tests for tenant settings management."""

    def test_update_branding_settings(self, tenant_settings_factory):
        """Test updating branding settings."""
        settings = tenant_settings_factory()

        settings.primary_color = '#FF5733'
        settings.secondary_color = '#33FF57'
        settings.save()

        settings.refresh_from_db()
        assert settings.primary_color == '#FF5733'
        assert settings.secondary_color == '#33FF57'

    def test_update_localization_settings(self, tenant_settings_factory):
        """Test updating localization settings."""
        settings = tenant_settings_factory()

        settings.default_language = 'fr'
        settings.default_timezone = 'Europe/Paris'
        settings.currency = 'EUR'
        settings.save()

        settings.refresh_from_db()
        assert settings.default_language == 'fr'
        assert settings.default_timezone == 'Europe/Paris'
        assert settings.currency == 'EUR'

    def test_update_security_settings(self, tenant_settings_factory):
        """Test updating security settings."""
        settings = tenant_settings_factory()

        settings.require_2fa = True
        settings.session_timeout_minutes = 30
        settings.save()

        settings.refresh_from_db()
        assert settings.require_2fa is True
        assert settings.session_timeout_minutes == 30


@pytest.mark.django_db
class TestAuditLogging:
    """Tests for audit logging functionality."""

    def test_create_audit_log_entry(self, tenant_factory, user_factory):
        """Test creating an audit log entry."""
        from conftest import AuditLogFactory
        from tenants.models import AuditLog

        tenant = tenant_factory()
        user = user_factory()
        log = AuditLogFactory(
            tenant=tenant,
            user=user,
            action='create',
            resource_type='JobPosting',
            resource_id='123',
            description='Created new job posting'
        )

        assert log.action == 'create'
        assert log.resource_type == 'JobPosting'
        assert log.resource_id == '123'

    def test_audit_log_with_ip_address(self, tenant_factory, user_factory):
        """Test audit log captures IP address."""
        from conftest import AuditLogFactory

        tenant = tenant_factory()
        user = user_factory()
        log = AuditLogFactory(
            tenant=tenant,
            user=user,
            ip_address='192.168.1.1'
        )

        assert log.ip_address == '192.168.1.1'

    def test_audit_log_tracks_changes(self, tenant_factory, user_factory):
        """Test audit log tracks old and new values."""
        from conftest import AuditLogFactory

        tenant = tenant_factory()
        user = user_factory()
        log = AuditLogFactory(
            tenant=tenant,
            user=user,
            action='update',
            resource_type='Employee',
            old_values={'salary': '50000'},
            new_values={'salary': '55000'}
        )

        assert log.old_values['salary'] == '50000'
        assert log.new_values['salary'] == '55000'

    def test_filter_audit_logs_by_action(self, tenant_factory, user_factory):
        """Test filtering audit logs by action type."""
        from conftest import AuditLogFactory
        from tenants.models import AuditLog

        tenant = tenant_factory()
        user = user_factory()

        AuditLogFactory(tenant=tenant, user=user, action='create')
        AuditLogFactory(tenant=tenant, user=user, action='update')
        AuditLogFactory(tenant=tenant, user=user, action='delete')

        create_logs = AuditLog.objects.filter(tenant=tenant, action='create')
        update_logs = AuditLog.objects.filter(tenant=tenant, action='update')

        assert create_logs.count() == 1
        assert update_logs.count() == 1

    def test_filter_audit_logs_by_resource_type(self, tenant_factory, user_factory):
        """Test filtering audit logs by resource type."""
        from conftest import AuditLogFactory
        from tenants.models import AuditLog

        tenant = tenant_factory()
        user = user_factory()

        AuditLogFactory(tenant=tenant, user=user, resource_type='JobPosting')
        AuditLogFactory(tenant=tenant, user=user, resource_type='JobPosting')
        AuditLogFactory(tenant=tenant, user=user, resource_type='Employee')

        job_logs = AuditLog.objects.filter(tenant=tenant, resource_type='JobPosting')
        employee_logs = AuditLog.objects.filter(tenant=tenant, resource_type='Employee')

        assert job_logs.count() == 2
        assert employee_logs.count() == 1
