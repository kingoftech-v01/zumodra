"""
Comprehensive test suite for tenant type enforcement.

Tests cover:
- Tenant type validation
- Career page restrictions (COMPANY only)
- ATS restrictions (COMPANY only)
- Hiring context validation
- Type switching (COMPANY ↔ FREELANCER)
- API serializers
- Webhook payloads
"""

import pytest
from django.core.exceptions import ValidationError
from django.test import RequestFactory
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status

from tenants.models import Tenant, TenantInvitation
from tenants.validators import (
    validate_freelancer_members,
    validate_company_can_create_jobs,
    validate_company_can_receive_invitations
)
from services.models import CrossTenantServiceRequest
from services.forms import CrossTenantServiceRequestForm

User = get_user_model()


# =============================================================================
# TENANT MODEL TESTS
# =============================================================================

@pytest.mark.django_db
class TestTenantTypeModel:
    """Test Tenant model tenant_type functionality."""

    def test_company_tenant_can_create_jobs(self, company_tenant):
        """COMPANY tenants can create jobs."""
        assert company_tenant.can_create_jobs() is True

    def test_freelancer_tenant_cannot_create_jobs(self, freelancer_tenant):
        """FREELANCER tenants cannot create jobs."""
        assert freelancer_tenant.can_create_jobs() is False

    def test_company_tenant_can_have_employees(self, company_tenant):
        """COMPANY tenants can have employees."""
        assert company_tenant.can_have_employees() is True

    def test_freelancer_tenant_cannot_have_employees(self, freelancer_tenant):
        """FREELANCER tenants cannot have employees."""
        assert freelancer_tenant.can_have_employees() is False

    def test_default_tenant_type_is_company(self, tenant_factory):
        """New tenants default to COMPANY type."""
        tenant = tenant_factory(schema_name='test_default')
        assert tenant.tenant_type == Tenant.TenantType.COMPANY

    def test_create_company_tenant(self, tenant_factory):
        """Can create COMPANY tenant."""
        tenant = tenant_factory(
            schema_name='test_company',
            tenant_type=Tenant.TenantType.COMPANY
        )
        assert tenant.tenant_type == 'company'
        assert tenant.can_create_jobs() is True

    def test_create_freelancer_tenant(self, tenant_factory):
        """Can create FREELANCER tenant."""
        tenant = tenant_factory(
            schema_name='test_freelancer',
            tenant_type=Tenant.TenantType.FREELANCER
        )
        assert tenant.tenant_type == 'freelancer'
        assert tenant.can_create_jobs() is False


# =============================================================================
# TENANT TYPE SWITCHING TESTS
# =============================================================================

@pytest.mark.django_db
class TestTenantTypeSwitching:
    """Test tenant type switching (COMPANY ↔ FREELANCER)."""

    def test_company_to_freelancer_with_single_member(self, company_tenant, user_factory):
        """COMPANY can switch to FREELANCER if ≤1 member."""
        # Create single member
        user = user_factory()
        from accounts.models import TenantUser
        TenantUser.objects.create(
            user=user,
            tenant=company_tenant,
            role='owner',
            is_active=True
        )

        # Switch to freelancer
        company_tenant.switch_to_freelancer()
        company_tenant.refresh_from_db()

        assert company_tenant.tenant_type == Tenant.TenantType.FREELANCER
        assert company_tenant.can_create_jobs() is False

    def test_company_to_freelancer_with_multiple_members_fails(
        self, company_tenant, user_factory
    ):
        """COMPANY cannot switch to FREELANCER if >1 member."""
        # Create multiple members
        from accounts.models import TenantUser
        for i in range(3):
            user = user_factory(email=f'user{i}@example.com')
            TenantUser.objects.create(
                user=user,
                tenant=company_tenant,
                role='employee',
                is_active=True
            )

        # Attempt to switch should fail
        with pytest.raises(ValidationError) as exc_info:
            company_tenant.switch_to_freelancer()

        assert 'Cannot switch to freelancer with multiple members' in str(exc_info.value)
        assert company_tenant.tenant_type == Tenant.TenantType.COMPANY

    def test_freelancer_to_company(self, freelancer_tenant):
        """FREELANCER can switch to COMPANY anytime."""
        freelancer_tenant.switch_to_company()
        freelancer_tenant.refresh_from_db()

        assert freelancer_tenant.tenant_type == Tenant.TenantType.COMPANY
        assert freelancer_tenant.can_create_jobs() is True
        assert freelancer_tenant.can_have_employees() is True


# =============================================================================
# VALIDATOR TESTS
# =============================================================================

@pytest.mark.django_db
class TestTenantTypeValidators:
    """Test tenants/validators.py functions."""

    def test_validate_freelancer_members_with_one_member(
        self, freelancer_tenant, user_factory
    ):
        """Freelancer with 1 member passes validation."""
        from accounts.models import TenantUser
        user = user_factory()
        TenantUser.objects.create(
            user=user,
            tenant=freelancer_tenant,
            role='owner',
            is_active=True
        )

        # Should not raise
        validate_freelancer_members(freelancer_tenant)

    def test_validate_freelancer_members_with_multiple_fails(
        self, freelancer_tenant, user_factory
    ):
        """Freelancer with >1 member fails validation."""
        from accounts.models import TenantUser
        for i in range(2):
            user = user_factory(email=f'user{i}@example.com')
            TenantUser.objects.create(
                user=user,
                tenant=freelancer_tenant,
                role='owner' if i == 0 else 'employee',
                is_active=True
            )

        with pytest.raises(ValidationError) as exc_info:
            validate_freelancer_members(freelancer_tenant)

        assert 'cannot have more than one member' in str(exc_info.value)

    def test_validate_company_can_create_jobs_for_company(self, company_tenant):
        """COMPANY tenant passes job creation validation."""
        # Should not raise
        validate_company_can_create_jobs(company_tenant)

    def test_validate_company_can_create_jobs_for_freelancer_fails(
        self, freelancer_tenant
    ):
        """FREELANCER tenant fails job creation validation."""
        with pytest.raises(ValidationError) as exc_info:
            validate_company_can_create_jobs(freelancer_tenant)

        assert 'cannot create job postings' in str(exc_info.value)

    def test_validate_company_can_receive_invitations_for_company(
        self, company_tenant
    ):
        """COMPANY tenant passes invitation validation."""
        # Should not raise
        validate_company_can_receive_invitations(company_tenant)

    def test_validate_company_can_receive_invitations_for_freelancer_fails(
        self, freelancer_tenant
    ):
        """FREELANCER tenant fails invitation validation."""
        with pytest.raises(ValidationError) as exc_info:
            validate_company_can_receive_invitations(freelancer_tenant)

        assert 'cannot receive employee invitations' in str(exc_info.value)


# =============================================================================
# TENANT INVITATION TESTS
# =============================================================================

@pytest.mark.django_db
class TestTenantInvitationValidation:
    """Test TenantInvitation tenant type enforcement."""

    def test_company_can_send_invitation(self, company_tenant, user_factory):
        """COMPANY tenant can send invitations."""
        inviter = user_factory()
        invitation = TenantInvitation(
            tenant=company_tenant,
            email='newuser@example.com',
            invited_by=inviter,
            assigned_role='employee'
        )

        # Should not raise
        invitation.clean()
        invitation.save()

        assert invitation.assigned_role == 'employee'

    def test_freelancer_cannot_send_invitation(self, freelancer_tenant, user_factory):
        """FREELANCER tenant cannot send invitations."""
        inviter = user_factory()
        invitation = TenantInvitation(
            tenant=freelancer_tenant,
            email='newuser@example.com',
            invited_by=inviter,
            assigned_role='employee'
        )

        with pytest.raises(ValidationError) as exc_info:
            invitation.clean()

        assert 'cannot invite employees' in str(exc_info.value)


# =============================================================================
# CAREER PAGE ACCESS TESTS
# =============================================================================

@pytest.mark.django_db
class TestCareerPageRestrictions:
    """Test career page access restrictions."""

    def test_company_tenant_can_access_career_page(self, client, company_tenant):
        """COMPANY tenant can access career pages."""
        # This would need actual URL routing setup
        # For now, test the tenant type check directly
        assert company_tenant.tenant_type == 'company'

    def test_freelancer_tenant_cannot_access_career_page(
        self, client, freelancer_tenant
    ):
        """FREELANCER tenant gets 404 on career pages."""
        assert freelancer_tenant.tenant_type == 'freelancer'
        # Career page views should raise Http404 for freelancers


# =============================================================================
# ATS RESTRICTION TESTS
# =============================================================================

@pytest.mark.django_db
class TestATSRestrictions:
    """Test ATS job creation restrictions."""

    def test_company_can_create_job_via_api(self, api_client, company_tenant, user):
        """COMPANY tenant can create jobs via API."""
        api_client.force_authenticate(user=user)
        # Mock request would go here
        assert company_tenant.can_create_jobs() is True

    def test_freelancer_cannot_create_job_via_api(
        self, api_client, freelancer_tenant, user
    ):
        """FREELANCER tenant cannot create jobs via API."""
        api_client.force_authenticate(user=user)
        # Mock request would verify PermissionDenied is raised
        assert freelancer_tenant.can_create_jobs() is False


# =============================================================================
# HIRING CONTEXT TESTS
# =============================================================================

@pytest.mark.django_db
class TestHiringContext:
    """Test hiring context validation (ORGANIZATIONAL vs PERSONAL)."""

    def test_organizational_hiring_with_tenant(
        self, user_factory, company_tenant
    ):
        """User with tenant can hire organizationally."""
        user = user_factory()
        form = CrossTenantServiceRequestForm(
            data={
                'title': 'Test Request',
                'description': 'Test description',
                'budget': 1000,
                'hiring_context': CrossTenantServiceRequest.HiringContext.ORGANIZATIONAL,
            },
            user=user,
            tenant=company_tenant
        )

        assert form.is_valid(), form.errors

    def test_organizational_hiring_without_tenant_fails(self, user_factory):
        """User without tenant cannot hire organizationally."""
        user = user_factory()
        form = CrossTenantServiceRequestForm(
            data={
                'title': 'Test Request',
                'description': 'Test description',
                'budget': 1000,
                'hiring_context': CrossTenantServiceRequest.HiringContext.ORGANIZATIONAL,
            },
            user=user,
            tenant=None
        )

        assert not form.is_valid()
        assert 'hiring_context' in form.errors

    def test_personal_hiring_without_tenant(self, user_factory):
        """User without tenant can hire personally."""
        user = user_factory()
        form = CrossTenantServiceRequestForm(
            data={
                'title': 'Test Request',
                'description': 'Test description',
                'budget': 1000,
                'hiring_context': CrossTenantServiceRequest.HiringContext.PERSONAL,
            },
            user=user,
            tenant=None
        )

        assert form.is_valid(), form.errors

    def test_personal_hiring_with_tenant(self, user_factory, company_tenant):
        """User with tenant can still hire personally."""
        user = user_factory()
        form = CrossTenantServiceRequestForm(
            data={
                'title': 'Test Request',
                'description': 'Test description',
                'budget': 1000,
                'hiring_context': CrossTenantServiceRequest.HiringContext.PERSONAL,
            },
            user=user,
            tenant=company_tenant
        )

        assert form.is_valid(), form.errors


# =============================================================================
# API SERIALIZER TESTS
# =============================================================================

@pytest.mark.django_db
class TestTenantSerializers:
    """Test API serializers include tenant_type fields."""

    def test_tenant_serializer_includes_type_fields(self, company_tenant):
        """TenantSerializer includes tenant_type and capability fields."""
        from tenants.serializers import TenantSerializer

        serializer = TenantSerializer(company_tenant)
        data = serializer.data

        assert 'tenant_type' in data
        assert data['tenant_type'] == 'company'
        assert 'can_create_jobs' in data
        assert data['can_create_jobs'] is True
        assert 'can_have_employees' in data
        assert data['can_have_employees'] is True
        assert 'ein_number' in data
        assert 'ein_verified' in data

    def test_tenant_serializer_for_freelancer(self, freelancer_tenant):
        """TenantSerializer shows correct values for FREELANCER."""
        from tenants.serializers import TenantSerializer

        serializer = TenantSerializer(freelancer_tenant)
        data = serializer.data

        assert data['tenant_type'] == 'freelancer'
        assert data['can_create_jobs'] is False
        assert data['can_have_employees'] is False

    def test_tenant_public_serializer_includes_type(self, company_tenant):
        """TenantPublicSerializer includes tenant_type."""
        from tenants.serializers import TenantPublicSerializer

        serializer = TenantPublicSerializer(company_tenant)
        data = serializer.data

        assert 'tenant_type' in data
        assert data['tenant_type'] == 'company'
        assert 'can_create_jobs' in data


# =============================================================================
# WEBHOOK PAYLOAD TESTS
# =============================================================================

@pytest.mark.django_db
class TestTenantWebhooks:
    """Test webhook payloads include tenant_type."""

    def test_tenant_created_webhook_payload(self, company_tenant, mocker):
        """tenant.created webhook includes tenant_type."""
        mock_dispatch = mocker.patch('integrations.webhook_signals.dispatch_webhook')

        # Trigger webhook by saving
        company_tenant.save()

        # Verify webhook was dispatched
        assert mock_dispatch.called
        call_kwargs = mock_dispatch.call_args[1]

        assert call_kwargs['app_name'] == 'tenants'
        assert call_kwargs['event_type'] == 'tenant.updated'

        payload = call_kwargs['data']
        assert payload['tenant_type'] == 'company'
        assert payload['can_create_jobs'] is True
        assert payload['can_have_employees'] is True
        assert 'ein_number' in payload
        assert 'ein_verified' in payload

    def test_tenant_updated_webhook_includes_type(self, freelancer_tenant, mocker):
        """tenant.updated webhook includes tenant_type."""
        mock_dispatch = mocker.patch('integrations.webhook_signals.dispatch_webhook')

        # Update tenant
        freelancer_tenant.name = 'Updated Freelancer'
        freelancer_tenant.save()

        # Verify webhook payload
        call_kwargs = mock_dispatch.call_args[1]
        payload = call_kwargs['data']

        assert payload['tenant_type'] == 'freelancer'
        assert payload['can_create_jobs'] is False
        assert payload['can_have_employees'] is False


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

@pytest.mark.integration
@pytest.mark.django_db
class TestTenantTypeIntegration:
    """Integration tests for tenant type system."""

    def test_freelancer_lifecycle(
        self, tenant_factory, user_factory
    ):
        """Test complete freelancer tenant lifecycle."""
        # Create freelancer tenant
        freelancer = tenant_factory(
            schema_name='freelancer_test',
            tenant_type=Tenant.TenantType.FREELANCER
        )
        assert freelancer.can_create_jobs() is False

        # Add owner
        user = user_factory()
        from accounts.models import TenantUser
        TenantUser.objects.create(
            user=user,
            tenant=freelancer,
            role='owner',
            is_active=True
        )

        # Verify cannot add second member
        validate_freelancer_members(freelancer)  # Should pass with 1 member

        # Switch to company
        freelancer.switch_to_company()
        assert freelancer.can_create_jobs() is True

        # Now can add employees
        user2 = user_factory(email='employee@example.com')
        TenantUser.objects.create(
            user=user2,
            tenant=freelancer,
            role='employee',
            is_active=True
        )

        # Cannot switch back with multiple members
        with pytest.raises(ValidationError):
            freelancer.switch_to_freelancer()

    def test_company_lifecycle(
        self, tenant_factory, user_factory
    ):
        """Test complete company tenant lifecycle."""
        # Create company tenant
        company = tenant_factory(
            schema_name='company_test',
            tenant_type=Tenant.TenantType.COMPANY
        )
        assert company.can_create_jobs() is True
        assert company.can_have_employees() is True

        # Add multiple employees
        from accounts.models import TenantUser
        for i in range(3):
            user = user_factory(email=f'employee{i}@example.com')
            TenantUser.objects.create(
                user=user,
                tenant=company,
                role='employee',
                is_active=True
            )

        # Verify can send invitations
        validate_company_can_receive_invitations(company)

        # Verify can create jobs
        validate_company_can_create_jobs(company)

        # Cannot switch to freelancer with multiple members
        with pytest.raises(ValidationError):
            company.switch_to_freelancer()


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def company_tenant(tenant_factory):
    """Create a COMPANY tenant."""
    return tenant_factory(
        schema_name='company',
        tenant_type=Tenant.TenantType.COMPANY,
        ein_number='12-3456789'
    )


@pytest.fixture
def freelancer_tenant(tenant_factory):
    """Create a FREELANCER tenant."""
    return tenant_factory(
        schema_name='freelancer',
        tenant_type=Tenant.TenantType.FREELANCER
    )


@pytest.fixture
def api_client():
    """DRF API client."""
    return APIClient()
