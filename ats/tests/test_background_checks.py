"""
Comprehensive tests for Background Check feature.

Tests cover:
- Model creation and validation
- Service layer integration
- API endpoints
- Webhook processing
- Status transitions
- Consent tracking
"""

import pytest
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status

from ats.models import (
    BackgroundCheck,
    BackgroundCheckDocument,
    Application,
    Candidate,
    JobPosting,
)
from ats.background_checks import BackgroundCheckService
from tenants.models import Tenant

User = get_user_model()


@pytest.mark.django_db
class TestBackgroundCheckModel:
    """Test BackgroundCheck model."""

    def test_create_background_check(self, tenant, application, user):
        """Test creating a background check."""
        bg_check = BackgroundCheck.objects.create(
            tenant=tenant,
            application=application,
            provider='checkr',
            package='standard',
            external_candidate_id='cand_123',
            external_report_id='report_456',
            initiated_by=user,
            consent_given=True
        )

        assert bg_check.status == 'pending'
        assert bg_check.provider == 'checkr'
        assert bg_check.package == 'standard'
        assert bg_check.consent_given is True
        assert bg_check.result is None

    def test_background_check_str_representation(self, tenant, application, user):
        """Test string representation."""
        bg_check = BackgroundCheck.objects.create(
            tenant=tenant,
            application=application,
            provider='checkr',
            package='standard',
            external_candidate_id='cand_123',
            external_report_id='report_456',
            initiated_by=user
        )

        assert str(bg_check) == f"Background Check for {application.candidate} - checkr (pending)"

    def test_mark_completed_clear(self, tenant, application, user):
        """Test marking background check as completed with clear result."""
        bg_check = BackgroundCheck.objects.create(
            tenant=tenant,
            application=application,
            provider='checkr',
            package='standard',
            external_candidate_id='cand_123',
            external_report_id='report_456',
            initiated_by=user,
            status='in_progress'
        )

        report_data = {
            'status': 'complete',
            'result': 'clear',
            'screenings': []
        }

        bg_check.mark_completed(result='clear', report_data=report_data)

        assert bg_check.status == 'completed'
        assert bg_check.result == 'clear'
        assert bg_check.completed_at is not None
        assert bg_check.report_data == report_data
        assert bg_check.application.status == 'background_check_cleared'

    def test_mark_completed_consider(self, tenant, application, user):
        """Test marking background check as completed with consider result."""
        bg_check = BackgroundCheck.objects.create(
            tenant=tenant,
            application=application,
            provider='sterling',
            package='pro',
            external_candidate_id='cand_789',
            external_report_id='report_012',
            initiated_by=user,
            status='in_progress'
        )

        bg_check.mark_completed(result='consider')

        assert bg_check.status == 'completed'
        assert bg_check.result == 'consider'
        # Application status should remain for manual review
        assert bg_check.application.status == 'background_check_in_progress'

    def test_unique_constraint_one_check_per_application(self, tenant, application, user):
        """Test that only one background check can exist per application."""
        BackgroundCheck.objects.create(
            tenant=tenant,
            application=application,
            provider='checkr',
            package='standard',
            external_candidate_id='cand_1',
            external_report_id='report_1',
            initiated_by=user
        )

        with pytest.raises(Exception):  # IntegrityError or ValidationError
            BackgroundCheck.objects.create(
                tenant=tenant,
                application=application,
                provider='sterling',
                package='basic',
                external_candidate_id='cand_2',
                external_report_id='report_2',
                initiated_by=user
            )


@pytest.mark.django_db
class TestBackgroundCheckDocument:
    """Test BackgroundCheckDocument model."""

    def test_create_document(self, tenant, application, user):
        """Test creating a background check document."""
        bg_check = BackgroundCheck.objects.create(
            tenant=tenant,
            application=application,
            provider='checkr',
            package='comprehensive',
            external_candidate_id='cand_abc',
            external_report_id='report_def',
            initiated_by=user
        )

        document = BackgroundCheckDocument.objects.create(
            tenant=tenant,
            background_check=bg_check,
            document_type='criminal_search',
            status='completed',
            result='clear',
            findings_summary='No records found'
        )

        assert document.document_type == 'criminal_search'
        assert document.status == 'completed'
        assert document.result == 'clear'
        assert document.findings_summary == 'No records found'

    def test_document_str_representation(self, tenant, application, user):
        """Test document string representation."""
        bg_check = BackgroundCheck.objects.create(
            tenant=tenant,
            application=application,
            provider='checkr',
            package='standard',
            external_candidate_id='cand_xyz',
            external_report_id='report_uvw',
            initiated_by=user
        )

        document = BackgroundCheckDocument.objects.create(
            tenant=tenant,
            background_check=bg_check,
            document_type='employment_verification',
            status='in_progress'
        )

        assert 'employment_verification' in str(document).lower()
        assert 'in_progress' in str(document).lower()


@pytest.mark.django_db
class TestBackgroundCheckService:
    """Test BackgroundCheckService."""

    def test_initiate_check_success(self, tenant, application, user, mocker):
        """Test successfully initiating a background check."""
        # Mock provider API calls
        mock_create_candidate = mocker.patch(
            'ats.background_checks.CheckrProvider.create_candidate',
            return_value={'id': 'checkr_cand_123'}
        )
        mock_create_invitation = mocker.patch(
            'ats.background_checks.CheckrProvider.create_invitation',
            return_value={'id': 'checkr_inv_456', 'status': 'pending'}
        )
        mock_create_report = mocker.patch(
            'ats.background_checks.CheckrProvider.create_report',
            return_value={'id': 'checkr_report_789', 'status': 'pending'}
        )

        service = BackgroundCheckService(tenant=tenant)
        bg_check = service.initiate_check(
            application=application,
            package='standard',
            initiated_by=user
        )

        assert bg_check is not None
        assert bg_check.provider == 'checkr'  # Default provider
        assert bg_check.status in ['pending', 'invited']
        assert bg_check.application == application
        assert bg_check.initiated_by == user
        assert application.status == 'background_check_in_progress'

    def test_initiate_check_feature_not_enabled(self, tenant, application, user):
        """Test initiating check when feature is not enabled."""
        # Disable background checks for tenant
        tenant.plan.feature_background_checks = False
        tenant.plan.save()

        service = BackgroundCheckService(tenant=tenant)

        with pytest.raises(Exception):  # PermissionDenied
            service.initiate_check(
                application=application,
                package='standard',
                initiated_by=user
            )

    def test_get_report(self, tenant, application, user, mocker):
        """Test retrieving a background check report."""
        bg_check = BackgroundCheck.objects.create(
            tenant=tenant,
            application=application,
            provider='checkr',
            package='standard',
            external_candidate_id='cand_report',
            external_report_id='report_test',
            initiated_by=user,
            status='completed',
            result='clear',
            report_data={'test': 'data'}
        )

        mock_get_report = mocker.patch(
            'ats.background_checks.CheckrProvider.get_report',
            return_value={'status': 'complete', 'result': 'clear'}
        )

        service = BackgroundCheckService(tenant=tenant)
        report = service.get_report(bg_check.id)

        assert report is not None
        assert 'status' in report or 'test' in report

    def test_handle_webhook_result(self, tenant, application, user):
        """Test processing webhook result."""
        bg_check = BackgroundCheck.objects.create(
            tenant=tenant,
            application=application,
            provider='checkr',
            package='standard',
            external_candidate_id='cand_webhook',
            external_report_id='report_webhook',
            initiated_by=user,
            status='in_progress'
        )

        payload = {
            'id': 'report_webhook',
            'status': 'complete',
            'result': 'clear',
            'adjudication': 'clear'
        }

        service = BackgroundCheckService(tenant=tenant)
        service.handle_webhook_result(
            report_id='report_webhook',
            payload=payload,
            provider_name='checkr'
        )

        bg_check.refresh_from_db()
        assert bg_check.status == 'completed'
        assert bg_check.result == 'clear'
        assert bg_check.completed_at is not None


@pytest.mark.django_db
class TestBackgroundCheckAPI:
    """Test Background Check API endpoints."""

    def test_initiate_background_check_endpoint(self, api_client, tenant, application, user, mocker):
        """Test POST /api/v1/ats/applications/{uuid}/background-check/initiate/"""
        api_client.force_authenticate(user=user)

        # Mock provider
        mocker.patch('ats.background_checks.CheckrProvider.create_candidate', return_value={'id': 'cand_api'})
        mocker.patch('ats.background_checks.CheckrProvider.create_invitation', return_value={'id': 'inv_api'})
        mocker.patch('ats.background_checks.CheckrProvider.create_report', return_value={'id': 'report_api'})

        url = f'/api/v1/ats/applications/{application.uuid}/background-check/initiate/'
        data = {
            'package': 'standard',
            'consent_given': True
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_200_OK]
        assert 'provider' in response.data or 'id' in response.data

    def test_get_background_check_status(self, api_client, tenant, application, user):
        """Test GET /api/v1/ats/applications/{uuid}/background-check/status/"""
        api_client.force_authenticate(user=user)

        # Create background check
        bg_check = BackgroundCheck.objects.create(
            tenant=tenant,
            application=application,
            provider='checkr',
            package='standard',
            external_candidate_id='cand_status',
            external_report_id='report_status',
            initiated_by=user,
            status='in_progress'
        )

        url = f'/api/v1/ats/applications/{application.uuid}/background-check/status/'
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'in_progress'
        assert response.data['provider'] == 'checkr'

    def test_get_background_check_report(self, api_client, tenant, application, user, mocker):
        """Test GET /api/v1/ats/applications/{uuid}/background-check/report/"""
        api_client.force_authenticate(user=user)

        bg_check = BackgroundCheck.objects.create(
            tenant=tenant,
            application=application,
            provider='sterling',
            package='pro',
            external_candidate_id='cand_full',
            external_report_id='report_full',
            initiated_by=user,
            status='completed',
            result='clear',
            report_data={'full': 'report'}
        )

        mocker.patch(
            'ats.background_checks.BackgroundCheckService.get_report',
            return_value={'status': 'complete', 'full': 'report'}
        )

        url = f'/api/v1/ats/applications/{application.uuid}/background-check/report/'
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert 'status' in response.data or 'full' in response.data

    def test_initiate_without_consent(self, api_client, tenant, application, user):
        """Test that initiating without consent fails."""
        api_client.force_authenticate(user=user)

        url = f'/api/v1/ats/applications/{application.uuid}/background-check/initiate/'
        data = {
            'package': 'standard',
            'consent_given': False
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestBackgroundCheckIntegration:
    """Integration tests for complete workflows."""

    def test_complete_background_check_workflow(self, tenant, application, user, mocker):
        """Test complete workflow from initiation to completion."""
        # Mock provider interactions
        mocker.patch('ats.background_checks.CheckrProvider.create_candidate', return_value={'id': 'workflow_cand'})
        mocker.patch('ats.background_checks.CheckrProvider.create_invitation', return_value={'id': 'workflow_inv'})
        mocker.patch('ats.background_checks.CheckrProvider.create_report', return_value={'id': 'workflow_report'})

        # 1. Initiate check
        service = BackgroundCheckService(tenant=tenant)
        bg_check = service.initiate_check(
            application=application,
            package='comprehensive',
            initiated_by=user
        )

        assert bg_check.status in ['pending', 'invited', 'in_progress']
        assert application.status == 'background_check_in_progress'

        # 2. Simulate webhook completion
        webhook_payload = {
            'id': bg_check.external_report_id,
            'status': 'complete',
            'result': 'clear',
            'screenings': [
                {'type': 'ssn', 'status': 'clear'},
                {'type': 'criminal', 'status': 'clear'}
            ]
        }

        service.handle_webhook_result(
            report_id=bg_check.external_report_id,
            payload=webhook_payload,
            provider_name='checkr'
        )

        # 3. Verify completion
        bg_check.refresh_from_db()
        application.refresh_from_db()

        assert bg_check.status == 'completed'
        assert bg_check.result == 'clear'
        assert bg_check.completed_at is not None
        assert application.status == 'background_check_cleared'

    def test_background_check_with_adverse_results(self, tenant, application, user, mocker):
        """Test workflow when background check returns adverse results."""
        mocker.patch('ats.background_checks.CheckrProvider.create_candidate', return_value={'id': 'adverse_cand'})
        mocker.patch('ats.background_checks.CheckrProvider.create_invitation', return_value={'id': 'adverse_inv'})
        mocker.patch('ats.background_checks.CheckrProvider.create_report', return_value={'id': 'adverse_report'})

        service = BackgroundCheckService(tenant=tenant)
        bg_check = service.initiate_check(
            application=application,
            package='standard',
            initiated_by=user
        )

        # Simulate adverse result
        adverse_payload = {
            'id': bg_check.external_report_id,
            'status': 'complete',
            'result': 'consider',
            'adjudication': 'consider'
        }

        service.handle_webhook_result(
            report_id=bg_check.external_report_id,
            payload=adverse_payload,
            provider_name='checkr'
        )

        bg_check.refresh_from_db()

        assert bg_check.status == 'completed'
        assert bg_check.result == 'consider'
        # Application should stay in review for manual decision
        assert bg_check.application.status in ['background_check_in_progress', 'in_review']


# =============================================================================
# PYTEST FIXTURES
# =============================================================================

@pytest.fixture
def tenant(db):
    """Create a test tenant."""
    from tenants.models import Tenant
    return Tenant.objects.create(
        name='Test Company',
        slug='test-company',
        tenant_type='company'
    )


@pytest.fixture
def user(db, tenant):
    """Create a test user."""
    user = User.objects.create_user(
        email='recruiter@test.com',
        password='testpass123'
    )
    # Associate with tenant
    from accounts.models import TenantUser
    TenantUser.objects.create(
        user=user,
        tenant=tenant,
        role='recruiter'
    )
    return user


@pytest.fixture
def candidate(db, tenant):
    """Create a test candidate."""
    return Candidate.objects.create(
        tenant=tenant,
        first_name='John',
        last_name='Doe',
        email='john.doe@example.com',
        phone='+1234567890'
    )


@pytest.fixture
def job_posting(db, tenant):
    """Create a test job posting."""
    return JobPosting.objects.create(
        tenant=tenant,
        title='Software Engineer',
        description='Test job description',
        status='open'
    )


@pytest.fixture
def application(db, tenant, candidate, job_posting):
    """Create a test application."""
    return Application.objects.create(
        tenant=tenant,
        candidate=candidate,
        job=job_posting,
        status='interviewing'
    )


@pytest.fixture
def api_client():
    """Create API client."""
    return APIClient()
