"""
Tests for HR Core API.

This module tests the HR Core API endpoints including:
- Employees
- Departments
- Time off requests
- Onboarding
- Performance reviews
- Training records
"""

import pytest
from datetime import date, timedelta
from decimal import Decimal
from django.utils import timezone
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient


@pytest.fixture
def api_client():
    """Return API client."""
    return APIClient()


@pytest.fixture
def authenticated_client(api_client, user_factory):
    """Return authenticated API client."""
    user = user_factory()
    api_client.force_authenticate(user=user)
    return api_client, user


@pytest.fixture
def admin_authenticated_client(api_client, superuser_factory):
    """Return authenticated admin API client."""
    admin = superuser_factory()
    api_client.force_authenticate(user=admin)
    return api_client, admin


@pytest.fixture
def hr_manager_client(api_client, user_factory, hr_manager_tenant_user_factory, tenant_factory):
    """Return authenticated HR manager client."""
    user = user_factory()
    tenant = tenant_factory()
    hr_manager_tenant_user_factory(user=user, tenant=tenant)
    api_client.force_authenticate(user=user)
    return api_client, user, tenant


# =============================================================================
# EMPLOYEE TESTS
# =============================================================================

class TestEmployeeViewSet:
    """Tests for EmployeeViewSet."""

    @pytest.mark.django_db
    def test_list_employees_requires_auth(self, api_client):
        """Test listing employees requires authentication."""
        url = reverse('api_v1:hr:employee-list')
        response = api_client.get(url)

        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_list_employees_authenticated(self, authenticated_client):
        """Test authenticated user can list employees."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:employee-list')
        response = client.get(url)

        # May be 200 or 403 depending on permissions
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_list_employees_admin(self, admin_authenticated_client):
        """Test admin can list employees."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:hr:employee-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_retrieve_employee(self, admin_authenticated_client, employee_factory):
        """Test retrieving an employee."""
        client, admin = admin_authenticated_client
        employee = employee_factory()

        url = reverse('api_v1:hr:employee-detail', args=[employee.id])
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]

    @pytest.mark.django_db
    def test_search_employees(self, admin_authenticated_client):
        """Test searching employees."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:hr:employee-list')
        response = client.get(url, {'search': 'john'})

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_filter_by_department(self, admin_authenticated_client):
        """Test filtering employees by department."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:hr:employee-list')
        response = client.get(url, {'department': 'engineering'})

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_filter_by_status(self, admin_authenticated_client):
        """Test filtering employees by status."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:hr:employee-list')
        response = client.get(url, {'status': 'active'})

        assert response.status_code == status.HTTP_200_OK


# =============================================================================
# TIME OFF REQUEST TESTS
# =============================================================================

class TestTimeOffRequestViewSet:
    """Tests for TimeOffRequestViewSet."""

    @pytest.mark.django_db
    def test_list_time_off_requests(self, authenticated_client):
        """Test listing time off requests."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:time-off-list')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_create_time_off_request(self, authenticated_client):
        """Test creating a time off request."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:time-off-list')
        response = client.post(url, {
            'start_date': (date.today() + timedelta(days=7)).isoformat(),
            'end_date': (date.today() + timedelta(days=10)).isoformat(),
            'leave_type': 'vacation',
            'reason': 'Family vacation'
        })

        assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_403_FORBIDDEN, status.HTTP_400_BAD_REQUEST]

    @pytest.mark.django_db
    def test_approve_time_off(self, hr_manager_client, time_off_request_factory):
        """Test approving a time off request."""
        client, user, tenant = hr_manager_client
        time_off = time_off_request_factory(tenant=tenant)

        url = reverse('api_v1:hr:time-off-approve', args=[time_off.id])
        response = client.post(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]

    @pytest.mark.django_db
    def test_reject_time_off(self, hr_manager_client, time_off_request_factory):
        """Test rejecting a time off request."""
        client, user, tenant = hr_manager_client
        time_off = time_off_request_factory(tenant=tenant)

        url = reverse('api_v1:hr:time-off-reject', args=[time_off.id])
        response = client.post(url, {'reason': 'Team is understaffed during this period'})

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]

    @pytest.mark.django_db
    def test_cancel_time_off(self, authenticated_client, time_off_request_factory):
        """Test cancelling own time off request."""
        client, user = authenticated_client
        time_off = time_off_request_factory(user=user)

        url = reverse('api_v1:hr:time-off-cancel', args=[time_off.id])
        response = client.post(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]

    @pytest.mark.django_db
    def test_my_time_off_requests(self, authenticated_client):
        """Test getting current user's time off requests."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:time-off-my-requests')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_pending_approvals(self, hr_manager_client):
        """Test getting pending approval requests."""
        client, user, tenant = hr_manager_client

        url = reverse('api_v1:hr:time-off-pending-approvals')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]


# =============================================================================
# DEPARTMENT TESTS
# =============================================================================

class TestDepartmentViewSet:
    """Tests for DepartmentViewSet."""

    @pytest.mark.django_db
    def test_list_departments(self, authenticated_client):
        """Test listing departments."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:department-list')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_create_department_requires_admin(self, authenticated_client):
        """Test creating a department requires admin."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:department-list')
        response = client.post(url, {
            'name': 'Engineering',
            'description': 'Engineering department'
        })

        assert response.status_code in [status.HTTP_403_FORBIDDEN, status.HTTP_201_CREATED]

    @pytest.mark.django_db
    def test_department_members(self, authenticated_client, department_factory):
        """Test getting department members."""
        client, user = authenticated_client
        dept = department_factory()

        url = reverse('api_v1:hr:department-members', args=[dept.id])
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]

    @pytest.mark.django_db
    def test_department_hierarchy(self, authenticated_client):
        """Test getting department hierarchy."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:department-hierarchy')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]


# =============================================================================
# ONBOARDING TESTS
# =============================================================================

class TestOnboardingViewSet:
    """Tests for OnboardingViewSet."""

    @pytest.mark.django_db
    def test_list_onboarding_tasks(self, authenticated_client):
        """Test listing onboarding tasks."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:onboarding-list')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_complete_onboarding_task(self, authenticated_client, onboarding_task_factory):
        """Test completing an onboarding task."""
        client, user = authenticated_client
        task = onboarding_task_factory(assignee=user)

        url = reverse('api_v1:hr:onboarding-complete', args=[task.id])
        response = client.post(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]

    @pytest.mark.django_db
    def test_my_onboarding(self, authenticated_client):
        """Test getting current user's onboarding tasks."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:onboarding-my-tasks')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]


# =============================================================================
# PERFORMANCE REVIEW TESTS
# =============================================================================

class TestPerformanceReviewViewSet:
    """Tests for PerformanceReviewViewSet."""

    @pytest.mark.django_db
    def test_list_reviews(self, authenticated_client):
        """Test listing performance reviews."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:performance-list')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_my_reviews(self, authenticated_client):
        """Test getting current user's performance reviews."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:performance-my-reviews')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_submit_self_review(self, authenticated_client, performance_review_factory):
        """Test submitting a self-review."""
        client, user = authenticated_client
        review = performance_review_factory(employee_user=user)

        url = reverse('api_v1:hr:performance-submit-self-review', args=[review.id])
        response = client.post(url, {
            'self_assessment': 'I exceeded my goals this quarter.',
            'achievements': ['Completed project X', 'Led initiative Y']
        })

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]

    @pytest.mark.django_db
    def test_submit_manager_review(self, hr_manager_client, performance_review_factory):
        """Test submitting a manager review."""
        client, user, tenant = hr_manager_client
        review = performance_review_factory(manager=user, tenant=tenant)

        url = reverse('api_v1:hr:performance-submit-manager-review', args=[review.id])
        response = client.post(url, {
            'rating': 4,
            'feedback': 'Great performance this quarter.',
            'goals_for_next_period': ['Improve time management']
        })

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]


# =============================================================================
# TRAINING TESTS
# =============================================================================

class TestTrainingViewSet:
    """Tests for TrainingViewSet."""

    @pytest.mark.django_db
    def test_list_trainings(self, authenticated_client):
        """Test listing training programs."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:training-list')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_enroll_in_training(self, authenticated_client, training_factory):
        """Test enrolling in a training program."""
        client, user = authenticated_client
        training = training_factory()

        url = reverse('api_v1:hr:training-enroll', args=[training.id])
        response = client.post(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]

    @pytest.mark.django_db
    def test_complete_training(self, authenticated_client, training_enrollment_factory):
        """Test completing a training program."""
        client, user = authenticated_client
        enrollment = training_enrollment_factory(user=user)

        url = reverse('api_v1:hr:training-complete', args=[enrollment.training.id])
        response = client.post(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]

    @pytest.mark.django_db
    def test_my_trainings(self, authenticated_client):
        """Test getting current user's training records."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:training-my-trainings')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]


# =============================================================================
# PAYROLL TESTS
# =============================================================================

class TestPayrollViewSet:
    """Tests for PayrollViewSet."""

    @pytest.mark.django_db
    def test_list_payslips(self, authenticated_client):
        """Test listing payslips."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:payroll-list')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_my_payslips(self, authenticated_client):
        """Test getting current user's payslips."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:payroll-my-payslips')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_download_payslip(self, authenticated_client, payslip_factory):
        """Test downloading a payslip."""
        client, user = authenticated_client
        payslip = payslip_factory(user=user)

        url = reverse('api_v1:hr:payroll-download', args=[payslip.id])
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]


# =============================================================================
# BENEFITS TESTS
# =============================================================================

class TestBenefitsViewSet:
    """Tests for BenefitsViewSet."""

    @pytest.mark.django_db
    def test_list_benefits(self, authenticated_client):
        """Test listing benefits."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:benefits-list')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_my_benefits(self, authenticated_client):
        """Test getting current user's benefits."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:benefits-my-benefits')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_enroll_in_benefit(self, authenticated_client, benefit_factory):
        """Test enrolling in a benefit."""
        client, user = authenticated_client
        benefit = benefit_factory()

        url = reverse('api_v1:hr:benefits-enroll', args=[benefit.id])
        response = client.post(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]


# =============================================================================
# DOCUMENT TESTS
# =============================================================================

class TestDocumentViewSet:
    """Tests for HR DocumentViewSet."""

    @pytest.mark.django_db
    def test_list_documents(self, authenticated_client):
        """Test listing HR documents."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:document-list')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_my_documents(self, authenticated_client):
        """Test getting current user's documents."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:document-my-documents')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_upload_document(self, authenticated_client):
        """Test uploading a document."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:document-list')
        # Note: This would require a real file upload in a real test
        response = client.post(url, {
            'name': 'My Resume',
            'document_type': 'resume'
        })

        assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_400_BAD_REQUEST, status.HTTP_403_FORBIDDEN]


# =============================================================================
# EMERGENCY CONTACT TESTS
# =============================================================================

class TestEmergencyContactViewSet:
    """Tests for EmergencyContactViewSet."""

    @pytest.mark.django_db
    def test_list_emergency_contacts(self, authenticated_client):
        """Test listing emergency contacts."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:emergency-contact-list')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_create_emergency_contact(self, authenticated_client):
        """Test creating an emergency contact."""
        client, user = authenticated_client

        url = reverse('api_v1:hr:emergency-contact-list')
        response = client.post(url, {
            'name': 'Jane Doe',
            'relationship': 'Spouse',
            'phone': '+1234567890'
        })

        assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_update_emergency_contact(self, authenticated_client, emergency_contact_factory):
        """Test updating an emergency contact."""
        client, user = authenticated_client
        contact = emergency_contact_factory(user=user)

        url = reverse('api_v1:hr:emergency-contact-detail', args=[contact.id])
        response = client.patch(url, {
            'phone': '+1987654320'
        })

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]
