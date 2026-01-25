"""
Tests for Security API.

This module tests the security API endpoints including:
- Audit logs
- Security events
- Failed login attempts
- User sessions
- Password reset requests
- Security analytics
"""

import pytest
from datetime import timedelta
from django.utils import timezone
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from security.models import (
    AuditLogEntry, SecurityEvent, FailedLoginAttempt,
    UserSession, PasswordResetRequest
)


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
def audit_log(db, user_factory):
    """Create test audit log entry."""
    user = user_factory()
    return AuditLogEntry.objects.create(
        actor=user,
        action='create',
        model_name='JobPosting',
        object_id='1',
        object_repr='Software Developer',
        change_message='Created new job posting'
    )


@pytest.fixture
def security_event(db, user_factory):
    """Create test security event."""
    user = user_factory()
    return SecurityEvent.objects.create(
        user=user,
        event_type='login',
        description='User logged in successfully',
        ip_address='192.168.1.1'
    )


@pytest.fixture
def failed_login(db, user_factory):
    """Create test failed login attempt."""
    user = user_factory()
    return FailedLoginAttempt.objects.create(
        user=user,
        username_entered=user.email,
        ip_address='192.168.1.100',
        user_agent='Mozilla/5.0',
        reason='Invalid password'
    )


@pytest.fixture
def user_session(db, user_factory):
    """Create test user session."""
    user = user_factory()
    return UserSession.objects.create(
        user=user,
        session_key='test_session_123',
        ip_address='192.168.1.1',
        user_agent='Mozilla/5.0',
        is_active=True,
        login_time=timezone.now()
    )


@pytest.fixture
def password_reset(db, user_factory):
    """Create test password reset request."""
    user = user_factory()
    return PasswordResetRequest.objects.create(
        user=user,
        token='reset_token_123',
        ip_address='192.168.1.1',
        used=False,
        expires_at=timezone.now() + timedelta(hours=24)
    )


# =============================================================================
# AUDIT LOG TESTS
# =============================================================================

class TestAuditLogViewSet:
    """Tests for AuditLogViewSet."""

    @pytest.mark.django_db
    def test_list_audit_logs_requires_admin(self, authenticated_client, audit_log):
        """Test listing audit logs requires admin."""
        client, user = authenticated_client

        url = reverse('api_v1:security:audit-log-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_list_audit_logs_admin(self, admin_authenticated_client, audit_log):
        """Test admin can list audit logs."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:audit-log-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_retrieve_audit_log(self, admin_authenticated_client, audit_log):
        """Test retrieving an audit log."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:audit-log-detail', args=[audit_log.id])
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_filter_by_action(self, admin_authenticated_client, audit_log):
        """Test filtering audit logs by action."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:audit-log-list')
        response = client.get(url, {'action': 'create'})

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_filter_by_model(self, admin_authenticated_client, audit_log):
        """Test filtering audit logs by model."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:audit-log-list')
        response = client.get(url, {'model_name': 'JobPosting'})

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_by_action(self, admin_authenticated_client, audit_log):
        """Test audit logs by action endpoint."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:audit-log-by-action')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data, list)

    @pytest.mark.django_db
    def test_by_model(self, admin_authenticated_client, audit_log):
        """Test audit logs by model endpoint."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:audit-log-by-model')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data, list)

    @pytest.mark.django_db
    def test_by_user(self, admin_authenticated_client, audit_log):
        """Test audit logs by user endpoint."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:audit-log-by-user')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data, list)


# =============================================================================
# SECURITY EVENT TESTS
# =============================================================================

class TestSecurityEventViewSet:
    """Tests for SecurityEventViewSet."""

    @pytest.mark.django_db
    def test_list_security_events_requires_admin(self, authenticated_client, security_event):
        """Test listing security events requires admin."""
        client, user = authenticated_client

        url = reverse('api_v1:security:security-event-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_list_security_events_admin(self, admin_authenticated_client, security_event):
        """Test admin can list security events."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:security-event-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_filter_by_event_type(self, admin_authenticated_client, security_event):
        """Test filtering security events by type."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:security-event-list')
        response = client.get(url, {'event_type': 'login'})

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_by_type(self, admin_authenticated_client, security_event):
        """Test security events by type endpoint."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:security-event-by-type')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data, list)


# =============================================================================
# FAILED LOGIN TESTS
# =============================================================================

class TestFailedLoginViewSet:
    """Tests for FailedLoginViewSet."""

    @pytest.mark.django_db
    def test_list_failed_logins_requires_admin(self, authenticated_client, failed_login):
        """Test listing failed logins requires admin."""
        client, user = authenticated_client

        url = reverse('api_v1:security:failed-login-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_list_failed_logins_admin(self, admin_authenticated_client, failed_login):
        """Test admin can list failed logins."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:failed-login-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_filter_by_ip(self, admin_authenticated_client, failed_login):
        """Test filtering failed logins by IP."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:failed-login-list')
        response = client.get(url, {'ip_address': '192.168.1.100'})

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_by_ip(self, admin_authenticated_client, failed_login):
        """Test failed logins by IP endpoint."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:failed-login-by-ip')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data, list)

    @pytest.mark.django_db
    def test_suspicious(self, admin_authenticated_client, user_factory):
        """Test suspicious IPs endpoint."""
        client, admin = admin_authenticated_client

        # Create multiple failed logins from same IP
        user = user_factory()
        for i in range(6):
            FailedLoginAttempt.objects.create(
                user=user,
                username_entered=f'user{i}@example.com',
                ip_address='10.0.0.1',
                user_agent='Mozilla/5.0'
            )

        url = reverse('api_v1:security:failed-login-suspicious')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        # Should find the suspicious IP
        suspicious_ips = [item['ip_address'] for item in response.data]
        assert '10.0.0.1' in suspicious_ips


# =============================================================================
# USER SESSION TESTS
# =============================================================================

class TestUserSessionViewSet:
    """Tests for UserSessionViewSet."""

    @pytest.mark.django_db
    def test_list_sessions_requires_admin(self, authenticated_client, user_session):
        """Test listing sessions requires admin."""
        client, user = authenticated_client

        url = reverse('api_v1:security:user-session-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_list_sessions_admin(self, admin_authenticated_client, user_session):
        """Test admin can list sessions."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:user-session-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_terminate_session(self, admin_authenticated_client, user_session):
        """Test terminating a session."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:user-session-terminate', args=[user_session.id])
        response = client.post(url)

        assert response.status_code == status.HTTP_200_OK
        user_session.refresh_from_db()
        assert user_session.is_active is False

    @pytest.mark.django_db
    def test_terminate_user_sessions(self, admin_authenticated_client, user_factory):
        """Test terminating all sessions for a user."""
        client, admin = admin_authenticated_client
        user = user_factory()

        # Create multiple sessions for the user
        for i in range(3):
            UserSession.objects.create(
                user=user,
                session_key=f'session_{i}',
                ip_address='192.168.1.1',
                is_active=True,
                login_time=timezone.now()
            )

        url = reverse('api_v1:security:user-session-terminate-user-sessions')
        response = client.post(url, {'user_id': user.id})

        assert response.status_code == status.HTTP_200_OK
        assert UserSession.objects.filter(user=user, is_active=True).count() == 0

    @pytest.mark.django_db
    def test_active_count(self, admin_authenticated_client, user_session):
        """Test active session count endpoint."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:user-session-active-count')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert 'active_sessions' in response.data
        assert 'unique_users' in response.data


# =============================================================================
# PASSWORD RESET REQUEST TESTS
# =============================================================================

class TestPasswordResetRequestViewSet:
    """Tests for PasswordResetRequestViewSet."""

    @pytest.mark.django_db
    def test_list_password_resets_requires_admin(self, authenticated_client, password_reset):
        """Test listing password resets requires admin."""
        client, user = authenticated_client

        url = reverse('api_v1:security:password-reset-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_list_password_resets_admin(self, admin_authenticated_client, password_reset):
        """Test admin can list password resets."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:password-reset-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_filter_by_used(self, admin_authenticated_client, password_reset):
        """Test filtering password resets by used status."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:password-reset-list')
        response = client.get(url, {'used': 'false'})

        assert response.status_code == status.HTTP_200_OK


# =============================================================================
# SECURITY ANALYTICS TESTS
# =============================================================================

class TestSecurityAnalyticsView:
    """Tests for SecurityAnalyticsView."""

    @pytest.mark.django_db
    def test_analytics_requires_admin(self, authenticated_client):
        """Test analytics requires admin."""
        client, user = authenticated_client

        url = reverse('api_v1:security:analytics')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_analytics_admin(self, admin_authenticated_client, audit_log, security_event, failed_login, user_session):
        """Test admin can access analytics."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:security:analytics')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert 'total_audit_logs' in response.data
        assert 'total_security_events' in response.data
        assert 'failed_logins_today' in response.data
        assert 'active_sessions' in response.data

    @pytest.mark.django_db
    def test_analytics_data_accuracy(self, admin_authenticated_client, user_factory):
        """Test analytics data is accurate."""
        client, admin = admin_authenticated_client
        user = user_factory()

        # Create test data
        AuditLogEntry.objects.create(
            actor=user,
            action='test',
            model_name='Test'
        )
        SecurityEvent.objects.create(
            user=user,
            event_type='test'
        )
        FailedLoginAttempt.objects.create(
            username_entered='test@test.com',
            ip_address='1.2.3.4'
        )
        UserSession.objects.create(
            user=user,
            session_key='test_key',
            is_active=True,
            login_time=timezone.now()
        )

        url = reverse('api_v1:security:analytics')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['total_audit_logs'] >= 1
        assert response.data['total_security_events'] >= 1
        assert response.data['active_sessions'] >= 1
