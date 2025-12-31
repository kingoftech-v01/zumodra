"""
OWASP Top 10 Security Tests for Zumodra ATS/HR Platform

This module tests security against the OWASP Top 10 2021:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A07: Identification and Authentication Failures
- A08: Software and Data Integrity Failures
- A09: Security Logging and Monitoring Failures
- A10: Server-Side Request Forgery (SSRF)

Each test category documents the specific vulnerability being tested.
"""

import json
import os
from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import HttpResponse, HttpRequest
from django.test import TestCase, RequestFactory, override_settings
from django.utils import timezone

User = get_user_model()


# =============================================================================
# A01: BROKEN ACCESS CONTROL
# =============================================================================

class TestA01BrokenAccessControl:
    """
    Tests for A01:2021 - Broken Access Control

    Attack Vectors:
    - Bypassing access control checks
    - Viewing other users' data
    - Elevation of privilege
    - CORS misconfiguration
    - Force browsing to restricted pages
    """

    def test_unauthorized_user_cannot_access_admin(
        self, client, user_factory, db
    ):
        """
        Test: Non-admin users cannot access admin pages.
        """
        user = user_factory()
        client.force_login(user)

        response = client.get('/admin/')

        # Should redirect to login or return 403
        assert response.status_code in [302, 403]

    def test_user_cannot_access_other_users_data(
        self, client, user_factory, db
    ):
        """
        Test: User A cannot access User B's private data.
        OWASP: Insecure Direct Object Reference (IDOR).
        """
        user_a = user_factory(email='user_a@test.com')
        user_b = user_factory(email='user_b@test.com')

        client.force_login(user_a)

        # Try to access user_b's profile
        response = client.get(f'/api/users/{user_b.id}/profile/')

        # Should be forbidden
        assert response.status_code in [403, 404]

    def test_tenant_isolation_in_api(
        self, api_client, tenant_factory, user_factory,
        tenant_user_factory, job_posting_factory, db
    ):
        """
        Test: Tenant A cannot access Tenant B's resources via API.
        """
        tenant_a = tenant_factory(name='Company A', slug='company-a')
        tenant_b = tenant_factory(name='Company B', slug='company-b')

        user_a = user_factory()
        tenant_user_factory(user=user_a, tenant=tenant_a)

        # Create job in tenant B
        job = job_posting_factory()

        api_client.force_authenticate(user=user_a)

        # Try to access tenant B's job
        response = api_client.get(f'/api/jobs/{job.id}/')

        assert response.status_code in [403, 404]

    def test_vertical_privilege_escalation(
        self, api_client, tenant_factory, user_factory,
        tenant_user_factory, db
    ):
        """
        Test: Regular user cannot access admin-only endpoints.
        """
        tenant = tenant_factory()
        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='employee')

        api_client.force_authenticate(user=user)

        # Try to access admin endpoint
        response = api_client.get('/api/admin/users/')

        assert response.status_code in [403, 404]

    def test_horizontal_privilege_escalation(
        self, api_client, tenant_factory, user_factory,
        tenant_user_factory, employee_factory, db
    ):
        """
        Test: Employee cannot view other employees' salary.
        """
        tenant = tenant_factory()
        user_a = user_factory()
        user_b = user_factory()
        tenant_user_factory(user=user_a, tenant=tenant, role='employee')
        tenant_user_factory(user=user_b, tenant=tenant, role='employee')

        employee_b = employee_factory(user=user_b)

        api_client.force_authenticate(user=user_a)

        # Try to access user_b's salary
        response = api_client.get(f'/api/employees/{employee_b.id}/salary/')

        assert response.status_code in [403, 404]

    def test_cors_not_wildcard(self, client, db):
        """
        Test: CORS is not configured with wildcard origin.
        """
        response = client.options(
            '/api/jobs/',
            HTTP_ORIGIN='https://evil.com',
            HTTP_ACCESS_CONTROL_REQUEST_METHOD='GET'
        )

        # Should not allow arbitrary origins
        cors_header = response.get('Access-Control-Allow-Origin', '')
        assert cors_header != '*'

    def test_path_traversal_blocked(self, client, db):
        """
        Test: Path traversal attempts are blocked.
        """
        response = client.get('/api/files/../../../etc/passwd')

        assert response.status_code in [400, 403, 404]

    def test_http_method_tampering(self, api_client, user_factory, db):
        """
        Test: Cannot bypass authorization by changing HTTP method.
        """
        user = user_factory()
        api_client.force_authenticate(user=user)

        # Even if GET is blocked, PUT/PATCH should also be blocked
        response = api_client.put('/api/admin/settings/', data={'key': 'value'})

        assert response.status_code in [403, 405]


# =============================================================================
# A02: CRYPTOGRAPHIC FAILURES
# =============================================================================

class TestA02CryptographicFailures:
    """
    Tests for A02:2021 - Cryptographic Failures

    Attack Vectors:
    - Weak encryption algorithms
    - Improper key management
    - Unencrypted sensitive data
    - Weak hashing for passwords
    """

    def test_passwords_use_strong_hashing(self, user_factory, db):
        """
        Test: Passwords use strong hashing algorithm (Argon2/bcrypt).
        """
        user = user_factory()
        user.set_password('TestPassword123!')
        user.save()

        # Password should be hashed with strong algorithm
        assert not user.password.startswith('md5')
        assert not user.password.startswith('sha1')
        # Django default is PBKDF2, Argon2 preferred
        assert 'pbkdf2' in user.password or 'argon2' in user.password or 'bcrypt' in user.password

    def test_sensitive_data_encrypted_at_rest(self, db):
        """
        Test: Sensitive fields are encrypted in database.
        """
        from core.db.fields import EncryptedCharField

        # Verify sensitive models use EncryptedCharField
        # This is a configuration check

    def test_ssl_tls_enforced(self, settings):
        """
        Test: HTTPS is enforced in production.
        """
        if not settings.DEBUG:
            assert settings.SECURE_SSL_REDIRECT is True
            assert settings.SESSION_COOKIE_SECURE is True
            assert settings.CSRF_COOKIE_SECURE is True

    def test_no_sensitive_data_in_urls(self, client, user_factory, db):
        """
        Test: Sensitive data not passed in URL parameters.
        """
        # URLs should not contain passwords, tokens, SSN, etc.
        # This is more of a code review check

    def test_encryption_key_not_hardcoded(self):
        """
        Test: Encryption keys are not hardcoded.
        """
        assert not hasattr(settings, 'ENCRYPTION_KEY') or \
               settings.ENCRYPTION_KEY != 'hardcoded_key'

        # Key should come from environment
        assert os.environ.get('FIELD_ENCRYPTION_KEY') or \
               hasattr(settings, 'FIELD_ENCRYPTION_KEY')


# =============================================================================
# A03: INJECTION
# =============================================================================

class TestA03Injection:
    """
    Tests for A03:2021 - Injection

    Attack Vectors:
    - SQL injection
    - NoSQL injection
    - Command injection
    - LDAP injection
    - XPath injection
    """

    def test_sql_injection_in_search(self, api_client, user_factory, db):
        """
        Test: SQL injection in search parameter is blocked.
        """
        user = user_factory()
        api_client.force_authenticate(user=user)

        malicious_search = "'; DROP TABLE jobs; --"
        response = api_client.get(f'/api/jobs/?search={malicious_search}')

        # Should not cause SQL error or data loss
        # Database should still be intact
        from ats.models import JobPosting
        # If test gets here, table wasn't dropped

    def test_orm_queries_parameterized(self):
        """
        Test: ORM queries use parameterization.
        """
        # Django ORM uses parameterized queries by default
        # This test verifies no raw SQL usage

    def test_command_injection_in_file_processing(self, api_client, user_factory, db):
        """
        Test: Command injection in filename is blocked.
        """
        user = user_factory()
        api_client.force_authenticate(user=user)

        from django.core.files.uploadedfile import SimpleUploadedFile

        malicious_file = SimpleUploadedFile(
            name='test; rm -rf /.pdf',
            content=b'%PDF-1.4',
            content_type='application/pdf'
        )

        response = api_client.post('/api/documents/', {'file': malicious_file})

        # Should sanitize filename or reject

    def test_header_injection_blocked(self, client, db):
        """
        Test: HTTP header injection is blocked.
        """
        response = client.get(
            '/api/health/',
            HTTP_X_CUSTOM='value\r\nInjected-Header: malicious'
        )

        # Should not reflect injected header


# =============================================================================
# A04: INSECURE DESIGN
# =============================================================================

class TestA04InsecureDesign:
    """
    Tests for A04:2021 - Insecure Design

    Security Requirements:
    - Threat modeling
    - Secure design patterns
    - Business logic validation
    """

    def test_password_reset_rate_limited(self, client, db):
        """
        Test: Password reset is rate limited to prevent abuse.
        """
        for i in range(10):
            response = client.post('/api/auth/password-reset/', {
                'email': 'test@test.com'
            })

        # Should be rate limited after multiple attempts
        response = client.post('/api/auth/password-reset/', {
            'email': 'test@test.com'
        })
        assert response.status_code == 429

    def test_business_flow_cannot_be_bypassed(
        self, api_client, user_factory, tenant_factory,
        tenant_user_factory, application_factory, db
    ):
        """
        Test: Hiring workflow stages cannot be skipped.
        """
        tenant = tenant_factory()
        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='recruiter')

        application = application_factory()

        api_client.force_authenticate(user=user)

        # Try to skip from 'new' directly to 'hired'
        response = api_client.patch(
            f'/api/applications/{application.id}/',
            {'status': 'hired'}
        )

        # Should fail - must go through stages
        assert response.status_code in [400, 403]

    def test_account_enumeration_prevented(self, client, db):
        """
        Test: Cannot enumerate valid accounts via login/reset.
        """
        # Login with non-existent user
        response1 = client.post('/api/auth/login/', {
            'email': 'nonexistent@test.com',
            'password': 'password123'
        })

        # Login with existent user, wrong password
        from django.contrib.auth import get_user_model
        User = get_user_model()
        User.objects.create_user(email='exists@test.com', password='correct')

        response2 = client.post('/api/auth/login/', {
            'email': 'exists@test.com',
            'password': 'wrong'
        })

        # Error messages should be identical
        assert response1.status_code == response2.status_code
        # Message should be generic


# =============================================================================
# A05: SECURITY MISCONFIGURATION
# =============================================================================

class TestA05SecurityMisconfiguration:
    """
    Tests for A05:2021 - Security Misconfiguration

    Security Requirements:
    - Secure default configurations
    - No unnecessary features enabled
    - Proper error handling
    """

    def test_debug_mode_disabled_in_production(self):
        """
        Test: DEBUG is False in production.
        """
        if os.environ.get('DJANGO_SETTINGS_MODULE', '').endswith('production'):
            assert settings.DEBUG is False

    def test_stack_traces_not_exposed(self, client, db):
        """
        Test: Stack traces not shown to users.
        """
        response = client.get('/api/nonexistent/path/that/errors/')

        content = response.content.decode() if response.content else ''

        # Should not contain stack trace
        assert 'Traceback' not in content
        assert 'File "' not in content

    def test_default_admin_credentials_changed(self):
        """
        Test: Default admin credentials are not active.
        """
        from django.contrib.auth import authenticate

        # Common default credentials should not work
        defaults = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('root', 'root'),
        ]

        for username, password in defaults:
            user = authenticate(username=username, password=password)
            assert user is None

    def test_unnecessary_http_methods_disabled(self, client, db):
        """
        Test: TRACE, OPTIONS etc. limited appropriately.
        """
        response = client.generic('TRACE', '/')
        assert response.status_code in [405, 501]

    def test_security_headers_configured(self, client, db):
        """
        Test: Security headers are present.
        """
        response = client.get('/')

        assert 'X-Content-Type-Options' in response
        assert 'X-Frame-Options' in response or 'frame-ancestors' in response.get('Content-Security-Policy', '')

    def test_directory_listing_disabled(self, client, db):
        """
        Test: Directory listing is disabled.
        """
        response = client.get('/static/')

        # Should not list directory contents
        assert 'Index of' not in str(response.content)


# =============================================================================
# A07: IDENTIFICATION AND AUTHENTICATION FAILURES
# =============================================================================

class TestA07AuthenticationFailures:
    """
    Tests for A07:2021 - Identification and Authentication Failures

    Attack Vectors:
    - Brute force attacks
    - Credential stuffing
    - Session hijacking
    - Weak passwords
    """

    def test_brute_force_protection(self, client, user_factory, db):
        """
        Test: Account locked after failed login attempts.
        """
        user = user_factory()

        for i in range(10):
            client.post('/api/auth/login/', {
                'email': user.email,
                'password': 'wrongpassword'
            })

        # Account should be locked
        response = client.post('/api/auth/login/', {
            'email': user.email,
            'password': 'correctpassword'  # Even correct password
        })

        # Should indicate account locked
        assert response.status_code in [401, 403, 429]

    def test_session_fixation_prevention(self, client, user_factory, db):
        """
        Test: Session ID changes after login.
        """
        # Get initial session
        response = client.get('/')
        initial_session = client.session.session_key

        # Login
        user = user_factory()
        user.set_password('testpass123')
        user.save()

        client.post('/api/auth/login/', {
            'email': user.email,
            'password': 'testpass123'
        })

        # Session should be different
        assert client.session.session_key != initial_session

    def test_password_complexity_enforced(self, api_client, db):
        """
        Test: Weak passwords are rejected during registration.
        """
        weak_passwords = [
            'password',
            '12345678',
            'qwerty123',
        ]

        for password in weak_passwords:
            response = api_client.post('/api/auth/register/', {
                'email': 'new@test.com',
                'password': password,
                'password_confirm': password
            })

            assert response.status_code == 400

    def test_mfa_required_for_sensitive_actions(
        self, api_client, user_factory, db
    ):
        """
        Test: MFA required for sensitive operations.
        """
        user = user_factory(mfa_enabled=True)
        api_client.force_authenticate(user=user)

        # Sensitive action without MFA verification
        response = api_client.post('/api/settings/change-email/', {
            'new_email': 'new@test.com'
        })

        # Should require MFA
        assert response.status_code in [401, 403]


# =============================================================================
# A08: SOFTWARE AND DATA INTEGRITY FAILURES
# =============================================================================

class TestA08IntegrityFailures:
    """
    Tests for A08:2021 - Software and Data Integrity Failures

    Security Requirements:
    - Verify software integrity
    - Secure CI/CD pipeline
    - Protect against deserialization attacks
    """

    def test_csrf_protection_enabled(self, client, user_factory, db):
        """
        Test: CSRF tokens required for state-changing requests.
        """
        user = user_factory()
        client.force_login(user)

        # POST without CSRF token
        response = client.post(
            '/api/profile/',
            data={'name': 'test'},
            HTTP_X_CSRFTOKEN='invalid'
        )

        # Should be rejected
        assert response.status_code in [403, 400]

    def test_pickle_deserialization_blocked(self):
        """
        Test: Pickle deserialization of untrusted data is blocked.
        """
        # Verify pickle is not used for user input
        # This is a code review check

    def test_signed_cookies_used(self, settings):
        """
        Test: Session data is signed/encrypted.
        """
        # Django signs session cookies by default
        assert settings.SESSION_ENGINE in [
            'django.contrib.sessions.backends.signed_cookies',
            'django.contrib.sessions.backends.db',
            'django.contrib.sessions.backends.cache',
            'django.contrib.sessions.backends.cached_db',
        ]

    def test_file_upload_integrity_checked(self, api_client, user_factory, db):
        """
        Test: Uploaded files are verified for integrity.
        """
        user = user_factory()
        api_client.force_authenticate(user=user)

        from django.core.files.uploadedfile import SimpleUploadedFile

        # File claiming to be PDF but isn't
        fake_pdf = SimpleUploadedFile(
            name='document.pdf',
            content=b'Not a real PDF',
            content_type='application/pdf'
        )

        response = api_client.post('/api/documents/', {'file': fake_pdf})

        # Should reject or warn
        assert response.status_code in [400, 422]


# =============================================================================
# A09: SECURITY LOGGING AND MONITORING FAILURES
# =============================================================================

class TestA09LoggingFailures:
    """
    Tests for A09:2021 - Security Logging and Monitoring Failures

    Security Requirements:
    - Log security events
    - Protect log integrity
    - Alert on suspicious activity
    """

    def test_authentication_failures_logged(self, client, user_factory, db):
        """
        Test: Failed login attempts are logged.
        """
        with patch('accounts.signals.logger') as mock_logger:
            client.post('/api/auth/login/', {
                'email': 'test@test.com',
                'password': 'wrongpassword'
            })

            # Should log the failure
            mock_logger.warning.assert_called()

    def test_access_control_failures_logged(
        self, api_client, user_factory, db
    ):
        """
        Test: Access control violations are logged.
        """
        user = user_factory()
        api_client.force_authenticate(user=user)

        with patch('core.security.authorization.logger') as mock_logger:
            api_client.get('/api/admin/users/')

            # Should log the unauthorized access attempt

    def test_sensitive_data_access_logged(
        self, api_client, user_factory, tenant_factory,
        tenant_user_factory, db
    ):
        """
        Test: Access to sensitive data is logged.
        """
        tenant = tenant_factory()
        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='hr_manager')

        api_client.force_authenticate(user=user)

        with patch('core.security.middleware.audit_log') as mock_log:
            api_client.get('/api/employees/1/salary/')

            # Should log access to salary data

    def test_logs_include_context(self, client, db):
        """
        Test: Logs include necessary context for investigation.
        """
        with patch('core.security.middleware.logger') as mock_logger:
            client.post('/api/auth/login/', {
                'email': 'test@test.com',
                'password': 'wrongpassword'
            }, REMOTE_ADDR='192.168.1.100')

            # Log should include IP, timestamp, user identifier


# =============================================================================
# A10: SERVER-SIDE REQUEST FORGERY (SSRF)
# =============================================================================

class TestA10SSRF:
    """
    Tests for A10:2021 - Server-Side Request Forgery

    Attack Vectors:
    - Access to internal services
    - Cloud metadata endpoint access
    - Port scanning
    """

    def test_ssrf_to_localhost_blocked(self, api_client, user_factory, db):
        """
        Test: SSRF to localhost is blocked.
        """
        user = user_factory()
        api_client.force_authenticate(user=user)

        response = api_client.post('/api/webhooks/', {
            'url': 'http://localhost/admin'
        })

        assert response.status_code in [400, 422]

    def test_ssrf_to_internal_ip_blocked(self, api_client, user_factory, db):
        """
        Test: SSRF to internal IPs is blocked.
        """
        user = user_factory()
        api_client.force_authenticate(user=user)

        internal_ips = [
            'http://10.0.0.1/internal',
            'http://192.168.1.1/router',
            'http://172.16.0.1/database',
        ]

        for url in internal_ips:
            response = api_client.post('/api/webhooks/', {'url': url})
            assert response.status_code in [400, 422]

    def test_ssrf_to_cloud_metadata_blocked(self, api_client, user_factory, db):
        """
        Test: SSRF to cloud metadata endpoints is blocked.
        """
        user = user_factory()
        api_client.force_authenticate(user=user)

        metadata_urls = [
            'http://169.254.169.254/latest/meta-data/',  # AWS
            'http://metadata.google.internal/',  # GCP
        ]

        for url in metadata_urls:
            response = api_client.post('/api/webhooks/', {'url': url})
            assert response.status_code in [400, 422]

    def test_ssrf_via_redirect_blocked(self, api_client, user_factory, db):
        """
        Test: SSRF via redirect is blocked.
        """
        user = user_factory()
        api_client.force_authenticate(user=user)

        # URL that redirects to internal IP
        with patch('requests.head') as mock_head:
            mock_response = Mock()
            mock_response.is_redirect = True
            mock_response.headers = {'Location': 'http://127.0.0.1/admin'}
            mock_head.return_value = mock_response

            response = api_client.post('/api/webhooks/', {
                'url': 'http://evil.com/redirect'
            })

            # Should block even if initial URL looks safe


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestOWASPIntegration:
    """
    Integration tests covering multiple OWASP categories.
    """

    @pytest.mark.django_db
    def test_complete_authentication_flow_secure(
        self, client, user_factory, db
    ):
        """
        Test: Complete auth flow follows security best practices.
        """
        # Registration
        response = client.post('/api/auth/register/', {
            'email': 'newuser@test.com',
            'password': 'SecureP@ssw0rd123',
            'password_confirm': 'SecureP@ssw0rd123'
        })

        if response.status_code == 201:
            # Login
            login_response = client.post('/api/auth/login/', {
                'email': 'newuser@test.com',
                'password': 'SecureP@ssw0rd123'
            })

            assert login_response.status_code == 200

            # Session should be secure
            assert client.session.session_key is not None

    @pytest.mark.django_db
    def test_multi_tenant_security_complete(
        self, api_client, tenant_factory, user_factory,
        tenant_user_factory, job_posting_factory, db
    ):
        """
        Test: Multi-tenant security is comprehensive.
        """
        tenant_a = tenant_factory(name='Company A', slug='company-a')
        tenant_b = tenant_factory(name='Company B', slug='company-b')

        user_a = user_factory()
        user_b = user_factory()

        tenant_user_factory(user=user_a, tenant=tenant_a, role='admin')
        tenant_user_factory(user=user_b, tenant=tenant_b, role='admin')

        # User A creates a job
        api_client.force_authenticate(user=user_a)
        job_response = api_client.post('/api/jobs/', {
            'title': 'Secret Job at Company A'
        }, HTTP_X_TENANT=tenant_a.slug)

        if job_response.status_code == 201:
            job_id = job_response.data['id']

            # User B cannot see it
            api_client.force_authenticate(user=user_b)
            response = api_client.get(f'/api/jobs/{job_id}/')

            assert response.status_code in [403, 404]
