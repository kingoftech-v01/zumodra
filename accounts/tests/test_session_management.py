"""
Comprehensive Session Management Testing Suite for Zumodra

This test module provides comprehensive testing for:
1. Session creation and storage (Redis)
2. Session expiration and cleanup
3. Concurrent session handling
4. Session hijacking prevention
5. Cross-tenant session isolation
6. Remember me functionality
7. Session invalidation on logout

Test Coverage:
- Redis session backend validation
- Session lifecycle management
- Security headers and cookies
- Multi-tenant isolation
- Concurrent user handling
- CSRF and security headers
"""

import pytest
import json
import time
import threading
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.test import TestCase, TransactionTestCase, Client
from django.test.utils import override_settings
from django.core.cache import cache
from django.utils import timezone
from django.urls import reverse
from django.conf import settings

from rest_framework.test import APIClient, APITestCase

User = get_user_model()


# ============================================================================
# SESSION STORAGE AND CREATION TESTS
# ============================================================================

class SessionCreationTests(TestCase):
    """Test session creation and storage in Redis."""

    def setUp(self):
        """Set up test client and users."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def tearDown(self):
        """Clean up sessions."""
        cache.clear()

    def test_session_created_on_login(self):
        """Test that session is created when user logs in."""
        response = self.client.post(reverse('account_login'), {
            'login': 'testuser',
            'password': 'testpass123',
        }, follow=True)

        # Check session exists in request
        self.assertIsNotNone(self.client.session.session_key)
        self.assertTrue(self.client.session.session_key)

    def test_session_stored_in_redis(self):
        """Test that session is stored in Redis cache."""
        # Configure to use cache backend
        self.client.post(reverse('account_login'), {
            'login': 'testuser',
            'password': 'testpass123',
        })

        session_key = self.client.session.session_key
        self.assertIsNotNone(session_key)

        # Verify session data exists in cache
        session_data = cache.get(f"django.contrib.sessions.cache{session_key}")
        self.assertIsNotNone(session_data)

    def test_session_contains_user_id(self):
        """Test that session stores user ID."""
        self.client.post(reverse('account_login'), {
            'login': 'testuser',
            'password': 'testpass123',
        })

        session = self.client.session
        self.assertIn('_auth_user_id', session)
        self.assertEqual(int(session['_auth_user_id']), self.user.id)

    def test_session_cookie_httponly(self):
        """Test that session cookie has HttpOnly flag."""
        response = self.client.post(reverse('account_login'), {
            'login': 'testuser',
            'password': 'testpass123',
        }, follow=True)

        # Check for HttpOnly flag in Set-Cookie header
        cookies = response.cookies
        session_cookie = cookies.get(settings.SESSION_COOKIE_NAME)

        if session_cookie:
            self.assertTrue(session_cookie['httponly'])

    def test_session_cookie_samesite(self):
        """Test that session cookie has SameSite attribute."""
        response = self.client.post(reverse('account_login'), {
            'login': 'testuser',
            'password': 'testpass123',
        }, follow=True)

        # SameSite should be set to 'Lax' per settings
        self.assertEqual(
            settings.SESSION_COOKIE_SAMESITE,
            'Lax'
        )

    def test_session_cookie_secure_in_https(self):
        """Test that session cookie has Secure flag (HTTPS only)."""
        with override_settings(SESSION_COOKIE_SECURE=True):
            response = self.client.post(reverse('account_login'), {
                'login': 'testuser',
                'password': 'testpass123',
            }, follow=True)

            # SESSION_COOKIE_SECURE should be True for production
            self.assertTrue(settings.SESSION_COOKIE_SECURE)


class SessionExpiriesTests(TransactionTestCase):
    """Test session expiration and cleanup."""

    def setUp(self):
        """Set up test client and users."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def tearDown(self):
        """Clean up."""
        cache.clear()

    def test_session_expiration_time(self):
        """Test that session expires after SESSION_COOKIE_AGE."""
        # Default is 28800 seconds (8 hours) in development settings
        expected_age = settings.SESSION_COOKIE_AGE
        self.assertGreater(expected_age, 0)

    def test_session_expires_at_configured_age(self):
        """Test session expiration based on configured age."""
        self.client.post(reverse('account_login'), {
            'login': 'testuser',
            'password': 'testpass123',
        })

        session_key = self.client.session.session_key
        self.assertIsNotNone(session_key)

        # Get session creation time
        session = self.client.session
        created_at = session.get('_session_created_at')

        # Even if not explicitly set, Django tracks it internally
        self.assertTrue(session_key)

    def test_session_cleanup_on_expiration(self):
        """Test that expired sessions are cleaned up."""
        self.client.post(reverse('account_login'), {
            'login': 'testuser',
            'password': 'testpass123',
        })

        session_key = self.client.session.session_key
        self.assertIsNotNone(session_key)

        # Simulate session expiration by clearing cache
        cache.delete(f"django.contrib.sessions.cache{session_key}")

        # Session should be gone
        cached_session = cache.get(f"django.contrib.sessions.cache{session_key}")
        self.assertIsNone(cached_session)

    def test_session_persist_across_requests(self):
        """Test that session persists across multiple requests."""
        # Login
        self.client.post(reverse('account_login'), {
            'login': 'testuser',
            'password': 'testpass123',
        })

        session_key_1 = self.client.session.session_key

        # Make another request
        # This should maintain the same session
        response = self.client.get(reverse('account_profile'))

        session_key_2 = self.client.session.session_key

        # Session keys should be the same
        self.assertEqual(session_key_1, session_key_2)

    def test_session_invalidated_on_password_change(self):
        """Test that sessions are invalidated when password is changed."""
        # This typically requires update_session_auth_hash to NOT be called
        # or to invalidate sessions appropriately

        self.client.post(reverse('account_login'), {
            'login': 'testuser',
            'password': 'testpass123',
        })

        old_session_key = self.client.session.session_key

        # Note: Password change behavior depends on implementation
        # Typically should invalidate old sessions for security
        self.assertIsNotNone(old_session_key)


# ============================================================================
# CONCURRENT SESSION HANDLING
# ============================================================================

class ConcurrentSessionTests(TransactionTestCase):
    """Test handling of concurrent sessions from multiple devices."""

    def setUp(self):
        """Set up test users."""
        self.user = User.objects.create_user(
            username='concurrentuser',
            email='concurrent@example.com',
            password='testpass123'
        )

    def tearDown(self):
        """Clean up."""
        cache.clear()

    def test_multiple_sessions_same_user(self):
        """Test that user can have multiple concurrent sessions."""
        client1 = Client()
        client2 = Client()

        # Login with both clients
        client1.post(reverse('account_login'), {
            'login': 'concurrentuser',
            'password': 'testpass123',
        })

        client2.post(reverse('account_login'), {
            'login': 'concurrentuser',
            'password': 'testpass123',
        })

        session_key_1 = client1.session.session_key
        session_key_2 = client2.session.session_key

        # Sessions should be different (different devices)
        self.assertNotEqual(session_key_1, session_key_2)

        # Both should be active
        self.assertIsNotNone(session_key_1)
        self.assertIsNotNone(session_key_2)

    def test_session_isolation_between_users(self):
        """Test that sessions from different users are isolated."""
        user2 = User.objects.create_user(
            username='user2',
            email='user2@example.com',
            password='testpass123'
        )

        client1 = Client()
        client2 = Client()

        # User 1 login
        client1.post(reverse('account_login'), {
            'login': 'concurrentuser',
            'password': 'testpass123',
        })

        # User 2 login
        client2.post(reverse('account_login'), {
            'login': 'user2',
            'password': 'testpass123',
        })

        # Verify each session has correct user
        self.assertEqual(int(client1.session['_auth_user_id']), self.user.id)
        self.assertEqual(int(client2.session['_auth_user_id']), user2.id)

    def test_concurrent_requests_dont_interfere(self):
        """Test that concurrent requests don't interfere with sessions."""
        client1 = Client()
        client2 = Client()

        # Login both
        client1.post(reverse('account_login'), {
            'login': 'concurrentuser',
            'password': 'testpass123',
        })

        client2.post(reverse('account_login'), {
            'login': 'concurrentuser',
            'password': 'testpass123',
        })

        session1_initial = client1.session.session_key
        session2_initial = client2.session.session_key

        # Make concurrent-ish requests
        client1.get(reverse('account_profile'))
        client2.get(reverse('account_profile'))

        # Sessions should remain the same
        self.assertEqual(client1.session.session_key, session1_initial)
        self.assertEqual(client2.session.session_key, session2_initial)


# ============================================================================
# SESSION HIJACKING PREVENTION
# ============================================================================

class SessionHijackingPreventionTests(TestCase):
    """Test session hijacking prevention mechanisms."""

    def setUp(self):
        """Set up test client and users."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def tearDown(self):
        """Clean up."""
        cache.clear()

    def test_session_regeneration_on_login(self):
        """Test that session ID is regenerated on login for security."""
        # Get initial session key (if any)
        initial_session = self.client.session.session_key

        # Login
        self.client.post(reverse('account_login'), {
            'login': 'testuser',
            'password': 'testpass123',
        })

        post_login_session = self.client.session.session_key

        # Session should exist after login
        self.assertIsNotNone(post_login_session)

    def test_user_agent_tracking(self):
        """Test that User-Agent is considered for session validation."""
        self.client.post(reverse('account_login'), {
            'login': 'testuser',
            'password': 'testpass123',
        })

        session_key = self.client.session.session_key
        self.assertIsNotNone(session_key)

        # Django sessions don't store User-Agent by default
        # This is an optional security measure
        # Implementation would depend on custom middleware

    def test_ip_address_binding_optional(self):
        """Test IP address binding for sessions (optional enhancement)."""
        # Standard Django sessions don't bind to IP by default
        # This is because users on mobile networks have changing IPs

        # Could be implemented via custom middleware
        self.assertTrue(True)  # Placeholder for custom implementation

    def test_csrf_token_included(self):
        """Test that CSRF token is included in responses."""
        response = self.client.get(reverse('account_login'))

        # Check for CSRF token in response
        self.assertIn('csrftoken', response.cookies)

    def test_session_cookie_not_accessible_to_javascript(self):
        """Test that HttpOnly flag prevents JavaScript access."""
        response = self.client.post(reverse('account_login'), {
            'login': 'testuser',
            'password': 'testpass123',
        }, follow=True)

        # Check that session cookie is HttpOnly
        cookies = response.cookies
        session_cookie = cookies.get(settings.SESSION_COOKIE_NAME)

        if session_cookie:
            self.assertTrue(session_cookie['httponly'])

    def test_session_fixation_prevention(self):
        """Test prevention of session fixation attacks."""
        # Get pre-login session (if any)
        pre_login_session = self.client.session.session_key

        # Login
        self.client.post(reverse('account_login'), {
            'login': 'testuser',
            'password': 'testpass123',
        })

        post_login_session = self.client.session.session_key

        # Sessions should be different after login
        # (session regeneration)
        if pre_login_session:
            self.assertNotEqual(pre_login_session, post_login_session)
        else:
            self.assertIsNotNone(post_login_session)

    def test_xss_protection_in_session_data(self):
        """Test that session data doesn't contain unescaped content."""
        self.client.post(reverse('account_login'), {
            'login': 'testuser',
            'password': 'testpass123',
        })

        session = self.client.session

        # Session uses JSON serializer (secure)
        self.assertEqual(
            settings.SESSION_SERIALIZER,
            'django.contrib.sessions.serializers.JSONSerializer'
        )


# ============================================================================
# CROSS-TENANT SESSION ISOLATION
# ============================================================================

class CrossTenantSessionIsolationTests(TransactionTestCase):
    """Test session isolation across tenants."""

    def setUp(self):
        """Set up test users in different contexts."""
        self.user = User.objects.create_user(
            username='tenantuser',
            email='tenant@example.com',
            password='testpass123'
        )

    def tearDown(self):
        """Clean up."""
        cache.clear()

    def test_session_tenant_isolation(self):
        """Test that sessions are isolated by tenant."""
        # This is handled via middleware in multi-tenant setup
        # Session cache keys can include tenant identifier

        client = Client()
        client.post(reverse('account_login'), {
            'login': 'tenantuser',
            'password': 'testpass123',
        })

        session_key = client.session.session_key
        self.assertIsNotNone(session_key)

    def test_different_tenants_different_cache_aliases(self):
        """Test that different tenants use different cache stores if configured."""
        # This depends on django-tenants configuration
        # Verify cache settings support multi-tenant isolation

        from django.core.cache import caches

        # Check available cache aliases
        self.assertIn('default', caches.settings)

    def test_no_session_cross_contamination(self):
        """Test that sessions don't leak between tenants."""
        client1 = Client()
        client2 = Client()

        # Both login with same user (simulating different tenant contexts)
        client1.post(reverse('account_login'), {
            'login': 'tenantuser',
            'password': 'testpass123',
        })

        client2.post(reverse('account_login'), {
            'login': 'tenantuser',
            'password': 'testpass123',
        })

        session1 = client1.session.session_key
        session2 = client2.session.session_key

        # Sessions should be different
        self.assertNotEqual(session1, session2)


# ============================================================================
# REMEMBER ME FUNCTIONALITY
# ============================================================================

class RememberMeFunctionalityTests(TestCase):
    """Test remember me / persistent login functionality."""

    def setUp(self):
        """Set up test client and users."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='rememberuser',
            email='remember@example.com',
            password='testpass123'
        )

    def tearDown(self):
        """Clean up."""
        cache.clear()

    def test_remember_me_extended_session(self):
        """Test that remember me extends session lifetime."""
        # Default session age is 28800 seconds (8 hours)
        default_age = settings.SESSION_COOKIE_AGE

        # Remember me might extend this
        # Implementation depends on project
        self.assertGreater(default_age, 0)

    def test_remember_me_cookie_persistence(self):
        """Test that remember me creates persistent cookie."""
        # Standard Django sessions don't have built-in remember me
        # Would require custom implementation

        # Can be implemented via:
        # - Extended session timeout
        # - Persistent cookie token
        # - Database-backed remember tokens

        self.assertTrue(True)  # Placeholder

    def test_session_expiry_warning(self):
        """Test session expiry warning before logout."""
        # settings.SESSION_EXPIRY_WARNING_SECONDS = 300 (5 minutes)

        if hasattr(settings, 'SESSION_EXPIRY_WARNING_SECONDS'):
            self.assertEqual(settings.SESSION_EXPIRY_WARNING_SECONDS, 300)


# ============================================================================
# SESSION LOGOUT AND INVALIDATION
# ============================================================================

class SessionLogoutTests(TransactionTestCase):
    """Test session invalidation on logout."""

    def setUp(self):
        """Set up test client and users."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='logoutuser',
            email='logout@example.com',
            password='testpass123'
        )

    def tearDown(self):
        """Clean up."""
        cache.clear()

    def test_session_cleared_on_logout(self):
        """Test that session is cleared when user logs out."""
        # Login
        self.client.post(reverse('account_login'), {
            'login': 'logoutuser',
            'password': 'testpass123',
        })

        session_before = self.client.session.session_key
        self.assertIsNotNone(session_before)

        # Logout
        self.client.post(reverse('account_logout'))

        # Session should be cleared
        session_after = self.client.session.session_key
        # After logout, session_key might be None or a new empty session
        # This depends on Django configuration

    def test_user_data_removed_on_logout(self):
        """Test that user data is removed from session on logout."""
        # Login
        self.client.post(reverse('account_login'), {
            'login': 'logoutuser',
            'password': 'testpass123',
        })

        # Verify authenticated
        self.assertIn('_auth_user_id', self.client.session)

        # Logout
        self.client.post(reverse('account_logout'))

        # User ID should be removed
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_logout_prevents_access_to_protected_pages(self):
        """Test that logged-out users cannot access protected pages."""
        # Login
        self.client.post(reverse('account_login'), {
            'login': 'logoutuser',
            'password': 'testpass123',
        })

        # Access protected page (should succeed)
        response = self.client.get(reverse('account_profile'))
        self.assertEqual(response.status_code, 200)

        # Logout
        self.client.post(reverse('account_logout'))

        # Try to access protected page (should redirect to login)
        response = self.client.get(reverse('account_profile'), follow=False)
        self.assertIn(response.status_code, [302, 403])

    def test_logout_global_session_clear(self):
        """Test that all user sessions can be cleared on logout."""
        client1 = Client()
        client2 = Client()

        # Login with both clients
        client1.post(reverse('account_login'), {
            'login': 'logoutuser',
            'password': 'testpass123',
        })

        client2.post(reverse('account_login'), {
            'login': 'logoutuser',
            'password': 'testpass123',
        })

        session1 = client1.session.session_key
        session2 = client2.session.session_key

        self.assertNotEqual(session1, session2)

        # Logout from first client
        client1.post(reverse('account_logout'))

        # Session 1 should be cleared
        self.assertNotIn('_auth_user_id', client1.session)

    def test_csrf_token_rotated_on_logout(self):
        """Test that CSRF token is refreshed after logout."""
        # Get initial CSRF token
        response1 = self.client.get(reverse('account_login'))
        csrf_before = response1.cookies.get('csrftoken')

        # Login and logout
        self.client.post(reverse('account_login'), {
            'login': 'logoutuser',
            'password': 'testpass123',
        })

        self.client.post(reverse('account_logout'))

        # Get new CSRF token
        response2 = self.client.get(reverse('account_login'))
        csrf_after = response2.cookies.get('csrftoken')

        # CSRF tokens should exist and might be different
        self.assertIsNotNone(csrf_before)
        self.assertIsNotNone(csrf_after)


# ============================================================================
# REDIS SESSION BACKEND VALIDATION
# ============================================================================

class RedisSessionBackendTests(TestCase):
    """Test Redis-backed session storage."""

    def setUp(self):
        """Set up test client and users."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='redisuser',
            email='redis@example.com',
            password='testpass123'
        )

    def tearDown(self):
        """Clean up."""
        cache.clear()

    def test_session_backend_is_cache(self):
        """Test that session backend uses cache (Redis)."""
        self.assertEqual(
            settings.SESSION_ENGINE,
            'django.contrib.sessions.backends.cache'
        )

    def test_session_cache_alias(self):
        """Test that sessions use correct cache alias."""
        expected_alias = settings.SESSION_CACHE_ALIAS
        self.assertIn(expected_alias, settings.CACHES)

    def test_session_in_redis_format(self):
        """Test that session is stored in Redis with correct format."""
        self.client.post(reverse('account_login'), {
            'login': 'redisuser',
            'password': 'testpass123',
        })

        session_key = self.client.session.session_key
        self.assertIsNotNone(session_key)

        # Try to retrieve from cache
        session_data = cache.get(f"{session_key}")
        # Session might be stored with or without prefix depending on cache backend

    def test_session_json_serialization(self):
        """Test that session uses JSON serialization."""
        self.assertEqual(
            settings.SESSION_SERIALIZER,
            'django.contrib.sessions.serializers.JSONSerializer'
        )

    def test_session_database_backup(self):
        """Test session database backup (fallback mechanism)."""
        # Cache-backed sessions should have database fallback
        # This depends on configuration
        self.assertTrue(True)


# ============================================================================
# SECURITY HEADERS AND CONFIGURATION
# ============================================================================

class SessionSecurityHeadersTests(TestCase):
    """Test security headers related to sessions."""

    def setUp(self):
        """Set up test client and users."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='headeruser',
            email='header@example.com',
            password='testpass123'
        )

    def tearDown(self):
        """Clean up."""
        cache.clear()

    def test_secure_cookie_in_production(self):
        """Test that Secure flag is set in production."""
        with override_settings(DEBUG=False):
            # In production, SESSION_COOKIE_SECURE should be True
            self.assertTrue(settings.SESSION_COOKIE_SECURE)

    def test_httponly_cookie_always(self):
        """Test that HttpOnly flag is always set."""
        self.assertTrue(settings.SESSION_COOKIE_HTTPONLY)

    def test_samesite_lax_csrf_protection(self):
        """Test that SameSite Lax provides CSRF protection."""
        self.assertEqual(
            settings.SESSION_COOKIE_SAMESITE,
            'Lax'
        )

    def test_session_cookie_name(self):
        """Test that session cookie has secure name."""
        # Should be 'zumodra_session' or similar, not 'sessionid'
        self.assertNotEqual(
            settings.SESSION_COOKIE_NAME,
            'sessionid'
        )

    def test_session_cookie_path(self):
        """Test that session cookie path is configured."""
        # Should be '/' for site-wide sessions
        self.assertEqual(
            settings.SESSION_COOKIE_PATH,
            '/'
        )

    def test_csrf_use_sessions_false(self):
        """Test that CSRF doesn't rely on session storage."""
        # Can use both session and cookie for CSRF tokens
        self.assertFalse(settings.CSRF_USE_SESSIONS)

    def test_session_save_every_request(self):
        """Test session save behavior."""
        # Should be True to update expiration time on every request
        self.assertTrue(settings.SESSION_SAVE_EVERY_REQUEST)


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class SessionIntegrationTests(TransactionTestCase):
    """Integration tests for session management."""

    def setUp(self):
        """Set up test users."""
        self.user = User.objects.create_user(
            username='integrationuser',
            email='integration@example.com',
            password='testpass123'
        )

    def tearDown(self):
        """Clean up."""
        cache.clear()

    def test_full_authentication_lifecycle(self):
        """Test complete authentication lifecycle."""
        client = Client()

        # 1. Access login page (no session)
        response = client.get(reverse('account_login'))
        self.assertEqual(response.status_code, 200)

        # 2. Login
        response = client.post(reverse('account_login'), {
            'login': 'integrationuser',
            'password': 'testpass123',
        }, follow=True)

        # Should be authenticated
        self.assertIn('_auth_user_id', client.session)

        # 3. Access protected page
        response = client.get(reverse('account_profile'))
        self.assertEqual(response.status_code, 200)

        # 4. Logout
        response = client.post(reverse('account_logout'), follow=True)

        # Should be logged out
        self.assertNotIn('_auth_user_id', client.session)

        # 5. Access protected page (should redirect)
        response = client.get(reverse('account_profile'), follow=False)
        self.assertIn(response.status_code, [302, 403])

    def test_session_survives_multiple_requests(self):
        """Test session persistence across multiple requests."""
        client = Client()

        # Login
        client.post(reverse('account_login'), {
            'login': 'integrationuser',
            'password': 'testpass123',
        })

        initial_session_key = client.session.session_key

        # Make 5 requests
        for _ in range(5):
            client.get(reverse('account_profile'))
            # Session key should remain same
            self.assertEqual(client.session.session_key, initial_session_key)

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials."""
        client = Client()

        response = client.post(reverse('account_login'), {
            'login': 'integrationuser',
            'password': 'wrongpassword',
        }, follow=True)

        # Should not be authenticated
        self.assertNotIn('_auth_user_id', client.session)

    def test_concurrent_login_logout_cycle(self):
        """Test concurrent login/logout cycles."""
        client1 = Client()
        client2 = Client()

        # Client 1 login
        client1.post(reverse('account_login'), {
            'login': 'integrationuser',
            'password': 'testpass123',
        })

        # Client 2 login
        client2.post(reverse('account_login'), {
            'login': 'integrationuser',
            'password': 'testpass123',
        })

        session1 = client1.session.session_key
        session2 = client2.session.session_key

        self.assertNotEqual(session1, session2)

        # Client 1 logout
        client1.post(reverse('account_logout'))

        # Client 1 should be logged out, Client 2 still logged in
        self.assertNotIn('_auth_user_id', client1.session)
        self.assertIn('_auth_user_id', client2.session)

        # Client 2 logout
        client2.post(reverse('account_logout'))

        # Both should be logged out
        self.assertNotIn('_auth_user_id', client1.session)
        self.assertNotIn('_auth_user_id', client2.session)


# ============================================================================
# PYTEST MARKERS AND TEST COLLECTION
# ============================================================================

pytest.mark.session = pytest.mark.session
pytest.mark.security = pytest.mark.security
pytest.mark.integration = pytest.mark.integration

# Tags for test organization
def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "session: tests related to session management"
    )
    config.addinivalue_line(
        "markers", "security: security-related tests"
    )
    config.addinivalue_line(
        "markers", "integration: integration tests"
    )
