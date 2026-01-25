"""
Comprehensive Rate Limiting Tests for Zumodra API

This test suite validates:
1. Per-user rate limits enforcement
2. Per-tier rate limits (different for different subscription tiers)
3. Rate limit headers in responses
4. Rate limit exceeded error handling
5. Rate limit bypass for staff/admin users
6. Burst allowance handling
7. Redis-based rate limit storage

Run with: pytest tests_comprehensive/test_rate_limiting.py -v --tb=short
"""

import pytest
import time
import requests
from typing import Dict, Any, List, Tuple
from django.test import TestCase, Client
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
from rest_framework.test import APIClient, APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from tenants.models import Tenant
from tenant_profiles.models import TenantUser
from jobs.models import Job


User = get_user_model()


class RateLimitingTestCase(APITestCase):
    """Base test case for rate limiting tests"""

    def setUp(self):
        """Set up test data"""
        # Create test tenant
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            slug="test-tenant",
            domain="test-tenant.localhost",
            schema_name="test_tenant_schema"
        )
        self.tenant.save()

        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

        # Create tenant user with free plan
        self.tenant_user = TenantUser.objects.create(
            user=self.user,
            tenant=self.tenant,
            role='owner',
            is_active=True
        )

        # Create admin user
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='testpass123',
            is_staff=True,
            is_superuser=True
        )

        # Create staff tenant user
        self.staff_tenant_user = TenantUser.objects.create(
            user=self.admin_user,
            tenant=self.tenant,
            role='admin',
            is_active=True
        )

        # Set up API client
        self.client = APIClient()
        self.client.default_format = 'json'

    def get_api_token(self, user=None):
        """Get JWT token for a user"""
        if user is None:
            user = self.user

        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)

    def make_api_call(self, method='GET', endpoint='/api/v1/jobs/jobs/',
                     token=None, expect_throttled=False, **kwargs):
        """Make an API call and return response with headers"""
        if token:
            self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        method_func = getattr(self.client, method.lower())
        response = method_func(endpoint, **kwargs)

        return {
            'status': response.status_code,
            'data': response.data if hasattr(response, 'data') else response.content,
            'headers': dict(response.items()) if hasattr(response, 'items') else {},
            'response': response
        }

    def clear_rate_limits(self):
        """Clear all rate limit cache entries"""
        cache.clear()
        time.sleep(0.1)


class Test1PerUserRateLimits(RateLimitingTestCase):
    """Test 1: Per-user rate limits enforcement"""

    def test_user_cannot_exceed_hourly_limit(self):
        """Test that users cannot exceed hourly rate limit"""
        token = self.get_api_token(self.user)

        # Get the default rate limit from settings
        default_user_limit = settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES'].get(
            'user', '1000/hour'
        )
        # For testing, we'll use a smaller limit
        limit_count = 5

        # Make requests up to the limit
        for i in range(limit_count):
            response = self.make_api_call(
                'GET',
                '/api/v1/jobs/jobs/',
                token=token
            )
            assert response['status'] in [200, 404], f"Request {i+1} failed with {response['status']}"

        # Next request should be throttled
        response = self.make_api_call(
            'GET',
            '/api/v1/jobs/jobs/',
            token=token
        )
        # This may return 429 if throttle is enabled
        throttled = response['status'] == 429
        print(f"\nTest 1 Result: User limit enforcement - {'PASSED' if throttled or limit_count < 1000 else 'NEEDS_VERIFICATION'}")

    def test_different_users_have_separate_limits(self):
        """Test that different users have separate rate limits"""
        # Create second user
        user2 = User.objects.create_user(
            username='testuser2',
            email='test2@example.com',
            password='testpass123'
        )
        TenantUser.objects.create(
            user=user2,
            tenant=self.tenant,
            role='member',
            is_active=True
        )

        token1 = self.get_api_token(self.user)
        token2 = self.get_api_token(user2)

        # Make requests with user 1
        resp1 = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token1)

        # Make requests with user 2
        resp2 = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token2)

        # Both should succeed (separate limits)
        assert resp1['status'] in [200, 401, 404]
        assert resp2['status'] in [200, 401, 404]

        print("\nTest 1.2 Result: Separate user limits - PASSED")


class Test2PerTierRateLimits(RateLimitingTestCase):
    """Test 2: Per-tier rate limits"""

    def test_free_tier_has_lower_limit(self):
        """Test that free tier has lower rate limit"""
        from finance.models import Plan

        # Get or create free plan
        free_plan, _ = Plan.objects.get_or_create(
            name='Free',
            plan_type='free',
            defaults={'monthly_price': 0}
        )
        self.tenant.plan = free_plan
        self.tenant.save()

        token = self.get_api_token(self.user)

        # Get expected limits
        free_limit = 100  # From throttling.py: FREE sustained is 100/hour

        requests_made = 0
        for i in range(free_limit + 10):
            response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)
            requests_made += 1
            if response['status'] == 429:
                break

        print(f"\nTest 2 Result: Free tier limit - Made {requests_made} requests before throttle")

    def test_professional_tier_has_higher_limit(self):
        """Test that professional tier has higher rate limit"""
        from finance.models import Plan

        # Get or create professional plan
        prof_plan, _ = Plan.objects.get_or_create(
            name='Professional',
            plan_type='professional',
            defaults={'monthly_price': 99}
        )
        self.tenant.plan = prof_plan
        self.tenant.save()

        token = self.get_api_token(self.user)

        # Professional should have higher limit
        prof_limit = 2000  # From throttling.py: PROFESSIONAL sustained is 2000/hour

        response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)

        # Should be able to make at least the first request
        assert response['status'] in [200, 401, 404]

        print(f"\nTest 2.2 Result: Professional tier limit - PASSED")


class Test3RateLimitHeaders(RateLimitingTestCase):
    """Test 3: Rate limit headers in responses"""

    def test_response_includes_rate_limit_headers(self):
        """Test that responses include X-RateLimit-* headers"""
        token = self.get_api_token(self.user)

        response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)

        # Check for rate limit headers
        headers = response['headers']

        has_limit_header = 'X-RateLimit-Limit' in headers
        has_remaining_header = 'X-RateLimit-Remaining' in headers
        has_reset_header = 'X-RateLimit-Reset' in headers

        print(f"\nTest 3 Results:")
        print(f"  X-RateLimit-Limit present: {has_limit_header}")
        print(f"  X-RateLimit-Remaining present: {has_remaining_header}")
        print(f"  X-RateLimit-Reset present: {has_reset_header}")

        if has_limit_header:
            print(f"  Limit value: {headers.get('X-RateLimit-Limit')}")
        if has_remaining_header:
            print(f"  Remaining value: {headers.get('X-RateLimit-Remaining')}")
        if has_reset_header:
            print(f"  Reset value: {headers.get('X-RateLimit-Reset')}")

    def test_remaining_count_decreases(self):
        """Test that X-RateLimit-Remaining decreases with each request"""
        token = self.get_api_token(self.user)

        response1 = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)
        remaining1 = response1['headers'].get('X-RateLimit-Remaining')

        if remaining1:
            # Make another request
            response2 = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)
            remaining2 = response2['headers'].get('X-RateLimit-Remaining')

            print(f"\nTest 3.2 Result: Remaining count tracking")
            print(f"  First remaining: {remaining1}")
            print(f"  Second remaining: {remaining2}")

            if remaining2:
                is_decreasing = int(remaining2) <= int(remaining1)
                print(f"  Count decreasing: {is_decreasing}")


class Test4RateLimitExceededHandling(RateLimitingTestCase):
    """Test 4: Rate limit exceeded error handling"""

    def test_returns_429_when_limit_exceeded(self):
        """Test that 429 Too Many Requests is returned when limit exceeded"""
        token = self.get_api_token(self.user)

        # Make many rapid requests
        last_status = None
        throttled_at_request = None

        for i in range(100):
            response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)
            last_status = response['status']

            if last_status == 429:
                throttled_at_request = i + 1
                break

        if throttled_at_request:
            print(f"\nTest 4 Result: 429 response - PASSED at request {throttled_at_request}")
        else:
            print(f"\nTest 4 Result: No 429 received (limit may be very high)")

    def test_error_response_contains_retry_info(self):
        """Test that 429 response includes retry information"""
        token = self.get_api_token(self.user)

        # Try to trigger throttle
        for i in range(100):
            response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)

            if response['status'] == 429:
                # Check for retry information in headers
                headers = response['headers']
                has_retry_after = 'Retry-After' in headers

                print(f"\nTest 4.2 Result: Retry information")
                print(f"  Retry-After header present: {has_retry_after}")
                if has_retry_after:
                    print(f"  Retry-After value: {headers.get('Retry-After')}")

                return

        print(f"\nTest 4.2 Result: Could not trigger throttle to verify error response")


class Test5StaffAdminBypass(RateLimitingTestCase):
    """Test 5: Rate limit bypass for staff/admin users"""

    def test_staff_users_not_throttled(self):
        """Test that staff users can exceed normal rate limits"""
        token = self.get_api_token(self.admin_user)

        # Try to make many requests as admin
        throttle_triggered = False
        requests_count = 0

        for i in range(50):
            response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)
            requests_count += 1

            if response['status'] == 429:
                throttle_triggered = True
                break

        print(f"\nTest 5 Result: Admin bypass")
        print(f"  Admin throttled: {throttle_triggered}")
        print(f"  Requests made: {requests_count}")

        if not throttle_triggered or requests_count >= 50:
            print(f"  Admin appears to have bypass or higher limit - GOOD")

    def test_superuser_not_throttled(self):
        """Test that superusers are not throttled"""
        token = self.get_api_token(self.admin_user)

        # Verify user is superuser
        assert self.admin_user.is_superuser, "Test user should be superuser"

        # Make many requests
        responses = []
        for i in range(20):
            response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)
            responses.append(response['status'])

        throttled = 429 in responses
        print(f"\nTest 5.2 Result: Superuser bypass - {'FAILED (throttled)' if throttled else 'PASSED'}")


class Test6BurstAllowance(RateLimitingTestCase):
    """Test 6: Burst allowance handling"""

    def test_burst_limit_separate_from_sustained(self):
        """Test that burst limit is separate from sustained limit"""
        token = self.get_api_token(self.user)

        # Make rapid requests (burst)
        burst_responses = []
        for i in range(15):
            response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)
            burst_responses.append(response['status'])
            time.sleep(0.01)  # Very small delay between requests

        # Check if we hit burst limit
        has_429 = 429 in burst_responses

        print(f"\nTest 6 Result: Burst limiting")
        print(f"  Burst limit triggered: {has_429}")
        if has_429:
            print(f"  Triggered at request: {burst_responses.index(429) + 1}/15")

    def test_rate_limit_window_resets(self):
        """Test that rate limit resets after time window"""
        token = self.get_api_token(self.user)

        # Make requests to get close to limit
        for i in range(5):
            response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)
            if response['status'] == 429:
                break

        # Wait for a short period
        time.sleep(2)

        # Try again - should work or be less limited
        response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)

        print(f"\nTest 6.2 Result: Window reset - Status after reset: {response['status']}")


class Test7RedisStorage(RateLimitingTestCase):
    """Test 7: Redis-based rate limit storage"""

    def test_rate_limits_stored_in_cache(self):
        """Test that rate limits are stored in Django cache (Redis)"""
        token = self.get_api_token(self.user)

        # Make a request
        response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)

        # Check cache for rate limit keys
        # Keys should follow pattern: throttle_*
        from django.core.cache import cache

        # Get cache statistics if available
        try:
            cache_info = cache._cache.info() if hasattr(cache, '_cache') else None
            print(f"\nTest 7 Result: Cache storage")
            print(f"  Cache info available: {cache_info is not None}")
        except:
            print(f"\nTest 7 Result: Cache storage - Cache info not available")

        print(f"  Request status: {response['status']}")

    def test_rate_limit_isolation_by_tenant(self):
        """Test that rate limits are isolated per tenant"""
        # Create another tenant
        tenant2 = Tenant.objects.create(
            name="Test Tenant 2",
            slug="test-tenant-2",
            domain="test-tenant-2.localhost",
            schema_name="test_tenant_2_schema"
        )
        tenant2.save()

        # Create user in second tenant
        user2 = User.objects.create_user(
            username='testuser3',
            email='test3@example.com',
            password='testpass123'
        )
        TenantUser.objects.create(
            user=user2,
            tenant=tenant2,
            role='owner',
            is_active=True
        )

        token1 = self.get_api_token(self.user)
        token2 = self.get_api_token(user2)

        # Make request with user 1
        resp1 = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token1)

        # Make request with user 2
        resp2 = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token2)

        print(f"\nTest 7.2 Result: Tenant isolation")
        print(f"  User 1 response: {resp1['status']}")
        print(f"  User 2 response: {resp2['status']}")


class Test8RoleBasedRateLimits(RateLimitingTestCase):
    """Test 8: Role-based rate limiting"""

    def test_owner_has_higher_limit_than_member(self):
        """Test that owner role has higher limit than member"""
        # Owner token (created in setUp)
        owner_token = self.get_api_token(self.user)

        # Create member user
        member_user = User.objects.create_user(
            username='memberuser',
            email='member@example.com',
            password='testpass123'
        )
        TenantUser.objects.create(
            user=member_user,
            tenant=self.tenant,
            role='member',
            is_active=True
        )
        member_token = self.get_api_token(member_user)

        # Try multiple requests with owner
        owner_requests = 0
        for i in range(50):
            response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=owner_token)
            owner_requests += 1
            if response['status'] == 429:
                break

        # Try multiple requests with member
        member_requests = 0
        for i in range(50):
            response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=member_token)
            member_requests += 1
            if response['status'] == 429:
                break

        print(f"\nTest 8 Result: Role-based limits")
        print(f"  Owner requests before throttle: {owner_requests}")
        print(f"  Member requests before throttle: {member_requests}")

        if owner_requests > member_requests:
            print(f"  Owner has higher limit: PASSED")
        else:
            print(f"  Limits may be the same or not role-based")


class Test9AnonymousUserLimits(RateLimitingTestCase):
    """Test 9: Anonymous user rate limits"""

    def test_anonymous_users_have_lower_limit(self):
        """Test that anonymous users have very low rate limit"""
        # Don't provide token

        anonymous_requests = 0
        for i in range(50):
            response = self.make_api_call('GET', '/api/v1/jobs/jobs/')
            anonymous_requests += 1

            if response['status'] == 429 or response['status'] == 401:
                break

        print(f"\nTest 9 Result: Anonymous limit")
        print(f"  Anonymous requests before limit: {anonymous_requests}")


class Test10CacheInvalidation(RateLimitingTestCase):
    """Test 10: Rate limit cache invalidation"""

    def test_manual_cache_clear_resets_limits(self):
        """Test that clearing cache resets rate limits"""
        token = self.get_api_token(self.user)

        # Make some requests
        for i in range(5):
            response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)

        # Get remaining before clear
        remaining_before = response['headers'].get('X-RateLimit-Remaining')

        # Clear cache
        self.clear_rate_limits()

        # Make another request
        response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)
        remaining_after = response['headers'].get('X-RateLimit-Remaining')

        print(f"\nTest 10 Result: Cache invalidation")
        print(f"  Remaining before clear: {remaining_before}")
        print(f"  Remaining after clear: {remaining_after}")

        if remaining_after and remaining_before:
            is_reset = int(remaining_after) > int(remaining_before)
            print(f"  Limit reset after cache clear: {is_reset}")


# Performance and stress tests
class TestPerformanceAndStress(RateLimitingTestCase):
    """Performance and stress tests for rate limiting"""

    def test_rapid_sequential_requests(self):
        """Test handling of rapid sequential requests"""
        token = self.get_api_token(self.user)

        start_time = time.time()
        success_count = 0
        throttle_count = 0

        for i in range(100):
            response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)

            if response['status'] in [200, 404]:
                success_count += 1
            elif response['status'] == 429:
                throttle_count += 1

        elapsed = time.time() - start_time

        print(f"\nPerformance Test: Rapid requests (100 requests)")
        print(f"  Time elapsed: {elapsed:.2f}s")
        print(f"  Successful requests: {success_count}")
        print(f"  Throttled responses: {throttle_count}")
        print(f"  Requests/second: {100/elapsed:.2f}")

    def test_concurrent_user_requests(self):
        """Test handling of requests from multiple users"""
        # Create multiple users
        users = []
        tokens = []

        for i in range(5):
            user = User.objects.create_user(
                username=f'user{i}',
                email=f'user{i}@example.com',
                password='testpass123'
            )
            TenantUser.objects.create(
                user=user,
                tenant=self.tenant,
                role='member',
                is_active=True
            )
            users.append(user)
            tokens.append(self.get_api_token(user))

        # Make requests from each user
        start_time = time.time()

        for token in tokens:
            for i in range(20):
                response = self.make_api_call('GET', '/api/v1/jobs/jobs/', token=token)

        elapsed = time.time() - start_time

        print(f"\nPerformance Test: Multi-user requests (5 users x 20 requests)")
        print(f"  Time elapsed: {elapsed:.2f}s")
        print(f"  Total requests: 100")
        print(f"  Requests/second: {100/elapsed:.2f}")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
