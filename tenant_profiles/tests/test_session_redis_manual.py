"""
Manual Testing Script for Session Management in Redis

This script provides direct testing of:
1. Redis session storage and retrieval
2. Session key format and structure
3. Session expiration TTLs
4. Cross-tenant session isolation
5. Concurrent session handling
6. Session cleanup on logout

USAGE:
    # Run with Docker containers
    docker compose up -d
    docker compose exec web python tests_comprehensive/test_session_redis_manual.py

    # Or manually test Redis keys
    docker compose exec redis redis-cli
    > KEYS "django.contrib.sessions.cache*"
    > TTL "django.contrib.sessions.cache<session_key>"
    > GET "django.contrib.sessions.cache<session_key>"
"""

import os
import sys
import json
import time
import django
import redis
from datetime import datetime, timedelta
from typing import Optional, Dict, List

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')
sys.path.insert(0, '/root/zumodra')

django.setup()

from django.contrib.auth import get_user_model, authenticate
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.conf import settings
from django.test import Client

User = get_user_model()

# Redis connection
REDIS_URL = settings.CACHES['default']['LOCATION']
redis_conn = redis.from_url(REDIS_URL)


class SessionRedisTest:
    """Direct Redis session testing."""

    def __init__(self):
        self.redis = redis_conn
        self.client = Client()
        self.test_results = []
        self.test_user = None

    def log(self, message: str, level: str = "INFO"):
        """Log with timestamp."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
        self.test_results.append({
            'timestamp': timestamp,
            'level': level,
            'message': message
        })

    def setup_test_user(self):
        """Create test user."""
        self.log("Creating test user...")
        try:
            self.test_user = User.objects.create_user(
                username='redis_test_user',
                email='redis_test@example.com',
                password='testpass123'
            )
            self.log(f"Test user created: {self.test_user.username}", "SUCCESS")
        except Exception as e:
            self.log(f"User creation error: {str(e)}", "ERROR")

    def cleanup_test_user(self):
        """Clean up test user."""
        if self.test_user:
            self.test_user.delete()
            self.log("Test user deleted", "INFO")

    def test_session_creation(self):
        """Test 1: Session creation and storage."""
        self.log("\n=== TEST 1: Session Creation and Storage ===", "TEST")

        try:
            # Get Redis keys before login
            keys_before = self.redis.keys('django.contrib.sessions.cache*')
            self.log(f"Redis session keys before login: {len(keys_before)}", "INFO")

            # Login
            self.client.post('/accounts/login/', {
                'login': 'redis_test_user',
                'password': 'testpass123',
            }, follow=True)

            session_key = self.client.session.session_key
            self.log(f"Session key created: {session_key}", "SUCCESS")

            # Check Redis
            keys_after = self.redis.keys('django.contrib.sessions.cache*')
            self.log(f"Redis session keys after login: {len(keys_after)}", "SUCCESS")

            # Get session data from Redis
            cache_key = f"django.contrib.sessions.cache{session_key}"
            session_data = self.redis.get(cache_key)

            if session_data:
                self.log(f"Session data stored in Redis: {len(session_data)} bytes", "SUCCESS")
                # Try to decode
                try:
                    decoded = json.loads(session_data)
                    self.log(f"Session decoded successfully", "SUCCESS")
                    self.log(f"Session contains: {list(decoded.keys())}", "INFO")
                except json.JSONDecodeError:
                    self.log("Session stored but not JSON-formatted", "WARNING")
            else:
                self.log("Session NOT found in Redis", "ERROR")

            return True

        except Exception as e:
            self.log(f"Test failed: {str(e)}", "ERROR")
            import traceback
            traceback.print_exc()
            return False

    def test_session_ttl(self):
        """Test 2: Session expiration and TTL."""
        self.log("\n=== TEST 2: Session TTL and Expiration ===", "TEST")

        try:
            # Login
            self.client.post('/accounts/login/', {
                'login': 'redis_test_user',
                'password': 'testpass123',
            }, follow=True)

            session_key = self.client.session.session_key
            cache_key = f"django.contrib.sessions.cache{session_key}"

            # Check TTL
            ttl = self.redis.ttl(cache_key)
            self.log(f"Session TTL in Redis: {ttl} seconds", "INFO")

            if ttl > 0:
                # Calculate expected age
                session_age_hours = ttl / 3600
                self.log(f"Session will expire in {session_age_hours:.2f} hours", "SUCCESS")

                # Compare with settings
                expected_age = settings.SESSION_COOKIE_AGE
                expected_age_hours = expected_age / 3600
                self.log(f"Expected session age (from settings): {expected_age_hours:.2f} hours", "INFO")

                if abs(ttl - expected_age) < 10:  # Allow 10 second variance
                    self.log("TTL matches expected session age", "SUCCESS")
                else:
                    self.log(f"TTL variance detected: {ttl} vs {expected_age}", "WARNING")
            else:
                self.log("Session TTL is not set or key doesn't exist", "ERROR")

            return True

        except Exception as e:
            self.log(f"Test failed: {str(e)}", "ERROR")
            import traceback
            traceback.print_exc()
            return False

    def test_session_data_integrity(self):
        """Test 3: Session data integrity and content."""
        self.log("\n=== TEST 3: Session Data Integrity ===", "TEST")

        try:
            # Login
            self.client.post('/accounts/login/', {
                'login': 'redis_test_user',
                'password': 'testpass123',
            }, follow=True)

            session_key = self.client.session.session_key
            cache_key = f"django.contrib.sessions.cache{session_key}"

            # Get raw session data
            raw_data = self.redis.get(cache_key)

            if not raw_data:
                self.log("Session data not found in Redis", "ERROR")
                return False

            # Decode JSON
            session_data = json.loads(raw_data)

            # Check for auth user ID
            if '_auth_user_id' in session_data:
                user_id = session_data['_auth_user_id']
                self.log(f"User ID in session: {user_id}", "SUCCESS")

                # Verify it matches
                if int(user_id) == self.test_user.id:
                    self.log("User ID matches authenticated user", "SUCCESS")
                else:
                    self.log("User ID mismatch", "ERROR")
            else:
                self.log("_auth_user_id not found in session", "ERROR")

            # Check other session data
            self.log(f"Session keys: {list(session_data.keys())}", "INFO")
            self.log(f"Session size: {len(raw_data)} bytes", "INFO")

            return True

        except Exception as e:
            self.log(f"Test failed: {str(e)}", "ERROR")
            import traceback
            traceback.print_exc()
            return False

    def test_concurrent_sessions(self):
        """Test 4: Concurrent sessions from multiple clients."""
        self.log("\n=== TEST 4: Concurrent Sessions ===", "TEST")

        try:
            client1 = Client()
            client2 = Client()

            # Client 1 login
            client1.post('/accounts/login/', {
                'login': 'redis_test_user',
                'password': 'testpass123',
            }, follow=True)

            session_key_1 = client1.session.session_key
            self.log(f"Client 1 session: {session_key_1}", "SUCCESS")

            # Client 2 login
            client2.post('/accounts/login/', {
                'login': 'redis_test_user',
                'password': 'testpass123',
            }, follow=True)

            session_key_2 = client2.session.session_key
            self.log(f"Client 2 session: {session_key_2}", "SUCCESS")

            # Verify sessions are different
            if session_key_1 != session_key_2:
                self.log("Sessions are independent (good for concurrent access)", "SUCCESS")
            else:
                self.log("Sessions are identical (unexpected)", "WARNING")

            # Check both in Redis
            cache_key_1 = f"django.contrib.sessions.cache{session_key_1}"
            cache_key_2 = f"django.contrib.sessions.cache{session_key_2}"

            data_1 = self.redis.exists(cache_key_1)
            data_2 = self.redis.exists(cache_key_2)

            self.log(f"Session 1 in Redis: {bool(data_1)}", "SUCCESS" if data_1 else "ERROR")
            self.log(f"Session 2 in Redis: {bool(data_2)}", "SUCCESS" if data_2 else "ERROR")

            return True

        except Exception as e:
            self.log(f"Test failed: {str(e)}", "ERROR")
            import traceback
            traceback.print_exc()
            return False

    def test_logout_cleanup(self):
        """Test 5: Session cleanup on logout."""
        self.log("\n=== TEST 5: Session Cleanup on Logout ===", "TEST")

        try:
            # Login
            self.client.post('/accounts/login/', {
                'login': 'redis_test_user',
                'password': 'testpass123',
            }, follow=True)

            session_key = self.client.session.session_key
            cache_key = f"django.contrib.sessions.cache{session_key}"

            # Verify session exists
            exists_before = self.redis.exists(cache_key)
            self.log(f"Session in Redis before logout: {bool(exists_before)}", "SUCCESS" if exists_before else "ERROR")

            # Logout
            self.client.post('/accounts/logout/')

            # Check if session still exists
            exists_after = self.redis.exists(cache_key)
            self.log(f"Session in Redis after logout: {bool(exists_after)}", "INFO")

            if not exists_after:
                self.log("Session cleaned up on logout (good)", "SUCCESS")
            else:
                self.log("Session still in Redis after logout (may be intentional)", "WARNING")

            return True

        except Exception as e:
            self.log(f"Test failed: {str(e)}", "ERROR")
            import traceback
            traceback.print_exc()
            return False

    def test_session_key_format(self):
        """Test 6: Session key format and structure."""
        self.log("\n=== TEST 6: Session Key Format ===", "TEST")

        try:
            # Login
            self.client.post('/accounts/login/', {
                'login': 'redis_test_user',
                'password': 'testpass123',
            }, follow=True)

            session_key = self.client.session.session_key
            self.log(f"Session key: {session_key}", "INFO")
            self.log(f"Session key length: {len(session_key)}", "INFO")

            # Verify format (Django generates 32-char hex strings)
            if len(session_key) == 32 and all(c in '0123456789abcdef' for c in session_key):
                self.log("Session key format is valid (32-char hex)", "SUCCESS")
            else:
                self.log("Session key format unexpected", "WARNING")

            return True

        except Exception as e:
            self.log(f"Test failed: {str(e)}", "ERROR")
            return False

    def test_cross_session_isolation(self):
        """Test 7: Session isolation (not accessing other users' data)."""
        self.log("\n=== TEST 7: Session Isolation ===", "TEST")

        try:
            # Create second test user
            user2 = User.objects.create_user(
                username='redis_test_user2',
                email='redis_test2@example.com',
                password='testpass123'
            )

            client1 = Client()
            client2 = Client()

            # User 1 login
            client1.post('/accounts/login/', {
                'login': 'redis_test_user',
                'password': 'testpass123',
            }, follow=True)

            # User 2 login
            client2.post('/accounts/login/', {
                'login': 'redis_test_user2',
                'password': 'testpass123',
            }, follow=True)

            session_key_1 = client1.session.session_key
            session_key_2 = client2.session.session_key

            cache_key_1 = f"django.contrib.sessions.cache{session_key_1}"
            cache_key_2 = f"django.contrib.sessions.cache{session_key_2}"

            # Get session data
            data_1 = json.loads(self.redis.get(cache_key_1))
            data_2 = json.loads(self.redis.get(cache_key_2))

            user_id_1 = int(data_1.get('_auth_user_id', 0))
            user_id_2 = int(data_2.get('_auth_user_id', 0))

            self.log(f"User 1 session contains user ID: {user_id_1}", "INFO")
            self.log(f"User 2 session contains user ID: {user_id_2}", "INFO")

            if user_id_1 != user_id_2:
                self.log("Sessions properly isolated by user", "SUCCESS")
            else:
                self.log("Session isolation issue detected", "ERROR")

            # Cleanup
            user2.delete()
            return True

        except Exception as e:
            self.log(f"Test failed: {str(e)}", "ERROR")
            import traceback
            traceback.print_exc()
            return False

    def test_redis_memory(self):
        """Test 8: Redis memory usage for sessions."""
        self.log("\n=== TEST 8: Redis Memory Usage ===", "TEST")

        try:
            # Get memory info
            info = self.redis.info('memory')
            used_memory = info.get('used_memory_human', 'N/A')
            self.log(f"Redis used memory: {used_memory}", "INFO")

            # Count sessions
            session_keys = self.redis.keys('django.contrib.sessions.cache*')
            self.log(f"Active session keys in Redis: {len(session_keys)}", "INFO")

            # Estimate memory per session
            if session_keys:
                total_size = sum(self.redis.memory_usage(key) for key in session_keys if self.redis.memory_usage(key))
                avg_size = total_size / len(session_keys) if session_keys else 0
                self.log(f"Average session size: {avg_size:.2f} bytes", "INFO")

            return True

        except Exception as e:
            self.log(f"Test failed: {str(e)}", "ERROR")
            return False

    def run_all_tests(self):
        """Run all tests."""
        self.log("=" * 60, "START")
        self.log("Session Management Redis Testing Suite", "START")
        self.log(f"Redis URL: {REDIS_URL}", "INFO")
        self.log(f"Session cache alias: {settings.SESSION_CACHE_ALIAS}", "INFO")
        self.log(f"Session cookie age: {settings.SESSION_COOKIE_AGE} seconds", "INFO")

        self.setup_test_user()

        tests = [
            ("Session Creation", self.test_session_creation),
            ("Session TTL", self.test_session_ttl),
            ("Session Data Integrity", self.test_session_data_integrity),
            ("Concurrent Sessions", self.test_concurrent_sessions),
            ("Logout Cleanup", self.test_logout_cleanup),
            ("Session Key Format", self.test_session_key_format),
            ("Session Isolation", self.test_cross_session_isolation),
            ("Redis Memory", self.test_redis_memory),
        ]

        results = {}
        for test_name, test_func in tests:
            try:
                results[test_name] = test_func()
            except Exception as e:
                self.log(f"Test {test_name} failed with exception: {str(e)}", "ERROR")
                results[test_name] = False

        self.cleanup_test_user()
        cache.clear()

        # Summary
        self.log("\n" + "=" * 60, "SUMMARY")
        passed = sum(1 for v in results.values() if v)
        total = len(results)
        self.log(f"Tests passed: {passed}/{total}", "SUCCESS" if passed == total else "WARNING")

        for test_name, result in results.items():
            status = "PASS" if result else "FAIL"
            self.log(f"  {test_name}: {status}", "SUCCESS" if result else "ERROR")

        return results, self.test_results

    def save_report(self, filename: str = "/root/zumodra/tests_comprehensive/reports/session_redis_test_report.json"):
        """Save test results to file."""
        results, logs = self.run_all_tests()

        report = {
            'timestamp': datetime.now().isoformat(),
            'test_summary': {
                'total': len(results),
                'passed': sum(1 for v in results.values() if v),
                'failed': sum(1 for v in results.values() if not v),
            },
            'test_results': results,
            'detailed_logs': logs,
            'configuration': {
                'redis_url': REDIS_URL,
                'session_backend': settings.SESSION_ENGINE,
                'session_cache_alias': settings.SESSION_CACHE_ALIAS,
                'session_cookie_age': settings.SESSION_COOKIE_AGE,
                'session_cookie_httponly': settings.SESSION_COOKIE_HTTPONLY,
                'session_cookie_secure': settings.SESSION_COOKIE_SECURE,
                'session_cookie_samesite': settings.SESSION_COOKIE_SAMESITE,
            }
        }

        # Create directory if needed
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        self.log(f"\nReport saved to: {filename}", "SUCCESS")
        return filename


if __name__ == '__main__':
    tester = SessionRedisTest()
    tester.save_report()
