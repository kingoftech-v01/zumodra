# Comprehensive Session Management Testing Guide

## Overview

This guide covers comprehensive testing of session management in the Zumodra multi-tenant SaaS platform. The testing covers all critical security and functional aspects of session handling.

## Test Areas

### 1. Session Creation and Storage (Redis)
Tests that verify sessions are properly created and stored in Redis.

**Tests:**
- `test_session_created_on_login` - Verify session exists after login
- `test_session_stored_in_redis` - Verify session stored in Redis cache
- `test_session_contains_user_id` - Verify user ID in session
- `test_session_cookie_httponly` - Verify HttpOnly flag
- `test_session_cookie_samesite` - Verify SameSite attribute
- `test_session_cookie_secure_in_https` - Verify Secure flag

**Files:**
- `/c/Users/techn/OneDrive/Documents/zumodra/tests_comprehensive/test_session_management.py` - Session creation tests

**Configuration:**
```python
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'
SESSION_COOKIE_AGE = 28800  # 8 hours
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
```

### 2. Session Expiration and Cleanup
Tests that verify sessions expire and are cleaned up properly.

**Tests:**
- `test_session_expiration_time` - Verify session expires after configured age
- `test_session_expires_at_configured_age` - Verify TTL behavior
- `test_session_cleanup_on_expiration` - Verify cleanup
- `test_session_persist_across_requests` - Verify persistence
- `test_session_invalidated_on_password_change` - Security test

**Configuration:**
- SESSION_COOKIE_AGE: 28800 seconds (8 hours development, 1209600 production)
- SESSION_SAVE_EVERY_REQUEST: True (updates expiration on every request)

### 3. Concurrent Session Handling
Tests that verify multiple sessions from same user are handled correctly.

**Tests:**
- `test_multiple_sessions_same_user` - Multiple devices for one user
- `test_session_isolation_between_users` - Users isolated
- `test_concurrent_requests_dont_interfere` - Concurrent request handling

**Scenarios Tested:**
- User login from browser 1
- Same user login from browser 2 (phone)
- Verify both sessions active and independent
- Verify one user cannot access another user's session

### 4. Session Hijacking Prevention
Tests that verify protection against session hijacking attacks.

**Tests:**
- `test_session_regeneration_on_login` - Session ID regenerated on login
- `test_user_agent_tracking` - Optional User-Agent verification
- `test_ip_address_binding_optional` - Optional IP binding
- `test_csrf_token_included` - CSRF token in responses
- `test_session_cookie_not_accessible_to_javascript` - HttpOnly flag
- `test_session_fixation_prevention` - Session fixation prevention
- `test_xss_protection_in_session_data` - JSON serialization

**Security Headers:**
```python
SESSION_COOKIE_HTTPONLY = True  # Prevents JavaScript access
SESSION_COOKIE_SAMESITE = 'Lax'  # Prevents CSRF
SESSION_COOKIE_SECURE = True  # HTTPS only
CSRF_USE_SESSIONS = False  # Separate CSRF tokens
```

### 5. Cross-Tenant Session Isolation
Tests that verify sessions don't leak between tenants.

**Tests:**
- `test_session_tenant_isolation` - Tenant isolation verification
- `test_different_tenants_different_cache_aliases` - Cache separation
- `test_no_session_cross_contamination` - No data leaks

**Implementation:**
- Each tenant uses own schema (django-tenants)
- Session cache keys can include tenant identifier
- Middleware enforces tenant context

### 6. Remember Me Functionality
Tests for persistent login feature.

**Tests:**
- `test_remember_me_extended_session` - Extended session lifetime
- `test_remember_me_cookie_persistence` - Persistent cookie creation
- `test_session_expiry_warning` - Expiry warning before logout

**Note:** Standard Django doesn't have built-in "remember me". Implementation options:
- Extended SESSION_COOKIE_AGE for opt-in users
- Persistent cookie tokens
- Database-backed remember tokens

### 7. Session Invalidation on Logout
Tests that verify sessions are properly cleared on logout.

**Tests:**
- `test_session_cleared_on_logout` - Session cleared after logout
- `test_user_data_removed_on_logout` - Auth data removed
- `test_logout_prevents_access_to_protected_pages` - Access denied after logout
- `test_logout_global_session_clear` - All user sessions cleared option
- `test_csrf_token_rotated_on_logout` - CSRF token refreshed

## Running Tests

### Unit/Integration Tests

```bash
# Run all session tests
pytest tests_comprehensive/test_session_management.py -v

# Run specific test class
pytest tests_comprehensive/test_session_management.py::SessionCreationTests -v

# Run specific test
pytest tests_comprehensive/test_session_management.py::SessionCreationTests::test_session_created_on_login -v

# Run with markers
pytest -m session -v

# Run with coverage
pytest tests_comprehensive/test_session_management.py --cov --cov-report=html
```

### Redis Manual Testing

Docker environment required:

```bash
# Start services
docker compose up -d

# Run manual Redis tests
docker compose exec web python tests_comprehensive/test_session_redis_manual.py

# Or run interactively
docker compose exec web python

# Then in Python shell:
from tests_comprehensive.test_session_redis_manual import SessionRedisTest
tester = SessionRedisTest()
tester.save_report()
```

### Redis CLI Inspection

```bash
# Connect to Redis
docker compose exec redis redis-cli

# List all session keys
KEYS "django.contrib.sessions.cache*"

# Check a specific session
GET "django.contrib.sessions.cache<session_key>"

# Check session TTL
TTL "django.contrib.sessions.cache<session_key>"

# Count sessions
DBSIZE

# Monitor in real-time
MONITOR

# Check memory
INFO memory

# Flush all (development only!)
FLUSHALL
```

### Browser Manual Testing

**Test Case 1: Basic Login/Logout**
1. Open browser developer tools (F12)
2. Go to Application → Cookies → Zumodra
3. Note zumodra_session cookie
4. Login with credentials
5. Observe cookie value changes (session regeneration)
6. Check HttpOnly flag is set
7. Logout and observe cookie is cleared

**Test Case 2: Multiple Devices**
1. Login on Browser 1 (Chrome, desktop)
2. Login on Browser 2 (Firefox, desktop)
3. Login on Browser 3 (Mobile Safari, mobile)
4. Verify all three sessions work independently
5. Logout on Browser 1, verify still logged in on 2 & 3
6. Use Redis CLI to verify 3 different session keys exist

**Test Case 3: Session Persistence**
1. Login on Browser
2. Leave inactive for 30 minutes
3. Access page - should still be authenticated (SESSION_SAVE_EVERY_REQUEST updates TTL)
4. Leave inactive for 8+ hours
5. Access page - should be logged out (session expired)

**Test Case 4: Session Hijacking Prevention**
1. Login and get session ID from cookies
2. Try to access session from different IP (VPN)
3. Verify request still works (Django allows this by default)
4. Note: IP binding would require custom middleware
5. Try XSS attack to access session (should fail with HttpOnly)

**Test Case 5: Cross-Tenant Isolation**
1. Create tenant A and tenant B
2. Login to tenant A with user@tenantA.zumodra.com
3. Login to tenant B with user@tenantB.zumodra.com
4. Verify no cross-contamination of session data
5. Check Redis for isolated cache keys

## Test Checklist

### Pre-Testing Setup
- [ ] Docker containers running (`docker compose up -d`)
- [ ] Database migrations complete (`python manage.py migrate_schemas`)
- [ ] Redis is accessible and working
- [ ] Test users created or factory configured
- [ ] Environment variables configured (`.env` file)

### Session Creation & Storage
- [ ] Login creates session in Redis
- [ ] Session cookie has correct name (`zumodra_session`)
- [ ] HttpOnly flag is set
- [ ] SameSite is set to 'Lax'
- [ ] Secure flag is set (production)
- [ ] User ID stored in session
- [ ] Session data is JSON serialized

### Session Expiration
- [ ] Sessions expire after 8 hours (dev) or 2 weeks (prod)
- [ ] SESSION_SAVE_EVERY_REQUEST extends expiration
- [ ] Redis TTL reflects correct age
- [ ] Expired sessions are cleaned up
- [ ] User cannot access after expiration

### Concurrent Sessions
- [ ] Multiple sessions per user work independently
- [ ] Different session IDs for different browsers
- [ ] Session isolation between users
- [ ] No race conditions with concurrent requests
- [ ] Logout from one device doesn't affect others

### Security
- [ ] Session hijacking attempts fail
- [ ] CSRF tokens are included
- [ ] Password change behavior (invalidate sessions or not)
- [ ] XSS protection (HttpOnly prevents JS access)
- [ ] Session fixation prevention works
- [ ] No sensitive data in session cookies

### Cross-Tenant
- [ ] Session data isolated by tenant
- [ ] No cross-contamination between tenants
- [ ] Tenant-aware cache keys (if implemented)
- [ ] Proper middleware routing

### Logout
- [ ] Session cleared from cache
- [ ] Auth user ID removed from session
- [ ] Access to protected pages denied
- [ ] CSRF token refreshed
- [ ] All user sessions can be cleared (optional)

### Performance & Scaling
- [ ] Redis handles hundreds of concurrent sessions
- [ ] Session creation/retrieval is fast (< 100ms)
- [ ] Memory usage is acceptable
- [ ] No connection pool exhaustion
- [ ] Cleanup doesn't impact performance

## Security Considerations

### Current Mitigations
✅ HttpOnly flag prevents JavaScript access to session cookies
✅ SameSite=Lax provides CSRF protection
✅ Secure flag ensures HTTPS only (production)
✅ JSON serialization prevents code injection
✅ Django generates cryptographically secure session IDs
✅ Cache-based backend is fast and scalable
✅ Multi-tenant isolation at middleware level

### Optional Enhancements
- [ ] IP address binding (custom middleware)
- [ ] User-Agent validation (custom middleware)
- [ ] Device fingerprinting
- [ ] Session activity logging
- [ ] Device tracking/management
- [ ] One-click logout from all devices
- [ ] Session timeout warnings
- [ ] Suspicious activity detection

### Known Issues & Mitigations
**Issue:** Mobile users have changing IP addresses
**Mitigation:** Don't use strict IP binding

**Issue:** User-Agent spoofing is trivial
**Mitigation:** Use as secondary signal, not primary

**Issue:** Session fixation in old browsers
**Mitigation:** Session regeneration on login (already implemented)

## Performance Benchmarks

Expected performance metrics:

| Metric | Target | Actual |
|--------|--------|--------|
| Session creation time | < 50ms | - |
| Session retrieval time | < 20ms | - |
| Redis memory per session | < 500 bytes | - |
| Concurrent sessions | > 10,000 | - |
| Session TTL/expiry accuracy | ±1 minute | - |

## Troubleshooting

### Session Not Created
**Symptom:** User can login but session_key is None
**Solutions:**
1. Verify Redis is running: `docker compose ps`
2. Check Redis connection: `docker compose exec redis redis-cli ping`
3. Check settings.SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
4. Check CACHES configuration for 'default' alias
5. Review logs for cache errors

### Sessions Lost After Redis Restart
**Symptom:** All users logged out when Redis restarts
**Solutions:**
1. This is expected with cache-based sessions (no persistence)
2. For persistence, switch to database backend or Redis with persistence
3. Enable Redis persistence in docker-compose
4. Configure Redis AOF (append-only file)

### Session Expiration Not Working
**Symptom:** Sessions expire early or don't expire
**Solutions:**
1. Check SESSION_COOKIE_AGE setting (in seconds)
2. Verify SESSION_SAVE_EVERY_REQUEST = True (updates TTL)
3. Check Redis TTL: `TTL django.contrib.sessions.cache<key>`
4. Ensure Django cache configuration is correct
5. Review middleware for session handling

### Cross-Tenant Contamination
**Symptom:** Session data visible across tenants
**Solutions:**
1. Verify django-tenants middleware is first in list
2. Check tenant routing configuration
3. Ensure cache keys include tenant identifier
4. Review middleware for tenant context
5. Add tenant to session key prefix

### High Memory Usage
**Symptom:** Redis memory grows without bound
**Solutions:**
1. Check for memory leaks in custom session code
2. Verify SESSION_COOKIE_AGE is reasonable
3. Implement session cleanup tasks
4. Monitor Redis memory: `docker compose exec redis redis-cli info memory`
5. Consider database-backed sessions for very large deployments

## Test Report Template

Save reports to: `/c/Users/techn/OneDrive/Documents/zumodra/tests_comprehensive/reports/`

Filename format: `session_test_report_YYYY-MM-DD_HHmmss.md`

```markdown
# Session Management Test Report
Date: YYYY-MM-DD HH:MM:SS
Tested By: [Your Name]
Environment: [Development/Production]

## Executive Summary
[Brief overview of test results]

## Test Results

### Session Creation & Storage
- [ ] PASS / [ ] FAIL - Session creation
- [ ] PASS / [ ] FAIL - Redis storage
- [ ] PASS / [ ] FAIL - Cookie flags

### Session Expiration
- [ ] PASS / [ ] FAIL - TTL behavior
- [ ] PASS / [ ] FAIL - Cleanup

### Concurrent Sessions
- [ ] PASS / [ ] FAIL - Multiple devices
- [ ] PASS / [ ] FAIL - User isolation

### Security
- [ ] PASS / [ ] FAIL - Hijacking prevention
- [ ] PASS / [ ] FAIL - CSRF protection

### Logout
- [ ] PASS / [ ] FAIL - Session clearing
- [ ] PASS / [ ] FAIL - Access denial

## Issues Found
[List any issues, with severity and remediation]

## Performance Metrics
- Session creation: [ms]
- Session retrieval: [ms]
- Memory per session: [bytes]

## Recommendations
[List any recommendations for improvement]
```

## References

- Django Session Documentation: https://docs.djangoproject.com/en/5.0/topics/http/sessions/
- Redis Documentation: https://redis.io/documentation
- OWASP Session Security: https://owasp.org/www-community/attacks/Session_fixation
- Django Security: https://docs.djangoproject.com/en/5.0/topics/security/

## Contact

For session security issues or questions:
- Project: Zumodra Multi-Tenant SaaS Platform
- Version: Based on Django 5.2.7
- Security Team: [contact information]
