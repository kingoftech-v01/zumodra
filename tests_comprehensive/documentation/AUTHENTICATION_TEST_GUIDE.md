# Zumodra Authentication & Session Management Testing Guide

## Server Under Test
**URL:** https://zumodra.rhematek-solutions.com

## Test Overview

This guide provides comprehensive testing procedures for authentication flows, session persistence, and logout functionality on the Zumodra production/development server.

## Prerequisites

```bash
# Install required packages
pip install requests beautifulsoup4 colorama
```

## Test Credentials

The platform uses **django-allauth** for authentication. You need valid test credentials to run the tests.

### Expected Test Users:
- **Demo Admin:** admin@demo.zumodra.com
- **Demo User:** user@demo.zumodra.com
- **Password:** Check with platform administrator

### To Create Test Users (if needed):
```bash
# Via Django management command
python manage.py createsuperuser --email admin@demo.zumodra.com

# Or via Django shell (if GDAL issues resolved):
python manage.py shell
from django.contrib.auth import get_user_model
User = get_user_model()
user = User.objects.create_user(email='test@demo.zumodra.com', password='testpass123')
user.is_active = True
user.save()
```

## Running the Automated Test Suite

```bash
# 1. Update test credentials in test_login_session_management.py
# Edit TEST_CONFIG section:
#   'valid_email': 'your-test-email@demo.zumodra.com',
#   'valid_password': 'your-test-password',

# 2. Run the test suite
python test_login_session_management.py
```

## Manual Testing Checklist

### Test 1: Standard Login Flow

**Steps:**
1. Navigate to https://zumodra.rhematek-solutions.com/accounts/login/
2. Enter valid credentials:
   - Email: `admin@demo.zumodra.com`
   - Password: `[your-password]`
3. Click "Sign In"

**Expected Results:**
- ✅ Redirected to `/app/dashboard/` or user profile
- ✅ Session cookie `sessionid` is set
- ✅ CSRF cookie `csrftoken` is set
- ✅ Navigation shows user's name and logout button
- ✅ Dashboard displays personalized content

**Inspection:**
```javascript
// Check cookies in browser DevTools (F12 → Application → Cookies)
document.cookie // Should show sessionid and csrftoken
```

---

### Test 2: Failed Login Attempts

**Test 2.1: Wrong Password**
1. Navigate to login page
2. Enter valid email with wrong password
3. Submit form

**Expected:**
- ✅ Error message: "The e-mail address and/or password you specified are not correct."
- ✅ Stays on login page
- ✅ No session cookie created

**Test 2.2: Non-existent Email**
1. Navigate to login page
2. Enter non-existent email
3. Submit form

**Expected:**
- ✅ Same generic error message (security: don't reveal if email exists)
- ✅ No session cookie created

**Test 2.3: Empty Credentials**
1. Navigate to login page
2. Leave email and password fields empty
3. Submit form

**Expected:**
- ✅ Form validation errors: "This field is required"
- ✅ Form doesn't submit (client-side validation)

---

### Test 3: Brute Force Protection (django-axes)

**Configuration:** 5 failed attempts = 1-hour lockout

**Steps:**
1. Attempt to login 5 times with wrong password from same IP
2. On 6th attempt, check response

**Expected Results:**
- ✅ After 5 failures, account/IP is locked
- ✅ Error message: "Too many failed login attempts" or "Account locked"
- ✅ Lockout persists for configured time (1 hour default)
- ✅ Successful login not possible even with correct password during lockout

**Notes:**
- Lockout applies per IP address
- Can be cleared via admin panel or Django shell
- Check `/admin-panel/axes/` for locked accounts (requires admin access)

---

### Test 4: Password Reset Flow

**Steps:**
1. Navigate to https://zumodra.rhematek-solutions.com/accounts/password/reset/
2. Enter email address
3. Submit form
4. Check email/MailHog for reset link
5. Click reset link
6. Enter new password
7. Confirm password
8. Submit
9. Login with new password

**Expected Results:**
- ✅ Step 2: "We have sent you an e-mail" confirmation message
- ✅ Step 4: Email received with reset token link
- ✅ Step 5: Password reset form displayed
- ✅ Step 8: Password updated successfully
- ✅ Step 9: Can login with new password
- ✅ Reset link is single-use (can't reuse)
- ✅ Reset link expires after 24 hours (default)

**Email Testing:**
- **Local:** Check MailHog at http://localhost:8026
- **Production:** Check actual email inbox

---

### Test 5: Session Management

**Test 5.1: Session Persistence**
1. Login successfully
2. Access dashboard
3. Refresh page multiple times
4. Wait 5 minutes
5. Access dashboard again

**Expected:**
- ✅ Session persists across page refreshes
- ✅ Session remains valid for configured timeout (8 hours default)
- ✅ No re-authentication required

**Test 5.2: Concurrent Sessions**
1. Login in Browser A (Chrome)
2. Login same user in Browser B (Firefox) or Incognito
3. Access dashboard in both browsers
4. Perform actions in both browsers

**Expected:**
- ✅ Both sessions are active simultaneously
- ✅ Different `sessionid` cookies for each browser
- ✅ Actions in one browser don't affect the other
- ✅ No conflicts or session hijacking

**Test 5.3: Session Cookie Inspection**
```javascript
// In browser console (F12)
document.cookie.split(';').forEach(c => console.log(c.trim()))

// Expected cookies:
// - sessionid=<random-hash>
// - csrftoken=<random-hash>
// - messages=<optional>
```

**Session Cookie Properties:**
- ✅ `HttpOnly=true` (not accessible via JavaScript)
- ✅ `Secure=true` (HTTPS only in production)
- ✅ `SameSite=Lax` or `Strict`
- ✅ `Domain=.zumodra.rhematek-solutions.com` (tenant-aware)

---

### Test 6: Logout Functionality

**Steps:**
1. Login successfully
2. Navigate to dashboard
3. Click "Logout" button/link
4. Confirm logout (if prompted)
5. Try to access dashboard directly

**Expected Results:**
- ✅ Redirected to home page after logout
- ✅ Session cookie `sessionid` is deleted or invalidated
- ✅ Navigation shows "Login" button instead of user name
- ✅ Attempting to access `/app/dashboard/` redirects to login page
- ✅ Browser back button doesn't show cached authenticated pages

**Manual Verification:**
```javascript
// After logout, check cookies
document.cookie // Should NOT contain sessionid

// Try to access protected endpoint
fetch('/app/dashboard/')
  .then(r => console.log('Status:', r.status, 'Redirected:', r.redirected, 'URL:', r.url))
// Expected: Status 302/200, Redirected: true, URL: login page
```

---

### Test 7: LoginHistory Tracking

**Verification:** Requires admin panel or API access

**Steps:**
1. Login successfully multiple times
2. Attempt failed login
3. Access admin panel: `/admin-panel/accounts/loginhistory/`
4. Review login history entries

**Expected Data:**
- ✅ Each login attempt is logged
- ✅ Timestamp recorded
- ✅ IP address captured
- ✅ User agent (browser) logged
- ✅ Result: success/failed/blocked
- ✅ Failure reason (if failed)

**API Endpoint (if available):**
```bash
# Get recent login history
curl -H "Authorization: Bearer <token>" \
  https://zumodra.rhematek-solutions.com/api/v1/accounts/login-history/recent/

# Expected response:
[
  {
    "user": "admin@demo.zumodra.com",
    "result": "success",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "timestamp": "2026-01-16T18:30:00Z"
  },
  ...
]
```

---

## Security Verification Checklist

### CSRF Protection
- ✅ Login form includes `csrfmiddlewaretoken` hidden field
- ✅ POST requests without CSRF token are rejected (403 Forbidden)
- ✅ CSRF cookie is set on first page visit

### Session Security
- ✅ Session cookie has `HttpOnly` flag (prevents XSS)
- ✅ Session cookie has `Secure` flag (HTTPS only)
- ✅ Session cookie has `SameSite` attribute (CSRF protection)
- ✅ Session ID is random and unpredictable
- ✅ Session regenerates after login (prevents fixation)

### Password Security
- ✅ Passwords are not visible in forms (type="password")
- ✅ Passwords are hashed (never stored plaintext)
- ✅ Password reset tokens are one-time use
- ✅ Password reset tokens expire after 24 hours

### Brute Force Protection
- ✅ django-axes installed and configured
- ✅ Failed attempts are tracked per IP/username
- ✅ Lockout occurs after 5 failed attempts
- ✅ Lockout duration is 1 hour (configurable)

### SSL/TLS
- ✅ Site forces HTTPS redirect
- ✅ HSTS header present
- ✅ SSL certificate is valid

---

## Common Issues & Troubleshooting

### Issue 1: "CSRF verification failed"
**Cause:** Missing or incorrect CSRF token

**Solution:**
- Ensure you're including the CSRF token in POST requests
- Check that cookies are enabled
- Verify `csrftoken` cookie is set
- Use `{% csrf_token %}` in Django templates

### Issue 2: Login succeeds but redirects to login again
**Cause:** Session middleware not configured or cookies blocked

**Solution:**
- Check `MIDDLEWARE` in settings.py includes `SessionMiddleware`
- Verify cookies are enabled in browser
- Check browser console for errors
- Verify `SESSION_COOKIE_DOMAIN` is correctly set

### Issue 3: "Too many authentication failures"
**Cause:** django-axes lockout after failed attempts

**Solution:**
```bash
# Clear lockout via Django shell
python manage.py axes_reset

# Or via admin panel: /admin-panel/axes/
```

### Issue 4: Password reset email not received
**Cause:** Email backend not configured or email in spam

**Solution:**
- Check MailHog (local): http://localhost:8026
- Check spam folder
- Verify `EMAIL_BACKEND` in settings.py
- Check email logs

### Issue 5: Session expires too quickly
**Cause:** Short `SESSION_COOKIE_AGE` setting

**Solution:**
- Check `SESSION_COOKIE_AGE` in settings.py (should be 28800 = 8 hours)
- Verify `SESSION_EXPIRE_AT_BROWSER_CLOSE = False`

---

## Expected Configuration

### Django Settings (settings.py)

```python
# Session Configuration
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_AGE = 28800  # 8 hours
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True  # HTTPS only
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

# CSRF Protection
CSRF_COOKIE_HTTPONLY = False  # Needs to be readable by JS for AJAX
CSRF_COOKIE_SECURE = True  # HTTPS only
CSRF_COOKIE_SAMESITE = 'Strict'

# Authentication
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]

# django-allauth Settings
ACCOUNT_AUTHENTICATION_METHOD = 'email'
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_EMAIL_VERIFICATION = 'optional'
LOGIN_REDIRECT_URL = '/app/dashboard/'
ACCOUNT_LOGOUT_REDIRECT_URL = '/'

# django-axes Settings (Brute Force Protection)
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(hours=1)
AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP = True
```

---

## Test Report Template

```markdown
# Authentication Test Report

**Date:** 2026-01-16
**Tester:** [Your Name]
**Server:** https://zumodra.rhematek-solutions.com
**Test Duration:** [Start Time] - [End Time]

## Test Results Summary

| Test | Status | Notes |
|------|--------|-------|
| 1.1 Standard Login | ✅ PASS | Redirected to dashboard |
| 1.2 Session Cookie | ✅ PASS | Cookie set correctly |
| 1.3 Dashboard Access | ✅ PASS | Authenticated content shown |
| 1.4 Session Persistence | ✅ PASS | Session valid after 5min |
| 2.1 Wrong Password | ✅ PASS | Error shown, no session |
| 2.2 Non-existent Email | ✅ PASS | Generic error message |
| 2.3 Empty Credentials | ✅ PASS | Validation error |
| 3.1 Brute Force Protection | ✅ PASS | Locked after 5 attempts |
| 4.1 Password Reset Request | ✅ PASS | Email sent |
| 4.2 Password Reset Link | ⏭️ SKIP | No email access |
| 5.1 Session Persistence | ✅ PASS | Persists across refresh |
| 5.2 Concurrent Sessions | ✅ PASS | Multiple sessions work |
| 6.1 Logout Redirect | ✅ PASS | Redirected to home |
| 6.2 Session Cleared | ✅ PASS | Cookie deleted |
| 6.3 Post-Logout Protection | ✅ PASS | Dashboard redirects to login |
| 7.1 LoginHistory Tracking | ❌ FAIL | No API access to verify |

**Overall Pass Rate:** 93% (14/15 tests passed)

## Security Concerns

- None identified

## Recommendations

1. Verify LoginHistory tracking via admin panel access
2. Test password reset email delivery in production
3. Consider adding rate limiting to login endpoint
4. Add security monitoring alerts for suspicious login patterns

## Screenshots

[Attach screenshots of test results, error messages, etc.]
```

---

## Running the Automated Test Suite

### Step 1: Configure Test Credentials

Edit `test_login_session_management.py`:

```python
TEST_CONFIG = {
    'base_url': 'https://zumodra.rhematek-solutions.com',
    'valid_email': 'admin@demo.zumodra.com',  # ← Update this
    'valid_password': 'YourPasswordHere',      # ← Update this
    # ...
}
```

### Step 2: Run Tests

```bash
# Run full test suite
python test_login_session_management.py

# Expected output:
# ════════════════════════════════════════
#  TEST 1: Standard Login
# ════════════════════════════════════════
# ► Step 1: Fetch login page and CSRF token
#   ✓ CSRF token retrieved: ...
# ► Step 2: Submit login credentials
#   ✓ Login request completed: 200
#   ✓ Redirected to: /app/dashboard/
# ...
```

### Step 3: Review Results

The test suite generates a JSON report:

```bash
# View the report
cat login_session_test_report_20260116_183045.json

# Report includes:
# - Summary (total tests, pass rate)
# - Detailed results per test
# - Timestamps and metadata
```

---

## Additional Resources

- **Django-allauth Docs:** https://docs.allauth.org/
- **Django-axes Docs:** https://django-axes.readthedocs.io/
- **Django Sessions:** https://docs.djangoproject.com/en/5.2/topics/http/sessions/
- **OWASP Authentication Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

---

## Contact

For issues or questions about authentication testing:
- **Platform Admin:** admin@zumodra.com
- **Security Team:** security@zumodra.com
