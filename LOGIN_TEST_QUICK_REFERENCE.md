# Zumodra Login Testing - Quick Reference Card

**Server:** https://zumodra.rhematek-solutions.com
**Auth System:** django-allauth v65.3.0+
**Session Backend:** Database (8-hour timeout)
**Brute Force Protection:** django-axes (5 attempts = 1-hour lockout)

---

## Test Status at a Glance

| Test | Status | Quick Check |
|------|--------|-------------|
| Server Connectivity | ✅ PASS | `curl https://zumodra.rhematek-solutions.com` |
| Login Page | ✅ PASS | Navigate to `/accounts/login/` |
| Logout Endpoint | ✅ PASS | Endpoint exists |
| Password Reset | ✅ PASS | Form accessible |
| Dashboard Protection | ✅ PASS | Requires auth |
| Security Headers | ✅ PASS | HSTS, CSP, X-Frame |
| **Login Workflow** | ⏸️ **PENDING** | **Needs credentials** |

---

## Quick Commands

### Run Connectivity Test (No Credentials Needed)
```bash
python quick_auth_test.py
```

### Run Full Login Test (Needs Credentials)
```bash
# 1. Edit test_login_session_management.py
# 2. Update TEST_CONFIG with valid email/password
# 3. Run:
python test_login_session_management.py
```

---

## Manual Test Checklist

### ☐ Test 1: Standard Login
1. Go to: https://zumodra.rhematek-solutions.com/accounts/login/
2. Enter email and password
3. Click "Sign In"
4. Expected: Redirect to dashboard, session cookie set

### ☐ Test 2: Wrong Password
1. Go to login page
2. Enter valid email with wrong password
3. Expected: Error message, no session cookie

### ☐ Test 3: Brute Force Protection
1. Fail login 5 times
2. Try 6th attempt
3. Expected: Account locked, "Too many failed attempts"

### ☐ Test 4: Password Reset
1. Go to: https://zumodra.rhematek-solutions.com/accounts/password/reset/
2. Enter email
3. Check email/MailHog
4. Expected: Reset email sent

### ☐ Test 5: Session Persistence
1. Login successfully
2. Refresh page 5 times
3. Wait 5 minutes
4. Refresh again
5. Expected: Still logged in

### ☐ Test 6: Concurrent Sessions
1. Login in Chrome
2. Login in Firefox (same user)
3. Expected: Both sessions active

### ☐ Test 7: Logout
1. Login
2. Click Logout
3. Try to access dashboard
4. Expected: Redirect to login

---

## Browser DevTools Checks

### Check Session Cookie
```javascript
// In browser console (F12)
document.cookie.split(';').forEach(c => console.log(c.trim()))

// Expected:
// sessionid=<hash>  (HttpOnly, Secure, SameSite=Lax)
// csrftoken=<hash>  (Secure, SameSite=Strict)
```

### Test Protected Endpoint After Logout
```javascript
fetch('/app/dashboard/')
  .then(r => console.log('Status:', r.status, 'URL:', r.url))

// Expected after logout: Redirect to login page
```

---

## API Test Commands

### Health Check
```bash
curl https://zumodra.rhematek-solutions.com/health/
```

### Login API (JWT)
```bash
curl -X POST https://zumodra.rhematek-solutions.com/api/v1/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@demo.zumodra.com",
    "password": "yourpassword"
  }'
```

### Get Login History
```bash
curl -H "Authorization: Bearer <token>" \
  https://zumodra.rhematek-solutions.com/api/v1/accounts/login-history/recent/
```

---

## Expected Credentials

**Test Account:**
- Email: `admin@demo.zumodra.com` (or similar)
- Password: *Contact platform administrator*

**To Request Credentials:**
- Email: admin@zumodra.com
- Specify: "Need test credentials for authentication testing"

---

## Configuration Reference

### Session Settings
```python
SESSION_COOKIE_AGE = 28800  # 8 hours
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = 'Lax'
```

### Brute Force Protection
```python
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(hours=1)
```

### django-allauth Settings
```python
ACCOUNT_AUTHENTICATION_METHOD = 'email'
ACCOUNT_EMAIL_REQUIRED = True
LOGIN_REDIRECT_URL = '/app/dashboard/'
ACCOUNT_LOGOUT_REDIRECT_URL = '/'
```

---

## Security Headers (Expected)

| Header | Value |
|--------|-------|
| Strict-Transport-Security | `max-age=31536000; includeSubDomains; preload` |
| X-Content-Type-Options | `nosniff` |
| X-Frame-Options | `DENY, SAMEORIGIN` |
| Content-Security-Policy | `script-src 'self' https://cdn.jsdelivr.net...` |

---

## Common Issues & Quick Fixes

### Issue: "CSRF verification failed"
**Fix:** Clear cookies, refresh page, try again

### Issue: "Too many authentication failures"
**Fix:**
```bash
python manage.py axes_reset
# Or wait 1 hour for automatic unlock
```

### Issue: Password reset email not received
**Check:**
1. Local: http://localhost:8026 (MailHog)
2. Spam folder
3. Email logs in Django admin

### Issue: Session expires immediately
**Check:**
```python
# In settings.py:
SESSION_EXPIRE_AT_BROWSER_CLOSE = False  # Should be False
```

---

## Test Report Files

| File | Purpose |
|------|---------|
| `AUTHENTICATION_TEST_REPORT.md` | Full detailed report |
| `AUTHENTICATION_TEST_GUIDE.md` | Step-by-step testing guide |
| `AUTHENTICATION_TEST_SUMMARY.txt` | Quick summary (visual) |
| `LOGIN_TEST_QUICK_REFERENCE.md` | This card (quick ref) |
| `test_login_session_management.py` | Automated test suite |
| `quick_auth_test.py` | Quick connectivity test |

---

## Key Endpoints

| Endpoint | Purpose | Auth Required |
|----------|---------|---------------|
| `/accounts/login/` | Login page | No |
| `/accounts/logout/` | Logout | Yes (session) |
| `/accounts/password/reset/` | Password reset | No |
| `/app/dashboard/` | User dashboard | Yes |
| `/admin-panel/` | Django admin | Yes (staff) |
| `/api/v1/auth/login/` | API login (JWT) | No |
| `/api/v1/accounts/login-history/` | Login history API | Yes (JWT) |
| `/health/` | Health check | No |

---

## Test Execution Flow

```
1. Run Quick Test (No Creds)
   ↓
   python quick_auth_test.py
   ↓
   7/7 tests pass ✅

2. Get Credentials
   ↓
   Contact: admin@zumodra.com

3. Configure Test Suite
   ↓
   Edit: test_login_session_management.py
   Update: TEST_CONFIG

4. Run Full Test Suite
   ↓
   python test_login_session_management.py
   ↓
   Results: JSON report

5. Manual Verification
   ↓
   Follow: AUTHENTICATION_TEST_GUIDE.md

6. Review Results
   ↓
   Check: All test reports
```

---

## Success Criteria

✅ **PASS Criteria:**
- Login succeeds with valid credentials
- Session cookie set with secure attributes
- Dashboard accessible after login
- Session persists across refreshes
- Brute force protection triggers after 5 failures
- Logout clears session
- Protected pages redirect to login after logout

❌ **FAIL Criteria:**
- Login fails with valid credentials
- Session cookie missing or insecure
- Dashboard accessible without login
- Session expires immediately
- No brute force protection
- Session persists after logout

---

## Contact

**Testing Support:** admin@zumodra.com
**Security Issues:** security@zumodra.com
**Report Issues:** Include timestamp, IP, steps to reproduce

---

**Quick Reference Version:** 1.0
**Last Updated:** January 16, 2026
**Platform:** Zumodra Multi-Tenant SaaS
**Server:** https://zumodra.rhematek-solutions.com
