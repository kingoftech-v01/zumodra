# Password Reset Workflow Testing Guide

## Overview
This guide provides comprehensive testing procedures for the password reset workflow in Zumodra, covering all 7 critical aspects.

**Test Date:** 2026-01-17
**Framework:** Django 5.2.7 + django-allauth
**Authentication Backend:** JWT + django-axes (brute force protection)

---

## Prerequisites

### Required Services
```bash
docker compose up -d
```

Services needed:
- **web** (port 8002): Django application server
- **db** (port 5434): PostgreSQL database
- **redis** (port 6380): Cache and session store
- **mailhog** (port 8026): Email testing interface

### Verify Setup
```bash
# Check all services are running
docker compose ps

# Check MailHog is accessible
curl http://localhost:1025/api/v2/messages
# Or visit: http://localhost:8026
```

---

## Test 1: Password Reset Request (Email Sending)

### Objective
Verify that password reset requests trigger email notifications with valid reset links.

### Test Steps

#### 1.1 Navigate to Password Reset Page
```
URL: http://localhost:8002/accounts/password/reset/
Expected: Form with email input field
```

#### 1.2 Request Password Reset
```
Steps:
1. Enter registered email: test.user@example.com
2. Click "Reset Password"
3. Expected: Success message - "Email sent with password reset link"
```

#### 1.3 Verify Email Sent
```
Steps:
1. Open MailHog: http://localhost:8026
2. Check Inbox for email from noreply@domain
3. Expected Email Content:
   - Subject: Contains "Password Reset" or similar
   - Body: Contains reset link with token
   - Link format: /accounts/password/reset/uidXXX/tokenXXX/
```

#### 1.4 Check Email Structure
```
Python Test:
from django.core.mail import outbox
# After password reset request:
assert len(outbox) > 0, "Email not sent"
email = outbox[0]
assert 'reset' in email.subject.lower()
assert 'http' in email.body  # Contains link
```

### Expected Results
- ✓ Email sent immediately
- ✓ Email contains valid reset link
- ✓ Email from configured noreply address
- ✓ Reset link includes unique token

### Common Issues
| Issue | Cause | Solution |
|-------|-------|----------|
| No email sent | EMAIL_BACKEND not configured | Check settings.py EMAIL_BACKEND |
| MailHog not accessible | Service not running | `docker compose up -d mailhog` |
| Email has broken link | SITE_URL not configured | Check PRIMARY_DOMAIN setting |

---

## Test 2: Reset Token Generation and Validation

### Objective
Verify that cryptographically secure tokens are generated and properly validated.

### Test Steps

#### 2.1 Extract Token from Email
```
Steps:
1. Open email in MailHog
2. Find reset link in email body
3. Extract token from URL: /accounts/password/reset/uid-XXX/token-YYY/
   - UID (user ID): First part
   - Token: Second part
4. Note the token format and length
```

#### 2.2 Verify Token Format
```
Python Validation:
from django.contrib.auth.tokens import default_token_generator

# Token should be base64-encoded string
# Format: {timestamp}-{hash}
# Length: Typically 40+ characters

token_length = len(extracted_token)
assert token_length >= 40, f"Token too short: {token_length}"
```

#### 2.3 Test Token Validity
```
Steps:
1. Click reset link from email
2. Expected: Form to enter new password
3. If token invalid: Error message - "This password reset link is invalid"

Python Test:
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model

User = get_user_model()
user = User.objects.get(email='test@example.com')

# Generate new token
token = default_token_generator.make_token(user)

# Verify it's valid
is_valid = default_token_generator.check_token(user, token)
assert is_valid, "Generated token should be valid"
```

### Expected Results
- ✓ Token is cryptographically secure (40+ character hash)
- ✓ Token validates against user
- ✓ Token is unique per reset request
- ✓ Token decodes properly

### Security Checks
```python
# Verify token uses HMAC-SHA256
import hashlib
token_should_use = "HMAC-SHA256"  # Django default
# Check in: django.contrib.auth.tokens.PasswordResetTokenGenerator
```

---

## Test 3: Token Expiration (Time-Limited)

### Objective
Verify tokens expire after configured timeout to prevent indefinite password resets.

### Test Steps

#### 3.1 Check Token Timeout Configuration
```
Python Command:
python manage.py shell

from django.conf import settings
timeout = getattr(settings, 'PASSWORD_RESET_TIMEOUT', 'Not configured')
print(f"Token timeout: {timeout} seconds")
print(f"Hours: {timeout / 3600}")

# Expected: 3600-259200 seconds (1-72 hours)
assert 3600 <= timeout <= 259200, "Timeout not configured properly"
```

#### 3.2 Test with Fresh Token
```
Steps:
1. Request new password reset
2. Immediately click reset link
3. Expected: Form accessible, no expiration error
```

#### 3.3 Test with Expired Token (Simulation)
```
Manual Method (without waiting):
1. Request password reset for user A
2. Change password for user A manually
3. Try to use old reset link
4. Expected: Error - "This password reset link is invalid or has expired"

Automated Test:
from django.contrib.auth.tokens import default_token_generator
from django.utils import timezone
from datetime import timedelta

user = User.objects.get(email='test@example.com')
old_token = default_token_generator.make_token(user)

# Simulate token aging by modifying creation time
# Note: Actual expiration check in PasswordResetTokenGenerator
```

#### 3.4 Verify Timeout in Database
```
Check User Password Change History:
from django.contrib.auth.models import User
user = User.objects.get(email='test@example.com')
print(f"Password last changed: {user.last_login}")

# Each password change resets token validity
```

### Expected Results
- ✓ Timeout configured: 24-72 hours (86400-259200 seconds)
- ✓ Fresh tokens are valid
- ✓ Expired tokens rejected
- ✓ Clear error message for expired tokens
- ✓ User can request new token

### Configuration Verification
```python
# In zumodra/settings.py:
PASSWORD_RESET_TIMEOUT = 86400  # 24 hours

# Or in settings_security.py:
# PASSWORD_RESET_TIMEOUT = 259200  # 72 hours (more lenient)
```

---

## Test 4: Password Strength Requirements

### Objective
Verify that weak passwords are rejected and strong passwords are accepted.

### Test Steps

#### 4.1 Check Password Validators Configuration
```
Python:
python manage.py shell

from django.conf import settings
validators = settings.AUTH_PASSWORD_VALIDATORS
print(f"Configured validators: {len(validators)}")
for v in validators:
    print(f"  - {v}")

# Expected validators:
# - UserAttributeSimilarityValidator (password not similar to username)
# - MinimumLengthValidator (minimum 8-10 characters)
# - CommonPasswordValidator (against common passwords list)
# - NumericPasswordValidator (not all numbers)
```

#### 4.2 Test Weak Passwords
Try resetting with these passwords, all should be REJECTED:

```
Test Cases:

1. Too Short (< 8 chars)
   Password: "Pass123"
   Expected Error: "Password must be at least 8 characters"

2. Too Common
   Password: "password123"
   Expected Error: "This password is too common"

3. Only Numbers
   Password: "12345678"
   Expected Error: "This password is entirely numeric"

4. Too Similar to Username
   Password: "testuser123" (if username is 'testuser')
   Expected Error: "Password too similar to username"

5. Only Letters
   Password: "abcdefgh"
   Expected Error: "Password must contain numbers and special chars"
```

#### 4.3 Test Strong Passwords
These should all be ACCEPTED:

```
Test Cases:

1. ✓ Complex: "MySecureP@ss2024!"
2. ✓ Long: "ThisIsAVeryLongPasswordWith123Numbers"
3. ✓ Mixed: "P@ssw0rd!Str0ng"
4. ✓ Special chars: "Secure$123@Pass"
```

#### 4.4 Automated Validation Test
```python
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

test_passwords = {
    "weak123": False,           # Too common
    "P@ssw0rd!2024": True,      # Strong
    "12345678": False,          # All numbers
    "MySecurePassword123!": True # Good
}

for pwd, should_pass in test_passwords.items():
    try:
        validate_password(pwd)
        assert should_pass, f"{pwd} should be rejected"
        print(f"✓ {pwd} passed validation")
    except ValidationError as e:
        assert not should_pass, f"{pwd} should be accepted"
        print(f"✓ {pwd} rejected: {e}")
```

### Expected Results
- ✓ Weak passwords rejected with clear error messages
- ✓ Strong passwords accepted
- ✓ Minimum length enforced (8+ characters)
- ✓ Complexity requirements enforced
- ✓ No common passwords allowed

### Django Password Requirements
```
Default validators in zumodra:

1. UserAttributeSimilarityValidator
   - Rejects passwords similar to username/email

2. MinimumLengthValidator (min_length=8)
   - Minimum 8 characters

3. CommonPasswordValidator
   - Checks against ~20,000 common passwords

4. NumericPasswordValidator
   - Rejects all-numeric passwords
```

---

## Test 5: Password Change Confirmation

### Objective
Verify that password can be successfully changed via reset link and new password works for login.

### Test Steps

#### 5.1 Request Password Reset
```
Steps:
1. Go to: http://localhost:8002/accounts/password/reset/
2. Enter email: test@example.com
3. Submit form
4. Check email for reset link
```

#### 5.2 Click Reset Link
```
Steps:
1. Open email in MailHog
2. Click reset link (or copy URL)
3. Navigate to: /accounts/password/reset/uidXXX/tokenXXX/
4. Expected: Form with "New Password" fields
```

#### 5.3 Enter New Password
```
Steps:
1. Form should have:
   - New Password field
   - Confirm Password field
2. Enter new password (must be strong): "NewSecure123!Pass"
3. Click "Change Password"
4. Expected: Success message - "Password has been reset"
```

#### 5.4 Verify Password Changed
```
Python Check:
from django.contrib.auth import get_user_model
User = get_user_model()
user = User.objects.get(email='test@example.com')

# Try with old password (should fail)
from django.contrib.auth import authenticate
auth1 = authenticate(username='test@example.com', password='OldPassword123')
assert auth1 is None, "Old password should not work"

# Try with new password (should succeed)
auth2 = authenticate(username='test@example.com', password='NewSecure123!Pass')
assert auth2 is not None, "New password should work"
```

#### 5.5 Test Login with New Password
```
Steps:
1. Go to: http://localhost:8002/accounts/login/
2. Enter email: test@example.com
3. Enter password: NewSecure123!Pass
4. Click "Login"
5. Expected: Successfully logged in, redirected to dashboard
```

### Expected Results
- ✓ Reset form displays correctly
- ✓ New password accepted
- ✓ Password validation applied
- ✓ Old password no longer works
- ✓ New password works for login
- ✓ Session established with new credentials

### Database Verification
```python
from django.contrib.auth import get_user_model
import hashlib

User = get_user_model()
user = User.objects.get(email='test@example.com')

# Password stored as hash, not plaintext
print(f"Password hash: {user.password[:20]}...")  # Should be salted hash

# Check format (Django uses PBKDF2 by default)
assert user.password.startswith('pbkdf2_sha256$'), "Password should be PBKDF2 hashed"
```

---

## Test 6: Account Lockout After Failed Attempts

### Objective
Verify brute force protection prevents unauthorized password reset and login attempts.

### Test Steps

#### 6.1 Check Axes Configuration
```
Python:
python manage.py shell

from django.conf import settings
print("AXES_FAILURE_LIMIT:", getattr(settings, 'AXES_FAILURE_LIMIT', 5))
print("AXES_COOLOFF_DURATION:", getattr(settings, 'AXES_COOLOFF_DURATION', 'Not set'))
print("AXES_LOCK_OUT_AT_FAILURE:", getattr(settings, 'AXES_LOCK_OUT_AT_FAILURE', True))

# Expected:
# AXES_FAILURE_LIMIT = 5 (lock after 5 failures)
# AXES_COOLOFF_DURATION = 1 hour
```

#### 6.2 Test Login Account Lockout
```
Steps:
1. Go to login: http://localhost:8002/accounts/login/
2. Enter correct email: test@example.com
3. Enter wrong password: WrongPass123 (5 times)
4. After 5 attempts:
   Expected: "Account locked. Try again after 1 hour"

Automated Test:
from axes.models import AccessAttempt
import requests

for i in range(6):
    response = requests.post(
        'http://localhost:8002/accounts/login/',
        data={
            'email': 'test@example.com',
            'password': 'WrongPassword'
        }
    )
    print(f"Attempt {i+1}: {response.status_code}")
    if 'locked' in response.text.lower():
        print("Account locked - brute force protection working!")
        break
```

#### 6.3 Test Password Reset Attempt During Lockout
```
Steps:
1. During lockout, try password reset
2. Expected behavior: May allow reset request (email-based attack prevention)
3. But login should still be blocked
```

#### 6.4 Verify Lockout Cleared After Cooloff
```
Manual Wait: (If AXES_COOLOFF_DURATION = 1 hour, this is tedious to test manually)

Automated:
from axes.models import AccessAttempt
from axes.helpers import reset_attempt

# Reset lockout
reset_attempt(ip_address='127.0.0.1')  # or relevant IP

# Try login again
from django.contrib.auth import authenticate
user = authenticate(username='test@example.com', password='OldPassword123')
assert user is not None, "Login should work after cooloff"
```

### Expected Results
- ✓ Failed login attempts tracked
- ✓ Account locked after 5 failures
- ✓ Clear error message on lockout
- ✓ Lockout duration respected (1-24 hours)
- ✓ Login available after cooloff period
- ✓ Lockout doesn't affect other accounts

### Security Considerations
```python
# Configuration in settings.py:
AXES_FAILURE_LIMIT = 5          # Lock after 5 failures
AXES_COOLOFF_DURATION = timedelta(hours=1)
AXES_LOCK_OUT_AT_FAILURE = True
AXES_USE_USER_AGENT = True      # Include user agent in tracking
AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP = True

# View configuration:
# from axes.decorators import axes_dispatch_decorator
# @axes_dispatch_decorator  # Applied to login views
```

---

## Test 7: Notification on Password Change

### Objective
Verify user is notified when their password is changed.

### Test Steps

#### 7.1 Change Password When Logged In
```
Steps:
1. Login with valid credentials
2. Go to: http://localhost:8002/accounts/me/ (or account settings)
3. Click "Change Password"
4. Enter:
   - Old Password: current password
   - New Password: NewPass123!
   - Confirm Password: NewPass123!
5. Click "Change Password"
6. Expected: Success message
```

#### 7.2 Check for Notification Email
```
Steps:
1. Open MailHog: http://localhost:8026
2. Look for email with subject containing:
   - "Password Changed"
   - "Account Security"
   - "Confirm Password Change"
3. Expected Email Content:
   - "Your password was changed at [timestamp]"
   - "If this wasn't you, please contact support"
   - "Revert link" or "Report suspicious activity" link
```

#### 7.3 Verify Email Details
```
Email should contain:
- Timestamp of change
- IP address (optional but recommended)
- Device/Browser info (optional)
- Action taken ("Password Changed")
- Support contact information
```

#### 7.4 Verify via Celery Tasks
```
Python:
from tenant_profiles.tasks import send_password_change_notification
from tenant_profiles.models import User

user = User.objects.get(email='test@example.com')

# Check if task is configured
from celery import current_app
tasks = list(current_app.tasks.keys())
password_tasks = [t for t in tasks if 'password' in t.lower()]
print(f"Password-related tasks: {password_tasks}")

# Should include something like:
# - accounts.tasks.send_password_change_notification
# - accounts.tasks.send_security_alert
```

### Expected Results
- ✓ Email sent on password change
- ✓ Email arrives within seconds (async)
- ✓ Email contains security information
- ✓ Email formatted clearly
- ✓ Includes revert/report options
- ✓ Task logged in Celery

### Implementation Verification
```python
# In accounts/signals.py or accounts/tasks.py:
from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=User)
def notify_password_change(sender, instance, **kwargs):
    # Should send notification email
    send_password_change_notification.delay(instance.id)

# Or in accounts/views.py (PasswordChangeView):
def form_valid(self, form):
    response = super().form_valid(form)
    # Send notification
    send_password_change_notification(self.request.user)
    return response
```

---

## Integration Test: Complete Workflow

### Full Password Reset Flow

```
1. REQUEST PHASE
   ↓ User goes to /accounts/password/reset/
   ↓ Enters email address
   ↓ System validates email exists (secretly)
   ↓ Email sent with reset link

2. EMAIL VERIFICATION PHASE
   ↓ User receives email (check MailHog)
   ↓ User clicks reset link
   ↓ System validates token:
     - Token format
     - Token signature
     - Token expiration
     - User still active

3. PASSWORD CHANGE PHASE
   ↓ User sees password change form
   ↓ Validates password strength:
     - Minimum length
     - Complexity
     - No common passwords
   ↓ User enters new password
   ↓ System hashes password
   ↓ Saves to database

4. CONFIRMATION PHASE
   ↓ Success message displayed
   ↓ Notification email sent
   ↓ Old session invalidated
   ↓ User redirected to login

5. LOGIN PHASE
   ↓ User logs in with new password
   ↓ System validates credentials
   ↓ Session created
   ↓ User can access account

```

### Complete Test Script
```bash
#!/bin/bash

# 1. Request reset
curl -X POST http://localhost:8002/accounts/password/reset/ \
  -d "email=test@example.com"

# 2. Check MailHog (manual)
# Open: http://localhost:8026
# Copy reset link from email

# 3. Extract token from URL
RESET_URL="http://localhost:8002/accounts/password/reset/uid123/token456/"

# 4. Submit password change
curl -X POST "$RESET_URL" \
  -d "new_password1=NewSecure123!&new_password2=NewSecure123!"

# 5. Test login with new password
curl -X POST http://localhost:8002/accounts/login/ \
  -d "email=test@example.com&password=NewSecure123!"

# 6. Check for notification email in MailHog
```

---

## Security Checklist

### For Each Test Case

#### Email Sending (Test 1)
- [ ] Email sent immediately
- [ ] Email from correct sender address
- [ ] Reset link in email (not in preview/subject)
- [ ] Link contains token (not plain password)
- [ ] Email encrypted in transit (TLS/SSL)
- [ ] No sensitive data in unencrypted fields

#### Token Generation (Test 2)
- [ ] Token is cryptographically secure
- [ ] Token includes salt/IV
- [ ] Token format consistent
- [ ] Token length adequate (40+ chars)
- [ ] HMAC verification implemented
- [ ] Token cannot be guessed

#### Token Expiration (Test 3)
- [ ] Timeout configured (24-72 hours)
- [ ] Expired tokens rejected
- [ ] Clear error message on expiration
- [ ] User can request new token
- [ ] No token reuse possible
- [ ] Old tokens invalidated on new request

#### Password Strength (Test 4)
- [ ] Minimum length enforced (8+ chars)
- [ ] Complexity enforced (mixed case, numbers, symbols)
- [ ] Common passwords blocked
- [ ] Attribute similarity checked
- [ ] History checked (no recent passwords)
- [ ] Real-time validation feedback

#### Password Change (Test 5)
- [ ] Old password no longer works
- [ ] New password works for login
- [ ] Database hash updated
- [ ] Sessions invalidated
- [ ] No plaintext storage
- [ ] Password history updated

#### Account Lockout (Test 6)
- [ ] Failed attempts tracked by IP
- [ ] Account locked after threshold
- [ ] Clear error message on lockout
- [ ] Lockout duration enforced
- [ ] Admin can unlock manually
- [ ] Legitimate users not affected

#### Notifications (Test 7)
- [ ] Notification email sent
- [ ] Email contains timestamp
- [ ] Email contains IP address
- [ ] Email contains device info
- [ ] Email has unsubscribe option
- [ ] Email has report link for unauthorized changes

---

## Troubleshooting

### Issue: No email sent
```
Checklist:
1. Is EMAIL_BACKEND configured?
   python manage.py shell
   from django.conf import settings
   print(settings.EMAIL_BACKEND)

2. Is MailHog running?
   docker compose ps mailhog

3. Is password reset form working?
   Check browser console for errors

Solution:
- Check settings.py EMAIL_BACKEND
- Ensure EMAIL_HOST and EMAIL_PORT correct
- Check Docker logs: docker compose logs mailhog
```

### Issue: Token invalid
```
Checklist:
1. Is token format correct in URL?
2. Did token expire (>24 hours old)?
3. Is user still active?
4. Was password reset since token generated?

Solution:
- Request new reset token
- Check PASSWORD_RESET_TIMEOUT setting
- Check user.is_active = True
- Clear browser cache (token may be in URL)
```

### Issue: Password change fails
```
Checklist:
1. Is password strong enough?
   - 8+ characters
   - Mixed case
   - Numbers and symbols

2. Are validators properly configured?
   python manage.py shell
   from django.conf import settings
   print(settings.AUTH_PASSWORD_VALIDATORS)

Solution:
- Review password requirements on form
- Check error messages on submit
- Run: python manage.py makemigrations accounts
- Run: python manage.py migrate
```

### Issue: Account locked on reset
```
Checklist:
1. Check axes lockout status:
   docker compose exec web python manage.py shell
   from axes.models import AccessAttempt
   AccessAttempt.objects.all()

2. Reset lockout:
   from axes.helpers import reset_attempt
   reset_attempt(ip_address='127.0.0.1')

Solution:
- Wait for AXES_COOLOFF_DURATION to expire
- Admin can reset in /admin/axes/
- Check AXES_FAILURE_LIMIT not too low
```

---

## Performance Benchmarks

### Expected Response Times

| Operation | Expected Time | Max Acceptable |
|-----------|---------------|-----------------|
| Reset request page load | 200-500ms | 1s |
| Email sending | 1-5 seconds | 10s (async) |
| Token validation | 50-100ms | 500ms |
| Password hash + save | 100-500ms | 1s |
| Login with new password | 200-500ms | 1s |
| Account lockout check | 50-100ms | 200ms |

### Load Testing
```bash
# Using Apache Bench (if available)
ab -n 100 -c 10 http://localhost:8002/accounts/password/reset/

# Using wrk (if available)
wrk -t4 -c100 -d30s http://localhost:8002/accounts/password/reset/
```

---

## Compliance Checklist

### OWASP Standards
- [ ] A01:2021 – Broken Access Control (User can only reset own password)
- [ ] A02:2021 – Cryptographic Failures (Tokens encrypted, passwords hashed)
- [ ] A04:2021 – Insecure Deserialization (No untrusted serialization)
- [ ] A05:2021 – Authorization (User auth required for some operations)
- [ ] A07:2021 – Identification and Authentication Failures (2FA optional)
- [ ] A09:2021 – Logging and Monitoring (Audit logs kept)

### GDPR/Data Protection
- [ ] User password reset is user-initiated
- [ ] Data processed securely
- [ ] Audit trail maintained
- [ ] Right to access password change history
- [ ] Right to be forgotten not violated

### Best Practices
- [ ] Tokens expire
- [ ] One-time use tokens
- [ ] Secure token generation
- [ ] Secure email transmission
- [ ] Audit logging
- [ ] Brute force protection
- [ ] Rate limiting

---

## References

- [Django Password Reset Docs](https://docs.djangoproject.com/en/5.2/topics/auth/passwords/#password-reset)
- [django-allauth Documentation](https://django-allauth.readthedocs.io/)
- [OWASP Password Reset Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [django-axes Brute Force Protection](https://django-axes.readthedocs.io/)
