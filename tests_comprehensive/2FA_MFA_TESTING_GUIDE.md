# Zumodra 2FA/MFA Comprehensive Testing Guide

## Overview

This document provides a complete guide for testing the Two-Factor Authentication (2FA) and Multi-Factor Authentication (MFA) system in Zumodra, including:

1. TOTP (Time-based One-Time Password) enrollment
2. QR code generation for authenticator apps
3. Backup codes generation and usage
4. 2FA verification on login
5. 2FA enforcement by role/admin requirement
6. 2FA disablement workflow
7. Recovery options when 2FA device is lost
8. django-two-factor-auth integration
9. django-otp plugin compatibility
10. allauth MFA integration

## Technology Stack

### 2FA/MFA Libraries
- **django-two-factor-auth** (1.18.1) - Primary 2FA framework
- **django-otp** (1.6.3) - OTP framework with plugins
- **allauth** (65.3.0) - Authentication with built-in MFA support
- **fido2** (1.1.0) - WebAuthn/FIDO2 support
- **pyotp** - Python library for TOTP/HOTP
- **qrcode** - QR code generation

### Plugins
- `django_otp.plugins.otp_totp` - TOTP implementation
- `django_otp.plugins.otp_hotp` - HMAC-based OTP
- `django_otp.plugins.otp_email` - Email-based OTP
- `django_otp.plugins.otp_static` - Static backup codes

## Architecture

### Data Models

```
User (django.contrib.auth.models.User)
├── TOTPDevice (django_otp.plugins.otp_totp.models.TOTPDevice)
│   ├── user
│   ├── name
│   ├── key (secret)
│   ├── confirmed
│   └── created_at
├── StaticDevice (django_otp.plugins.otp_static.models.StaticDevice)
│   ├── user
│   ├── name
│   ├── confirmed
│   └── token_set (StaticToken)
│       └── token (backup codes)
└── Authenticator (allauth.mfa.models.Authenticator) [if using allauth MFA]
    ├── user
    ├── type (totp/webauthn)
    └── data
```

### Configuration

**Settings Location:** `zumodra/settings.py` and `zumodra/settings_security.py`

```python
# Django OTP Configuration
OTP_TOTP_ISSUER = 'Zumodra'
OTP_TOTP_INTERVAL = 30  # Token refresh in seconds
OTP_TOTP_DIGITS = 6     # OTP length
OTP_STATIC_THROTTLE_FACTOR = 1

# 2FA Enforcement
TWO_FACTOR_MANDATORY = False  # Can be set to True in settings_security.py
ALLAUTH_2FA_FORCE_2FA = True  # Security setting

# Middleware
OTPMiddleware - validates OTP tokens
Require2FAMiddleware - enforces 2FA if mandatory
```

## Test Suites

### Suite 1: TOTP Enrollment Process

#### Test Cases

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| `test_totp_enrollment_page_requires_login` | Unauthenticated access to TOTP page | Redirects to login |
| `test_totp_enrollment_page_loads_authenticated` | TOTP page loads for authenticated user | Returns 200 status |
| `test_totp_device_creation` | Create TOTP device for user | Device created successfully |
| `test_totp_device_secret_key_generation` | TOTP secret key is generated | Key is valid base32 |
| `test_totp_confirm_flow` | Verify and confirm TOTP device | Device marked as confirmed |
| `test_multiple_totp_devices_not_allowed` | Only one active TOTP device per user | Device management enforced |
| `test_totp_timezone_independence` | TOTP works in any timezone | Token verification succeeds |

#### Manual Testing Steps

1. **Enroll in TOTP:**
   ```
   1. Log in to the application
   2. Navigate to Settings > Security > Two-Factor Authentication
   3. Click "Set up Authenticator"
   4. Page loads with QR code and manual entry code
   5. Complete enrollment with authenticator app
   ```

2. **Verify Token Generation:**
   ```
   1. Open authenticator app (Google Authenticator, Authy, etc.)
   2. Scan QR code from enrollment page
   3. Verify 6-digit code updates every 30 seconds
   4. Codes should be valid for current 30-second window
   ```

### Suite 2: QR Code Generation

#### Test Cases

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| `test_totp_qr_code_generation` | QR code is generated during enrollment | URL format is valid |
| `test_totp_qr_code_content` | QR code contains correct TOTP configuration | Config parameters present |
| `test_qr_code_is_valid` | Generated QR code is scannable | Code follows otpauth:// spec |
| `test_qr_code_unique_per_device` | Each device has unique QR code | URLs differ by secret |

#### Manual Testing Steps

1. **Test QR Code Scannability:**
   ```
   1. Initiate TOTP enrollment
   2. Use multiple authenticator apps to scan QR code:
      - Google Authenticator
      - Microsoft Authenticator
      - Authy
      - FreeOTP
   3. Verify all apps show same 6-digit code
   ```

2. **Verify QR Code Content:**
   ```
   1. Open enrollment page
   2. Inspect QR code URL (right-click > Inspect)
   3. Verify format: otpauth://totp/[issuer]:[user]?secret=[key]&period=30&digits=6
   4. Check issuer is "Zumodra"
   ```

### Suite 3: Backup Codes

#### Test Cases

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| `test_backup_codes_creation` | Backup codes device is created | Device object exists |
| `test_backup_codes_generation` | Backup codes are generated | 10 codes created by default |
| `test_backup_code_usage` | Backup code can be used for authentication | Code validates successfully |
| `test_backup_code_single_use` | Backup code is consumed after use | Cannot reuse same code |
| `test_backup_code_count` | Correct number of backup codes | 10 codes generated |
| `test_invalid_backup_code_rejected` | Invalid code is rejected | Verification fails |

#### Manual Testing Steps

1. **Generate Backup Codes:**
   ```
   1. Complete TOTP enrollment
   2. Click "Generate Backup Codes"
   3. 10 codes displayed (format: XXXX-XXXX-XXXX)
   4. Download/print codes securely
   5. Confirm codes are saved
   ```

2. **Use Backup Code:**
   ```
   1. Log out from all sessions
   2. Log in to account
   3. When prompted for TOTP:
      - Enter backup code instead of TOTP token
      - Code should be accepted
      - Try same code again - should be rejected
   ```

3. **Backup Code Management:**
   ```
   1. Navigate to 2FA settings
   2. View generated backup codes
   3. Delete individual codes
   4. Regenerate new codes
   5. Old codes should no longer work
   ```

### Suite 4: 2FA Verification on Login

#### Test Cases

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| `test_login_without_mfa_setup` | Login without MFA setup | Access granted normally |
| `test_login_with_mfa_enabled_requires_challenge` | Login with MFA requires challenge | Redirect to MFA verification |
| `test_valid_totp_token_accepts_login` | Valid TOTP token completes login | Session established |
| `test_invalid_totp_token_rejects_login` | Invalid TOTP token rejected | Login fails |
| `test_expired_totp_token_rejected` | Expired token is rejected | Verification fails |
| `test_totp_rate_limiting` | TOTP attempts are rate-limited | Brute force protection |

#### Manual Testing Steps

1. **Test MFA Challenge on Login:**
   ```
   1. Enroll in TOTP (see Suite 1)
   2. Log out
   3. Log in with correct username/password
   4. Page should ask for TOTP code
   5. Enter current 6-digit code
   6. Login completes successfully
   ```

2. **Test Invalid Token Handling:**
   ```
   1. Log in with correct credentials
   2. When asked for TOTP:
      - Enter wrong code (e.g., 000000)
      - Should show error
      - Allow retry with correct code
   ```

3. **Test Rate Limiting:**
   ```
   1. Log in with correct credentials
   2. When asked for TOTP:
      - Enter 5 incorrect codes in rapid succession
      - Should be rate limited
      - Wait period before retry
   ```

### Suite 5: 2FA Enforcement

#### Test Cases

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| `test_mfa_optional_by_default` | MFA is optional by default | Users can access without MFA |
| `test_mfa_mandatory_enforced` | MFA is enforced when mandatory | Redirect to MFA setup |
| `test_mfa_enforcement_skipped_with_setup` | MFA enforcement skipped if setup | Access granted |
| `test_admin_mfa_enforcement` | Admin users have MFA enforcement | Admin enforced to use MFA |
| `test_admin_with_mfa_can_access` | Admin with MFA can access panel | Admin panel accessible |

#### Configuration for Testing

**In development environment:**

```bash
# Make MFA mandatory
export TWO_FACTOR_MANDATORY=true

# Make MFA optional
export TWO_FACTOR_MANDATORY=false
```

**In Django settings:**

```python
# settings_security.py
TWO_FACTOR_MANDATORY = env.bool('TWO_FACTOR_MANDATORY', default=False)
ALLAUTH_2FA_FORCE_2FA = True  # Enforces for allauth
```

#### Manual Testing Steps

1. **Test Mandatory Enforcement:**
   ```
   1. Set TWO_FACTOR_MANDATORY=true
   2. Create new user without MFA
   3. Log in as new user
   4. Should be redirected to MFA setup page
   5. Cannot proceed without completing MFA
   ```

2. **Test Admin Enforcement:**
   ```
   1. Create admin user without MFA
   2. Try to access admin panel
   3. Should be redirected to MFA setup
   4. Admin panel inaccessible until MFA setup
   ```

### Suite 6: 2FA Disablement

#### Test Cases

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| `test_mfa_device_removal` | TOTP device can be removed | Device deleted from database |
| `test_backup_codes_removal` | Backup codes can be removed | Device deleted |
| `test_all_mfa_devices_removal` | All MFA devices removed | Complete MFA disabled |
| `test_mfa_disablement_allows_login` | Login works without MFA after disablement | Normal login flow |
| `test_disablement_requires_confirmation` | Disablement requires user confirmation | Two-step process |

#### Manual Testing Steps

1. **Disable TOTP:**
   ```
   1. Log in to account with TOTP enabled
   2. Navigate to Settings > Security > Two-Factor
   3. Click "Remove Authenticator"
   4. Confirm removal
   5. Log out and log back in
   6. Should NOT ask for TOTP code
   ```

2. **Disable All 2FA:**
   ```
   1. Navigate to Settings > Security
   2. Remove all MFA devices
   3. Confirm removals
   4. Verify no 2FA prompt on next login
   ```

3. **Re-enroll After Disablement:**
   ```
   1. Disable TOTP (see above)
   2. Re-enroll with new authenticator app
   3. Should generate new secret
   4. Old codes from previous enrollment should NOT work
   ```

### Suite 7: Recovery Options

#### Test Cases

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| `test_recovery_with_backup_codes` | Can recover with backup codes | Authentication succeeds |
| `test_recovery_with_email` | Email available for recovery | Email on file |
| `test_recovery_process_verification` | Recovery verification flow works | Email verified |
| `test_backup_device_for_recovery` | Backup device enables recovery | Device exists |
| `test_recovery_codes_are_unique` | Recovery codes are unique | No duplicates |

#### Manual Testing Steps

1. **Prepare for Device Loss:**
   ```
   1. Enroll in TOTP
   2. Generate and save backup codes
   3. Print/export codes to safe location
   4. Test code validation (use one code)
   ```

2. **Simulate Device Loss - Use Backup Codes:**
   ```
   1. "Lose" access to authenticator app
   2. Log in to account
   3. When asked for TOTP:
      - Use backup code instead
      - Should authenticate successfully
   ```

3. **Recovery via Email:**
   ```
   1. If locked out of account:
      - Use "Lost access to authenticator?" link
      - Request email recovery
      - Check email for recovery link
      - Reset 2FA through email link
   ```

4. **Account Recovery Process:**
   ```
   1. Contact support if all recovery methods fail
   2. Verify identity (email, phone, KYC)
   3. Admin can reset 2FA
   4. User re-enrolls in TOTP
   ```

## Running the Test Suite

### Automated Testing

#### Using pytest

```bash
# Run all 2FA tests
pytest tests_comprehensive/test_2fa_mfa_complete.py -v

# Run specific test suite
pytest tests_comprehensive/test_2fa_mfa_complete.py::TestTOTPEnrollment -v

# Run with coverage
pytest tests_comprehensive/test_2fa_mfa_complete.py --cov=accounts --cov-report=html

# Run quick tests only
pytest tests_comprehensive/test_2fa_mfa_complete.py -m "not slow" -v
```

#### Using Docker Compose

```bash
# Start services
docker compose up -d

# Run tests inside container
docker compose exec web pytest tests_comprehensive/test_2fa_mfa_complete.py -v

# Run with coverage
docker compose exec web pytest tests_comprehensive/test_2fa_mfa_complete.py --cov

# Stop services
docker compose down
```

#### Using Test Script

```bash
# Run all tests
cd tests_comprehensive
./run_2fa_tests.sh

# Run with Docker
./run_2fa_tests.sh --docker

# Run quick tests
./run_2fa_tests.sh --quick

# Generate coverage report
./run_2fa_tests.sh --coverage

# Verbose output
./run_2fa_tests.sh --verbose
```

### Manual Testing Checklist

```
2FA/MFA Manual Testing Checklist
================================

TOTP Enrollment:
☐ TOTP enrollment page accessible
☐ QR code displays correctly
☐ Manual entry code available
☐ Authenticator app scans QR code
☐ TOTP codes update every 30 seconds
☐ 6-digit codes generated correctly

QR Code:
☐ QR code is scannable with multiple apps
☐ QR code format is correct (otpauth://)
☐ Issuer is set to "Zumodra"
☐ Secret is encoded correctly

Backup Codes:
☐ Backup codes can be generated
☐ Exactly 10 codes generated
☐ Codes have correct format
☐ Codes can be copied/printed
☐ Backup codes can be used for login

2FA Login:
☐ Login with TOTP code works
☐ Invalid code rejected
☐ Rate limiting works
☐ Session established after MFA
☐ Logout works

Enforcement:
☐ Mandatory mode forces MFA setup
☐ Optional mode allows access without MFA
☐ Admin enforcement works
☐ Role-based enforcement works

Disablement:
☐ TOTP device can be removed
☐ Login works normally after removal
☐ Re-enrollment generates new codes
☐ Old codes don't work after re-enrollment

Recovery:
☐ Backup codes work for login
☐ Recovery email works
☐ Lost device recovery flow works
☐ Support can reset 2FA
```

## Security Considerations

### Best Practices

1. **Secret Storage:**
   - TOTP secrets stored securely (encrypted in database)
   - Secrets never exposed in logs
   - Secrets never sent in email

2. **Token Validation:**
   - Tokens validated server-side only
   - Token time window checked (+/- 30 seconds)
   - Rate limiting on failed attempts

3. **Backup Codes:**
   - Generated cryptographically
   - Single-use enforcement
   - Not stored in plaintext

4. **Session Management:**
   - 2FA verification required for sensitive operations
   - Session timeout after 2FA challenge
   - Re-authentication on role changes

### Known Issues

1. **QR Code Display:** QR codes may not display in all email clients
2. **Authenticator Compatibility:** Some apps may have timezone issues
3. **Backup Code Exhaustion:** Users need recovery plan if all codes used
4. **Session Timeouts:** 2FA session may timeout on slow networks

### Security Testing

```python
# Test secret is not exposed
def test_totp_secret_not_exposed_in_logs():
    device = TOTPDevice.objects.create(user=user)
    # Verify logs don't contain secret
    assert device.key not in captured_logs

# Test rate limiting
def test_totp_rate_limiting():
    for i in range(10):
        verify_invalid_token()
    # Should be rate limited after 5 attempts
    assert rate_limit_exceeded

# Test concurrent verification
def test_concurrent_verification():
    # Multiple simultaneous attempts should not cause issues
    thread1.start(verify_token)
    thread2.start(verify_token)
    assert both_succeed
```

## Troubleshooting

### Common Issues

**Issue:** TOTP codes not working
```
Solution:
1. Check device time synchronization
2. Verify TOTP secret is correct
3. Check time window allowance (+/- 30 seconds)
4. Regenerate TOTP device
```

**Issue:** QR code not scanning
```
Solution:
1. Use manual entry code instead
2. Try different authenticator app
3. Ensure camera focus clear
4. Check screen brightness
```

**Issue:** Backup codes not working
```
Solution:
1. Ensure code format is correct (spaces, dashes)
2. Check code hasn't been used before
3. Regenerate new backup codes
4. Use email recovery if needed
```

**Issue:** Locked out of account
```
Solution:
1. Check for backup codes
2. Try email recovery
3. Contact support for account recovery
4. Verify identity via KYC
```

## Performance Metrics

### Expected Performance

| Operation | Target | Acceptable Range |
|-----------|--------|------------------|
| TOTP token generation | < 10ms | < 50ms |
| TOTP verification | < 50ms | < 100ms |
| Backup code lookup | < 10ms | < 50ms |
| QR code generation | < 100ms | < 500ms |
| Device retrieval | < 5ms | < 20ms |

### Load Testing

```bash
# Load test TOTP verification
locust -f tests_comprehensive/load_2fa.py --host=http://localhost:8000

# Expected metrics:
# - 500 RPS handling
# - 95th percentile < 100ms
# - 99th percentile < 500ms
```

## Compliance

### Standards Implemented

- **RFC 6238:** TOTP (Time-based One-Time Password)
- **RFC 4226:** HOTP (HMAC-based One-Time Password)
- **WebAuthn Level 2:** FIDO2 support
- **NIST SP 800-63B:** Digital Identity Guidelines

### Regulatory Requirements

- **GDPR:** User data handling and privacy
- **PCI DSS:** Payment authentication
- **SOC 2:** Security controls
- **HIPAA:** Healthcare data protection (if applicable)

## References

### Documentation

- [django-two-factor-auth](https://github.com/Bouke/django-two-factor-auth)
- [django-otp](https://django-otp-official.readthedocs.io/)
- [django-allauth](https://django-allauth.readthedocs.io/)
- [PyOTP Documentation](https://github.com/pyauth/pyotp)

### RFC Standards

- [RFC 6238 - TOTP](https://tools.ietf.org/html/rfc6238)
- [RFC 4226 - HOTP](https://tools.ietf.org/html/rfc4226)
- [WebAuthn Spec](https://w3c.github.io/webauthn/)

## Appendix

### Useful Commands

```bash
# Create user for testing
python manage.py create_user --username testuser --email test@zumodra.test --password TestPassword123!

# Reset 2FA for user (admin only)
python manage.py shell
>>> from django.contrib.auth import get_user_model
>>> User = get_user_model()
>>> user = User.objects.get(username='testuser')
>>> from django_otp.plugins.otp_totp.models import TOTPDevice
>>> TOTPDevice.objects.filter(user=user).delete()

# View TOTP secret (testing only)
>>> device = TOTPDevice.objects.get(user=user)
>>> print(device.key)

# Test TOTP token generation
>>> import pyotp
>>> totp = pyotp.TOTP(device.key)
>>> print(totp.now())
```

### Test Environment Setup

```bash
# Create .env for testing
TEST_MODE=true
DEBUG=true
TWO_FACTOR_MANDATORY=false
ENABLE_2FA=true
OTP_TOTP_ISSUER=Zumodra

# Run development server
python manage.py runserver

# Run tests
pytest tests_comprehensive/test_2fa_mfa_complete.py
```

## Support and Contact

For issues, questions, or additional testing requirements:

- **QA Team:** qa@zumodra.test
- **Security Team:** security@zumodra.test
- **GitHub Issues:** https://github.com/zumodra/zumodra/issues
- **Documentation:** https://docs.zumodra.test

---

**Last Updated:** 2026-01-17
**Version:** 1.0
**Status:** Active
