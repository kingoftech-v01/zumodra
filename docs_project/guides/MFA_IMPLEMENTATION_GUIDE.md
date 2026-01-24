# MFA Implementation Guide - Zumodra

**Date:** 2026-01-16
**Server:** zumodra.rhematek-solutions.com
**Implementation:** django-allauth 65.3.0+ with MFAEnforcementMiddleware

---

## Overview

Zumodra implements Two-Factor Authentication (MFA) using:
- **django-allauth 65.3.0+** - Built-in MFA support (TOTP and WebAuthn)
- **MFAEnforcementMiddleware** - Custom 30-day grace period enforcement
- **Grace Period:** 30 days for new users to set up MFA
- **Reminder:** 7 days before MFA becomes required

---

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                         User Request                        │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              TenantMainMiddleware (django-tenants)          │
│              Resolves tenant from subdomain/domain          │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│          MFAEnforcementMiddleware (accounts/middleware.py)  │
│          ┌────────────────────────────────────────────┐     │
│          │ 1. Check if user authenticated             │     │
│          │ 2. Check if path is exempt                 │     │
│          │ 3. Check if user is superuser (exempt)     │     │
│          │ 4. Check if user has MFA enabled           │     │
│          │ 5. Check grace period (30 days)            │     │
│          │ 6. Show reminder (7 days before deadline)  │     │
│          │ 7. Redirect to MFA setup if expired        │     │
│          └────────────────────────────────────────────┘     │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                         View/Template                        │
│              (Dashboard, ATS, HR Core, etc.)                 │
└─────────────────────────────────────────────────────────────┘
```

### Middleware Configuration

**File:** `zumodra/settings.py`

```python
MIDDLEWARE = [
    # ... other middleware ...
    'django_tenants.middleware.main.TenantMainMiddleware',
    'tenants.middleware.TenantURLConfMiddleware',
    'tenant_profiles.middleware.MFAEnforcementMiddleware',  # 30-day MFA grace period enforcement
    # ... other middleware ...
]
```

### MFA URLs

**File:** `zumodra/urls.py`

```python
urlpatterns += i18n_patterns(
    # ... other patterns ...
    path('accounts/', include('allauth.urls')),                 # allauth URLs
    path('accounts/two-factor/', include('allauth.mfa.urls')),  # MFA URLs (built-in allauth 65.3.0+)
    # ... other patterns ...
)
```

---

## MFAEnforcementMiddleware Details

**File:** `c:\Users\techn\OneDrive\Documents\zumodra\accounts\middleware.py`

### Configuration

```python
class MFAEnforcementMiddleware:
    EXEMPT_PATHS = [
        '/accounts/two-factor/',  # MFA setup pages
        '/accounts/mfa/',         # Alternative MFA path
        '/accounts/logout/',      # Logout
        '/accounts/password/reset/',  # Password reset
        '/static/',               # Static files
        '/media/',                # Media files
        '/api/',                  # API endpoints
        '/health/',               # Health checks
        '/.well-known/',          # ACME/OAuth discovery
    ]

    GRACE_PERIOD_DAYS = 30  # Days before MFA is required
    REMINDER_DAYS = 7       # Show reminder when X days remaining
```

### Flow Chart

```
User Request
    │
    ▼
Is user authenticated? ──No──► Allow (continue to view)
    │ Yes
    ▼
Is path exempt? ──Yes──► Allow (continue to view)
    │ No
    ▼
Is user superuser? ──Yes──► Allow (continue to view)
    │ No
    ▼
Does user have MFA enabled? ──Yes──► Allow (continue to view)
    │ No
    ▼
Has grace period (30 days) expired? ──No──► Check reminder
    │ Yes                                        │
    ▼                                            ▼
Redirect to MFA setup                    Days remaining ≤ 7? ──Yes──► Show reminder
with warning message                         │ No               (once per session)
                                             ▼
                                       Allow (continue to view)
```

### Key Methods

#### `_user_has_mfa(user)`
Checks if user has any active MFA method enabled.

```python
def _user_has_mfa(self, user):
    try:
        # Check for allauth MFA authenticators
        if hasattr(user, 'mfa_authenticators'):
            return user.mfa_authenticators.filter(is_active=True).exists()
    except Exception:
        pass
    return False
```

#### `_grace_period_expired(user)`
Checks if 30-day grace period has expired.

```python
def _grace_period_expired(self, user):
    if not user.date_joined:
        return False
    cutoff_date = timezone.now() - timedelta(days=self.GRACE_PERIOD_DAYS)
    return user.date_joined < cutoff_date
```

#### `_days_until_mfa_required(user)`
Calculates days remaining in grace period.

```python
def _days_until_mfa_required(self, user):
    if not user.date_joined:
        return self.GRACE_PERIOD_DAYS
    required_date = user.date_joined + timedelta(days=self.GRACE_PERIOD_DAYS)
    delta = required_date - timezone.now()
    return max(0, delta.days)
```

---

## User Experience Flow

### New User (First 30 Days)

```
Day 1: User signs up
   │
   ├─► Login: ✅ Success (no MFA required)
   │
   ├─► Dashboard: ℹ️ Info banner: "Consider setting up MFA for security"
   │
Day 23: 7 days remaining
   │
   ├─► Login: ✅ Success
   │
   ├─► Dashboard: ⚠️ Warning: "Please set up MFA. Required in 7 days."
   │
Day 30: Grace period ends
   │
   ├─► Login: ⚠️ Redirected to /accounts/two-factor/
   │
   └─► Warning: "MFA is required. Please set it up to continue."
```

### User with MFA Enabled

```
Login
   │
   ├─► Username/Password: ✅ Correct
   │
   ├─► MFA Challenge: Enter 6-digit code
   │       │
   │       ├─► Valid Code: ✅ Access granted → Dashboard
   │       │
   │       └─► Invalid Code: ❌ Error → Retry
   │
   └─► Alternative: Use backup code
           │
           ├─► Valid Backup Code: ✅ Access granted
           │
           └─► Code is invalidated after use
```

### Old User Without MFA (>30 Days)

```
Login
   │
   ├─► Username/Password: ✅ Correct
   │
   ├─► Redirect: → /accounts/two-factor/
   │
   ├─► Warning Message: "MFA is required for your security"
   │
   └─► Setup Required:
           │
           ├─► Setup TOTP: Scan QR code → Verify → ✅ Enabled
           │
           └─► Now can access dashboard
```

---

## MFA Setup Process

### TOTP Setup (Authenticator App)

1. **Navigate to MFA Setup**
   - URL: `/en-us/accounts/two-factor/`
   - Click "Enable Authenticator App"

2. **QR Code Display**
   - URL: `/en-us/accounts/two-factor/totp/activate/`
   - QR code generated using user's secret
   - Manual entry secret also displayed

3. **Scan with Authenticator App**
   - Google Authenticator
   - Authy
   - Microsoft Authenticator
   - 1Password
   - Bitwarden

4. **Verify Code**
   - Enter 6-digit TOTP code
   - Submit form
   - Success: TOTP activated

5. **Generate Backup Codes**
   - URL: `/en-us/accounts/two-factor/recovery-codes/`
   - Generate 8-10 single-use backup codes
   - Save securely

### WebAuthn Setup (Security Key)

1. **Navigate to MFA Setup**
   - URL: `/en-us/accounts/two-factor/`
   - Click "Add Security Key"

2. **Browser Prompt**
   - Insert security key (YubiKey, etc.)
   - Follow browser prompts
   - Touch/activate key

3. **Name Your Key**
   - Give key a recognizable name
   - Submit

4. **Success**
   - Security key registered
   - Can use for login

---

## Database Schema

### MFA-Related Models

#### `allauth_mfa_authenticator`
Stores user's MFA authenticators (TOTP, WebAuthn).

```sql
CREATE TABLE allauth_mfa_authenticator (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES auth_user(id),
    type VARCHAR(50) NOT NULL,  -- 'totp' or 'webauthn'
    secret TEXT,                -- Encrypted TOTP secret
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP,
    CONSTRAINT unique_user_type UNIQUE (user_id, type)
);
```

#### `allauth_mfa_recovery_code`
Stores single-use backup/recovery codes.

```sql
CREATE TABLE allauth_mfa_recovery_code (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES auth_user(id),
    code VARCHAR(100) NOT NULL,  -- Hashed recovery code
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    used_at TIMESTAMP
);
```

### Querying MFA Status

```python
# Check if user has MFA enabled
from allauth.mfa.models import Authenticator

user_has_mfa = Authenticator.objects.filter(
    user=user,
    is_active=True
).exists()

# Get user's MFA methods
mfa_methods = Authenticator.objects.filter(
    user=user,
    is_active=True
).values_list('type', flat=True)
# Returns: ['totp'] or ['totp', 'webauthn']

# Check days until MFA required
from django.utils import timezone
from datetime import timedelta

grace_period_days = 30
cutoff_date = timezone.now() - timedelta(days=grace_period_days)
grace_period_expired = user.date_joined < cutoff_date

if not grace_period_expired:
    required_date = user.date_joined + timedelta(days=grace_period_days)
    days_remaining = (required_date - timezone.now()).days
```

---

## API Integration

### REST API MFA Endpoints

**Note:** API uses JWT authentication, not session-based MFA.

```bash
# Login (get JWT token)
POST /api/v1/auth/token/
{
    "email": "user@example.com",
    "password": "password123"
}

# Response (if MFA enabled)
{
    "mfa_required": true,
    "temp_token": "eyJ0eXAiOiJKV1QiLCJh...",
    "methods": ["totp"]
}

# Verify MFA
POST /api/v1/auth/mfa/verify/
{
    "temp_token": "eyJ0eXAiOiJKV1QiLCJh...",
    "code": "123456"
}

# Response (success)
{
    "access": "eyJ0eXAiOiJKV1QiLCJh...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJh..."
}
```

---

## Security Considerations

### Exempt Paths Security

The middleware **MUST** exempt certain paths to prevent redirect loops:

```python
EXEMPT_PATHS = [
    '/accounts/two-factor/',  # Required: MFA setup pages
    '/accounts/logout/',      # Required: Allow logout
    '/static/',               # Safe: Static assets
    '/media/',                # Safe: User uploads
    '/api/',                  # Safe: API uses JWT
    '/health/',               # Safe: Health checks
]
```

**Warning:** Do NOT exempt business logic paths like `/dashboard/` or `/app/`.

### Session Management

The middleware uses session keys to prevent annoying users:

```python
# Only show reminder once per session
session_key = f'mfa_reminder_shown_{request.user.id}'
if not request.session.get(session_key):
    messages.info(request, f'Please set up MFA. Required in {days_remaining} days.')
    request.session[session_key] = True
```

### Superuser Exemption

Superusers are exempt from MFA enforcement for emergency access:

```python
# Skip for superusers (admins need emergency access)
if request.user.is_superuser:
    return self.get_response(request)
```

**Production Note:** Consider enforcing MFA even for superusers in high-security environments.

---

## Troubleshooting

### Common Issues

#### 1. Redirect Loop
**Symptom:** Browser shows "Too many redirects" error.
**Cause:** MFA setup page not in EXEMPT_PATHS.
**Fix:** Ensure `/accounts/two-factor/` is in EXEMPT_PATHS.

#### 2. Reminder Shows Every Page Load
**Symptom:** MFA reminder appears on every page.
**Cause:** Session key not being set.
**Fix:** Check session middleware is enabled.

#### 3. Old Users Not Redirected
**Symptom:** Users >30 days old can access without MFA.
**Cause:** Grace period check logic error.
**Fix:** Verify `user.date_joined` is set correctly.

#### 4. TOTP Code Invalid
**Symptom:** Valid codes rejected.
**Cause:** Server time drift.
**Fix:** Sync server time with NTP:
```bash
sudo ntpdate -s time.nist.gov
```

#### 5. Backup Codes Not Working
**Symptom:** Backup codes show "Invalid code" error.
**Cause:** Codes not generated or already used.
**Fix:** Generate new backup codes at `/accounts/two-factor/recovery-codes/`.

---

## Testing Guide

### Manual Testing Checklist

1. **New User Grace Period**
   - Create new user
   - Login should succeed without MFA
   - Dashboard should show reminder

2. **Old User Enforcement**
   - Use user created >30 days ago
   - Login should redirect to MFA setup
   - Should block access until MFA set up

3. **TOTP Setup**
   - Navigate to `/accounts/two-factor/`
   - Scan QR code with authenticator app
   - Verify code works

4. **MFA Challenge**
   - Logout and login
   - Should prompt for MFA code
   - Valid code should grant access

5. **Backup Codes**
   - Generate backup codes
   - Use one to login
   - Code should be invalidated

6. **Exempt Paths**
   - Test `/static/`, `/api/`, `/health/`
   - Should not require MFA

### Automated Testing

Run the test script:

```bash
python test_mfa_enforcement.py
```

Review test report:

```bash
cat MFA_TEST_REPORT_*.json
```

---

## Monitoring & Metrics

### Key Metrics to Track

1. **MFA Adoption Rate**
   ```sql
   SELECT
       COUNT(DISTINCT user_id) AS users_with_mfa,
       (SELECT COUNT(*) FROM auth_user) AS total_users,
       ROUND(COUNT(DISTINCT user_id)::NUMERIC / (SELECT COUNT(*) FROM auth_user) * 100, 2) AS adoption_rate
   FROM allauth_mfa_authenticator
   WHERE is_active = TRUE;
   ```

2. **Grace Period Users**
   ```sql
   SELECT COUNT(*)
   FROM auth_user
   WHERE date_joined > NOW() - INTERVAL '30 days'
     AND id NOT IN (
         SELECT user_id FROM allauth_mfa_authenticator WHERE is_active = TRUE
     );
   ```

3. **Overdue Users** (>30 days, no MFA)
   ```sql
   SELECT COUNT(*)
   FROM auth_user
   WHERE date_joined < NOW() - INTERVAL '30 days'
     AND id NOT IN (
         SELECT user_id FROM allauth_mfa_authenticator WHERE is_active = TRUE
     )
     AND NOT is_superuser;
   ```

---

## Appendix

### URLs Quick Reference

| Path | Purpose | Auth Required | MFA Required |
|------|---------|---------------|--------------|
| `/en-us/accounts/two-factor/` | MFA setup index | ✅ | ❌ |
| `/en-us/accounts/two-factor/totp/activate/` | TOTP setup | ✅ | ❌ |
| `/en-us/accounts/two-factor/totp/deactivate/` | TOTP disable | ✅ | ❌ |
| `/en-us/accounts/two-factor/recovery-codes/` | Backup codes | ✅ | ❌ |
| `/en-us/accounts/two-factor/authenticate/` | MFA challenge | ✅ | ❌ |
| `/en-us/accounts/logout/` | Logout | ✅ | ❌ |
| `/en-us/app/dashboard/` | Dashboard | ✅ | ✅ (after 30 days) |

### Templates Location

```
templates_auth/
├── mfa/
│   ├── index.html                    # MFA setup index
│   ├── authenticate.html             # MFA challenge
│   ├── totp/
│   │   ├── activate_form.html        # TOTP setup form
│   │   └── deactivate_form.html      # TOTP disable form
│   └── recovery_codes/
│       ├── index.html                # Backup codes index
│       └── generate.html             # Generate backup codes
└── allauth_2fa/                      # Legacy 2FA templates (if using django-allauth-2fa)
```

### Configuration Settings

**File:** `zumodra/settings.py`

```python
# Django-allauth MFA settings
ACCOUNT_MFA_ENABLED = True
ACCOUNT_MFA_FORMS = {
    'totp': 'allauth.mfa.totp.forms.ActivateTOTPForm',
}

# Session settings
SESSION_COOKIE_AGE = 86400  # 24 hours
SESSION_COOKIE_SECURE = True  # HTTPS only
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'

# MFA enforcement
MFA_GRACE_PERIOD_DAYS = 30
MFA_REMINDER_DAYS = 7
```

---

**End of Implementation Guide**
