# 🔐 Security Policy - Zumodra

**Last Updated:** December 25, 2025
**Security Level:** Enterprise-Grade
**Compliance:** GDPR-Ready, OWASP Top 10 Protected

---

## 📋 Table of Contents

1. [Security Overview](#security-overview)
2. [Reporting Vulnerabilities](#reporting-vulnerabilities)
3. [Security Features](#security-features)
4. [Authentication & Authorization](#authentication--authorization)
5. [Data Protection](#data-protection)
6. [Infrastructure Security](#infrastructure-security)
7. [Security Checklist](#security-checklist)
8. [Incident Response](#incident-response)
9. [Security Best Practices](#security-best-practices)
10. [Compliance](#compliance)

---

## 🛡️ Security Overview

Zumodra implements multiple layers of security to protect user data and prevent common vulnerabilities.

### Security Stack

| Layer | Technology | Status |
|-------|------------|--------|
| **Authentication** | Django Allauth + 2FA | ✅ Active |
| **Brute Force Protection** | django-axes | ✅ Active |
| **Admin Security** | admin_honeypot | ✅ Active |
| **Content Security** | django-csp | ✅ Active |
| **Audit Logging** | django-auditlog | ✅ Active |
| **SSL/TLS** | Certbot + Nginx | ⚠️ Production Only |
| **API Security** | JWT + Rate Limiting | ✅ Active |
| **Data Encryption** | django-cryptography | ✅ Available |

---

## 🚨 Reporting Vulnerabilities

### How to Report

If you discover a security vulnerability, please:

1. **DO NOT** open a public GitHub issue
2. **Email:** security@zumodra.com (if configured)
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if applicable)

### Response Timeline

- **Acknowledgment:** Within 24 hours
- **Initial Assessment:** Within 48 hours
- **Fix Development:** 1-7 days (based on severity)
- **Patch Release:** As soon as tested
- **Public Disclosure:** 30 days after patch release

### Severity Levels

| Level | Response Time | Examples |
|-------|---------------|----------|
| **Critical** | < 24 hours | RCE, SQL Injection, Authentication Bypass |
| **High** | < 48 hours | XSS, CSRF, Privilege Escalation |
| **Medium** | < 7 days | Information Disclosure, DoS |
| **Low** | < 30 days | Minor issues, UI bugs |

---

## 🔒 Security Features

### 1. Authentication Security

#### Two-Factor Authentication (2FA)
**Status:** ✅ **Mandatory for all users**

```python
# settings.py
ALLAUTH_2FA_FORCE_2FA = True  # Enforces 2FA
TWO_FACTOR_MANDATORY = True
```

**Supported Methods:**
- ✅ TOTP (Time-based One-Time Password) - Google Authenticator, Authy
- ✅ HOTP (HMAC-based One-Time Password)
- ✅ Email-based OTP
- ✅ Static backup codes

**Configuration:**
```python
INSTALLED_APPS = [
    'django_otp',
    'django_otp.plugins.otp_totp',
    'django_otp.plugins.otp_hotp',
    'django_otp.plugins.otp_email',
    'django_otp.plugins.otp_static',
    'allauth_2fa',
]
```

#### Password Security
**Policy:**
- ✅ Minimum 8 characters
- ✅ Must contain uppercase, lowercase, numbers
- ✅ Password history (last 3 passwords)
- ✅ Password expiration (90 days - configurable)
- ✅ Bcrypt hashing (Django default)

**Settings:**
```python
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 8}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]
```

#### Session Security
```python
# Session expires after 2 weeks of inactivity
SESSION_COOKIE_AGE = 1209600  # 2 weeks

# Secure session cookies in production
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'

# CSRF protection
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Lax'
```

---

### 2. Brute Force Protection

**Package:** django-axes

**Protection:**
- ✅ Locks account after 5 failed login attempts
- ✅ 30-minute cooldown period
- ✅ IP-based tracking
- ✅ Admin notification on repeated attacks

**Configuration:**
```python
# settings.py
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = 0.5  # 30 minutes
AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP = True
AXES_RESET_ON_SUCCESS = True
```

**Monitor Attacks:**
```bash
# View locked out IPs/users
python manage.py axes_reset

# Reset specific IP
python manage.py axes_reset_ip 192.168.1.1

# Reset specific user
python manage.py axes_reset_username john@example.com
```

---

### 3. Admin Panel Security

#### Honeypot Protection
**Package:** admin_honeypot

**How it works:**
- Fake admin panel at `/admin/` traps attackers
- Real admin panel at `/admin-panel/` (custom URL)
- Logs all honeypot access attempts
- Alerts on repeated attempts

**Configuration:**
```python
# zumodra/urls.py
urlpatterns = [
    path('admin/', include('admin_honeypot.urls', namespace='admin_honeypot')),  # Fake
    path('admin-panel/', admin.site.urls),  # Real
]
```

**Monitor Attacks:**
```python
# View honeypot attempts
from admin_honeypot.models import LoginAttempt
attempts = LoginAttempt.objects.all()
```

#### Admin Access Controls
```python
# Custom admin middleware
class AdminAccessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith('/admin-panel/'):
            # Require 2FA for admin access
            if not request.user.is_verified():
                return redirect('account_login')
        return self.get_response(request)
```

---

### 4. Content Security Policy (CSP)

**Package:** django-csp

**Policy:**
```python
# settings.py
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'", 'cdn.jsdelivr.net', 'code.jquery.com')
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'", 'fonts.googleapis.com')
CSP_FONT_SRC = ("'self'", 'fonts.gstatic.com')
CSP_IMG_SRC = ("'self'", 'data:', 'https:')
CSP_CONNECT_SRC = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)  # Prevents clickjacking
CSP_INCLUDE_NONCE_IN = ['script-src']
```

**Headers Set:**
- ✅ Content-Security-Policy
- ✅ X-Frame-Options: DENY
- ✅ X-Content-Type-Options: nosniff
- ✅ X-XSS-Protection: 1; mode=block

---

### 5. API Security

#### JWT Authentication
**Package:** djangorestframework-simplejwt

**Configuration:**
```python
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
}
```

**Usage:**
```bash
# Get token
curl -X POST http://localhost:8000/api/auth/token/ \
  -d '{"username": "user", "password": "pass"}'

# Use token
curl http://localhost:8000/api/services/ \
  -H "Authorization: Bearer <access_token>"

# Refresh token
curl -X POST http://localhost:8000/api/auth/token/refresh/ \
  -d '{"refresh": "<refresh_token>"}'
```

#### Rate Limiting
**Package:** django-ratelimit

**Limits:**
```python
# settings.py
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',      # Anonymous users
        'user': '1000/hour',     # Authenticated users
        'staff': '10000/hour',   # Staff users
    }
}
```

**Custom Rate Limits:**
```python
from django_ratelimit.decorators import ratelimit

@ratelimit(key='ip', rate='5/m', method='POST')
def login_view(request):
    # Limited to 5 POST requests per minute per IP
    pass

@ratelimit(key='user', rate='100/h')
def api_endpoint(request):
    # Limited to 100 requests per hour per user
    pass
```

#### CORS Configuration
**Package:** django-cors-headers

```python
# settings.py
CORS_ALLOWED_ORIGINS = env.list('CORS_ALLOWED_ORIGINS', default=[
    'http://localhost:3000',
    'http://localhost:8080',
])

CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
```

---

### 6. Audit Logging

**Package:** django-auditlog

**What's Logged:**
- ✅ Model changes (create, update, delete)
- ✅ User authentication events
- ✅ Admin actions
- ✅ Permission changes
- ✅ Security events

**Configuration:**
```python
# models.py
from auditlog.registry import auditlog
from auditlog.models import AuditlogHistoryField

class DService(models.Model):
    # ... fields ...
    history = AuditlogHistoryField()

auditlog.register(DService)
auditlog.register(User)
auditlog.register(DServiceContract)
```

**Query Logs:**
```python
from auditlog.models import LogEntry

# Get all logs for a user
logs = LogEntry.objects.filter(actor=user)

# Get changes to a specific object
logs = LogEntry.objects.get_for_object(service_instance)

# Get all deletions
logs = LogEntry.objects.filter(action=LogEntry.Action.DELETE)
```

---

## 🔐 Data Protection

### Encryption at Rest

#### Database Encryption
**Package:** django-cryptography

```python
from django_cryptography.fields import encrypt

class Payment(models.Model):
    card_number = encrypt(models.CharField(max_length=20))  # Encrypted
    amount = models.DecimalField(max_digits=10, decimal_places=2)  # Not encrypted
```

#### Environment Variables
```bash
# .env file (NEVER commit to git)
SECRET_KEY=<256-bit random key>
DB_PASSWORD=<strong password>
EMAIL_HOST_PASSWORD=<email password>
STRIPE_SECRET_KEY=sk_live_...
JWT_SECRET_KEY=<random key>
```

**Generate Secure Keys:**
```python
# Generate SECRET_KEY
from django.core.management.utils import get_random_secret_key
print(get_random_secret_key())

# Generate JWT key
import secrets
print(secrets.token_urlsafe(32))
```

### Encryption in Transit

#### SSL/TLS Configuration
**Production Only:**
```python
# settings.py
if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
```

**Nginx SSL Configuration:**
```nginx
# docker/nginx/nginx.conf (production)
server {
    listen 443 ssl http2;
    ssl_certificate /etc/letsencrypt/live/domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/domain.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}
```

---

## 🏗️ Infrastructure Security

### Docker Security

```yaml
# compose.yaml
services:
  web:
    # Run as non-root user
    user: "1000:1000"

    # Read-only root filesystem
    read_only: true

    # Drop all capabilities
    cap_drop:
      - ALL

    # Limit resources
    mem_limit: 1g
    cpus: 1.0

    # Security options
    security_opt:
      - no-new-privileges:true
```

### Database Security

```python
# settings.py
DATABASES = {
    'default': {
        'ENGINE': 'django.contrib.gis.db.backends.postgis',
        'NAME': env('DB_NAME'),
        'USER': env('DB_USER'),  # Use dedicated DB user, NOT postgres
        'PASSWORD': env('DB_PASSWORD'),  # Strong password
        'HOST': env('DB_HOST'),
        'PORT': env('DB_PORT', default='5432'),
        'OPTIONS': {
            'sslmode': 'require',  # Enforce SSL in production
        },
    }
}
```

**PostgreSQL Security:**
```sql
-- Create dedicated user with limited permissions
CREATE USER zumodra_app WITH PASSWORD 'strong_password';
GRANT CONNECT ON DATABASE zumodra TO zumodra_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO zumodra_app;

-- Revoke dangerous permissions
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE zumodra FROM PUBLIC;
```

### Redis Security

```python
# settings.py
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('REDIS_URL', default='redis://127.0.0.1:6379/1'),
        'OPTIONS': {
            'PASSWORD': env('REDIS_PASSWORD', default=''),  # Set in production
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}
```

---

## ✅ Security Checklist

### Before Deployment

#### Environment
- [ ] `DEBUG=False` in production
- [ ] Strong `SECRET_KEY` (256-bit random)
- [ ] All secrets in `.env`, not in code
- [ ] `.env` in `.gitignore`
- [ ] Unique passwords for each service

#### SSL/TLS
- [ ] SSL certificate installed (Let's Encrypt)
- [ ] HTTPS redirect enabled
- [ ] HSTS headers configured
- [ ] SSL grade A+ on SSL Labs

#### Authentication
- [ ] 2FA mandatory for all users
- [ ] Password policy enforced
- [ ] Session timeout configured
- [ ] Brute force protection active

#### API
- [ ] JWT tokens expire (1 hour)
- [ ] Rate limiting enabled
- [ ] CORS properly configured
- [ ] API authentication required

#### Headers
- [ ] CSP headers configured
- [ ] X-Frame-Options: DENY
- [ ] X-Content-Type-Options: nosniff
- [ ] X-XSS-Protection enabled

#### Admin
- [ ] Admin URL changed from `/admin/`
- [ ] Admin honeypot active
- [ ] Admin access restricted by IP (optional)
- [ ] Admin login attempts logged

#### Database
- [ ] Dedicated database user
- [ ] Strong database password
- [ ] SSL connection enforced
- [ ] Regular backups configured

#### Logging
- [ ] Audit logging enabled
- [ ] Security events logged
- [ ] Log rotation configured
- [ ] Logs monitored

#### Updates
- [ ] All packages up to date
- [ ] Security patches applied
- [ ] Django security releases monitored
- [ ] Dependency vulnerability scanning

---

## 🚨 Incident Response

### Security Incident Procedure

#### 1. Detection
- Monitor audit logs
- Review login attempts
- Check honeypot logs
- Monitor API rate limits

#### 2. Containment
```bash
# Block IP address
python manage.py axes_reset_ip <attacker_ip>

# Disable compromised user
User.objects.filter(email='compromised@user.com').update(is_active=False)

# Invalidate all JWT tokens
# Force re-authentication
```

#### 3. Investigation
```python
from auditlog.models import LogEntry

# Review all actions by user
logs = LogEntry.objects.filter(actor__email='suspicious@user.com')

# Review all login attempts
from admin_honeypot.models import LoginAttempt
attempts = LoginAttempt.objects.filter(ip_address='suspicious_ip')
```

#### 4. Recovery
- Patch vulnerability
- Reset compromised passwords
- Review and update security policies
- Notify affected users

#### 5. Post-Incident
- Document incident
- Update security procedures
- Implement additional controls
- Train team on lessons learned

---

## 🛡️ Security Best Practices

### Development

```python
# Never commit secrets
# ❌ BAD
SECRET_KEY = "1_v5itzez)b(o-9eb@c4%)%hkgof^%-&7i*h2ne(7d7f-5p(z9"

# ✅ GOOD
SECRET_KEY = env('SECRET_KEY')
```

```python
# Use parameterized queries (Django ORM does this automatically)
# ❌ BAD
results = MyModel.objects.raw(f"SELECT * FROM table WHERE id = {user_input}")

# ✅ GOOD
results = MyModel.objects.filter(id=user_input)
```

```python
# Validate user input
# ❌ BAD
service_id = request.GET.get('id')
service = DService.objects.get(id=service_id)

# ✅ GOOD
try:
    service_id = int(request.GET.get('id'))
    service = DService.objects.get(id=service_id)
except (ValueError, DService.DoesNotExist):
    return HttpResponse("Invalid service", status=400)
```

### Production

```bash
# Regular security audits
python manage.py check --deploy

# Keep dependencies updated
pip list --outdated
pip-audit  # Check for known vulnerabilities

# Monitor logs
tail -f /var/log/zumodra/security.log

# Backup database daily
pg_dump zumodra > backup_$(date +%Y%m%d).sql
```

---

## 📜 Compliance

### GDPR (General Data Protection Regulation)

#### Data Protection
- ✅ Encryption at rest and in transit
- ✅ Audit logging of all data access
- ✅ User consent tracking
- ✅ Right to access (user can download their data)
- ✅ Right to deletion (user can delete account)
- ✅ Data portability (export in JSON format)

#### Implementation:
```python
# Export user data
def export_user_data(user):
    data = {
        'profile': UserSerializer(user).data,
        'services': DServiceSerializer(user.services.all(), many=True).data,
        'contracts': DServiceContractSerializer(user.contracts.all(), many=True).data,
        # ... more data
    }
    return data

# Delete user data
def delete_user_data(user):
    user.services.all().delete()
    user.contracts.all().delete()
    user.delete()
```

### OWASP Top 10 Protection

| Vulnerability | Protection | Status |
|---------------|------------|--------|
| **A01:2021 - Broken Access Control** | Django permissions, JWT | ✅ |
| **A02:2021 - Cryptographic Failures** | SSL, encryption at rest | ✅ |
| **A03:2021 - Injection** | Django ORM, parameterized queries | ✅ |
| **A04:2021 - Insecure Design** | Security architecture review | ✅ |
| **A05:2021 - Security Misconfiguration** | Settings review, `check --deploy` | ✅ |
| **A06:2021 - Vulnerable Components** | Regular updates, pip-audit | ⚠️ |
| **A07:2021 - Authentication Failures** | 2FA, brute force protection | ✅ |
| **A08:2021 - Software and Data Integrity** | Checksums, audit logs | ✅ |
| **A09:2021 - Logging & Monitoring Failures** | auditlog, security logging | ✅ |
| **A10:2021 - Server-Side Request Forgery** | Input validation, URL whitelist | ⚠️ |

---

## 🔧 Security Tools

### Recommended Tools

```bash
# Vulnerability scanning
pip install safety
safety check

pip install pip-audit
pip-audit

# Code security analysis
pip install bandit
bandit -r zumodra/

# Dependency checking
pip install dependencycheck
dependency-check --scan .
```

### Django Security Commands

```bash
# Check for security issues
python manage.py check --deploy

# Review permissions
python manage.py show_permissions

# Audit database
python manage.py inspectdb

# Check for outdated packages
pip list --outdated
```

---

## 📞 Security Contacts

### Internal Team
- **Security Lead:** [Name] - security@zumodra.com
- **DevOps Lead:** [Name] - devops@zumodra.com
- **CTO:** [Name] - cto@zumodra.com

### External Resources
- **Django Security:** https://docs.djangoproject.com/en/stable/topics/security/
- **OWASP:** https://owasp.org/
- **CVE Database:** https://cve.mitre.org/

---

## 📝 Security Changelog

### December 25, 2025
- ✅ Documented comprehensive security policy
- ✅ Verified all security features active
- ✅ Created security checklist

### [Previous dates]
- Created `.env.example` with secure defaults
- Fixed hardcoded secrets in settings
- Implemented conditional SSL settings
- Configured Celery for background tasks
- Set up Nginx with security headers

---

**Document Version:** 1.0
**Last Security Audit:** Pending
**Next Audit:** [Schedule regular audits]
**Maintained By:** Security Team

---

**Remember:** Security is an ongoing process, not a one-time setup. Regular audits, updates, and monitoring are essential.
