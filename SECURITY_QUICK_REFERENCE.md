# Zumodra Security Quick Reference Card

**Last Updated:** 2026-01-16
**Security Rating:** A- (85/100)
**Production Status:** Ready with critical fixes needed

---

## 🚨 CRITICAL ACTIONS REQUIRED

### Before Production Deployment:

**1. Install HTML Sanitization (CRITICAL)**
```bash
pip install nh3==0.2.15
```

**2. Apply Sanitization to User Content**
```python
from core.security.sanitizers import sanitize_html

# In models:
def save(self, *args, **kwargs):
    self.description = sanitize_html(self.description)
    super().save(*args, **kwargs)
```

**3. Verify Environment Variables**
```bash
# Must be set in production:
DEBUG=False
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
```

---

## ✅ WHAT'S WORKING WELL

| Feature | Status | Notes |
|---------|--------|-------|
| HTTPS Enforcement | ✅ | SSL redirect enabled in production |
| HSTS | ✅ | 1-year max-age, preload eligible |
| CSRF Protection | ✅ | SameSite cookies, trusted origins |
| SQL Injection | ✅ | ORM-only, no raw SQL |
| Brute Force | ✅ | Django-Axes + custom middleware |
| Admin Security | ✅ | Honeypot at /admin/ |
| MFA | ✅ | TOTP + WebAuthn, 30-day grace |
| Secrets | ✅ | Environment variables only |

---

## ⚠️ WHAT NEEDS ATTENTION

| Issue | Priority | Timeline | Action |
|-------|----------|----------|--------|
| HTML Sanitization Missing | 🔴 CRITICAL | 24 hours | Install nh3 |
| CSP Allows unsafe-inline | 🟡 HIGH | 1 week | Implement nonces |
| No SSRF Protection | 🟡 HIGH | 1 week | URL validation |
| Virus Scanning Disabled | 🟢 MEDIUM | 2 weeks | Enable ClamAV |

---

## 🔒 Security Headers (Production)

### Expected Headers:
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; ...
Referrer-Policy: strict-origin-when-cross-origin
```

### Test Headers:
```bash
curl -I https://zumodra.com
```

---

## 🛡️ Security Configuration Files

### Key Files:
```
zumodra/settings_security.py  # Security settings (AXES, CSRF, HSTS)
zumodra/settings.py           # Main settings (CSP, SSL)
api/middleware.py             # Security headers middleware
custom_account_u/middleware.py # Brute force protection
accounts/middleware.py        # MFA enforcement
```

### Security Middleware Stack:
```python
MIDDLEWARE = [
    'django_tenants.middleware.main.TenantMainMiddleware',
    'django.middleware.security.SecurityMiddleware',  # SSL redirect
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',      # CSRF
    'custom_account_u.middleware.Require2FAMiddleware',  # MFA
    'accounts.middleware.MFAEnforcementMiddleware',   # MFA grace
    'csp.middleware.CSPMiddleware',                   # CSP
    'axes.middleware.AxesMiddleware',                 # Brute force
]
```

---

## 🔐 Authentication & Authorization

### Brute Force Protection:
```python
# Django-Axes
AXES_FAILURE_LIMIT = 5          # 5 failed attempts
AXES_COOLOFF_TIME = 1 hour      # Lockout duration

# DRF Rate Limiting
'auth': '5/minute'              # Login endpoint
'password': '3/minute'          # Password reset
'registration': '5/hour'        # New accounts
```

### MFA Enforcement:
```python
MFA_GRACE_PERIOD = 30 days      # Grace period for new users
MFA_SUPPORTED = ['totp', 'webauthn']
```

### Admin Security:
```
/admin/        → Honeypot (fake admin, logs attempts)
/admin-panel/  → Real Django admin (protected)
/cms/          → Wagtail CMS (protected)
```

---

## 🔍 Input Validation

### Current State:
- ✅ Django form validation
- ✅ DRF serializer validation
- ✅ TinyMCE sanitizes rich text
- ❌ **Missing:** General HTML sanitization library

### Required Implementation:

**1. Install Sanitizer:**
```bash
pip install nh3
```

**2. Create Sanitizer Module:**
```python
# core/security/sanitizers.py
import nh3

def sanitize_html(content: str) -> str:
    return nh3.clean(
        content,
        tags={'p', 'br', 'strong', 'em', 'a', 'ul', 'ol', 'li'},
        attributes={'a': {'href', 'title'}},
        link_rel="noopener noreferrer"
    )

def sanitize_text(text: str) -> str:
    return nh3.clean(text, tags=set())
```

**3. Apply to Models:**
```python
from core.security.sanitizers import sanitize_html

class MyModel(models.Model):
    description = models.TextField()

    def save(self, *args, **kwargs):
        self.description = sanitize_html(self.description)
        super().save(*args, **kwargs)
```

### Critical Fields to Sanitize:
- [ ] User bio/profiles (accounts.CustomUser.bio)
- [ ] Job descriptions (ats.Job.description)
- [ ] Service descriptions (services.Service.description)
- [ ] Messages (messages_sys.Message.content)
- [ ] Comments (blog.Comment.content)

---

## 🌐 Content Security Policy

### Current CSP (Settings):
```python
CONTENT_SECURITY_POLICY = {
    'DIRECTIVES': {
        'default-src': ("'self'",),
        'script-src': ("'self'", "'unsafe-inline'", "'unsafe-eval'"),  # ⚠️
        'style-src': ("'self'", "'unsafe-inline'"),
        'img-src': ("'self'", "data:", "https:"),
        'connect-src': ("'self'", "wss:", "https:"),
        'frame-src': ("'self'",),
        'object-src': ("'none'",),
    }
}
```

### ⚠️ Issues:
- **unsafe-inline** and **unsafe-eval** weaken XSS protection
- Multiple CDN sources allowed
- img-src allows all HTTPS

### Recommended CSP:
```python
CONTENT_SECURITY_POLICY = {
    'DIRECTIVES': {
        'default-src': ("'self'",),
        'script-src': ("'self'", "https://js.stripe.com"),  # No unsafe
        'style-src': ("'self'",),  # No unsafe-inline
        'img-src': ("'self'", "data:", "blob:"),
        'connect-src': ("'self'", "wss:", "https://api.stripe.com"),
        'frame-src': ("'none'",),  # More restrictive
        'object-src': ("'none'",),
    }
}
```

---

## 🔑 Secrets Management

### Environment Variables:
```bash
# Required in production:
SECRET_KEY=<strong-random-key>
DB_PASSWORD=<secure-password>
STRIPE_SECRET_KEY=sk_live_xxx
AWS_SECRET_ACCESS_KEY=<aws-secret>
OPENAI_API_KEY=<openai-key>

# SSL Settings:
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
```

### Generate Secret Key:
```python
python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
```

### Best Practices:
- ✅ Never commit .env files
- ✅ Use different keys for dev/staging/prod
- ✅ Rotate secrets quarterly
- ✅ Use secret management service (AWS Secrets Manager, Vault)

---

## 🧪 Security Testing

### Test HTTPS Redirect:
```bash
curl -I http://zumodra.com
# Should redirect to https://
```

### Test Security Headers:
```bash
curl -I https://zumodra.com | grep -i "strict-transport-security"
```

### Test Rate Limiting:
```bash
# Should get 429 Too Many Requests after 5 attempts
for i in {1..10}; do
  curl -X POST https://zumodra.com/accounts/login/ \
    -d "username=test&password=wrong" -w "%{http_code}\n"
done
```

### Test CSRF Protection:
```bash
# Should get 403 Forbidden without CSRF token
curl -X POST https://zumodra.com/api/v1/jobs/ \
  -H "Content-Type: application/json" \
  -d '{"title":"Test"}' -w "%{http_code}\n"
```

### External Security Scans:
- SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=zumodra.com
- Security Headers: https://securityheaders.com/?q=zumodra.com
- Mozilla Observatory: https://observatory.mozilla.org/analyze/zumodra.com

---

## 📊 Security Monitoring

### Log Files:
```
logs/security.log              # Security events
logs/django.log                # General application logs
```

### What's Logged:
- ✅ Failed login attempts (django-axes)
- ✅ Admin honeypot access
- ✅ Brute force attacks
- ✅ CSRF failures
- ✅ Permission denials
- ✅ Webhook signature failures

### Check Locked Accounts:
```python
# Django shell
from axes.models import AccessAttempt

# View recent failures
AccessAttempt.objects.order_by('-attempt_time')[:10]

# Unlock user
from axes.utils import reset
reset(username='user@example.com')
```

---

## 🚨 Incident Response

### Security Breach Detected:

**1. Immediate Actions:**
- [ ] Rotate all secrets (SECRET_KEY, DB_PASSWORD, API keys)
- [ ] Lock affected accounts
- [ ] Review access logs
- [ ] Notify security team

**2. Investigation:**
- [ ] Check `logs/security.log` for anomalies
- [ ] Review recent admin honeypot attempts
- [ ] Check for unusual login patterns
- [ ] Verify database integrity

**3. Recovery:**
- [ ] Patch vulnerability
- [ ] Deploy security updates
- [ ] Run security audit
- [ ] Document incident

### Contact:
- Security Team: security@zumodra.com
- Emergency: [To be configured]

---

## 📋 Pre-Deployment Checklist

### Before Deploying to Production:

**Environment:**
- [ ] DEBUG=False
- [ ] SECURE_SSL_REDIRECT=True
- [ ] SESSION_COOKIE_SECURE=True
- [ ] CSRF_COOKIE_SECURE=True
- [ ] Strong SECRET_KEY set
- [ ] Production database credentials
- [ ] Production API keys (Stripe, AWS, etc.)

**Security:**
- [ ] ALLOWED_HOSTS configured
- [ ] CSRF_TRUSTED_ORIGINS set
- [ ] CORS_ALLOWED_ORIGINS configured
- [ ] HSTS enabled (31536000)
- [ ] CSP tightened (no unsafe directives)
- [ ] nh3 or bleach installed
- [ ] Input sanitization applied

**Testing:**
- [ ] Security headers verified
- [ ] HTTPS redirect working
- [ ] CSRF protection tested
- [ ] Rate limiting functional
- [ ] MFA enforcement active
- [ ] SSL certificate valid

**Monitoring:**
- [ ] Error tracking (Sentry) configured
- [ ] Security logging enabled
- [ ] Backup system operational
- [ ] Alerts configured

---

## 🔧 Quick Fixes

### Fix: Add HTML Sanitization
```bash
# 1. Install
pip install nh3

# 2. Create sanitizer
cat > core/security/sanitizers.py << 'EOF'
import nh3

def sanitize_html(content: str) -> str:
    return nh3.clean(content, tags={'p', 'br', 'strong', 'em', 'a'})
EOF

# 3. Apply to models (example)
# Edit ats/models.py:
from core.security.sanitizers import sanitize_html

class Job(models.Model):
    def save(self, *args, **kwargs):
        self.description = sanitize_html(self.description)
        super().save(*args, **kwargs)
```

### Fix: Tighten CSP
```python
# Edit zumodra/settings.py
CONTENT_SECURITY_POLICY = {
    'DIRECTIVES': {
        'default-src': ("'self'",),
        'script-src': ("'self'", "https://js.stripe.com"),  # Remove unsafe
        'style-src': ("'self'",),
        'img-src': ("'self'", "data:", "blob:"),
        'connect-src': ("'self'", "wss:", "https://api.stripe.com"),
        'frame-src': ("'none'",),
        'object-src': ("'none'",),
    }
}
```

### Fix: Enable HTTPS in Production
```bash
# .env (production)
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
```

---

## 📚 Resources

### Documentation:
- **Full Audit:** `SECURITY_AUDIT_REPORT.md`
- **Checklist:** `SECURITY_CHECKLIST.md`
- **Project Guide:** `CLAUDE.md`

### Django Security:
- Django Security Docs: https://docs.djangoproject.com/en/5.2/topics/security/
- Django Deployment Checklist: https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/

### Security Standards:
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- OWASP Cheat Sheets: https://cheatsheetseries.owasp.org/

### Tools:
- Bandit (Python security): https://github.com/PyCQA/bandit
- Safety (dependency scan): https://github.com/pyupio/safety
- OWASP ZAP: https://www.zaproxy.org/

---

## 🎯 Security Score

**Current:** 85/100 (A-)
**Target:** 95/100 (A+)

**To Reach A+:**
1. ✅ Install nh3 sanitization library
2. ✅ Tighten CSP (remove unsafe directives)
3. ✅ Enable virus scanning
4. ✅ Implement SSRF protection
5. ✅ Add comprehensive monitoring

---

**Print this card and keep it handy during development!**

*Last Updated: 2026-01-16*
*Next Review: 2026-04-16*
