# Zumodra Security Documentation

**Version:** 1.1.0
**Last Updated:** January 2026

This document outlines security measures, policies, and best practices for the Zumodra platform.

---

## Table of Contents

1. [Security Overview](#security-overview)
2. [Authentication & Authorization](#authentication--authorization)
3. [Data Protection](#data-protection)
4. [API Security](#api-security)
5. [Infrastructure Security](#infrastructure-security)
6. [Multi-Tenant Isolation](#multi-tenant-isolation)
7. [Compliance](#compliance)
8. [Incident Response](#incident-response)
9. [Security Checklist](#security-checklist)

---

## Security Overview

Zumodra implements defense-in-depth security with multiple layers of protection:

| Layer | Measures |
|-------|----------|
| Network | Firewall, SSL/TLS, rate limiting |
| Application | Authentication, RBAC, input validation |
| Data | Encryption at rest/transit, secure storage |
| Infrastructure | Container isolation, secret management |
| Monitoring | Audit logs, intrusion detection |

---

## Authentication & Authorization

### JWT Token Authentication

```python
# Token configuration (settings.py)
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
}
```

### Two-Factor Authentication (2FA)

- TOTP-based 2FA via django-otp
- Backup codes for recovery
- Can be enforced per-tenant via `TenantSettings.require_2fa`

### Password Policy

```python
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
     'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]
```

### Login Protection

- **django-axes**: Brute force protection
- Lockout after 5 failed attempts
- IP-based and username-based tracking

```python
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(hours=1)
AXES_LOCKOUT_TEMPLATE = 'security/lockout.html'
```

### Role-Based Access Control (RBAC)

| Role | Scope | Permissions |
|------|-------|-------------|
| PDG/CEO | Full tenant | All operations |
| Supervisor | Circusale | Team management, approvals |
| HR Personnel | Circusale | Onboarding, compliance |
| Hiring Manager | Jobs | ATS operations |
| Employee | Personal | View/edit own data |
| Viewer | Assigned | Read-only access |

---

## Data Protection

### Encryption at Rest

- Database: PostgreSQL with encrypted storage
- Media files: Server-side encryption
- Secrets: Environment variables (never in code)

### Encryption in Transit

```python
# Enforce HTTPS
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

### Sensitive Data Handling

**Never store in plain text:**
- Passwords (hashed with Argon2)
- API keys and secrets
- Payment information (handled by Stripe)
- KYC documents (encrypted storage)

**Data masking in logs:**
```python
SENSITIVE_FIELDS = ['password', 'token', 'secret', 'card', 'ssn']
```

### PII Protection

| Data Type | Storage | Access Control | Retention |
|-----------|---------|----------------|-----------|
| Email | Encrypted DB | Tenant-scoped | Account lifetime |
| Phone | Encrypted DB | Tenant-scoped | Account lifetime |
| Address | Encrypted DB | Tenant-scoped | Account lifetime |
| KYC Documents | Encrypted S3 | User + Admin | 7 years |
| Payment Data | Stripe (tokenized) | None stored | Stripe handles |

---

## API Security

### Rate Limiting

```python
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'api.throttling.TenantAwareThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
        'staff': '10000/hour',
        'auth': '5/minute',  # Login attempts
    }
}
```

### Input Validation

All API inputs are validated using DRF serializers:

```python
class JobPostingSerializer(serializers.ModelSerializer):
    title = serializers.CharField(max_length=200)
    salary_min = serializers.DecimalField(min_value=0)
    salary_max = serializers.DecimalField(min_value=0)

    def validate(self, data):
        if data.get('salary_max') < data.get('salary_min'):
            raise serializers.ValidationError("Max salary must exceed min")
        return data
```

### CORS Configuration

```python
CORS_ALLOWED_ORIGINS = [
    "https://yourdomain.com",
    "https://app.yourdomain.com",
]
CORS_ALLOW_CREDENTIALS = True
```

### Content Security Policy (CSP)

Zumodra enforces a strict **local-only asset policy** with no external CDN dependencies:

```python
CONTENT_SECURITY_POLICY = {
    'default-src': ["'self'"],
    'script-src': ["'self'"],
    'style-src': ["'self'", "'unsafe-inline'"],  # inline for Alpine.js
    'img-src': ["'self'", "data:", "blob:"],
    'font-src': ["'self'"],
    'connect-src': ["'self'", "wss:"],
    'frame-src': ["'none'"],
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'frame-ancestors': ["'none'"],
}
```

### Local Asset Policy

All CSS, JavaScript, fonts, and icons are served locally from `staticfiles/`:

```
staticfiles/
├── assets/
│   ├── js/vendor/     # Alpine.js, HTMX, Chart.js, SortableJS
│   ├── css/           # Icomoon icons, Leaflet
│   └── fonts/         # Local web fonts
└── dist/
    └── output-tailwind.css  # Compiled Tailwind CSS
```

**Prohibited:** CDN-hosted JavaScript, CSS, fonts, or icons (jsdelivr, unpkg, cdnjs, Google Fonts, etc.)

**Exception:** OpenStreetMap tiles for Leaflet maps (required for map functionality)

---

## Infrastructure Security

### Container Security

```dockerfile
# Non-root user
RUN addgroup --system --gid 1001 django
RUN adduser --system --uid 1001 --gid 1001 django
USER django

# Read-only filesystem where possible
# No unnecessary packages
```

### Secret Management

**Environment Variables:**
```bash
# .env (never commit)
SECRET_KEY=<random-64-chars>
DB_PASSWORD=<strong-password>
STRIPE_SECRET_KEY=sk_live_...
```

**For production, use:**
- Docker Secrets
- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault

### Network Security

```yaml
# docker-compose.yml
networks:
  zumodra_network:
    driver: bridge
    internal: false  # Only nginx exposed

# Only expose required ports
ports:
  - "80:80"    # Nginx HTTP
  - "443:443"  # Nginx HTTPS
```

### Firewall Rules

```bash
# Allow only essential ports
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP (redirect to HTTPS)
ufw allow 443/tcp   # HTTPS
ufw enable
```

---

## Multi-Tenant Isolation

### Schema Isolation

Each tenant has a separate PostgreSQL schema:

```python
# Tenant middleware ensures schema isolation
class TenantMiddleware:
    def __call__(self, request):
        tenant = get_tenant_from_request(request)
        connection.set_tenant(tenant)
        return self.get_response(request)
```

### Data Access Control

```python
class TenantAwareManager(models.Manager):
    def get_queryset(self):
        tenant = get_current_tenant()
        return super().get_queryset().filter(tenant=tenant)
```

### WebSocket Tenant Isolation

```python
class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Validate user belongs to conversation's tenant
        tenant_id = await self.get_conversation_tenant()
        user_tenant = self.scope['user'].tenant_id

        if tenant_id != user_tenant:
            await self.close(code=4003)  # Forbidden
            return

        # Tenant-namespaced channel group
        self.room_group_name = f"tenant_{tenant_id}_chat_{conversation_id}"
```

### Cross-Tenant Prevention

- All queries automatically scoped to current tenant
- Shared tables (public schema) have explicit tenant checks
- API responses never leak cross-tenant data
- Audit logs are tenant-isolated

---

## Compliance

### GDPR Compliance

| Requirement | Implementation |
|-------------|----------------|
| Right to Access | Data export endpoint |
| Right to Erasure | Account deletion with cascade |
| Right to Portability | JSON/CSV export |
| Consent | Explicit opt-in for marketing |
| Breach Notification | Incident response process |

### Data Export

```python
# User can export their data
GET /api/v1/accounts/data-export/

# Returns all user data in JSON format
{
    "profile": {...},
    "applications": [...],
    "messages": [...],
    "settings": {...}
}
```

### SOC 2 Considerations

- Audit logging enabled (django-auditlog)
- Access controls documented
- Change management process
- Incident response plan

---

## Incident Response

### Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| Critical | Data breach, system compromise | 15 minutes |
| High | Security vulnerability exploited | 1 hour |
| Medium | Potential vulnerability identified | 24 hours |
| Low | Security improvement needed | 1 week |

### Response Process

1. **Detect:** Monitoring alerts, user reports
2. **Contain:** Isolate affected systems
3. **Investigate:** Determine scope and cause
4. **Remediate:** Fix vulnerability, patch systems
5. **Recover:** Restore normal operations
6. **Document:** Post-incident report

### Security Contacts

- **Security Team:** security@zumodra.com
- **Bug Bounty:** security@zumodra.com
- **On-Call:** PagerDuty escalation

---

## Audit Logging

### Logged Events

```python
class AuditLog(models.Model):
    class ActionType(models.TextChoices):
        CREATE = 'create'
        UPDATE = 'update'
        DELETE = 'delete'
        LOGIN = 'login'
        LOGOUT = 'logout'
        EXPORT = 'export'
        PERMISSION_CHANGE = 'permission_change'
        SETTING_CHANGE = 'setting_change'

    tenant = models.ForeignKey(Tenant)
    user = models.ForeignKey(User)
    action = models.CharField(choices=ActionType.choices)
    resource_type = models.CharField()  # Model name
    resource_id = models.CharField()
    old_values = models.JSONField()
    new_values = models.JSONField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
```

### Log Retention

| Log Type | Retention |
|----------|-----------|
| Audit logs | 7 years |
| Application logs | 90 days |
| Security logs | 1 year |
| Access logs | 30 days |

---

## Security Checklist

### Development

- [ ] No secrets in code or git history
- [ ] Dependencies regularly updated
- [ ] SQL injection prevention (ORM usage)
- [ ] XSS prevention (template escaping)
- [ ] CSRF protection enabled
- [ ] Input validation on all endpoints
- [ ] File upload validation (type + size)

### Deployment

- [ ] HTTPS enforced
- [ ] HSTS enabled
- [ ] Security headers configured
- [ ] Firewall rules applied
- [ ] Database not publicly accessible
- [ ] Redis/RabbitMQ not publicly accessible
- [ ] Secrets in environment/vault

### Operations

- [ ] Regular security updates
- [ ] Vulnerability scanning
- [ ] Penetration testing (annual)
- [ ] Audit log review (monthly)
- [ ] Access review (quarterly)
- [ ] Backup verification (weekly)
- [ ] Incident response drill (annual)

### Code Review

- [ ] No hardcoded credentials
- [ ] Proper error handling (no stack traces to users)
- [ ] Secure random number generation
- [ ] Timing-safe comparisons for secrets
- [ ] SQL parameterization
- [ ] Output encoding

---

## Vulnerability Disclosure

### Reporting Security Issues

If you discover a security vulnerability, please report it to:

**Email:** security@zumodra.com

Include:
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested remediation (optional)

### Response Timeline

- **Acknowledgment:** 24 hours
- **Initial Assessment:** 72 hours
- **Resolution:** Varies by severity
- **Disclosure:** After fix deployed

---

## Security Tools

### Static Analysis

```bash
# Bandit - Python security linter
pip install bandit
bandit -r . -ll

# Safety - Dependency vulnerabilities
pip install safety
safety check
```

### Dynamic Testing

```bash
# OWASP ZAP for API testing
docker run -t owasp/zap2docker-stable zap-api-scan.py \
  -t https://api.zumodra.com/api/schema/ -f openapi
```

### Dependency Scanning

```bash
# pip-audit for Python
pip install pip-audit
pip-audit

# GitHub Dependabot (enabled)
# Snyk (optional)
```

---

**Document maintained by:** Security Team
**Review frequency:** Monthly
**Last security audit:** January 2026
