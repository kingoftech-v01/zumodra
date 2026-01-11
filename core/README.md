# Core App

## Overview

Core utilities, base classes, mixins, validators, and shared functionality used across all Zumodra apps. This app provides the foundation for the entire platform.

## Key Components

### Base Classes & Mixins

- `TenantViewMixin`: Automatic tenant scoping for views
- `ATSPermissionMixin`: ATS permission enforcement
- `HTMXMixin`: HTMX-aware views with custom headers
- `SecureTenantViewSet`: Tenant-scoped DRF viewsets
- `TimestampedModel`: Abstract model with created/updated timestamps
- `TenantAwareModel`: Abstract model with tenant FK

### Validators

- `SSRFValidator`: Prevent Server-Side Request Forgery
- `PhoneNumberValidator`: International phone validation
- `EmailDomainValidator`: Email domain verification
- `FileTypeValidator`: Allowed file type validation
- `FileSizeValidator`: File size limits

### Utilities

#### Domain Utilities (`core/domain.py`)
```python
from core.domain import (
    get_primary_domain,      # Get PRIMARY_DOMAIN
    get_site_url,            # Get SITE_URL with protocol
    get_tenant_url,          # Build tenant-specific URL
    build_absolute_url,      # Build full URL for path
    get_noreply_email,       # Get noreply@{domain}
)
```

#### Cache Utilities (`core/cache/`)
- Tenant-aware caching
- Cache key generation
- Cache invalidation signals

#### Email Utilities (`core/email/`)
- Email template rendering
- Multi-tenant email sending
- Email tracking

### Management Commands

Located in `core/management/commands/`:

- `health_check.py`: System health check
- `sync_site_domain.py`: Sync Django Site object
- `cleanup_sessions.py`: Clean expired sessions
- `generate_test_data.py`: Generate test data

### Middleware

- `TenantMiddleware`: Resolve tenant from domain
- `SecurityHeadersMiddleware`: Add security headers
- `RequestLoggingMiddleware`: Log all requests
- `PerformanceMiddleware`: Track request performance

### Context Processors

```python
# Available in all templates
CONTEXT_PROCESSORS = [
    'core.context_processors.tenant_context',
    'core.context_processors.user_context',
    'core.context_processors.settings_context',
]
```

## File Structure

```
core/
├── __init__.py
├── apps.py
├── models.py               # Abstract base models
├── views.py                # Base view classes
├── mixins.py               # Reusable mixins
├── validators.py           # Custom validators
├── utils.py                # Utility functions
├── domain.py               # Domain utilities
├── middleware.py           # Custom middleware
├── context_processors.py   # Template context processors
├── cache/                  # Caching utilities
│   ├── __init__.py
│   ├── tenant_cache.py
│   └── invalidation.py
├── email/                  # Email utilities
│   ├── __init__.py
│   └── sender.py
└── management/
    └── commands/
        ├── health_check.py
        └── sync_site_domain.py
```

## Integration Points

**Used by ALL apps** for:
- Base model classes
- View mixins
- Validators
- Caching
- Email sending
- Domain utilities

## Configuration

### Environment Variables

Core reads these environment variables:

```bash
# Domain Configuration
PRIMARY_DOMAIN=zumodra.com
SITE_URL=https://zumodra.com
TENANT_BASE_DOMAIN=zumodra.com

# Cache Configuration
REDIS_URL=redis://localhost:6379/0
CACHE_TTL=300

# Email Configuration
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_DOMAIN=zumodra.com
```

## Security Features

### SSRF Protection

```python
from core.validators import SSRFValidator

# Prevents requests to private networks
validator = SSRFValidator()
validator('http://example.com')  # OK
validator('http://localhost')    # Raises ValidationError
validator('http://10.0.0.1')     # Raises ValidationError
```

### Content Security Policy

Enforced via middleware:
- No external CDNs allowed
- All assets served locally
- Strict script-src policy

### Security Headers

Automatically added:
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security`
- `Content-Security-Policy`

## Future Improvements

### High Priority

1. **Advanced Caching**
   - Cache warming strategies
   - Predictive caching
   - Cache analytics
   - Distributed caching

2. **Performance Monitoring**
   - APM integration (New Relic/Datadog)
   - Custom metrics
   - Performance profiling
   - Query optimization tools

3. **Feature Flags**
   - Per-tenant feature toggles
   - A/B testing framework
   - Gradual rollouts
   - Kill switches

4. **API Rate Limiting**
   - Per-user rate limits
   - Per-tenant quotas
   - Custom limit rules
   - Rate limit analytics

5. **Audit Logging**
   - Comprehensive audit trail
   - Immutable logs
   - Compliance reporting
   - Log analytics

### Medium Priority

6. **Error Tracking**: Sentry integration, error analytics
7. **Metrics Collection**: Prometheus metrics, custom metrics
8. **Health Checks**: Advanced health monitoring
9. **Background Jobs**: Celery task monitoring
10. **Data Export**: Tenant data export tools

## Testing

Critical: 95%+ coverage for core utilities

```
tests/
├── test_mixins.py
├── test_validators.py
├── test_domain_utils.py
├── test_cache.py
├── test_middleware.py
└── test_security.py
```

## Best Practices

### When Adding to Core

1. **Only add truly shared functionality**
2. **Keep it lightweight and dependency-free**
3. **Document all public APIs**
4. **Write comprehensive tests**
5. **Consider backwards compatibility**
6. **Avoid app-specific logic**

### Using Core Utilities

```python
# Good: Using provided mixins
from core.mixins import TenantViewMixin

class MyView(TenantViewMixin, ListView):
    model = MyModel

# Good: Using domain utilities
from core.domain import get_tenant_url
url = get_tenant_url(tenant, '/jobs/')

# Good: Using validators
from core.validators import SSRFValidator
validator = SSRFValidator()
```

## Contributing

Changes to core require:
- Approval from senior developers
- Comprehensive tests
- Documentation updates
- Migration guide if breaking changes
- Performance impact assessment

---

**Status:** Production
**Critical Component:** Platform foundation
**Coverage:** 95%+
