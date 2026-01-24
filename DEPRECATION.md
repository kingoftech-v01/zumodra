# Deprecation Log

This document tracks deprecated features, APIs, and code in the Zumodra codebase.

**Last Updated**: 2026-01-18

---

## Removed in Current Version

### FREELANCER Tenant Type (Removed: Phase 2)

**Status**: ✅ **REMOVED**

**Reason**: Architectural inefficiency - individual freelancers created full tenant schemas causing massive database overhead.

**Replacement**: `FreelancerProfile` user profile in `tenant_profiles/` app (formerly `accounts/`)

**What Was Removed**:
- `TenantType.FREELANCER` choice from `tenants/models.py`
- All FREELANCER-specific validators in `tenants/validators.py`
- `switch_to_freelancer()` method in `tenants/models.py`
- Test files:
  - `tenants/tests/test_freelancer_setup.py` (did not exist)
  - `tenants/management/commands/test_freelancer_flow.py` (did not exist)
  - `tenants/tests/integration/test_tenant_types.py` (deleted 2026-01-18)

**Migration Path**:
```python
# Old (DEPRECATED):
tenant = Tenant.objects.create(
    name="John Freelancer",
    tenant_type=TenantType.FREELANCER
)

# New:
from tenant_profiles.models import FreelancerProfile

freelancer_profile = FreelancerProfile.objects.create(
    user=user,
    professional_title="Web Developer",
    hourly_rate=75.00,
    available_for_work=True
)
```

---

### Old Monolithic Finance App (Removed: Phase 11)

**Status**: ✅ **REMOVED**

**Reason**: Monolithic `finance/` app (15 models, 833 lines) conflated multiple concerns. Split into 10 specialized apps.

**Replacement**: 10 specialized finance apps:
1. `payments/` - Payment transactions
2. `escrow/` - Escrow management
3. `payroll/` - Employee payroll
4. `expenses/` - Expense tracking
5. `subscriptions/` - Tenant subscription products
6. `stripe_connect/` - Marketplace payments
7. `tax/` - Tax automation
8. `billing/` - Platform billing (PUBLIC schema)
9. `accounting/` - QuickBooks/Xero integration
10. `finance_webhooks/` - Webhook handling

**What Was Removed**:
- `finance/` app from TENANT_APPS
- Old API route: `/api/v1/finance/` (removed 2026-01-18)

**Migration**: All finance models automatically migrated to new apps. No user action required.

---

### dashboard_service App (Removed: Phase 5)

**Status**: ✅ **REMOVED**

**Reason**: Functionality merged into `dashboard/` app. No need for separate service layer.

**Replacement**: `dashboard/` app

**What Was Removed**:
- `dashboard_service/` directory
- Commented app reference in `settings.py` (removed 2026-01-18)
- Commented app reference in `settings_tenants.py` (removed 2026-01-18)

---

## Deprecated but Not Yet Removed

### Legacy URL Namespace: `appointment`

**Status**: ⚠️ **DEPRECATED** (Being phased out)

**Reason**: App renamed from `appointment/` to `interviews/` for clarity (Phase 9)

**Current State**:
- Directory renamed: `appointment/` → `interviews/`
- Some API endpoints still use old namespace for backward compatibility

**Replacement**: Use `interviews` namespace

**Migration Path**:
```python
# Old (DEPRECATED):
{% url 'appointment:service-list' %}
reverse('appointment:service-list')

# New:
{% url 'interviews:service-list' %}
reverse('interviews:service-list')
```

**Timeline**: Full removal targeted for v2.3.0 (after 6-month grace period)

---

### Deprecated Fields in `services/models.py`

**Field**: `Service.is_private`

**Status**: ⚠️ **DEPRECATED**

**Reason**: Use `marketplace_enabled` instead for clearer semantics.

**Replacement**: `marketplace_enabled` field

**Migration Path**:
```python
# Old (DEPRECATED):
service = Service.objects.filter(is_private=False)

# New:
service = Service.objects.filter(marketplace_enabled=True)
```

**Timeline**: Field will be removed in v2.4.0

---

### Legacy Hash Method in `tenant_profiles/security.py`

**Status**: ⚠️ **DEPRECATED** (Maintained for backward compatibility)

**Reason**: SHA256 hashing replaced with Django's modern password hashing.

**Current Behavior**: System computes both modern hash AND legacy SHA256 for backward compatibility with old data.

**Replacement**: Django's `make_password()` / `check_password()`

**Timeline**: Legacy hash support will be removed in v3.0.0 (major version)

---

### Utility Functions in `tenants/utils.py`

**Deprecated Functions**:
- `with_tenant_context()` → Use `tenants.context.tenant_context()` instead
- `with_public_schema()` → Use `tenants.context.public_schema_context()` instead
- `get_tenant()` → Use `tenants.context.get_current_tenant()` instead
- `get_schema_name()` → Use `tenants.context.get_current_schema()` instead

**Status**: ⚠️ **DEPRECATED** (Functions still work but emit warnings)

**Reason**: Centralized context management in `tenants.context` module for consistency.

**Timeline**: Functions will be removed in v2.5.0

---

### Old App Names (Being Phased Out)

**Status**: ⚠️ **IN PROGRESS**

Phase 7-10 renamed several apps for clarity:

| Old Name | New Name | Status |
|----------|----------|--------|
| `ats` | `jobs` | ⏳ Planned (Phase 7) |
| `ats_public` | `jobs_public` | ⏳ Planned (Phase 7) |
| `appointment` | `interviews` | ✅ Done (Phase 9) |
| `marketing` + `newsletter` | `marketing_campaigns` | ⏳ Planned (Phase 8) |
| `accounts` | `tenant_profiles` | ✅ Done (Phase 10) |
| `custom_account_u` | `core_identity` | ⏳ Planned (Phase 10) |

---

## Security-Related Deprecations

### X-XSS-Protection Header

**Status**: ⚠️ **ACCEPTABLE** (Deprecated by browsers but still sent)

**Reason**: Modern browsers have deprecated this header in favor of CSP (Content Security Policy).

**Current State**: Still sent for legacy browser support, but CSP is primary defense.

**Timeline**: Will be removed when all supported browsers fully deprecate it.

---

## Testing Deprecations

### Integration Test: `test_tenant_functionality.py`

**Status**: ⚠️ **DEPRECATED**

**File**: `tests/integration/test_tenant_functionality.py`

**Reason**: Tests FREELANCER tenant type which no longer exists.

**Current State**: File still contains some useful company tenant tests. Marked as deprecated at top of file.

**Action Needed**: Extract useful company tenant tests, delete deprecated FREELANCER tests.

---

## How to Handle Deprecations

### For Developers:

1. **Check this file regularly** for deprecated features you may be using
2. **Update your code** to use replacement APIs before removal deadline
3. **Run deprecation warnings**: `pytest -W default::DeprecationWarning`
4. **Add new deprecations** to this file when marking code as deprecated

### Deprecation Markers in Code:

```python
# DEPRECATED (Phase X, v2.Y.0): Reason here
# TODO: Remove in v2.Z.0
# Use replacement_function() instead
def old_function():
    warnings.warn(
        "old_function() is deprecated. Use replacement_function() instead.",
        DeprecationWarning,
        stacklevel=2
    )
    # Implementation
```

---

## Removed Deprecation Comments (Phase 12.2)

As of 2026-01-18, the following deprecation comments were removed as part of Phase 12.2 cleanup:

**settings.py**:
- Removed: `# 'finance',        # DEPRECATED (2026-01-18): Split into 10 specialized apps above`
- Removed: `# 'dashboard_service',  # REMOVED: Deprecated app, all functionality migrated to 'services'`

**settings_tenants.py**:
- Removed: `# REMOVED (2026-01-16): 'blog' moved to SHARED_APPS - tenants don't publish blog posts`
- Removed: `# REMOVED (2026-01-17): 'finance' split into 9 specialized apps (see below)`
- Removed: `# 'dashboard_service',  # REMOVED (2026-01-17): Deprecated, migrated to 'services'`
- Removed: `# 'appointment.apps.AppointmentConfig',  # REMOVED (2026-01-18): Renamed to 'interviews'`

**api/urls_v1.py**:
- Removed: Old monolithic finance app comment block (lines 111-113)

---

## Version History

- **v2.2.0 (2026-01-18)**: Phase 11 complete - finance app split, Phase 12.2 deprecation cleanup
- **v2.1.0 (2026-01-17)**: Phase 10 complete - accounts → tenant_profiles
- **v2.0.0 (2025-12-15)**: Phase 1-9 complete - major architectural refactoring

---

**Questions?** Contact the development team or check the architectural plan in `refactored-roaming-pascal.md`.
