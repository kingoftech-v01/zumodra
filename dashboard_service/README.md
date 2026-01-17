# Dashboard Service App

> **⚠️ DEPRECATED - DO NOT USE FOR NEW DEVELOPMENT**
>
> **Migration Status:** COMPLETE - All functionality moved to `services` app
>
> This app is maintained for backwards compatibility only. All models, views, forms, and WebSocket consumers have been migrated to the `services` app. Import from `services.*` instead of `dashboard_service.*` for all new code.
>
> **Target Removal:** Q2 2026 (pending removal of all legacy references)

---

## Overview

The `dashboard_service` app was the original implementation of Zumodra's freelance marketplace service functionality. It has been **completely migrated** to the `services` app as part of the codebase consolidation effort.

This app now serves exclusively as a backwards compatibility shim, re-exporting all models, views, forms, and consumers from the `services` app with deprecation warnings.

## Migration Summary

### What Was Migrated

All functionality from `dashboard_service` has been consolidated into the `services` app:

| Old Location | New Location | Status |
|--------------|--------------|--------|
| `dashboard_service.models` | `services.models` | ✅ Migrated |
| `dashboard_service.views` | `services.views` | ✅ Migrated |
| `dashboard_service.forms` | `services.forms` | ✅ Migrated |
| `dashboard_service.consumers` | `services.consumers` | ✅ Migrated |
| `dashboard_service.admin` | `services.admin` | ✅ Migrated |

### Model Renames

The following models were renamed during migration for clarity:

| Old Name (dashboard_service) | New Name (services) |
|------------------------------|---------------------|
| `ServicesTag` | `ServiceTag` |
| `ServicesPicture` | `ServiceImage` |
| `ServiceProviderProfile` | `ServiceProvider` |
| `Match` | `ProviderMatch` |
| `ServiceRequest` | `ClientRequest` |
| `ServiceComment` | `ServiceReview` |
| `ServiceMessage` | `ContractMessage` |

### View Aliases

These view aliases are maintained for backwards compatibility:

| Old Name | New Name |
|----------|----------|
| `service_view` | `provider_dashboard` |
| `add_service_view` | `create_service` |
| `service_detail_view` | `service_detail` |
| `update_service_view` | `edit_service` |
| `delete_service_view` | `delete_service` |
| `browse_service` | `browse_services` |
| `browse_service_detail` | `service_detail` |

## Current Structure

### Backwards Compatibility Layer

All modules in this app now emit `DeprecationWarning` and re-export from `services`:

**models.py:**
```python
# Emits deprecation warning
from services.models import (
    ServiceCategory, ServiceTag, ServiceProvider, Service,
    ServiceProposal, ServiceContract, # ... and more
)
```

**views.py:**
```python
# Emits deprecation warning
from services.views import (
    browse_services, service_detail, create_service,
    edit_service, provider_dashboard, # ... and more
)
```

**forms.py:**
```python
# Emits deprecation warning
# Re-exports ServiceCategoryForm, ServiceProviderForm, etc.
```

**consumers.py:**
```python
# Emits deprecation warning
from services.consumers import (
    LocationConsumer, ProviderStatusConsumer
)
```

**admin.py:**
```python
# Emits deprecation warning
# No models registered (to avoid duplicates)
```

### URL Configuration

The URL patterns in `urls.py` still exist but reference deprecated view aliases:

```python
urlpatterns = [
    path('services/', service_view, name='my_services'),
    path('add-service/', add_service_view, name='add_service'),
    path('service/<int:pk>', service_detail_view, name='service_detail'),
    path('service/<int:pk>/update', update_service_view, name='update_service'),
    path('service/<int:pk>/delete', delete_service_view, name='delete_service'),
    path('browse-service/', browse_service, name='browse_service'),
    path('browse-service/detail/<str:service_uuid>', browse_service_detail, name='browse_service_detail'),
    path('browse-nearby-service/', browse_nearby_services, name='browse_nearby_services'),
]
```

### WebSocket Routing

WebSocket routing in `routing.py` re-exports from `services.consumers`:

```python
websocket_urlpatterns = [
    re_path(r'ws/location/$', consumers.LocationConsumer.as_asgi()),
]
```

## Migration Guide

### For Developers

If you encounter code importing from `dashboard_service`, update it as follows:

**Old Code:**
```python
from dashboard_service.models import ServiceProviderProfile, Service
from dashboard_service.views import browse_service, add_service_view
from dashboard_service.forms import ServiceProviderForm
```

**New Code:**
```python
from services.models import ServiceProvider, Service
from services.views import browse_services, create_service
from services.forms import ServiceProviderForm
```

### URL Reversing

If you're using old URL names, update to the new `services` URL namespace:

**Old:**
```python
{% url 'my_services' %}
{% url 'service_detail' pk=service.pk %}
```

**New:**
```python
{% url 'frontend:services:service_list' %}
{% url 'frontend:services:service_detail' pk=service.pk %}
```

### Deprecation Warnings

All imports from `dashboard_service` will emit:
```
DeprecationWarning: dashboard_service.models is deprecated.
Import from services.models instead.
```

Ensure you run with warnings enabled to catch these:
```bash
python -W all manage.py runserver
```

## Integration Points

Since this app is deprecated, all integration has moved to the `services` app:

- **Finance**: Escrow payments → `services.views.escrow_*`
- **Accounts**: Provider profiles → `services.models.ServiceProvider`
- **Messages**: Contract messaging → `services.consumers.ContractMessageConsumer`
- **ATS**: Freelance hiring → `services` + `ats` integration
- **Notifications**: Service updates → `services.signals`

See the [Services App README](../services/README.md) for current integration documentation.

## Architecture (Historical)

This section documents the original architecture for historical reference only.

### Original Models (Now in `services`)

The app originally defined these models:

- **ServiceCategory**: Hierarchical service categorization
- **ServiceTag**: Tagging system for services
- **ServiceImage**: Service portfolio images
- **ProviderSkill**: Provider skill proficiency tracking
- **ServiceProvider**: Freelancer/provider profiles with location
- **Service**: Service listings with pricing and terms
- **ServiceLike**: Saved/favorited services
- **ClientRequest**: Job posting by clients
- **ProviderMatch**: Algorithmic provider-job matching
- **ServiceProposal**: Provider proposals on client requests
- **ServiceContract**: Contracts with milestones
- **ServiceReview**: Post-contract reviews
- **ContractMessage**: In-contract messaging

### Original Features (Now in `services`)

- Service browsing and search
- Geospatial "services near me" (PostGIS)
- Provider profile management
- Service creation and management
- Client request posting
- Proposal submission and acceptance
- Contract lifecycle management
- Real-time location sharing (WebSockets)
- Provider availability status

## Security & Permissions

All security and permission logic has been migrated to the `services` app. See [Services Security Documentation](../services/README.md#security).

## Testing

No tests should be written for this deprecated app. All tests have been migrated to:

```
tests/
├── test_services_models.py
├── test_services_views.py
├── test_service_providers.py
└── test_marketplace.py
```

Run services tests:
```bash
pytest tests/test_services_*.py
pytest -m marketplace
```

## Removal Roadmap

### Phase 1: Deprecation Warnings (COMPLETE)
- ✅ Add deprecation warnings to all modules
- ✅ Migrate all models to `services`
- ✅ Migrate all views to `services`
- ✅ Migrate all forms to `services`
- ✅ Migrate all consumers to `services`

### Phase 2: Find & Replace (IN PROGRESS)
- 🔄 Scan codebase for `dashboard_service` imports
- 🔄 Update all import statements
- 🔄 Update all URL references
- 🔄 Update templates

### Phase 3: Remove App (Q2 2026)
- ⏳ Remove from `INSTALLED_APPS`
- ⏳ Delete `dashboard_service` directory
- ⏳ Remove URL includes
- ⏳ Update documentation

## FAQ

### Why was this app deprecated?

The app name `dashboard_service` was misleading - it suggested dashboard functionality when it actually contained marketplace service functionality. Consolidating into the `services` app provides:

1. **Clearer naming**: `services` accurately describes marketplace functionality
2. **Better organization**: All marketplace code in one place
3. **Reduced confusion**: No overlap with `dashboard` app
4. **Simpler architecture**: Fewer apps to maintain

### Can I still use dashboard_service imports?

Yes, but you'll get deprecation warnings. The compatibility layer will be removed in Q2 2026, so migrate your code now.

### What about existing migrations?

All database migrations remain intact. The models are now defined in `services.models`, but Django migration history is preserved.

### Will URLs break?

Old URLs in `dashboard_service.urls` still work through view aliases, but should be migrated to `services.urls` with the proper namespace.

### Where did the models go?

All models are now in `services.models` with cleaner names (e.g., `ServiceProvider` instead of `ServiceProviderProfile`).

## Related Documentation

- [Services App README](../services/README.md) - Current marketplace documentation
- [Dashboard App README](../dashboard/README.md) - Actual dashboard functionality
- [Migration Guide](../docs/migrations/dashboard_service_to_services.md) - Detailed migration steps

---

**Status:** Deprecated
**Migration:** Complete
**Target Removal:** Q2 2026
**Last Updated:** January 2026

**For all new development, use the [`services`](../services/README.md) app.**
