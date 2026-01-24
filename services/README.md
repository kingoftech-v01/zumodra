# Services App

## Overview

Service marketplace for ongoing service offerings (NOT time-bound projects).

**Schema**: TENANT (each tenant has own service listings)

**Pattern**: Follows public/private catalog pattern with `services_public/` app

## Models

- **Service**: Service offerings with pricing
- **ServiceProvider**: Provider profiles
- **ServiceCategory**: Hierarchical categorization
- **ClientRequest**: Client service requests
- **ServiceProposal**: Provider proposals on requests
- **ServiceContract**: Binding service agreements
- **ServiceReview**: Post-service reviews

## Key Features

- Service listings (hourly/fixed pricing)
- Provider profiles with portfolios
- Client request/proposal workflow
- Service contracts with escrow integration
- Reviews and ratings
- Marketplace visibility toggle

## API Endpoints

### Services
- **GET/POST** `/api/v1/services/services/`
- **GET/PUT/PATCH/DELETE** `/api/v1/services/services/<id>/`
- **POST** `/api/v1/services/services/<id>/publish/` - Publish to marketplace

### Providers
- **GET/POST** `/api/v1/services/providers/`
- **GET/PUT/PATCH/DELETE** `/api/v1/services/providers/<id>/`

### Requests & Proposals
- **GET/POST** `/api/v1/services/requests/`
- **GET/POST** `/api/v1/services/proposals/`
- **POST** `/api/v1/services/proposals/<id>/accept/` - Accept proposal

### Contracts
- **GET/POST** `/api/v1/services/contracts/`
- **GET** `/api/v1/services/contracts/<id>/`

## Integration

- **escrow**: Escrow for service payments
- **services_public**: Public catalog for cross-tenant browsing
- **payments**: Payment processing
- **reviews**: Rating system

## Permissions

- `IsServiceAdmin`: PDG, Supervisor, HR Manager
- `CanManageService`: Service owner or admin
- `CanViewPublicServices`: All authenticated users

## Tasks (Celery)

- `sync_services_data`: Sync with services_public catalog
- `daily_services_cleanup`: Remove expired/stale data

## Signals

- `service_saved`: Sync to public catalog when published
- `service_deleted`: Remove from public catalog

## Configuration

Environment variables:
- `SERVICE_APPROVAL_REQUIRED`: Require admin approval for new services (default: False)

## Testing

```bash
pytest services/tests/
```

## Notes

- Services are ONGOING offerings (e.g., "Web Design Services")
- For TIME-BOUND missions with deliverables, use `projects/` app
- Marketplace visibility controlled by `marketplace_enabled` field
- Old `is_private` field DEPRECATED - use `marketplace_enabled` instead
