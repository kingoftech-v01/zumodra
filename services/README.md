# Services App

## Overview

Tenant-side service marketplace management for providers offering ongoing services (NOT time-bound projects).

**Schema**: TENANT (each tenant has isolated service listings)

**Pattern**: Follows public/private catalog pattern with [services_public](../services_public) app for cross-tenant browsing

## Architecture

### Tenant-Aware Design

- All models inherit from `TenantAwareModel`
- Automatic tenant isolation via django-tenants
- Services can be published to public marketplace (`is_public=True`)
- Automatic sync to `services_public` catalog via Django signals + Celery

### Key Differences from services_public

- **services**: Provider dashboard for managing services (WRITE operations, tenant-scoped)
- **services_public**: Public marketplace for browsing services (READ-only, cross-tenant)

## Models

### Core Models

#### ServiceProvider
Provider profiles with skills, portfolio, ratings:

- User identity, company link, provider type (individual/agency/company)
- Bio, tagline, avatar, cover image
- Skills with proficiency levels (ProviderSkill)
- Location (PostGIS Point for geographic queries)
- Pricing (hourly rate, minimum budget)
- Ratings & stats (avg rating, reviews, completed jobs, earnings)
- Availability status, verification status
- **Marketplace visibility**: `marketplace_enabled` flag

#### Service
Service offerings with flexible pricing:

- Provider (FK to ServiceProvider)
- Category, tags, description
- Pricing: service type (fixed/hourly/custom), price range
- Delivery: type (remote/onsite/hybrid), duration, revisions
- Media: thumbnail, images (M2M), video URL
- **Public marketplace**: `is_public`, `published_to_catalog`, `catalog_synced_at`
- Stats: view count, order count
- PostGIS location for geographic features

#### ServicePricingTier
Pricing packages for services (e.g., Starter, Professional, Executive):

- Name, price, delivery time, revisions
- Features (JSONField)
- Sort order, recommended flag
- **Synced to public catalog** when service is public

#### ProviderPortfolio
Portfolio showcase for providers:

- Portfolio image, title, description
- Grid layout configuration (col/row span)
- **Synced to public catalog** when associated services are public

### Workflow Models

#### ClientRequest
Client service requests for matching:

- Title, description, category, required skills
- Budget range, deadline
- Location preferences, remote allowed
- Status (open, in_progress, closed, cancelled)

#### CrossTenantServiceRequest
Requests from one tenant to hire another tenant's public service:

- Client (requesting user), target service/provider/tenant
- Hiring context: organizational or personal
- Budget, deadline, attachments
- Provider response, contract link
- **Cross-schema workflow** with async notifications

#### ServiceProposal
Provider proposals on client requests:

- Client request FK, provider FK
- Proposed rate (fixed/hourly), estimated hours
- Cover letter, timeline, attachments
- Status (pending, accepted, rejected, withdrawn)

#### ServiceContract
Binding agreements with escrow integration:

- Client, provider, service, proposal (optional)
- Contract details: title, description, agreed rate, deadline
- Revisions allowed/used
- **Escrow integration**: links to EscrowTransaction
- Platform fee, provider payout calculation
- Status workflow: draft → pending_payment → funded → in_progress → delivered → completed
- Methods: `start()`, `deliver()`, `complete()`, `cancel()`

### Support Models

#### ServiceCategory
Hierarchical service categorization:

- Name, slug, parent (self-FK for nesting)
- Icon, color, sort order
- Properties: `full_path`, `depth`

#### ServiceTag
Tags for service filtering and search:

- Name, slug (auto-generated)

#### ServiceImage
Service gallery images:

- Image file, description, alt text
- Sort order for display

#### ServiceReview
Post-service reviews with ratings:

- Contract FK (one-to-one), reviewer, provider
- Ratings: overall, communication, quality, timeliness
- Title, content
- Provider response, responded_at
- **Triggers provider rating recalculation** on save

#### ContractMessage
Messages within service contracts:

- Contract FK, sender
- Content, attachments (JSON)
- System message flag
- Read status tracking

#### ProviderSkill
Links skills to providers with proficiency:

- Provider FK, Skill FK (from configurations app)
- Level (beginner/intermediate/advanced/expert)
- Years of experience, verification status

#### ServiceLike
User favorites/likes for services:

- User FK, Service FK
- Unique constraint per user-service pair

## REST API (NEW - 2026-01-25)

### API Architecture

- **Framework**: Django REST Framework 3.14+
- **Authentication**: IsAuthenticated (tenant-scoped)
- **Permissions**: TenantAwareViewSetMixin + custom permissions
- **Format**: JSON
- **Pagination**: 20 items/page (configurable)
- **Tenant Isolation**: ALL ViewSets enforce tenant boundaries

### API Endpoints

**Base URL**: `/services/api/`

#### Providers

- `GET /providers/` - List providers (filterable)
- `POST /providers/` - Create provider profile
- `GET /providers/{uuid}/` - Provider detail
- `PUT/PATCH /providers/{uuid}/` - Update provider
- `DELETE /providers/{uuid}/` - Delete provider
- `GET /providers/me/` - Current user's provider profile (auto-create)
- `GET /providers/{uuid}/stats/` - Provider statistics (ratings, earnings, etc.)

**Filters**: `provider_type`, `is_verified`, `is_featured`, `availability_status`, `can_work_remotely`, `city`, `state`, `country`, `min_rate`, `max_rate`, `min_rating`, `category`, `skill`

#### Services

- `GET /services/` - List services (filterable)
- `POST /services/` - Create service (provider auto-set from user)
- `GET /services/{uuid}/` - Service detail
- `PUT/PATCH /services/{uuid}/` - Update service
- `DELETE /services/{uuid}/` - Delete service
- `GET /services/my-services/` - Current user's services
- `POST /services/{uuid}/publish/` - Publish to public marketplace
- `POST /services/{uuid}/unpublish/` - Remove from public marketplace
- `POST /services/{uuid}/duplicate/` - Duplicate service

**Filters**: `provider`, `category`, `service_type`, `delivery_type`, `is_active`, `is_featured`, `is_public`, `min_price`, `max_price`, `city`, `state`, `country`, `tag`, `provider_verified`

**Custom Actions**:

- `publish`: Sets `is_public=True`, triggers sync to public catalog
- `unpublish`: Sets `is_public=False`, removes from public catalog
- `duplicate`: Creates copy with "(Copy)" suffix, starts inactive

#### Categories & Tags

- `GET /categories/` - List categories (read-only)
- `GET /categories/{id}/` - Category detail
- `GET /categories/tree/` - Hierarchical category tree
- `GET /tags/` - List tags (read-only)
- `GET /tags/{id}/` - Tag detail

#### Pricing Tiers & Portfolio

- `GET/POST /pricing-tiers/` - List/create pricing tiers
- `GET/PUT/PATCH/DELETE /pricing-tiers/{id}/` - Pricing tier CRUD
- `GET/POST /portfolio/` - List/create portfolio items
- `GET/PUT/PATCH/DELETE /portfolio/{id}/` - Portfolio item CRUD

**Permissions**: User must own the parent service/provider

#### Contracts

- `GET/POST /contracts/` - List/create contracts
- `GET /contracts/{uuid}/` - Contract detail
- `PUT/PATCH /contracts/{uuid}/` - Update contract
- `GET /contracts/my-contracts/` - User's contracts (as client OR provider)
- `POST /contracts/{uuid}/deliver/` - Provider marks as delivered
- `POST /contracts/{uuid}/complete/` - Client marks as complete (releases escrow)
- `POST /contracts/{uuid}/request-revision/` - Client requests revision

**Filters**: `status`, `rate_type`, `client`, `provider`, `service`, `deadline_after`, `deadline_before`

**Permissions**:

- List/Detail: User must be client OR provider
- Custom actions: Role-specific (provider for deliver, client for complete/request-revision)

#### Reviews

- `GET /reviews/` - List reviews (read-only)
- `GET /reviews/{id}/` - Review detail
- `POST /reviews/{id}/respond/` - Provider responds to review

**Filters**: `provider`, `rating`, `min_communication`, `min_quality`, `min_timeliness`, `has_response`

**Permissions**: Provider can only respond to their own reviews

#### Messages

- `GET/POST /messages/` - List/create contract messages
- `GET /messages/{id}/` - Message detail

**Permissions**: User must be involved in the contract (client or provider)

#### Images

- `GET/POST /images/` - List/create service images
- `GET/PUT/PATCH/DELETE /images/{id}/` - Image CRUD

#### Cross-Tenant Requests

- `GET/POST /cross-tenant-requests/` - List/create cross-tenant hiring requests
- `GET /cross-tenant-requests/{uuid}/` - Request detail
- `PUT/PATCH /cross-tenant-requests/{uuid}/` - Update request

**Filters**: `status`, `hiring_context`, `target_tenant_schema`, `target_service_uuid`, `has_response`

**Permissions**: User must own the request

### Serializers

**Provider Serializers**:

- `ServiceProviderListSerializer`: Lightweight for list views
- `ServiceProviderDetailSerializer`: Complete with skills, portfolio, categories
- `ServiceProviderUpdateSerializer`: For profile updates

**Service Serializers**:

- `ServiceListSerializer`: Lightweight with provider summary, tags, category
- `ServiceDetailSerializer`: Complete with images, pricing tiers, tags, provider
- `ServiceCreateSerializer`: For service creation (handles M2M relationships)
- `ServiceUpdateSerializer`: For service updates (handles M2M relationships)

**Contract Serializers**:

- `ServiceContractListSerializer`: Lightweight for contract lists
- `ServiceContractDetailSerializer`: Complete with escrow, service, proposal
- `ServiceContractCreateSerializer`: For creating bookings

**Other Serializers**:

- `ServiceCategorySerializer`: With subcategories and full_path
- `ServiceTagSerializer`
- `ServiceImageSerializer`
- `ServicePricingTierSerializer`: With features_list helper
- `ProviderPortfolioSerializer`
- `ServiceReviewSerializer`: With reviewer anonymization
- `ContractMessageSerializer`
- `CrossTenantServiceRequestSerializer`

### Permissions

#### IsProviderOwner

- User must own the ServiceProvider instance
- Applies to provider updates, service CRUD

#### CanManageService

- User must own the service's provider
- Applies to service updates, deletions

### Filters

Comprehensive django-filters FilterSets:

- `ServiceProviderFilter`: 20+ filter options
- `ServiceFilter`: 25+ filter options
- `ServiceContractFilter`: Contract management filters
- `ServiceReviewFilter`: Review filtering and sorting
- `ClientRequestFilter`: Request filtering
- `CrossTenantServiceRequestFilter`: Cross-tenant request filters

See `services/filters.py` for complete implementation.

## Synchronization to Public Catalog

### Automatic Sync

Services are automatically synced to [services_public](../services_public) when published:

**Trigger**:

```python
service.is_public = True
service.save()  # OR via API: POST /services/{uuid}/publish/
```

**Workflow**:

1. Django `post_save` signal fires (`services/signals.py`)
2. Signal validates sync conditions (is_public, is_active, provider.marketplace_enabled)
3. Celery task `sync_service_to_public_catalog` queued
4. Task switches to tenant schema
5. Task fetches Service with related data (images, pricing tiers, provider portfolio)
6. `ServicePublicSyncService` extracts and sanitizes data (HTML sanitization, XSS prevention)
7. Task switches to public schema
8. `PublicService` created/updated atomically
9. Related models synced (PublicServiceImage, PublicServicePricingTier, PublicServicePortfolio)
10. Service fields updated: `published_to_catalog=True`, `catalog_synced_at=now()`

**Removal from Catalog**:

```python
service.is_public = False
service.save()  # OR via API: POST /services/{uuid}/unpublish/
```

Triggers `remove_service_from_public_catalog` task.

### Sync Requirements

For successful sync, service must meet:

- `is_public=True`
- `is_active=True`
- `provider.marketplace_enabled=True`
- Has name and description

### Related Model Sync

When syncing, these related models are automatically included:

- **Images**: All `ServiceImage` instances linked to service
- **Pricing Tiers**: All `ServicePricingTier` instances for service
- **Portfolio**: All `ProviderPortfolio` instances for service's provider
- **Reviews**: All `ServiceReview` instances (denormalized and anonymized)

## URL Structure

### Frontend URLs (HTML)

Defined in `services/views_frontend.py`:

- `/services/` - Service listing
- `/services/service/{uuid}/` - Service detail
- `/services/service/{uuid}/like/` - Like service
- `/services/nearby/` - Nearby services
- `/services/search/ajax/` - AJAX search
- `/services/providers/` - Provider browsing
- `/services/provider/dashboard/` - Provider dashboard
- `/services/provider/create/` - Create provider profile
- `/services/provider/edit/` - Edit provider profile
- `/services/provider/{uuid}/` - Provider profile view
- `/services/service/create/` - Create service
- `/services/service/{uuid}/edit/` - Edit service
- `/services/service/{uuid}/delete/` - Delete service
- `/services/request/create/` - Create client request
- `/services/request/my-requests/` - My requests
- `/services/request/{uuid}/` - View request
- `/services/request/{uuid}/submit-proposal/` - Submit proposal
- `/services/proposal/{id}/accept/` - Accept proposal
- `/services/contract/{id}/` - View contract
- `/services/contracts/` - My contracts
- `/services/contract/{id}/update-status/` - Update contract status
- `/services/contract/{id}/fund/` - Fund contract
- `/services/contract/{id}/dispute/` - Create dispute
- `/services/dispute/{id}/` - View dispute
- `/services/service/{uuid}/review/` - Add review

### API URLs (JSON)

Defined in `services/views_api.py`:

- `/services/api/providers/` - Provider API
- `/services/api/services/` - Service API
- `/services/api/categories/` - Categories API
- `/services/api/tags/` - Tags API
- `/services/api/images/` - Images API
- `/services/api/pricing-tiers/` - Pricing tiers API
- `/services/api/portfolio/` - Portfolio API
- `/services/api/reviews/` - Reviews API
- `/services/api/contracts/` - Contracts API
- `/services/api/messages/` - Messages API
- `/services/api/cross-tenant-requests/` - Cross-tenant requests API

See [services/urls.py](urls.py) for complete routing.

## Tasks (Celery)

Defined in `services/tasks.py`:

- `sync_service_to_public_catalog` - Sync service to public catalog
- `remove_service_from_public_catalog` - Remove service from public catalog
- `bulk_sync_tenant_services` - Bulk sync all tenant services
- `cleanup_orphaned_catalog_entries` - Daily cleanup (3 AM)
- `resync_stale_catalog_entries` - Daily re-sync (2 AM)

## Signals

Defined in `services/signals.py`:

- `post_save(Service)` - Queue sync task when is_public=True
- `pre_delete(Service)` - Queue removal task
- `post_save(ServiceImage)` - Trigger parent service re-sync
- `post_save(ServicePricingTier)` - Trigger parent service re-sync
- `post_save(ProviderPortfolio)` - Trigger associated services re-sync

**Important**: Signals skip public schema to prevent circular updates.

## Integration Points

### Escrow App

- ServiceContract links to `escrow.EscrowTransaction`
- Contract completion releases escrowed funds
- Platform fee calculated: `provider_payout_amount = agreed_rate - (agreed_rate * platform_fee_percent / 100)`

### Services Public App

- Automatic sync when `service.is_public=True`
- Cross-tenant service discovery
- Booking URLs redirect to tenant domain

### Configurations App

- Categories shared across tenants
- Skills linked to providers via ProviderSkill
- Company linked to providers

### Payments App

- Contract funding via payment processing
- Payout to providers via Stripe Connect

## Testing

Tests located in `services/tests/`:

```bash
pytest services/tests/ --cov=services --cov-report=html
```

**Test Files** (to be written - Phase 10):

- `test_models.py` - Model tests
- `test_views_frontend.py` - Frontend view tests
- `test_views_api.py` - API endpoint tests
- `test_serializers.py` - Serializer tests
- `test_filters.py` - Filter tests
- `test_signals.py` - Signal tests
- `test_tasks.py` - Celery task tests
- `test_permissions.py` - Permission tests
- `test_integration.py` - End-to-end tests

**Target Coverage**: 90%+

## Development

### Setup

1. Install dependencies: `pip install -r requirements.txt`
2. Run migrations: `python manage.py migrate_schemas`
3. Create test data: `python manage.py create_test_services`
4. Start Celery: `celery -A zumodra worker -l info`
5. Run server: `python manage.py runserver`

### Creating a Service via API

```bash
# Create provider profile
POST /services/api/providers/me/

# Create service
POST /services/api/services/
{
  "name": "Professional Web Design",
  "category": 1,
  "description": "...",
  "short_description": "...",
  "service_type": "fixed",
  "price": 1500.00,
  "currency": "CAD",
  "delivery_type": "remote",
  "duration_days": 14,
  "is_active": true,
  "is_public": false
}

# Add pricing tiers
POST /services/api/pricing-tiers/
{
  "service": "<service_uuid>",
  "name": "Starter",
  "price": 500.00,
  "delivery_time_days": 7,
  "revisions": 2,
  "features": {"pages": 3, "responsive": true}
}

# Publish to marketplace
POST /services/api/services/<uuid>/publish/
```

### Publishing Workflow

1. Create service with `is_public=False` (draft)
2. Add images, pricing tiers, portfolio
3. Publish via API or admin: `POST /services/{uuid}/publish/`
4. Signal triggers Celery task
5. Service appears on public catalog ([services_public](../services_public))
6. Track sync status: `published_to_catalog`, `catalog_synced_at`

## Configuration

### Environment Variables

- `SERVICE_APPROVAL_REQUIRED` - Require admin approval for new services (default: False)
- `MARKETPLACE_SYNC_ENABLED` - Enable automatic sync to public catalog (default: True)

### Settings

- `CELERY_BEAT_SCHEDULE` - Configure periodic tasks (cleanup, re-sync)
- `DRF_DEFAULT_PAGINATION_CLASS` - API pagination settings

## Notes

### Services vs Projects

- **Services**: ONGOING offerings (e.g., "Web Design Services", "SEO Consulting")
- **Projects**: TIME-BOUND deliverables (e.g., "Build E-commerce Site", "Mobile App Development")

Use `projects/` app for time-bound missions.

### Marketplace Visibility

- `marketplace_enabled` (Provider): Provider can publish services to marketplace
- `is_public` (Service): Service is published to public catalog
- Old `is_private` field DEPRECATED - use `marketplace_enabled` instead

### Security

- **Tenant Isolation**: All ViewSets use TenantAwareViewSetMixin
- **HTML Sanitization**: User-generated content sanitized before sync to public catalog
- **Permission Checks**: IsProviderOwner, CanManageService enforced
- **No Sensitive Data**: Emails, passwords never synced to public catalog

## Future Enhancements

See [TODO.md](TODO.md) for comprehensive list of planned features:

- Provider dashboard UI enhancements
- Pricing tier management interface
- Portfolio gallery interface
- Analytics dashboard
- Notification system
- Service templates
- Availability calendar
- And more...

## Related Apps

- **services_public**: Public marketplace for cross-tenant browsing
- **projects**: Time-bound project management (different from ongoing services)
- **escrow**: Secure payment holding for contracts
- **core.sync**: Base sync infrastructure
- **tenants**: Multi-tenant core functionality

## License

Proprietary - Zumodra Platform

## Support

For issues or questions:

- File an issue in the project repository
- Contact the development team
- See [TODO.md](TODO.md) for known limitations and planned improvements
