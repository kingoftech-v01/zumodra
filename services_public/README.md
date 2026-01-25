# Services Public Catalog

Public marketplace for browsing services across all tenants in the Zumodra multi-tenant platform.

## Overview

The `services_public` app provides a cross-tenant service marketplace where users can discover and browse services offered by providers across all tenants. Services are automatically synchronized from tenant schemas when marked as public.

## Architecture

### Service-Centric Catalog

The catalog is organized by **individual services** rather than providers:
- One service = one catalog entry
- Each service contains complete information (pricing, images, portfolio, reviews)
- Denormalized data structure optimized for fast read operations
- No tenant context switching required for browsing

### Data Synchronization

Services are synced from tenant schemas to the public catalog automatically:

1. **Trigger**: Service marked with `is_public=True` in tenant schema
2. **Signal**: Django post_save signal fires
3. **Task**: Celery async task queued
4. **Sync**: ServicePublicSyncService extracts and sanitizes data
5. **Storage**: PublicService created/updated in public schema
6. **Related**: Images, pricing tiers, portfolio synced
7. **Broadcast**: WebSocket notifies connected clients

### Security

- **HTML Sanitization**: All user-generated content sanitized to prevent XSS
- **Schema Isolation**: Signals prevent circular updates in public schema
- **No Sensitive Data**: Emails, phones, passwords never synced
- **Idempotent Tasks**: Safe retry design for all Celery tasks

## Components

### Models

#### PublicService
Main service catalog entry with denormalized data:
- Service information (name, description, tags)
- Provider information (name, avatar, rating, verification status)
- Pricing (price range, currency, delivery type)
- Location (PostGIS Point for geographic queries)
- Rating statistics (average, breakdown by star count)
- URLs (booking link, detail page)

#### PublicServiceImage
Gallery images for services:
- Image URL, alt text, description
- Sort order for display

#### PublicServicePricingTier
Pricing packages (e.g., Starter, Professional, Executive):
- Name, price, currency
- Delivery time, revisions included
- Feature list (JSON)
- Recommended flag

#### PublicServicePortfolio
Provider portfolio items:
- Portfolio image URL
- Title, description
- Grid layout configuration (col/row span)

#### PublicServiceReview
Denormalized service reviews:
- Reviewer information (anonymized, verified status)
- Rating (overall and breakdown)
- Review content, provider response
- Helpful count

### Views

#### service_list_view()
Paginated service listing with filtering and search:
- **URL**: `/browse-services/`
- **Filters**: Category, location, price range, rating, verified providers
- **Search**: Full-text search across name, description, tags
- **Sorting**: Rating, price, newest, popular
- **Pagination**: 20 items per page
- **Performance**: Optimized with `.only()` for minimal fields

#### service_detail_view(service_uuid)
Detailed service information:
- **URL**: `/browse-services/<uuid>/`
- **Data**: Service info, provider details, gallery, pricing tiers, portfolio, reviews
- **Features**: View count tracking, similar services, breadcrumbs
- **SEO**: Meta tags, structured data

#### service_map_view()
Geographic map view of services:
- **URL**: `/browse-services/map/`
- **Map**: Interactive Leaflet.js map with markers
- **Filters**: Same as list view plus geographic radius
- **Clustering**: Marker clustering for performance
- **Limit**: 200 services max for performance

### WebSocket Consumers

#### ServiceCatalogConsumer
Real-time service filtering:
- **URL**: `ws://domain/ws/services-catalog/`
- **Actions**: Filter services, subscribe to updates
- **Features**: Real-time results, pagination, notifications

#### ServiceMapConsumer
Interactive map updates:
- **URL**: `ws://domain/ws/services-map/`
- **Actions**: Update viewport, receive marker updates
- **Features**: GeoJSON streaming, viewport-based filtering

### JavaScript Components

#### WebSocketClient (`websocket-client.js`)
WebSocket wrapper with robust error handling:
- Auto-reconnect with exponential backoff
- Message queuing when disconnected
- Multiple message handler registration
- Connection state management

#### ServiceMapViewer (`map-viewer.js`)
Interactive map viewer using Leaflet.js:
- GeoJSON marker rendering
- Marker clustering for performance
- Custom popups with service information
- WebSocket integration for live updates
- Viewport-based filtering

#### FilterHandler (`filter-handler.js`)
Dynamic filter management:
- Collects filter values from form inputs
- Debounced search input (300ms)
- Sends filters via WebSocket
- Updates results without page reload
- Synchronizes filters with URL parameters
- Pagination controls

#### Main (`main.js`)
Application entry point:
- Detects page type (list, map, detail)
- Initializes appropriate components
- Coordinates WebSocket communication
- Page-specific initialization logic

## Sync Process

### Automatic Sync

When a service is marked public in a tenant schema:

```python
# In tenant schema
service.is_public = True
service.save()  # Triggers signal
```

**Workflow:**
1. `post_save` signal fires in `services/signals.py`
2. Signal checks sync conditions (is_public, is_active, provider enabled)
3. `sync_service_to_public_catalog_task` queued in Celery
4. Task switches to tenant schema
5. Task fetches Service with all related data
6. `ServicePublicSyncService` extracts and sanitizes data
7. Task switches to public schema
8. `PublicService` created/updated with atomic transaction
9. Related models synced (images, pricing tiers, portfolio)
10. Service field `published_to_catalog=True` updated
11. WebSocket broadcasts update to connected clients

### Manual Bulk Sync

For initial population or full re-sync:

```bash
# Python shell
from services.tasks import bulk_sync_tenant_services
bulk_sync_tenant_services.delay(tenant_id)
```

### Periodic Cleanup

Scheduled Celery tasks:
- **cleanup_orphaned_catalog_entries**: Daily at 3 AM (removes orphaned entries)
- **resync_stale_catalog_entries**: Daily at 2 AM (re-syncs entries older than 24h)

## REST API

The `services_public` app provides a read-only REST API for programmatic access to the public catalog.

### API Architecture

- **Framework**: Django REST Framework 3.14+
- **Authentication**: AllowAny (public data)
- **Format**: JSON
- **Pagination**: Configurable (default 20 items/page)
- **Versioning**: URL-based (currently v1)

### API Endpoints

**Base URL**: `/browse-services/api/`

#### Services

- `GET /services/` - List services with filtering and pagination
- `GET /services/{uuid}/` - Service detail with all related data
- `GET /services/search/` - Full-text search endpoint
- `GET /services/nearby/?lat=X&lng=Y&radius=Z` - Geographic search
- `GET /services/featured/` - Get featured services
- `GET /services/{uuid}/similar/` - Get similar services
- `GET /services/categories/` - Get all categories

**List Filters:**

- `category` - Filter by category slug
- `city`, `state`, `country` - Location filters
- `min_price`, `max_price` - Price range
- `min_rating` - Minimum rating (0-5)
- `service_type` - Filter by type (fixed, hourly, custom)
- `delivery_type` - Filter by delivery (remote, onsite, hybrid)
- `is_featured` - Featured services only (true/false)
- `provider_is_verified` - Verified providers only (true/false)
- `can_work_remotely` - Remote-capable providers (true/false)
- `ordering` - Sort results (rating, price, newest, popular, reviews)

#### Images

- `GET /images/` - List service images
- `GET /images/{id}/` - Image detail

#### Pricing Tiers

- `GET /pricing-tiers/` - List pricing tiers
- `GET /pricing-tiers/{id}/` - Pricing tier detail

#### Portfolio

- `GET /portfolio/` - List portfolio items
- `GET /portfolio/{id}/` - Portfolio item detail

#### Reviews

- `GET /reviews/` - List reviews
- `GET /reviews/{id}/` - Review detail

### Serializers

**PublicServiceListSerializer**: Lightweight for list views

- Basic service info (name, description, price)
- Provider summary (name, avatar, rating)
- Category information
- Thumbnail URL

**PublicServiceDetailSerializer**: Complete service data

- All service fields
- Nested images, pricing tiers, portfolio, reviews
- Provider details
- Tags and categories

**PublicServiceGeoSerializer**: GeoJSON format for maps

- Service location as Point geometry
- Essential service metadata
- Compatible with Leaflet.js and mapping libraries

**PublicServiceSearchSerializer**: Search-optimized

- Highlighted name (if search matched)
- Match score for ranking
- Essential display fields

### Filters

**PublicServiceFilter** (django-filter):

- Text search across name, description, tags, provider
- Category filtering (by ID or slug)
- Location filtering (city, state, country)
- Price range (min_price, max_price)
- Rating filters (min_rating)
- Service type (fixed, hourly, custom)
- Delivery type (remote, onsite, hybrid)
- Boolean filters (is_featured, provider_is_verified, can_work_remotely)
- Date filters (published_after, published_before)
- Ordering (rating, price, newest, popular, reviews)

### Example API Requests

**List services:**
```http
GET /browse-services/api/services/?category=web-development&min_rating=4.0&ordering=-rating
```

**Search services:**
```http
GET /browse-services/api/services/search/?q=logo+design
```

**Nearby services:**
```http
GET /browse-services/api/services/nearby/?lat=45.5017&lng=-73.5673&radius=50
```

**Service detail:**
```http
GET /browse-services/api/services/550e8400-e29b-41d4-a716-446655440000/
```

**Similar services:**
```http
GET /browse-services/api/services/550e8400-e29b-41d4-a716-446655440000/similar/
```

**Example Response (List):**
```json
{
  "count": 150,
  "next": "/browse-services/api/services/?page=2",
  "previous": null,
  "results": [
    {
      "service_uuid": "550e8400-e29b-41d4-a716-446655440000",
      "name": "Professional Logo Design",
      "slug": "professional-logo-design",
      "short_description": "Custom logo designs for your brand",
      "provider_name": "Creative Studios Inc.",
      "provider_avatar_url": "https://example.com/media/avatars/...",
      "provider_is_verified": true,
      "category_name": "Graphic Design",
      "category_slug": "graphic-design",
      "thumbnail_url": "https://example.com/media/services/...",
      "price": 299.99,
      "currency": "CAD",
      "service_type": "fixed",
      "rating_avg": 4.8,
      "total_reviews": 42,
      "is_featured": true,
      "location_city": "Montreal",
      "location_state": "Quebec",
      "location_country": "Canada",
      "detail_url": "/browse-services/550e8400-e29b-41d4-a716-446655440000/"
    }
  ]
}
```

### API Usage Notes

- **Rate Limiting**: Not currently implemented (add if needed)
- **CORS**: Configured for cross-origin requests
- **Caching**: Responses are cacheable (varies by endpoint)
- **Pagination**: Use `page` query parameter
- **Filtering**: Combine multiple filters with `&`
- **Ordering**: Prefix field with `-` for descending order

### API Documentation

Interactive API documentation available at:
- **Browsable API**: `/browse-services/api/` (when logged in)
- **OpenAPI/Swagger**: (To be implemented)

## URL Structure

### Frontend URLs (HTML)

- `/browse-services/` - Service listing
- `/browse-services/<uuid>/` - Service detail
- `/browse-services/map/` - Map view

### API URLs (JSON)

- `/browse-services/api/services/` - Service list API
- `/browse-services/api/services/{uuid}/` - Service detail API
- `/browse-services/api/services/search/` - Search API
- `/browse-services/api/services/nearby/` - Geographic search API
- `/browse-services/api/services/featured/` - Featured services API
- `/browse-services/api/services/categories/` - Categories API
- `/browse-services/api/images/` - Images API
- `/browse-services/api/pricing-tiers/` - Pricing tiers API
- `/browse-services/api/portfolio/` - Portfolio API
- `/browse-services/api/reviews/` - Reviews API

### WebSocket URLs
- `ws://domain/ws/services-catalog/` - Real-time filtering
- `ws://domain/ws/services-map/` - Map updates

### Query Parameters

**List/Map Views:**
- `q` - Search query
- `category` - Category slug
- `city`, `state`, `country` - Location filters
- `min_price`, `max_price` - Price range
- `min_rating` - Minimum rating (1-5)
- `verified` - Only verified providers (true/false)
- `remote` - Can work remotely (true/false)
- `accepting_work` - Currently accepting work (true/false)
- `service_type` - Service type filter
- `sort` - Sort order (rating, price_asc, price_desc, newest, popular, default)
- `page` - Page number

**Map View Additional:**
- `lat`, `lng` - Center coordinates
- `radius` - Search radius in kilometers (default: 50)

## Development

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for detailed development setup and guidelines.

## Dependencies

### Python Packages
- Django 4.2+
- django-tenants (multi-tenancy)
- Celery (async tasks)
- Channels (WebSocket support)
- PostGIS (geographic queries)
- nh3 or bleach (HTML sanitization)

### JavaScript Libraries
- Leaflet.js (map display)
- Leaflet.markercluster (marker clustering)
- Native WebSocket API (real-time communication)

## Performance Considerations

### Database Optimization
- **Indexes**: Strategic indexes on frequently queried fields
- **GIN Index**: Full-text search on tags_list
- **GIST Index**: Geographic queries on location field
- **Query Optimization**: Use `.only()` and `.select_related()` for minimal data transfer

### Caching
- **Filter Options**: Cached for 15 minutes (categories, cities, countries)
- **Similar Services**: Cached for 1 hour per service
- **WebSocket Results**: No caching (real-time data)

### Limits
- **List View**: 20 services per page
- **Map View**: 200 services max (prevent browser slowdown)
- **Reviews**: 10 per page (load more via AJAX)
- **WebSocket Connections**: Unlimited (Django Channels scaling)

## Testing

Tests are located in `services_public/tests/`:
- `test_models.py` - Model tests
- `test_views.py` - View tests
- `test_sync.py` - Sync infrastructure tests
- `test_signals.py` - Signal tests
- `test_tasks.py` - Celery task tests
- `test_consumers.py` - WebSocket consumer tests
- `test_integration.py` - End-to-end tests
- `test_performance.py` - Performance/load tests

**Run tests:**
```bash
pytest services_public/tests/ --cov=services_public --cov-report=html
```

**Target Coverage:** 90%+

## Future Improvements

See [TODO.md](TODO.md) for planned enhancements and known limitations.

## Related Apps

- **services**: Tenant-side service management (provider dashboard)
- **core.sync**: Base sync infrastructure classes
- **tenants**: Multi-tenant core functionality

## License

Proprietary - Zumodra Platform

## Support

For issues or questions, contact the development team or file an issue in the project repository.
