# Jobs_Public App

**Public Job Catalog** - Cross-tenant job board aggregating all published jobs from tenant schemas into a unified public catalog.

## Overview

The `jobs_public` app provides a public-facing job board that aggregates job postings from all tenants in the system. It operates in the public schema (shared across all tenants) and synchronizes job data automatically using Django signals and Celery tasks.

### Key Features

- **Cross-tenant Aggregation**: Automatically syncs jobs from all tenant schemas to public catalog
- **Real-time Map Updates**: Interactive job map with WebSocket live updates
- **Advanced Filtering**: Search by location, category, employment type, salary range, remote status
- **Multiple View Layouts**: Grid view, list view, map view with customizable templates
- **RESTful API**: Full-featured API with pagination, filtering, and custom endpoints
- **Geocoding**: Automatic location-to-coordinates conversion for map display
- **Rich Content**: Support for job images, videos, formatted lists (responsibilities, benefits)
- **Performance Optimized**: Denormalized data, database indexing, Redis caching
- **Security First**: HTML sanitization, public-only data, no sensitive information

---

## Architecture

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Tenant Schemas                               │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐                    │
│  │  Tenant A  │  │  Tenant B  │  │  Tenant C  │                    │
│  │            │  │            │  │            │                    │
│  │ JobPosting │  │ JobPosting │  │ JobPosting │                    │
│  │  (Save)    │  │  (Save)    │  │  (Save)    │                    │
│  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘                    │
│        │                │                │                           │
│        └────────────────┴────────────────┘                           │
│                         │                                            │
│                    Django Signal                                     │
│                   (post_save)                                        │
│                         │                                            │
└─────────────────────────┼────────────────────────────────────────────┘
                          │
                          ▼
                  ┌───────────────┐
                  │ Celery Task   │
                  │ (Async Queue) │
                  └───────┬───────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
   Geocode          Parse HTML       Extract Images
   Location         to Lists         from JobImage
        │                 │                 │
        └─────────────────┴─────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Public Schema                                   │
│                                                                      │
│              ┌────────────────────────────┐                         │
│              │   PublicJobCatalog         │                         │
│              │   (Denormalized)           │                         │
│              │                            │                         │
│              │  - Job Details             │                         │
│              │  - Company Info (Tenant)   │                         │
│              │  - Geocoded Location       │                         │
│              │  - Parsed HTML Lists       │                         │
│              │  - Image Gallery           │                         │
│              └────────────┬───────────────┘                         │
│                           │                                          │
│                           ▼                                          │
│                  WebSocket Broadcast                                 │
│                  (Django Channels)                                   │
│                           │                                          │
└───────────────────────────┼──────────────────────────────────────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │  Public Users   │
                   │                 │
                   │  - Browse Jobs  │
                   │  - View Map     │
                   │  - Real-time    │
                   │    Updates      │
                   └─────────────────┘
```

### Components

#### Models (`models.py`)
- **PublicJobCatalog**: Denormalized job catalog with 50+ fields
  - Job details (title, description, requirements, benefits)
  - Location data (city, state, country, lat/lng coordinates)
  - Company information (from Tenant model)
  - Rich content (responsibilities, requirements, qualifications, benefits as JSON lists)
  - Media (image gallery, video URL)
  - Metadata (view count, application count, expiration date)
  - Status flags (is_active, is_expired, is_featured)

#### Signals (`signals.py`)
- **sync_job_to_public_catalog**: Triggered when JobPosting is saved
  - Checks if job should be public (published_on_career_page=True, status='open', not internal)
  - Queues Celery task for async sync
- **remove_deleted_job_from_public**: Triggered when JobPosting is deleted
  - Removes job from public catalog

#### Celery Tasks (`tasks.py`)
- **sync_job_to_public**: Main synchronization task
  - Extracts data from JobPosting and Tenant models
  - Geocodes location using GeoPy (with 30-day Redis caching)
  - Parses HTML content to structured lists
  - Extracts image gallery from JobImage model
  - Broadcasts WebSocket event for real-time updates
- **remove_job_from_public**: Removal task
  - Deletes job from public catalog
  - Broadcasts removal event via WebSocket
- **bulk_sync_all_public_jobs**: Initial sync utility
  - Syncs all published jobs from all tenants

#### Views (`views.py`)
- **List Views**:
  - `job_list_default`: 3-column grid layout
  - `job_list_grid`: 2-column grid layout
  - `job_list_list`: 1-column list layout
- **Detail Views**:
  - `job_detail_v1`: Job detail page (version 1)
  - `job_detail_v2`: Job detail page (version 2)
- **Map Views**:
  - `job_map_grid_v1`: Interactive map with WebSocket
  - `job_map_grid_v2`: Alternative map layout
- **AJAX Endpoints**:
  - `wishlist_toggle`: Toggle job wishlist (authenticated users)

#### WebSocket (`consumer.py`, `routing.py`)
- **PublicJobsConsumer**: Handles WebSocket connections
  - Broadcasts job_created, job_updated, job_removed events
  - Ping/pong keep-alive mechanism
  - Auto-reconnect on disconnect

#### API (`api/views.py`, `api/serializers.py`)
- **PublicJobCatalogViewSet**: RESTful API endpoints
  - List, retrieve, filter, search, pagination
  - Custom actions:
    - `map_data`: Lightweight data for map markers (max 500 jobs)
    - `nearby`: Find jobs within radius of location
- **Serializers**:
  - `PublicJobCatalogListSerializer`: Lightweight for list views
  - `PublicJobCatalogDetailSerializer`: Full details with nested data
  - `PublicJobCatalogMapSerializer`: Optimized for map display

#### JavaScript (`static/jobs_public/js/`)
- **jobs_map.js**: Interactive map with Leaflet.js
  - Renders job markers on OpenStreetMap
  - WebSocket connection for real-time updates
  - Popup with job details on marker click
  - Auto-reconnect with exponential backoff
- **jobs_filters.js**: Filter and interactivity
  - Filter form handling
  - Layout switching (grid/list)
  - Sorting controls
  - Wishlist toggle (AJAX)
  - Search query handling

---

## Installation

### 1. Dependencies

The app requires the following packages (already in requirements.txt):

```txt
geopy>=2.4.0          # Geocoding
nh3>=0.2.0            # HTML sanitization
channels>=4.0.0       # WebSocket support
channels-redis>=4.0.0 # Redis channel layer
celery>=5.3.0         # Task queue
```

### 2. Database Migrations

Run migrations to create PublicJobCatalog table in public schema:

```bash
python manage.py migrate jobs_public
```

This creates:
- PublicJobCatalog model with 50+ fields
- Database indexes for performance (location, category, dates, geocoding)

### 3. Settings Configuration

Ensure these settings are configured in `zumodra/settings.py`:

```python
# Add to SHARED_APPS (public schema)
SHARED_APPS = [
    # ...
    'jobs_public',
]

# Celery configuration
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'

# Channels configuration
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [('localhost', 6379)],
        },
    },
}

# Cache for geocoding
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
    }
}
```

### 4. URL Configuration

Add to `zumodra/urls.py`:

```python
urlpatterns += i18n_patterns(
    # ...
    path('jobs/', include('jobs_public.urls', namespace='jobs_public')),
)
```

### 5. ASGI Configuration

WebSocket routing is already configured in `zumodra/asgi.py`:

```python
import jobs_public.routing

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AllowedHostsOriginValidator(
        AuthMiddlewareStack(
            URLRouter(
                # ...
                jobs_public.routing.websocket_urlpatterns
            )
        )
    ),
})
```

### 6. Start Services

Start Celery worker and Daphne (WebSocket server):

```bash
# Terminal 1: Celery worker
celery -A zumodra worker -l info

# Terminal 2: Daphne (WebSocket)
daphne -b 0.0.0.0 -p 8000 zumodra.asgi:application
```

---

## Usage

### Web Interface

#### Browse Jobs

Navigate to `/jobs/` to view the job list in default 3-column grid layout:

```
http://localhost:8000/jobs/
http://localhost:8000/jobs/grid/     # 2-column grid
http://localhost:8000/jobs/list/     # 1-column list
```

#### Filter Jobs

Use query parameters to filter jobs:

```
# Search by keyword
/jobs/?q=python+developer

# Filter by location
/jobs/?city=San+Francisco&state=CA&country=USA

# Filter by category
/jobs/?category=engineering

# Filter by employment type
/jobs/?employment_type=full-time

# Show only remote jobs
/jobs/?remote_only=true

# Filter by salary range
/jobs/?salary_min=80000&salary_max=150000

# Sort results
/jobs/?sort=newest      # Newest first
/jobs/?sort=oldest      # Oldest first
/jobs/?sort=random      # Random order
/jobs/?sort=default     # Featured first, then newest
```

#### View Job Details

Navigate to `/jobs/<uuid>/` to view full job details:

```
http://localhost:8000/jobs/123e4567-e89b-12d3-a456-426614174000/
http://localhost:8000/jobs/123e4567-e89b-12d3-a456-426614174000/v2/  # Alternative design
```

#### Interactive Map

View jobs on an interactive map with real-time updates:

```
http://localhost:8000/jobs/map/
http://localhost:8000/jobs/map/v2/
```

Map features:
- Leaflet.js-powered interactive map
- Job markers with popup details
- Real-time updates via WebSocket (new jobs appear instantly)
- Filter panel for search and filtering
- Auto-center on job locations

### API

#### Base URL

```
http://localhost:8000/jobs/api/
```

#### Endpoints

##### List Jobs

```http
GET /jobs/api/jobs/
```

Query parameters:
- `page`: Page number (default: 1)
- `page_size`: Results per page (default: 20, max: 100)
- `search`: Search query (title, company, description)
- `category`: Filter by category slug
- `location_city`: Filter by city
- `location_country`: Filter by country
- `employment_type`: Filter by employment type
- `is_remote`: Filter remote jobs (true/false)
- `ordering`: Sort field (published_at, -published_at, view_count, -view_count)

Example:

```bash
curl "http://localhost:8000/jobs/api/jobs/?search=developer&is_remote=true&page=1"
```

Response:

```json
{
  "count": 42,
  "next": "http://localhost:8000/jobs/api/jobs/?page=2",
  "previous": null,
  "results": [
    {
      "id": 1,
      "jobposting_uuid": "123e4567-e89b-12d3-a456-426614174000",
      "title": "Senior Python Developer",
      "company_name": "Tech Corp",
      "employment_type": "full-time",
      "location": {
        "city": "San Francisco",
        "state": "CA",
        "country": "USA",
        "display": "San Francisco, CA, USA",
        "is_remote": true
      },
      "salary": {
        "min": 120000,
        "max": 180000,
        "currency": "USD",
        "period": "yearly",
        "display": "$120,000 - $180,000"
      },
      "is_featured": true,
      "published_at": "2025-01-20T10:30:00Z",
      "view_count": 245,
      "application_count": 12
    }
  ]
}
```

##### Get Job Detail

```http
GET /jobs/api/jobs/{uuid}/
```

Example:

```bash
curl "http://localhost:8000/jobs/api/jobs/123e4567-e89b-12d3-a456-426614174000/"
```

Response includes full job details with nested objects (company_info, job_overview, rich_content, media).

##### Map Data

Get lightweight data for map markers (max 500 jobs):

```http
GET /jobs/api/jobs/map_data/
```

Returns only essential fields for map display (id, title, company, location coordinates, employment_type).

##### Nearby Jobs

Find jobs within radius of location:

```http
GET /jobs/api/jobs/nearby/?lat=37.7749&lng=-122.4194&radius=50
```

Query parameters:
- `lat`: Latitude (required)
- `lng`: Longitude (required)
- `radius`: Radius in kilometers (default: 50)

### Python API

#### Sync Jobs Manually

```python
from jobs_public.tasks import sync_job_to_public, bulk_sync_all_public_jobs

# Sync single job
from jobs.models import JobPosting
job = JobPosting.objects.get(id=123)
sync_job_to_public.delay(str(job.id), 'tenant_schema_name')

# Bulk sync all published jobs from all tenants
bulk_sync_all_public_jobs.delay()
```

#### Query Public Jobs

```python
from jobs_public.models import PublicJobCatalog

# Get all active jobs
jobs = PublicJobCatalog.objects.filter(is_active=True, is_expired=False)

# Search jobs
jobs = PublicJobCatalog.objects.filter(
    title__icontains='python',
    is_remote=True,
    is_active=True
)

# Get jobs with geocoding
map_jobs = PublicJobCatalog.objects.filter(
    latitude__isnull=False,
    longitude__isnull=False,
    is_active=True
)

# Get job and increment view count
job = PublicJobCatalog.objects.get(jobposting_uuid='uuid-here')
job.increment_view_count()
```

---

## How It Works

### 1. Job Publication Flow

1. **Tenant Creates Job**: JobPosting created in tenant schema with `published_on_career_page=True` and `status='open'`
2. **Signal Triggered**: `post_save` signal fires in `jobs_public/signals.py`
3. **Celery Task Queued**: `sync_job_to_public.delay()` queued for async processing
4. **Data Extraction**: Task extracts data from JobPosting and Tenant models
5. **Data Processing**:
   - Geocode location (city, state, country) → (lat, lng)
   - Parse HTML content (responsibilities, requirements) → JSON lists
   - Extract images from JobImage model → JSON list of URLs
   - Denormalize company data from Tenant model
6. **Save to Public Catalog**: PublicJobCatalog created/updated in public schema
7. **WebSocket Broadcast**: `job_created` or `job_updated` event sent to all connected clients
8. **Real-time Update**: Map markers update instantly for all users viewing the map

### 2. Job Removal Flow

1. **Job Becomes Private**: JobPosting updated with `status='closed'` or `is_internal_only=True` or `published_on_career_page=False`
2. **Signal Triggered**: `post_save` signal detects job should not be public
3. **Celery Task Queued**: `remove_job_from_public.delay()` queued
4. **Deletion**: PublicJobCatalog entry deleted from public schema
5. **WebSocket Broadcast**: `job_removed` event sent with job UUID
6. **Real-time Update**: Map marker removed instantly for all users

### 3. Geocoding

Location-to-coordinates conversion uses GeoPy with Nominatim (OpenStreetMap):

```python
def geocode_location(city: str, state: str, country: str) -> Tuple[Optional[float], Optional[float]]:
    # Build location string
    location_string = ", ".join([city, state, country])

    # Check Redis cache (30-day TTL)
    cache_key = f"geocode:{location_string}"
    cached_result = cache.get(cache_key)
    if cached_result:
        return cached_result

    # Geocode with GeoPy
    geolocator = Nominatim(user_agent="zumodra_jobs_public", timeout=5)
    location = geolocator.geocode(location_string)

    if location:
        result = (location.latitude, location.longitude)
        cache.set(cache_key, result, 30 * 24 * 60 * 60)  # Cache 30 days
        return result

    return None, None
```

Benefits:
- **Free**: No API key required (OpenStreetMap)
- **Cached**: 30-day Redis caching prevents repeated API calls
- **Fallback**: Uses existing location_coordinates PointField if available

### 4. HTML Parsing

Convert HTML lists to structured JSON:

```python
def parse_html_to_list(html_text: str) -> List[str]:
    # Extract <li> items
    li_pattern = re.compile(r'<li[^>]*>(.*?)</li>', re.DOTALL | re.IGNORECASE)
    matches = li_pattern.findall(html_text)

    if matches:
        return [re.sub(r'<[^>]+>', '', item).strip() for item in matches]

    # Fallback: split by line breaks
    lines = html_text.replace('<br>', '\n').replace('<br/>', '\n')
    lines = re.sub(r'<[^>]+>', '', lines)
    return [line.strip() for line in lines.split('\n') if line.strip()]
```

Input:
```html
<ul>
  <li>Develop Python applications</li>
  <li>Write unit tests</li>
  <li>Code review</li>
</ul>
```

Output:
```python
['Develop Python applications', 'Write unit tests', 'Code review']
```

### 5. Real-time WebSocket Updates

WebSocket flow:

```
1. User opens map page → JavaScript connects to ws://host/ws/jobs/public/
2. Server accepts connection → User joins 'public_jobs_updates' group
3. Tenant publishes job → Celery task syncs to PublicJobCatalog
4. Task broadcasts event → channel_layer.group_send('public_jobs_updates', {...})
5. Consumer receives event → Forwards to all connected clients
6. JavaScript receives event → Adds marker to map instantly
```

JavaScript WebSocket client:

```javascript
const socket = new WebSocket('ws://localhost:8000/ws/jobs/public/');

socket.onmessage = function(event) {
    const data = JSON.parse(event.data);

    switch(data.type) {
        case 'job_created':
            addJobMarker(data.job);
            showNotification(`New job: ${data.job.title}`);
            break;

        case 'job_updated':
            updateJobMarker(data.job);
            break;

        case 'job_removed':
            removeJobMarker(data.job_uuid);
            break;
    }
};
```

---

## Performance Considerations

### Database Indexing

PublicJobCatalog has 15+ indexes for optimized queries:

```python
indexes = [
    models.Index(fields=['is_active', 'is_expired']),
    models.Index(fields=['-published_at']),
    models.Index(fields=['location_city', 'location_state', 'location_country']),
    models.Index(fields=['latitude', 'longitude']),
    models.Index(fields=['category_slugs'], name='ats_pub_cat_idx', opclasses=['gin']),
    models.Index(fields=['experience_level']),
    models.Index(fields=['-view_count']),
    models.Index(fields=['expiration_date']),
    # ... more indexes
]
```

### Caching Strategy

1. **Geocoding Cache**: 30-day Redis cache for location coordinates
2. **Query Caching**: Consider caching filtered querysets for common searches
3. **Static Assets**: Use CDN for JavaScript/CSS files

### Denormalization

PublicJobCatalog denormalizes data from 3 sources:
- JobPosting model (job details)
- Tenant model (company information)
- JobImage model (image gallery)

Benefits:
- **Single Query**: No joins across tenant schemas
- **Fast Reads**: All data in one table
- **Scalable**: Read-heavy workload optimized

Trade-offs:
- **Storage**: Duplicated data across schemas
- **Sync Lag**: Async Celery tasks (usually <1 second)
- **Stale Data**: If sync fails, data may be outdated

### Limiting Results

Map views limit to 500 jobs to prevent performance issues:

```python
map_jobs = jobs.filter(
    latitude__isnull=False,
    longitude__isnull=False
)[:500]  # Limit for performance
```

API pagination limits to 100 results per page:

```python
class PublicJobCatalogPagination(PageNumberPagination):
    page_size = 20
    max_page_size = 100
```

---

## Security

### Public Data Only

PublicJobCatalog contains ONLY public information:
- ✅ Job title, description, requirements, benefits
- ✅ Company name, logo, social links
- ✅ Location (city, state, country)
- ✅ Salary range (if show_salary=True)
- ❌ Internal notes, hiring manager info
- ❌ Candidate applications, interview feedback
- ❌ Sensitive tenant data, internal metrics

### HTML Sanitization

All HTML content sanitized with `nh3` library before public display:

```python
import nh3

# In Celery task
catalog_data['description_html'] = nh3.clean(
    job.description,
    tags=ALLOWED_HTML_TAGS,
    attributes=ALLOWED_HTML_ATTRIBUTES
)
```

Prevents XSS attacks from malicious HTML in job descriptions.

### Application URLs

Job applications redirect to tenant-specific URLs for proper authentication:

```python
# In template
<a href="{{ job.tenant_career_page_url }}/jobs/{{ job.jobposting_uuid }}/apply/">
    Apply Now
</a>
```

Users must authenticate on tenant domain to submit applications.

### WebSocket Security

WebSocket is public broadcast only (no user-specific data):
- No authentication required to connect
- Only broadcasts public job events (created, updated, removed)
- No sensitive data in broadcasts

### Rate Limiting

Consider adding rate limiting to API endpoints:

```python
# In settings.py
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
    }
}
```

---

## Troubleshooting

### Jobs Not Appearing in Catalog

**Symptoms**: Job published but not visible on public job board.

**Possible Causes**:
1. Job not marked as public (`published_on_career_page=False`)
2. Job status is not 'open' (`status='closed'` or `status='draft'`)
3. Job marked as internal only (`is_internal_only=True`)
4. Celery worker not running
5. Signal not firing (in public schema instead of tenant schema)

**Solutions**:
```bash
# Check job status
python manage.py shell
>>> from jobs.models import JobPosting
>>> job = JobPosting.objects.get(id=123)
>>> job.published_on_career_page, job.status, job.is_internal_only
(True, 'open', False)  # Should be this

# Check Celery worker logs
tail -f celery.log | grep sync_job_to_public

# Manually trigger sync
>>> from jobs_public.tasks import sync_job_to_public
>>> sync_job_to_public.delay(str(job.id), 'tenant_schema_name')
```

### Geocoding Fails

**Symptoms**: Jobs appear on list but not on map (no coordinates).

**Possible Causes**:
1. Invalid location data (city/country missing or incorrect)
2. GeoPy API timeout or rate limiting
3. Network connectivity issues
4. Redis cache unavailable

**Solutions**:
```bash
# Check location data
>>> from jobs_public.models import PublicJobCatalog
>>> job = PublicJobCatalog.objects.get(id=123)
>>> job.location_city, job.location_country
('San Francisco', 'USA')  # Should have valid city/country

# Test geocoding manually
>>> from jobs_public.tasks import geocode_location
>>> lat, lng = geocode_location('San Francisco', 'CA', 'USA')
>>> lat, lng
(37.7749, -122.4194)  # Should return coordinates

# Clear geocoding cache and retry
>>> from django.core.cache import cache
>>> cache.delete('geocode:San Francisco, CA, USA')
```

### WebSocket Not Connecting

**Symptoms**: Map loads but no real-time updates.

**Possible Causes**:
1. Daphne server not running
2. WebSocket URL incorrect (ws:// vs wss://)
3. Browser blocking WebSocket connections
4. Nginx/reverse proxy not configured for WebSocket

**Solutions**:
```bash
# Check Daphne is running
ps aux | grep daphne

# Check browser console for errors
# Open DevTools → Console → Look for WebSocket errors

# Test WebSocket manually
wscat -c ws://localhost:8000/ws/jobs/public/

# Nginx WebSocket configuration (if using Nginx)
location /ws/ {
    proxy_pass http://localhost:8000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

### Map Not Rendering

**Symptoms**: Blank map or Leaflet.js errors.

**Possible Causes**:
1. Leaflet.js CDN not loading
2. JavaScript errors in console
3. Map container missing required data attributes
4. No jobs with geocoding available

**Solutions**:
```html
<!-- Check template has Leaflet.js CDN -->
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

<!-- Check map container has data attributes -->
<div id="map"
     data-jobs='[...]'
     data-center-lat="37.7749"
     data-center-lng="-122.4194"
     data-zoom-level="10">
</div>
```

### High Memory Usage

**Symptoms**: Server memory increases over time.

**Possible Causes**:
1. Too many WebSocket connections
2. Large querysets not paginated
3. Celery tasks not releasing memory
4. Redis memory not configured

**Solutions**:
```bash
# Monitor WebSocket connections
netstat -an | grep :8000 | grep ESTABLISHED | wc -l

# Configure Redis maxmemory
redis-cli CONFIG SET maxmemory 256mb
redis-cli CONFIG SET maxmemory-policy allkeys-lru

# Restart services periodically
supervisorctl restart celery daphne
```

---

## Development

### Running Tests

Tests are comprehensive but should NOT be run locally during development:

```bash
# DO NOT RUN - Tests exist but are not executed locally
# pytest jobs_public/tests/ -v --cov=jobs_public --cov-report=html
```

Test files:
- `test_models.py` - Model creation, properties, methods
- `test_signals.py` - Signal triggering, sync conditions
- `test_tasks.py` - Celery task execution, geocoding, HTML parsing
- `test_api.py` - API endpoints, filtering, pagination
- `test_views.py` - View rendering, context, filtering
- `test_websocket.py` - WebSocket connection, broadcasts
- `test_integration.py` - End-to-end workflows

### Code Style

Follow project conventions:
- **English comments and docstrings** throughout
- **Google-style docstrings** with Args, Returns, Raises, Examples
- **Type hints** for function signatures
- **Comprehensive logging** with appropriate levels
- **NO modifications to template CSS/styles** (STRICTLY FORBIDDEN)

### Adding New Fields

If adding new fields to PublicJobCatalog:

1. Add field to model in `models.py`
2. Create migration: `python manage.py makemigrations jobs_public`
3. Run migration: `python manage.py migrate jobs_public`
4. Update `sync_job_to_public` task in `tasks.py` to populate field
5. Update serializers in `api/serializers.py` if exposing via API
6. Add to templates if displaying on web pages
7. Update this README documentation

### Debugging Celery Tasks

Enable verbose logging:

```bash
celery -A zumodra worker -l debug
```

Use Celery Flower for monitoring:

```bash
pip install flower
celery -A zumodra flower

# Access at http://localhost:5555
```

---

## File Structure

```
jobs_public/
├── __init__.py
├── apps.py
├── models.py                    # PublicJobCatalog model
├── signals.py                   # Django signal handlers
├── tasks.py                     # Celery tasks (sync, geocoding)
├── consumer.py                  # WebSocket consumer
├── routing.py                   # WebSocket URL routing
├── views.py                     # Web views (list, detail, map)
├── urls.py                      # URL patterns
├── admin.py                     # Django admin configuration
├── README.md                    # This file
│
├── api/
│   ├── __init__.py
│   ├── views.py                 # DRF ViewSet
│   ├── serializers.py           # DRF serializers
│   └── urls.py                  # API URL routing
│
├── static/jobs_public/
│   └── js/
│       ├── jobs_map.js          # Interactive map with WebSocket
│       └── jobs_filters.js      # Filter handling
│
├── templates/jobs_public/
│   ├── list_default.html        # 3-column grid view
│   ├── grid_view.html           # 2-column grid view
│   ├── list_view.html           # 1-column list view
│   ├── detail_v1.html           # Job detail page (v1)
│   ├── detail_v2.html           # Job detail page (v2)
│   ├── map_grid_v1.html         # Interactive map (v1)
│   └── map_grid_v2.html         # Interactive map (v2)
│
├── migrations/
│   ├── 0001_initial.py
│   └── 0002_add_template_fields.py
│
└── tests/
    ├── conftest.py              # Test fixtures
    ├── test_models.py
    ├── test_signals.py
    ├── test_tasks.py
    ├── test_api.py
    ├── test_views.py
    ├── test_websocket.py
    └── test_integration.py
```

---

## Related Documentation

- **Jobs App**: See `jobs/README.md` for tenant-specific job posting functionality
- **Services Public**: Similar public catalog pattern for services
- **Blog App**: Similar public content aggregation pattern
- **Django Tenants**: See official docs for multi-tenancy architecture

---

## License

Copyright © 2025 Zumodra. All rights reserved.

---

## Support

For issues, questions, or contributions:
- Create issue in project repository
- Contact development team
- Review troubleshooting section above

---

**Last Updated**: 2025-01-24
**Version**: 1.0.0
**Status**: Production Ready
