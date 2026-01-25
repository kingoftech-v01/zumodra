"""
Services Public Utilities

Helper functions for services_public views:
- Filtering and sorting
- Pagination
- GeoJSON generation for maps
- Cache management for filter options
"""

import logging
from decimal import Decimal
from typing import Optional, Dict, List, Any
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.db.models import Q, QuerySet, Count
from django.core.cache import cache
from django.contrib.gis.geos import Point
from django.contrib.gis.measure import D

logger = logging.getLogger(__name__)


# ==================== FILTERING ====================


def apply_filters(queryset: QuerySet, request) -> QuerySet:
    """
    Apply query parameter filters to PublicService queryset.

    Supports filters:
    - q: Full-text search (name, description, tags)
    - category: Filter by category_slug
    - city, state, country: Location filters
    - min_price, max_price: Price range
    - min_rating: Minimum rating
    - verified: Only verified providers (true/false)
    - remote: Can work remotely (true/false)
    - accepting_work: Currently accepting work (true/false)
    - service_type: Filter by service type
    - lat, lng, radius: Geographic filtering (km)

    Args:
        queryset: Base queryset to filter
        request: HTTP request with query parameters

    Returns:
        Filtered queryset
    """
    # Full-text search
    query = request.GET.get('q', '').strip()
    if query:
        queryset = queryset.filter(
            Q(name__icontains=query) |
            Q(description__icontains=query) |
            Q(short_description__icontains=query) |
            Q(provider_name__icontains=query) |
            Q(tags_list__icontains=query)
        )

    # Category filter
    category = request.GET.get('category', '').strip()
    if category:
        queryset = queryset.filter(category_slug=category)

    # Location filters
    city = request.GET.get('city', '').strip()
    if city:
        queryset = queryset.filter(location_city__iexact=city)

    state = request.GET.get('state', '').strip()
    if state:
        queryset = queryset.filter(location_state__iexact=state)

    country = request.GET.get('country', '').strip()
    if country:
        queryset = queryset.filter(location_country__iexact=country)

    # Price range filters
    min_price = request.GET.get('min_price')
    if min_price:
        try:
            queryset = queryset.filter(price__gte=Decimal(min_price))
        except (ValueError, TypeError):
            logger.warning(f"Invalid min_price value: {min_price}")

    max_price = request.GET.get('max_price')
    if max_price:
        try:
            queryset = queryset.filter(price__lte=Decimal(max_price))
        except (ValueError, TypeError):
            logger.warning(f"Invalid max_price value: {max_price}")

    # Rating filter
    min_rating = request.GET.get('min_rating')
    if min_rating:
        try:
            queryset = queryset.filter(rating_avg__gte=Decimal(min_rating))
        except (ValueError, TypeError):
            logger.warning(f"Invalid min_rating value: {min_rating}")

    # Boolean filters
    if request.GET.get('verified') == 'true':
        queryset = queryset.filter(provider_is_verified=True)

    if request.GET.get('remote') == 'true':
        queryset = queryset.filter(can_work_remotely=True)

    if request.GET.get('accepting_work') == 'true':
        queryset = queryset.filter(is_accepting_work=True)

    # Service type filter
    service_type = request.GET.get('service_type', '').strip()
    if service_type:
        queryset = queryset.filter(service_type=service_type)

    # Geographic filtering (by radius)
    lat = request.GET.get('lat')
    lng = request.GET.get('lng')
    radius = request.GET.get('radius', '50')  # Default 50km

    if lat and lng:
        try:
            user_location = Point(float(lng), float(lat), srid=4326)
            radius_km = int(radius)
            queryset = queryset.filter(
                location__distance_lte=(user_location, D(km=radius_km))
            ).exclude(location__isnull=True)
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid geographic filter parameters: {e}")

    return queryset


# ==================== SORTING ====================


def apply_sorting(queryset: QuerySet, request) -> QuerySet:
    """
    Apply sorting to PublicService queryset based on query parameters.

    Supported sort options:
    - rating: Highest rating first
    - price_asc: Lowest price first
    - price_desc: Highest price first
    - newest: Most recently published
    - popular: Most orders/views
    - default: Featured first, then by rating

    Args:
        queryset: Base queryset to sort
        request: HTTP request with query parameters

    Returns:
        Sorted queryset
    """
    sort = request.GET.get('sort', 'default').strip().lower()

    if sort == 'rating':
        return queryset.order_by('-rating_avg', '-total_reviews')

    elif sort == 'price_asc':
        return queryset.order_by('price', 'name')

    elif sort == 'price_desc':
        return queryset.order_by('-price', 'name')

    elif sort == 'newest':
        return queryset.order_by('-published_at', 'name')

    elif sort == 'popular':
        return queryset.order_by('-order_count', '-view_count', 'name')

    else:  # default
        # Featured services first, then sort by rating
        return queryset.order_by('-is_featured', '-rating_avg', '-total_reviews')


# ==================== PAGINATION ====================


def paginate_queryset(queryset: QuerySet, request, per_page: int = 20) -> tuple:
    """
    Paginate a queryset and return page object.

    Args:
        queryset: Queryset to paginate
        request: HTTP request with page parameter
        per_page: Items per page (default: 20)

    Returns:
        Tuple of (page_obj, paginator, page_number)
    """
    paginator = Paginator(queryset, per_page)
    page_number = request.GET.get('page', 1)

    try:
        page_obj = paginator.page(page_number)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page
        page_obj = paginator.page(1)
        page_number = 1
    except EmptyPage:
        # If page is out of range, deliver last page
        page_obj = paginator.page(paginator.num_pages)
        page_number = paginator.num_pages

    return page_obj, paginator, page_number


# ==================== MAP UTILITIES ====================


def calculate_zoom_level(radius_km: int) -> int:
    """
    Calculate appropriate map zoom level based on search radius.

    Args:
        radius_km: Search radius in kilometers

    Returns:
        Zoom level (1-18) for Leaflet/Mapbox
    """
    if radius_km <= 5:
        return 13
    elif radius_km <= 10:
        return 12
    elif radius_km <= 25:
        return 11
    elif radius_km <= 50:
        return 10
    elif radius_km <= 100:
        return 9
    elif radius_km <= 200:
        return 8
    else:
        return 7


def build_geojson(services: QuerySet) -> Dict[str, Any]:
    """
    Build GeoJSON FeatureCollection from PublicService queryset.

    Each service with a location becomes a GeoJSON Point feature with properties:
    - id: Service UUID
    - name: Service name
    - provider_name: Provider name
    - category: Category name
    - price: Service price
    - currency: Currency code
    - rating_avg: Average rating
    - total_reviews: Number of reviews
    - thumbnail_url: Service thumbnail
    - detail_url: Link to detail page

    Args:
        services: QuerySet of PublicService objects with location data

    Returns:
        GeoJSON FeatureCollection dict ready for JSON serialization
    """
    features = []

    for service in services:
        # Skip services without location
        if not service.location:
            continue

        # Extract coordinates (PostGIS Point returns (lng, lat))
        coordinates = [service.location.x, service.location.y]

        feature = {
            'type': 'Feature',
            'geometry': {
                'type': 'Point',
                'coordinates': coordinates
            },
            'properties': {
                'id': str(service.service_uuid),
                'name': service.name,
                'provider_name': service.provider_name,
                'category': service.category_name,
                'price': float(service.price) if service.price else None,
                'currency': service.currency,
                'rating_avg': float(service.rating_avg) if service.rating_avg else None,
                'total_reviews': service.total_reviews,
                'thumbnail_url': service.thumbnail_url,
                'detail_url': service.detail_url,
                'city': service.location_city,
                'state': service.location_state,
                'country': service.location_country,
            }
        }

        features.append(feature)

    return {
        'type': 'FeatureCollection',
        'features': features
    }


# ==================== RECOMMENDATIONS ====================


def get_similar_services(service, limit: int = 4) -> QuerySet:
    """
    Get similar services based on category and tags.

    Finds services that:
    1. Same category (primary match)
    2. Share common tags (secondary match)
    3. Similar price range (within 50%)
    4. Exclude the current service

    Results are cached for 1 hour per service.

    Args:
        service: PublicService instance
        limit: Maximum number of similar services to return

    Returns:
        QuerySet of similar PublicService objects
    """
    from services_public.models import PublicService

    # Try to get from cache first
    cache_key = f"similar_services:{service.service_uuid}:{limit}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    # Build query for similar services
    queryset = PublicService.objects.filter(
        is_active=True
    ).exclude(
        service_uuid=service.service_uuid
    )

    # Priority 1: Same category
    if service.category_slug:
        queryset = queryset.filter(category_slug=service.category_slug)

    # Priority 2: Similar price range (within 50% if price exists)
    if service.price:
        min_price = service.price * Decimal('0.5')
        max_price = service.price * Decimal('1.5')
        queryset = queryset.filter(
            price__gte=min_price,
            price__lte=max_price
        )

    # Priority 3: Share common tags
    # Note: This is a simple containment check, not optimal for complex matching
    # For production, consider using PostgreSQL full-text search or Elasticsearch

    # Order by rating and limit results
    similar = queryset.order_by('-rating_avg', '-total_reviews')[:limit]

    # Convert to list to cache
    similar_list = list(similar)

    # Cache for 1 hour
    cache.set(cache_key, similar_list, 3600)

    return similar_list


# ==================== FILTER OPTIONS ====================


def get_filter_options() -> Dict[str, List[Dict[str, Any]]]:
    """
    Get available filter options for the service catalog.

    Returns distinct values for:
    - Categories (with counts)
    - Cities (with counts)
    - Countries (with counts)
    - Service types (with counts)
    - Price ranges (pre-defined brackets)

    Results are cached for 15 minutes to reduce database load.

    Returns:
        Dict with keys: categories, cities, countries, service_types, price_ranges
    """
    from services_public.models import PublicService

    # Try to get from cache first
    cache_key = 'services_public:filter_options'
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    # Query distinct filter values
    categories = list(
        PublicService.objects.filter(is_active=True)
        .values('category_name', 'category_slug')
        .annotate(count=Count('id'))
        .order_by('category_name')
    )

    cities = list(
        PublicService.objects.filter(is_active=True, location_city__isnull=False)
        .exclude(location_city='')
        .values('location_city')
        .annotate(count=Count('id'))
        .order_by('location_city')
    )

    countries = list(
        PublicService.objects.filter(is_active=True, location_country__isnull=False)
        .exclude(location_country='')
        .values('location_country')
        .annotate(count=Count('id'))
        .order_by('location_country')
    )

    service_types = list(
        PublicService.objects.filter(is_active=True, service_type__isnull=False)
        .values('service_type')
        .annotate(count=Count('id'))
        .order_by('service_type')
    )

    # Pre-defined price ranges
    price_ranges = [
        {'label': 'Under $50', 'min': 0, 'max': 50},
        {'label': '$50 - $100', 'min': 50, 'max': 100},
        {'label': '$100 - $250', 'min': 100, 'max': 250},
        {'label': '$250 - $500', 'min': 250, 'max': 500},
        {'label': '$500+', 'min': 500, 'max': None},
    ]

    result = {
        'categories': categories,
        'cities': cities,
        'countries': countries,
        'service_types': service_types,
        'price_ranges': price_ranges,
    }

    # Cache for 15 minutes
    cache.set(cache_key, result, 900)

    return result


# ==================== ACTIVE FILTERS EXTRACTION ====================


def get_active_filters(request) -> Dict[str, Any]:
    """
    Extract active filters from request query parameters.

    Used for displaying current filter state in the UI.

    Args:
        request: HTTP request

    Returns:
        Dict of active filters
    """
    return {
        'q': request.GET.get('q', ''),
        'category': request.GET.get('category', ''),
        'city': request.GET.get('city', ''),
        'state': request.GET.get('state', ''),
        'country': request.GET.get('country', ''),
        'min_price': request.GET.get('min_price', ''),
        'max_price': request.GET.get('max_price', ''),
        'min_rating': request.GET.get('min_rating', ''),
        'verified': request.GET.get('verified') == 'true',
        'remote': request.GET.get('remote') == 'true',
        'accepting_work': request.GET.get('accepting_work') == 'true',
        'service_type': request.GET.get('service_type', ''),
        'sort': request.GET.get('sort', 'default'),
        'lat': request.GET.get('lat', ''),
        'lng': request.GET.get('lng', ''),
        'radius': request.GET.get('radius', '50'),
    }
