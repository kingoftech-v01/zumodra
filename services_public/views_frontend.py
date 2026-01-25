"""
Services Public Views

Django views for the public service catalog:
- service_list_view: Browse services with filtering and search
- service_detail_view: View service details
- service_map_view: Geographic map view of services
"""

import logging
from django.shortcuts import render, get_object_or_404
from django.db.models import F
from django.http import JsonResponse
from django.views.decorators.cache import cache_page
from django.db import transaction

from services_public.models import (
    PublicService,
    PublicServiceImage,
    PublicServicePricingTier,
    PublicServicePortfolio,
    PublicServiceReview
)
from services_public.utils import (
    apply_filters,
    apply_sorting,
    paginate_queryset,
    build_geojson,
    get_similar_services,
    get_filter_options,
    get_active_filters,
    calculate_zoom_level,
)

logger = logging.getLogger(__name__)


# ==================== SERVICE LIST VIEW ====================


def service_list_view(request):
    """
    Display paginated list of services with filters and search.

    Supports:
    - Full-text search (q parameter)
    - Category, location, price, rating filters
    - Sorting (rating, price, newest, popular)
    - Pagination (20 items per page)

    Query Parameters:
        q: Search query
        category: Category slug
        city, state, country: Location filters
        min_price, max_price: Price range
        min_rating: Minimum rating
        verified: Only verified providers (true/false)
        remote: Can work remotely (true/false)
        accepting_work: Currently accepting work (true/false)
        service_type: Service type filter
        sort: Sort order (rating, price_asc, price_desc, newest, popular, default)
        page: Page number

    Template:
        services/list.html

    Context:
        services: Page object with PublicService instances
        total_count: Total number of services (before pagination)
        page_obj: Paginator page object
        paginator: Paginator instance
        active_filters: Dict of active filter parameters
        filter_options: Available filter options (categories, cities, etc.)
        sort_options: List of available sort options
    """
    # Base queryset: only active services
    queryset = PublicService.objects.filter(is_active=True)

    # Apply filters from query parameters
    queryset = apply_filters(queryset, request)

    # Get total count before pagination
    total_count = queryset.count()

    # Apply sorting
    queryset = apply_sorting(queryset, request)

    # Optimize query: select only needed fields for list view
    queryset = queryset.only(
        'service_uuid',
        'name',
        'slug',
        'short_description',
        'provider_name',
        'provider_avatar_url',
        'category_name',
        'category_slug',
        'thumbnail_url',
        'price',
        'currency',
        'rating_avg',
        'total_reviews',
        'is_featured',
        'provider_is_verified',
        'detail_url',
    )

    # Paginate results (20 items per page)
    page_obj, paginator, page_number = paginate_queryset(queryset, request, per_page=20)

    # Get filter options (cached for 15 minutes)
    filter_options = get_filter_options()

    # Get active filters for UI state
    active_filters = get_active_filters(request)

    # Define sort options for UI
    sort_options = [
        {'value': 'default', 'label': 'Featured'},
        {'value': 'rating', 'label': 'Highest Rated'},
        {'value': 'price_asc', 'label': 'Price: Low to High'},
        {'value': 'price_desc', 'label': 'Price: High to Low'},
        {'value': 'newest', 'label': 'Newest'},
        {'value': 'popular', 'label': 'Most Popular'},
    ]

    context = {
        'services': page_obj,
        'total_count': total_count,
        'page_obj': page_obj,
        'paginator': paginator,
        'current_page': page_number,
        'active_filters': active_filters,
        'filter_options': filter_options,
        'sort_options': sort_options,
    }

    return render(request, 'services/list.html', context)


# ==================== SERVICE DETAIL VIEW ====================


def service_detail_view(request, service_uuid):
    """
    Display detailed information about a specific service.

    Increments view count atomically and displays:
    - Service information
    - Provider details
    - Gallery images
    - Pricing tiers
    - Provider portfolio
    - Customer reviews
    - Similar services

    Args:
        service_uuid: UUID of the service

    Template:
        services/detail.html

    Context:
        service: PublicService instance
        images: QuerySet of PublicServiceImage
        pricing_tiers: QuerySet of PublicServicePricingTier (ordered by sort_order)
        portfolio_images: QuerySet of PublicServicePortfolio
        reviews: QuerySet of PublicServiceReview (latest 10)
        similar_services: List of similar services (max 4)
        breadcrumbs: List of breadcrumb items
        meta_title: SEO meta title
        meta_description: SEO meta description
    """
    # Get service or 404
    service = get_object_or_404(
        PublicService.objects.select_related(),
        service_uuid=service_uuid,
        is_active=True
    )

    # Increment view count atomically (prevent race conditions)
    with transaction.atomic():
        PublicService.objects.filter(service_uuid=service_uuid).update(
            view_count=F('view_count') + 1
        )

    # Get related data with prefetch optimization
    images = PublicServiceImage.objects.filter(
        service=service
    ).order_by('sort_order')

    pricing_tiers = PublicServicePricingTier.objects.filter(
        service=service
    ).order_by('sort_order')

    portfolio_images = PublicServicePortfolio.objects.filter(
        service=service
    ).order_by('sort_order')

    reviews = PublicServiceReview.objects.filter(
        service=service
    ).order_by('-created_at')[:10]

    # Get similar services (cached for 1 hour)
    similar_services = get_similar_services(service, limit=4)

    # Build breadcrumbs
    breadcrumbs = [
        {'label': 'Home', 'url': '/'},
        {'label': 'Browse Services', 'url': '/browse-services/'},
    ]
    if service.category_name:
        breadcrumbs.append({
            'label': service.category_name,
            'url': f'/browse-services/?category={service.category_slug}'
        })
    breadcrumbs.append({'label': service.name, 'url': ''})

    # SEO metadata
    meta_title = f"{service.name} - {service.provider_name}"
    meta_description = service.short_description or service.description[:200]

    context = {
        'service': service,
        'images': images,
        'pricing_tiers': pricing_tiers,
        'portfolio_images': portfolio_images,
        'reviews': reviews,
        'similar_services': similar_services,
        'breadcrumbs': breadcrumbs,
        'meta_title': meta_title,
        'meta_description': meta_description,
    }

    return render(request, 'services/detail.html', context)


# ==================== SERVICE MAP VIEW ====================


def service_map_view(request):
    """
    Display geographic map of services with filtering.

    Shows services on an interactive map with:
    - GeoJSON markers for each service with location
    - Same filters as list view
    - Sidebar with service cards
    - Map controls (zoom, pan)

    Query Parameters:
        All filters from service_list_view, plus:
        lat: Center latitude (default: auto-calculated)
        lng: Center longitude (default: auto-calculated)
        radius: Search radius in km (default: 50)

    Template:
        services/map.html

    Context:
        services: QuerySet of PublicService with location data
        geojson: GeoJSON FeatureCollection for map markers
        map_center: Dict with lat/lng for map center
        map_zoom: Zoom level based on radius
        radius_km: Search radius
        total_count: Number of services with location
        active_filters: Active filter parameters
        filter_options: Available filter options
    """
    # Base queryset: only active services with location data
    queryset = PublicService.objects.filter(
        is_active=True,
        location__isnull=False
    )

    # Apply filters from query parameters
    queryset = apply_filters(queryset, request)

    # Apply sorting
    queryset = apply_sorting(queryset, request)

    # Limit to first 200 services for performance
    # (rendering too many markers can slow down the map)
    services = queryset[:200]

    total_count = queryset.count()

    # Build GeoJSON for map markers
    geojson = build_geojson(services)

    # Determine map center
    lat = request.GET.get('lat')
    lng = request.GET.get('lng')
    radius_km = int(request.GET.get('radius', '50'))

    if lat and lng:
        # Use provided center
        try:
            map_center = {
                'lat': float(lat),
                'lng': float(lng)
            }
        except (ValueError, TypeError):
            # Default to North America center if invalid
            map_center = {'lat': 39.8283, 'lng': -98.5795}
    else:
        # Auto-calculate center from services
        if services:
            # Use first service location as center
            first_service = services[0]
            if first_service.location:
                map_center = {
                    'lat': first_service.location.y,
                    'lng': first_service.location.x
                }
            else:
                map_center = {'lat': 39.8283, 'lng': -98.5795}
        else:
            # Default center if no services
            map_center = {'lat': 39.8283, 'lng': -98.5795}

    # Calculate appropriate zoom level based on radius
    map_zoom = calculate_zoom_level(radius_km)

    # Get filter options
    filter_options = get_filter_options()
    active_filters = get_active_filters(request)

    context = {
        'services': services,
        'geojson': geojson,
        'map_center': map_center,
        'map_zoom': map_zoom,
        'radius_km': radius_km,
        'total_count': total_count,
        'active_filters': active_filters,
        'filter_options': filter_options,
    }

    return render(request, 'services/map.html', context)
