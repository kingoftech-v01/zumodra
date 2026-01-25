"""
Public Job Catalog Template Views - Frontend HTML views.

This module provides template-based views for public job browsing:
- List views with filtering/pagination
- Detail views with job information
- Map views with geocoded jobs
- AJAX endpoints for dynamic features

All views render HTML templates using Django's render().
Uses HTMX for dynamic interactions.

Views:
    - job_list_default: Main job listing (3-column grid)
    - job_list_grid: Grid view (2-column)
    - job_list_list: List view (1-column)
    - job_detail_v1: Job detail page (version 1)
    - job_detail_v2: Job detail page (version 2)
    - job_map_grid_v1: Interactive map view with real-time WebSocket updates (v1)
    - job_map_grid_v2: Interactive map view (v2)
    - wishlist_toggle: AJAX endpoint for wishlist functionality

Features:
    - Search by title, company, description
    - Filter by location, category, employment type, remote, salary range
    - Sort by date, random
    - Pagination (12 jobs per page)
    - Real-time map updates via WebSocket
"""

import json
import logging
from typing import Optional
from django.shortcuts import render, get_object_or_404
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q, Count
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.utils import timezone

from .models import PublicJobCatalog

logger = logging.getLogger(__name__)

# Constants
JOBS_PER_PAGE = 12
DEFAULT_CENTER_LAT = 37.7749  # San Francisco
DEFAULT_CENTER_LNG = -122.4194


# ==================== Helper Functions ====================

def _get_filtered_jobs(request):
    """
    Apply filters, search, and sorting to job queryset based on request parameters.

    Query Parameters:
        - q: Search query (title, company, description)
        - city: Filter by city
        - state: Filter by state
        - country: Filter by country
        - category: Filter by category slug
        - employment_type: Filter by employment type
        - remote_only: Show only remote jobs (true/false)
        - salary_min: Minimum salary
        - salary_max: Maximum salary
        - sort: Sort order (default/newest/oldest/random)

    Returns:
        QuerySet of filtered PublicJobCatalog entries
    """
    # Start with active, non-expired jobs
    queryset = PublicJobCatalog.objects.filter(
        is_active=True,
        is_expired=False
    )

    # Search query (across title, company, description)
    search_query = request.GET.get('q', '').strip()
    if search_query:
        queryset = queryset.filter(
            Q(title__icontains=search_query) |
            Q(company_name__icontains=search_query) |
            Q(description_html__icontains=search_query)
        )

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

    # Category filter
    category = request.GET.get('category', '').strip()
    if category:
        queryset = queryset.filter(category_slugs__contains=[category])

    # Employment type filter
    employment_type = request.GET.get('employment_type', '').strip()
    if employment_type:
        queryset = queryset.filter(employment_type__iexact=employment_type)

    # Remote only filter
    remote_only = request.GET.get('remote_only', '').lower() == 'true'
    if remote_only:
        queryset = queryset.filter(is_remote=True)

    # Salary range filters
    salary_min = request.GET.get('salary_min', '').strip()
    if salary_min:
        try:
            queryset = queryset.filter(salary_min__gte=float(salary_min))
        except ValueError:
            pass

    salary_max = request.GET.get('salary_max', '').strip()
    if salary_max:
        try:
            queryset = queryset.filter(salary_max__lte=float(salary_max))
        except ValueError:
            pass

    # Sorting
    sort_by = request.GET.get('sort', 'default')
    if sort_by == 'newest':
        queryset = queryset.order_by('-published_at')
    elif sort_by == 'oldest':
        queryset = queryset.order_by('published_at')
    elif sort_by == 'random':
        queryset = queryset.order_by('?')
    else:  # default: featured first, then newest
        queryset = queryset.order_by('-is_featured', '-published_at')

    return queryset


def _paginate_queryset(queryset, page_number, per_page=JOBS_PER_PAGE):
    """
    Paginate queryset and return paginator and page object.

    Args:
        queryset: QuerySet to paginate
        page_number: Requested page number
        per_page: Number of items per page

    Returns:
        Tuple of (paginator, page_obj)
    """
    paginator = Paginator(queryset, per_page)

    try:
        page_obj = paginator.page(page_number)
    except PageNotAnInteger:
        page_obj = paginator.page(1)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)

    return paginator, page_obj


def _get_filter_context(request):
    """
    Build context dict with current filter values for template.

    Returns:
        Dict with filter values from request
    """
    return {
        'search_query': request.GET.get('q', ''),
        'selected_city': request.GET.get('city', ''),
        'selected_state': request.GET.get('state', ''),
        'selected_country': request.GET.get('country', ''),
        'selected_category': request.GET.get('category', ''),
        'selected_employment_type': request.GET.get('employment_type', ''),
        'remote_only': request.GET.get('remote_only', '') == 'true',
        'salary_min': request.GET.get('salary_min', ''),
        'salary_max': request.GET.get('salary_max', ''),
        'sort_by': request.GET.get('sort', 'default'),
    }


# ==================== List Views ====================

def job_list_default(request):
    """
    Main job listing view (3-column grid layout).

    Features:
        - Search and filter functionality
        - Pagination (12 jobs per page)
        - Featured jobs highlighted
        - Responsive grid layout

    Template: jobs_public/list_default.html
    """
    # Get filtered jobs
    jobs = _get_filtered_jobs(request)

    # Pagination
    page_number = request.GET.get('page', 1)
    paginator, page_obj = _paginate_queryset(jobs, page_number)

    # Build context
    context = {
        'jobs': page_obj,
        'paginator': paginator,
        'page_obj': page_obj,
        'total_jobs': paginator.count,
        **_get_filter_context(request),
    }

    return render(request, 'jobs_public/list_default.html', context)


def job_list_grid(request):
    """
    Grid view (2-column layout).

    Similar to default view but with different template for 2-column grid.

    Template: jobs_public/grid_view.html
    """
    # Get filtered jobs
    jobs = _get_filtered_jobs(request)

    # Pagination
    page_number = request.GET.get('page', 1)
    paginator, page_obj = _paginate_queryset(jobs, page_number)

    # Build context
    context = {
        'jobs': page_obj,
        'paginator': paginator,
        'page_obj': page_obj,
        'total_jobs': paginator.count,
        **_get_filter_context(request),
    }

    return render(request, 'jobs_public/grid_view.html', context)


def job_list_list(request):
    """
    List view (1-column layout with more detail).

    Shows jobs in single-column list format with expanded information.

    Template: jobs_public/list_view.html
    """
    # Get filtered jobs
    jobs = _get_filtered_jobs(request)

    # Pagination
    page_number = request.GET.get('page', 1)
    paginator, page_obj = _paginate_queryset(jobs, page_number)

    # Build context
    context = {
        'jobs': page_obj,
        'paginator': paginator,
        'page_obj': page_obj,
        'total_jobs': paginator.count,
        **_get_filter_context(request),
    }

    return render(request, 'jobs_public/list_view.html', context)


# ==================== Detail Views ====================

def job_detail_v1(request, pk):
    """
    Job detail page (version 1).

    Shows full job description, requirements, benefits, company info, and related jobs.
    Increments view count on each page load.

    Args:
        request: HTTP request
        pk: Job UUID (jobposting_uuid field)

    Returns:
        Rendered detail_v1.html template

    Template: jobs_public/detail_v1.html
    """
    # Get job and increment view count
    job = get_object_or_404(PublicJobCatalog, jobposting_uuid=pk, is_active=True)
    job.increment_view_count()

    # Get related jobs (same category or location)
    related_jobs = PublicJobCatalog.objects.filter(
        is_active=True,
        is_expired=False
    ).exclude(
        jobposting_uuid=pk
    ).filter(
        Q(category_slugs__overlap=job.category_slugs) |
        Q(location_city=job.location_city)
    ).order_by('-published_at')[:6]

    # Build context
    context = {
        'job': job,
        'related_jobs': related_jobs,
    }

    return render(request, 'jobs_public/detail_v1.html', context)


def job_detail_v2(request, pk):
    """
    Job detail page (version 2).

    Alternative design for job detail page.

    Args:
        request: HTTP request
        pk: Job UUID (jobposting_uuid field)

    Returns:
        Rendered detail_v2.html template

    Template: jobs_public/detail_v2.html
    """
    # Get job and increment view count
    job = get_object_or_404(PublicJobCatalog, jobposting_uuid=pk, is_active=True)
    job.increment_view_count()

    # Get related jobs
    related_jobs = PublicJobCatalog.objects.filter(
        is_active=True,
        is_expired=False
    ).exclude(
        jobposting_uuid=pk
    ).filter(
        Q(category_slugs__overlap=job.category_slugs) |
        Q(location_city=job.location_city)
    ).order_by('-published_at')[:6]

    # Build context
    context = {
        'job': job,
        'related_jobs': related_jobs,
    }

    return render(request, 'jobs_public/detail_v2.html', context)


# ==================== Map Views ====================

def job_map_grid_v1(request):
    """
    Interactive map view with job markers and WebSocket real-time updates (version 1).

    Features:
        - Leaflet.js map with job location markers
        - WebSocket connection for real-time job updates
        - Filter panel for search and filtering
        - Job cards displayed alongside map

    Template: jobs_public/map_grid_v1.html
    """
    # Get filtered jobs
    jobs = _get_filtered_jobs(request)

    # Limit to jobs with geocoding for map display (max 500 for performance)
    map_jobs = jobs.filter(
        latitude__isnull=False,
        longitude__isnull=False
    )[:500]

    # Serialize job data for map markers (JSON)
    jobs_data = []
    for job in map_jobs:
        jobs_data.append({
            'id': str(job.id),
            'uuid': str(job.jobposting_uuid),
            'title': job.title,
            'company_name': job.company_name,
            'location': {
                'lat': job.latitude,
                'lng': job.longitude,
                'display': job.location_display,
            },
            'employment_type': job.employment_type,
            'salary_display': job.salary_display,
            'is_remote': job.is_remote,
            'detail_url': f'/jobs/{job.jobposting_uuid}/',
        })

    # Calculate map center (average of all job locations or default)
    if jobs_data:
        avg_lat = sum(j['location']['lat'] for j in jobs_data) / len(jobs_data)
        avg_lng = sum(j['location']['lng'] for j in jobs_data) / len(jobs_data)
    else:
        avg_lat, avg_lng = DEFAULT_CENTER_LAT, DEFAULT_CENTER_LNG

    # Build context
    context = {
        'jobs': list(jobs[:JOBS_PER_PAGE]),  # Show first page of jobs in sidebar
        'total_jobs': jobs.count(),
        'jobs_data_json': json.dumps(jobs_data),
        'map_center_lat': avg_lat,
        'map_center_lng': avg_lng,
        'map_zoom_level': 10,
        **_get_filter_context(request),
    }

    return render(request, 'jobs_public/map_grid_v1.html', context)


def job_map_grid_v2(request):
    """
    Interactive map view (version 2).

    Alternative design for map view.

    Template: jobs_public/map_grid_v2.html
    """
    # Get filtered jobs
    jobs = _get_filtered_jobs(request)

    # Limit to jobs with geocoding for map display
    map_jobs = jobs.filter(
        latitude__isnull=False,
        longitude__isnull=False
    )[:500]

    # Serialize job data for map markers
    jobs_data = []
    for job in map_jobs:
        jobs_data.append({
            'id': str(job.id),
            'uuid': str(job.jobposting_uuid),
            'title': job.title,
            'company_name': job.company_name,
            'location': {
                'lat': job.latitude,
                'lng': job.longitude,
                'display': job.location_display,
            },
            'employment_type': job.employment_type,
            'salary_display': job.salary_display,
            'is_remote': job.is_remote,
            'detail_url': f'/jobs/{job.jobposting_uuid}/',
        })

    # Calculate map center
    if jobs_data:
        avg_lat = sum(j['location']['lat'] for j in jobs_data) / len(jobs_data)
        avg_lng = sum(j['location']['lng'] for j in jobs_data) / len(jobs_data)
    else:
        avg_lat, avg_lng = DEFAULT_CENTER_LAT, DEFAULT_CENTER_LNG

    # Build context
    context = {
        'jobs': list(jobs[:JOBS_PER_PAGE]),
        'total_jobs': jobs.count(),
        'jobs_data_json': json.dumps(jobs_data),
        'map_center_lat': avg_lat,
        'map_center_lng': avg_lng,
        'map_zoom_level': 10,
        **_get_filter_context(request),
    }

    return render(request, 'jobs_public/map_grid_v2.html', context)


# ==================== AJAX Endpoints ====================

@require_http_methods(["POST"])
@login_required
def wishlist_toggle(request, job_id):
    """
    Toggle job wishlist status for authenticated user (AJAX endpoint).

    Args:
        job_id: PublicJobCatalog ID

    Returns:
        JSON response with new wishlist status

    Response Format:
        {
            "success": true,
            "wishlisted": true/false,
            "message": "Added to wishlist" / "Removed from wishlist"
        }
    """
    try:
        job = get_object_or_404(PublicJobCatalog, id=job_id, is_active=True)

        # TODO: Implement wishlist functionality with UserProfile model
        # For now, return placeholder response
        # In production: check UserProfile.wishlisted_jobs and toggle

        return JsonResponse({
            'success': True,
            'wishlisted': True,  # Placeholder
            'message': 'Wishlist functionality coming soon'
        })

    except Exception as e:
        logger.error(f"Error toggling wishlist for job {job_id}: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
