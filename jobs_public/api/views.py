"""
Jobs Public Catalog API Views.

RESTful API endpoints for job catalog with filtering, search, and map support.
"""

import logging
from rest_framework import viewsets, filters, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q

from jobs_public.models import PublicJobCatalog
from .serializers import (
    PublicJobCatalogListSerializer,
    PublicJobCatalogDetailSerializer,
    PublicJobCatalogMapSerializer,
)

logger = logging.getLogger(__name__)


class PublicJobCatalogPagination(PageNumberPagination):
    """Custom pagination for job catalog API."""
    page_size = 12
    page_size_query_param = 'page_size'
    max_page_size = 100


class PublicJobCatalogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Public Job Catalog API ViewSet.

    Provides read-only access to public job catalog with:
    - List: GET /api/jobs/
    - Detail: GET /api/jobs/{uuid}/
    - Search: GET /api/jobs/?search={query}
    - Filter: GET /api/jobs/?category={slug}&location_city={city}
    - Map Data: GET /api/jobs/map_data/
    - Nearby Jobs: GET /api/jobs/nearby/?lat={lat}&lng={lng}&radius={km}

    Permissions: Public access (no authentication required)
    """

    queryset = PublicJobCatalog.objects.filter(
        is_active=True,
        is_expired=False
    ).order_by('-is_featured', '-published_at')

    pagination_class = PublicJobCatalogPagination
    lookup_field = 'jobposting_uuid'
    lookup_url_kwarg = 'uuid'

    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]

    # Filter fields
    filterset_fields = {
        'employment_type': ['exact'],
        'location_city': ['exact', 'icontains'],
        'location_state': ['exact'],
        'location_country': ['exact'],
        'is_remote': ['exact'],
        'experience_level': ['exact'],
        'is_featured': ['exact'],
    }

    # Search fields
    search_fields = [
        'title',
        'company_name',
        'description_html',
        'location_city',
        'location_state',
    ]

    # Ordering fields
    ordering_fields = [
        'published_at',
        'view_count',
        'application_count',
        'salary_min',
        'salary_max',
    ]

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == 'retrieve':
            return PublicJobCatalogDetailSerializer
        elif self.action == 'map_data':
            return PublicJobCatalogMapSerializer
        return PublicJobCatalogListSerializer

    @action(detail=False, methods=['get'])
    def map_data(self, request):
        """
        Get jobs with geocoding for map display.

        Returns lightweight job data optimized for map markers.
        Limited to 500 jobs with valid coordinates for performance.

        Query Parameters:
            - All standard filters apply
            - Automatically filters to jobs with valid lat/lng

        Response Format:
            {
                "count": 150,
                "results": [
                    {
                        "id": "...",
                        "uuid": "...",
                        "title": "...",
                        "company_name": "...",
                        "location": {"lat": 37.7749, "lng": -122.4194, "display": "..."},
                        "employment_type": "full-time",
                        "salary_display": "$80,000 - $120,000",
                        "is_remote": false
                    },
                    ...
                ]
            }
        """
        # Get filtered queryset
        queryset = self.filter_queryset(self.get_queryset())

        # Filter to jobs with valid geocoding
        queryset = queryset.filter(
            latitude__isnull=False,
            longitude__isnull=False
        )[:500]  # Limit for performance

        # Serialize without pagination for map
        serializer = self.get_serializer(queryset, many=True)

        return Response({
            'count': queryset.count(),
            'results': serializer.data
        })

    @action(detail=False, methods=['get'])
    def nearby(self, request):
        """
        Find jobs near a specific location using distance calculation.

        Query Parameters:
            - lat (required): Latitude
            - lng (required): Longitude
            - radius (optional): Search radius in kilometers (default: 50km)

        Response Format:
            {
                "count": 25,
                "center": {"lat": 37.7749, "lng": -122.4194},
                "radius_km": 50,
                "results": [...]
            }

        Note: Uses basic distance calculation. For production, consider using
        PostGIS ST_Distance for more accurate geospatial queries.
        """
        # Get query parameters
        try:
            lat = float(request.query_params.get('lat'))
            lng = float(request.query_params.get('lng'))
        except (TypeError, ValueError):
            return Response(
                {'error': 'Invalid or missing lat/lng parameters'},
                status=status.HTTP_400_BAD_REQUEST
            )

        radius_km = float(request.query_params.get('radius', 50))

        # Get jobs with valid coordinates
        queryset = self.filter_queryset(self.get_queryset())
        queryset = queryset.filter(
            latitude__isnull=False,
            longitude__isnull=False
        )

        # Filter by approximate bounding box (rough filter)
        # 1 degree latitude ≈ 111 km
        # 1 degree longitude ≈ 111 km * cos(latitude)
        import math
        lat_range = radius_km / 111.0
        lng_range = radius_km / (111.0 * math.cos(math.radians(lat)))

        nearby_jobs = queryset.filter(
            latitude__gte=lat - lat_range,
            latitude__lte=lat + lat_range,
            longitude__gte=lng - lng_range,
            longitude__lte=lng + lng_range,
        )

        # Paginate results
        page = self.paginate_queryset(nearby_jobs)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(nearby_jobs, many=True)

        return Response({
            'count': nearby_jobs.count(),
            'center': {'lat': lat, 'lng': lng},
            'radius_km': radius_km,
            'results': serializer.data
        })

    @action(detail=True, methods=['post'])
    def increment_view(self, request, uuid=None):
        """
        Increment view count for a job.

        This endpoint can be called when a user views a job detail page.

        Response:
            {"view_count": 123}
        """
        job = self.get_object()
        job.increment_view_count()

        # Refresh from DB to get updated count
        job.refresh_from_db()

        return Response({'view_count': job.view_count})
