"""
API ViewSets for Public Service Catalog.

Provides read-only public API for browsing service provider listings.
"""

from django.db import models
from django.contrib.gis.geos import Point
from django.contrib.gis.measure import D
from django_filters import rest_framework as filters
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from drf_spectacular.types import OpenApiTypes

from services_public.models import PublicServiceCatalog
from .serializers import PublicServiceCatalogSerializer, PublicServiceCatalogListSerializer


class PublicServiceCatalogFilter(filters.FilterSet):
    """Filters for public service catalog browsing."""

    business_name = filters.CharFilter(lookup_expr='icontains')
    location_city = filters.CharFilter(lookup_expr='icontains')
    location_country = filters.CharFilter(lookup_expr='iexact')
    category = filters.CharFilter(field_name='service_category_slugs', lookup_expr='contains')
    is_mobile = filters.BooleanFilter()
    is_verified = filters.BooleanFilter()
    accepts_online_payment = filters.BooleanFilter()
    hourly_rate_min = filters.NumberFilter(field_name='hourly_rate', lookup_expr='gte')
    hourly_rate_max = filters.NumberFilter(field_name='hourly_rate', lookup_expr='lte')
    min_rating = filters.NumberFilter(field_name='rating', lookup_expr='gte')
    min_completed_jobs = filters.NumberFilter(field_name='completed_jobs', lookup_expr='gte')

    class Meta:
        model = PublicServiceCatalog
        fields = [
            'business_name',
            'location_city',
            'location_country',
            'category',
            'is_mobile',
            'is_verified',
            'accepts_online_payment',
            'hourly_rate_min',
            'hourly_rate_max',
            'min_rating',
            'min_completed_jobs',
        ]


@extend_schema_view(
    list=extend_schema(
        summary="List public service providers",
        description="Browse public service provider listings without authentication. Supports filtering, search, and geographic queries.",
        tags=['Public Service Catalog'],
    ),
    retrieve=extend_schema(
        summary="Get provider details",
        description="Get detailed information about a specific service provider.",
        tags=['Public Service Catalog'],
    ),
)
class PublicServiceCatalogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Public service catalog API.

    Read-only endpoints for browsing service providers without authentication.

    Features:
    - List all active providers with filtering and search
    - Get detailed provider information
    - Increment view count on retrieve
    - Verified providers endpoint
    - Top-rated providers endpoint
    - Geographic search (nearby providers)
    - Search by keywords
    """

    permission_classes = [AllowAny]
    filterset_class = PublicServiceCatalogFilter
    search_fields = [
        'business_name',
        'description_html',
        'service_category_names',
        'skills',
        'location_city',
        'location_country'
    ]
    ordering_fields = ['rating', 'completed_jobs', 'view_count', 'hourly_rate', 'published_at']
    ordering = ['-rating', '-completed_jobs']

    def get_queryset(self):
        """Get only active service provider listings."""
        return PublicServiceCatalog.objects.filter(is_active=True)

    def get_serializer_class(self):
        """Use lightweight serializer for list, full serializer for detail."""
        if self.action == 'list':
            return PublicServiceCatalogListSerializer
        return PublicServiceCatalogSerializer

    def retrieve(self, request, *args, **kwargs):
        """Get provider details and increment view count."""
        instance = self.get_object()

        # Increment view count asynchronously
        PublicServiceCatalog.objects.filter(pk=instance.pk).update(
            view_count=models.F('view_count') + 1
        )

        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    @extend_schema(
        summary="List verified providers",
        description="Get service providers verified by platform admins.",
        tags=['Public Service Catalog'],
    )
    @action(detail=False, methods=['get'])
    def verified(self, request):
        """Get verified service provider listings."""
        queryset = self.get_queryset().filter(is_verified=True)
        queryset = self.filter_queryset(queryset)

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = PublicServiceCatalogListSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = PublicServiceCatalogListSerializer(queryset, many=True)
        return Response(serializer.data)

    @extend_schema(
        summary="List top-rated providers",
        description="Get service providers with highest ratings (minimum 5 reviews).",
        tags=['Public Service Catalog'],
    )
    @action(detail=False, methods=['get'])
    def top_rated(self, request):
        """Get top-rated service providers."""
        queryset = self.get_queryset().filter(
            rating__gte=4.0,
            rating_count__gte=5
        ).order_by('-rating', '-rating_count')

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = PublicServiceCatalogListSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = PublicServiceCatalogListSerializer(queryset, many=True)
        return Response(serializer.data)

    @extend_schema(
        summary="Find nearby providers",
        description="Find service providers within a specified radius of a location.",
        tags=['Public Service Catalog'],
        parameters=[
            OpenApiParameter('lat', OpenApiTypes.FLOAT, description='Latitude', required=True),
            OpenApiParameter('lng', OpenApiTypes.FLOAT, description='Longitude', required=True),
            OpenApiParameter('radius', OpenApiTypes.INT, description='Search radius in kilometers (default: 50km)', required=False),
        ],
    )
    @action(detail=False, methods=['get'])
    def nearby(self, request):
        """Find service providers near a location."""
        try:
            lat = float(request.query_params.get('lat'))
            lng = float(request.query_params.get('lng'))
        except (TypeError, ValueError):
            return Response(
                {'error': 'Valid "lat" and "lng" query parameters are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            radius_km = int(request.query_params.get('radius', 50))
            if radius_km <= 0 or radius_km > 500:
                raise ValueError("Radius must be between 1 and 500 km")
        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create point for user location
        point = Point(lng, lat, srid=4326)

        # Find providers within radius
        queryset = self.get_queryset().filter(
            location__distance_lte=(point, D(km=radius_km))
        ).annotate(
            distance=models.functions.GeometryDistance('location', point)
        ).order_by('distance')

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = PublicServiceCatalogListSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = PublicServiceCatalogListSerializer(queryset, many=True)
        return Response(serializer.data)

    @extend_schema(
        summary="Search providers by keyword",
        description="Search service providers by keyword in business name, description, categories, and skills.",
        tags=['Public Service Catalog'],
        parameters=[
            OpenApiParameter('q', str, description='Search query', required=True),
        ],
    )
    @action(detail=False, methods=['get'])
    def search(self, request):
        """Search providers by keyword."""
        query = request.query_params.get('q', '').strip()

        if not query:
            return Response(
                {'error': 'Query parameter "q" is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        queryset = self.get_queryset().filter(
            models.Q(business_name__icontains=query) |
            models.Q(description_html__icontains=query) |
            models.Q(service_category_names__contains=[query]) |
            models.Q(skills__contains=[query]) |
            models.Q(location_city__icontains=query) |
            models.Q(location_country__icontains=query)
        )

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = PublicServiceCatalogListSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = PublicServiceCatalogListSerializer(queryset, many=True)
        return Response(serializer.data)
