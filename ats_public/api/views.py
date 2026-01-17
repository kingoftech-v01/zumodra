"""
API ViewSets for Public Job Catalog.

Provides read-only public API for browsing job listings.
"""

from django.utils import timezone
from django_filters import rest_framework as filters
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter

from ats_public.models import PublicJobCatalog
from .serializers import PublicJobCatalogSerializer, PublicJobCatalogListSerializer


class PublicJobCatalogFilter(filters.FilterSet):
    """Filters for public job catalog browsing."""

    company = filters.CharFilter(field_name='company_name', lookup_expr='icontains')
    title = filters.CharFilter(field_name='title', lookup_expr='icontains')
    location_city = filters.CharFilter(lookup_expr='icontains')
    location_country = filters.CharFilter(lookup_expr='iexact')
    employment_type = filters.ChoiceFilter(choices=[
        ('full-time', 'Full Time'),
        ('part-time', 'Part Time'),
        ('contract', 'Contract'),
        ('temporary', 'Temporary'),
        ('internship', 'Internship'),
    ])
    is_remote = filters.BooleanFilter()
    is_featured = filters.BooleanFilter()
    category = filters.CharFilter(field_name='category_slugs', lookup_expr='contains')
    salary_min = filters.NumberFilter(field_name='salary_min', lookup_expr='gte')
    salary_max = filters.NumberFilter(field_name='salary_max', lookup_expr='lte')

    class Meta:
        model = PublicJobCatalog
        fields = [
            'company',
            'title',
            'location_city',
            'location_country',
            'employment_type',
            'is_remote',
            'is_featured',
            'category',
            'salary_min',
            'salary_max',
        ]


@extend_schema_view(
    list=extend_schema(
        summary="List public jobs",
        description="Browse public job listings without authentication. Supports filtering, search, and ordering.",
        tags=['Public Job Catalog'],
    ),
    retrieve=extend_schema(
        summary="Get job details",
        description="Get detailed information about a specific public job listing.",
        tags=['Public Job Catalog'],
    ),
)
class PublicJobCatalogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Public job catalog API.

    Read-only endpoints for browsing job listings without authentication.

    Features:
    - List all active jobs with filtering and search
    - Get detailed job information
    - Increment view count on retrieve
    - Featured jobs endpoint
    - Search by keywords
    """

    permission_classes = [AllowAny]
    filterset_class = PublicJobCatalogFilter
    search_fields = ['title', 'company_name', 'description_html', 'location_city', 'location_country']
    ordering_fields = ['posted_at', 'view_count', 'application_count', 'salary_min']
    ordering = ['-is_featured', '-posted_at']

    def get_queryset(self):
        """Get only active, non-expired job listings."""
        return PublicJobCatalog.objects.filter(
            is_active=True
        ).exclude(
            posted_at__gt=timezone.now()  # Exclude future-dated posts
        )

    def get_serializer_class(self):
        """Use lightweight serializer for list, full serializer for detail."""
        if self.action == 'list':
            return PublicJobCatalogListSerializer
        return PublicJobCatalogSerializer

    def retrieve(self, request, *args, **kwargs):
        """Get job details and increment view count."""
        instance = self.get_object()

        # Increment view count asynchronously
        PublicJobCatalog.objects.filter(pk=instance.pk).update(
            view_count=models.F('view_count') + 1
        )

        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    @extend_schema(
        summary="List featured jobs",
        description="Get jobs marked as featured by admins.",
        tags=['Public Job Catalog'],
    )
    @action(detail=False, methods=['get'])
    def featured(self, request):
        """Get featured job listings."""
        queryset = self.get_queryset().filter(is_featured=True)
        queryset = self.filter_queryset(queryset)

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = PublicJobCatalogListSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = PublicJobCatalogListSerializer(queryset, many=True)
        return Response(serializer.data)

    @extend_schema(
        summary="Search jobs by keyword",
        description="Search jobs by keyword in title, description, company name, and location.",
        tags=['Public Job Catalog'],
        parameters=[
            OpenApiParameter('q', str, description='Search query'),
        ],
    )
    @action(detail=False, methods=['get'])
    def search(self, request):
        """Search jobs by keyword."""
        query = request.query_params.get('q', '').strip()

        if not query:
            return Response(
                {'error': 'Query parameter "q" is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        queryset = self.get_queryset().filter(
            models.Q(title__icontains=query) |
            models.Q(company_name__icontains=query) |
            models.Q(description_html__icontains=query) |
            models.Q(location_city__icontains=query) |
            models.Q(location_country__icontains=query) |
            models.Q(category_names__contains=[query])
        )

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = PublicJobCatalogListSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = PublicJobCatalogListSerializer(queryset, many=True)
        return Response(serializer.data)


# Fix import
from django.db import models
