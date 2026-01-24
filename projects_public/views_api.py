"""
Projects Public API Views - Public catalog browsing.

This module provides read-only API views for browsing project opportunities.
No authentication required - public access for cross-tenant browsing.

All views return JSON responses.
API URL namespace: api:v1:public:projects:*
"""

from rest_framework import viewsets, status, filters, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q, Count

from .models import PublicProjectCatalog, PublicProjectStats
from .serializers import (
    PublicProjectCatalogSerializer,
    PublicProjectCatalogListSerializer,
    PublicProjectStatsSerializer
)


# ============================================================================
# PUBLIC PROJECT CATALOG VIEWSET
# ============================================================================

class PublicProjectCatalogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for public project catalog (read-only, no auth required).

    Provides:
    - list: GET /api/v1/public/projects/
    - retrieve: GET /api/v1/public/projects/{uuid}/
    - stats: GET /api/v1/public/projects/stats/
    - search: GET /api/v1/public/projects/search/?q=keyword

    Filtering:
    - ?category_slug=web-development
    - ?experience_level=MID
    - ?budget_type=FIXED
    - ?location_type=REMOTE
    - ?location_country=Canada
    - ?is_open=true
    - ?is_featured=true

    Search:
    - ?search=keyword (searches title, description, skills, company_name)

    Ordering:
    - ?ordering=-published_at (newest first)
    - ?ordering=deadline (soonest deadline)
    - ?ordering=-budget_max (highest budget)
    - ?ordering=budget_min (lowest budget)
    """

    queryset = PublicProjectCatalog.objects.filter(is_open=True)
    permission_classes = [permissions.AllowAny]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = [
        'category_slug',
        'experience_level',
        'budget_type',
        'location_type',
        'location_country',
        'location_city',
        'is_open',
        'is_featured',
        'budget_currency'
    ]
    search_fields = [
        'title',
        'description',
        'required_skills',
        'company_name',
        'category_name'
    ]
    ordering_fields = [
        'published_at',
        'deadline',
        'budget_max',
        'budget_min',
        'proposal_count'
    ]
    ordering = ['-published_at']
    lookup_field = 'uuid'

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == 'list':
            return PublicProjectCatalogListSerializer
        return PublicProjectCatalogSerializer

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """
        Get overall statistics for public projects.

        GET /api/v1/public/projects/stats/

        Returns:
            200: Statistics object with counts by category, country, budget range
        """
        queryset = self.get_queryset()

        # Overall counts
        total_count = queryset.count()
        open_count = queryset.filter(is_open=True).count()
        featured_count = queryset.filter(is_featured=True).count()

        # By category
        by_category = dict(
            queryset.values('category_name')
            .annotate(count=Count('id'))
            .order_by('-count')
            .values_list('category_name', 'count')
        )

        # By country
        by_country = dict(
            queryset.exclude(location_country='')
            .values('location_country')
            .annotate(count=Count('id'))
            .order_by('-count')
            .values_list('location_country', 'count')
        )

        # By budget type
        by_budget_type = dict(
            queryset.values('budget_type')
            .annotate(count=Count('id'))
            .values_list('budget_type', 'count')
        )

        # By experience level
        by_experience = dict(
            queryset.values('experience_level')
            .annotate(count=Count('id'))
            .values_list('experience_level', 'count')
        )

        stats = {
            'total_count': total_count,
            'open_count': open_count,
            'featured_count': featured_count,
            'by_category': by_category,
            'by_country': by_country,
            'by_budget_type': by_budget_type,
            'by_experience_level': by_experience,
        }

        return Response(stats)

    @action(detail=False, methods=['get'])
    def featured(self, request):
        """
        Get featured projects.

        GET /api/v1/public/projects/featured/

        Returns:
            200: List of featured projects
        """
        featured = self.queryset.filter(
            is_featured=True,
            is_open=True
        ).order_by('-published_at')[:10]

        serializer = self.get_serializer(featured, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def recent(self, request):
        """
        Get recently published projects.

        GET /api/v1/public/projects/recent/

        Returns:
            200: List of recently published projects
        """
        recent = self.queryset.filter(
            is_open=True
        ).order_by('-published_at')[:20]

        serializer = self.get_serializer(recent, many=True)
        return Response(serializer.data)


# ============================================================================
# PUBLIC PROJECT STATS VIEWSET
# ============================================================================

class PublicProjectStatsViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for public project statistics (read-only).

    Provides:
    - list: GET /api/v1/public/project-stats/
    - retrieve: GET /api/v1/public/project-stats/{date}/
    - latest: GET /api/v1/public/project-stats/latest/
    """

    queryset = PublicProjectStats.objects.all()
    serializer_class = PublicProjectStatsSerializer
    permission_classes = [permissions.AllowAny]
    ordering = ['-snapshot_date']

    @action(detail=False, methods=['get'])
    def latest(self, request):
        """
        Get latest statistics snapshot.

        GET /api/v1/public/project-stats/latest/

        Returns:
            200: Latest statistics object
        """
        latest = self.queryset.first()
        if not latest:
            return Response(
                {'error': 'No statistics available'},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = self.get_serializer(latest)
        return Response(serializer.data)
