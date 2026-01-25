"""
Services Public API Views

Django REST Framework ViewSets for the public service catalog API.
All ViewSets are read-only (no create/update/delete) since the public catalog
is managed via sync from tenant schemas.
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
from django.contrib.gis.geos import Point
from django.contrib.gis.measure import D
from django.db.models import Count, Q

from .models import (
    PublicService,
    PublicServiceImage,
    PublicServicePricingTier,
    PublicServicePortfolio,
    PublicServiceReview
)
from .serializers import (
    PublicServiceListSerializer,
    PublicServiceDetailSerializer,
    PublicServiceGeoSerializer,
    PublicServiceSearchSerializer,
    PublicServiceImageSerializer,
    PublicServicePricingTierSerializer,
    PublicServicePortfolioSerializer,
    PublicServiceReviewSerializer,
)
from .filters import PublicServiceFilter


class PublicServiceViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Public Service Catalog API ViewSet.

    Provides read-only access to the public service catalog.

    List endpoint: GET /api/services/
    Detail endpoint: GET /api/services/{uuid}/
    Search endpoint: GET /api/services/search/?q=query
    Nearby endpoint: GET /api/services/nearby/?lat=X&lng=Y&radius=50
    Featured endpoint: GET /api/services/featured/
    Categories endpoint: GET /api/services/categories/
    Similar endpoint: GET /api/services/{uuid}/similar/
    """

    queryset = PublicService.objects.filter(is_active=True)
    permission_classes = [AllowAny]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = PublicServiceFilter
    search_fields = ['name', 'description', 'short_description', 'provider_name', 'tags_list']
    ordering_fields = ['rating_avg', 'price', 'published_at', 'view_count', 'total_reviews']
    ordering = ['-is_featured', '-rating_avg']
    lookup_field = 'service_uuid'
    lookup_url_kwarg = 'service_uuid'

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == 'retrieve':
            return PublicServiceDetailSerializer
        elif self.action == 'search':
            return PublicServiceSearchSerializer
        elif self.action == 'nearby':
            return PublicServiceGeoSerializer
        return PublicServiceListSerializer

    def get_queryset(self):
        """Optimize queryset based on action."""
        queryset = super().get_queryset()

        if self.action == 'retrieve':
            # Prefetch related data for detail view
            queryset = queryset.prefetch_related(
                'images',
                'pricing_tiers',
                'portfolio_images',
                'reviews'
            )
        elif self.action == 'list':
            # Minimal fields for list view
            queryset = queryset.only(
                'service_uuid', 'name', 'slug', 'short_description',
                'provider_name', 'provider_avatar_url', 'provider_is_verified',
                'category_name', 'category_slug', 'thumbnail_url',
                'price', 'currency', 'service_type', 'rating_avg', 'total_reviews',
                'is_featured', 'is_accepting_work',
                'location_city', 'location_state', 'location_country', 'detail_url'
            )

        return queryset

    @action(detail=False, methods=['get'], url_path='search')
    def search(self, request):
        """
        Full-text search endpoint.

        Query Parameters:
            q: Search query string (required)
            limit: Maximum results (default: 20)

        Example:
            GET /api/services/search/?q=web+design&limit=10
        """
        query = request.query_params.get('q', '').strip()
        if not query:
            return Response(
                {'error': 'Query parameter "q" is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        limit = int(request.query_params.get('limit', 20))

        queryset = self.filter_queryset(self.get_queryset())
        queryset = queryset[:limit]

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'], url_path='nearby')
    def nearby(self, request):
        """
        Geographic search endpoint.

        Find services within a radius of a given location.

        Query Parameters:
            lat: Latitude (required)
            lng: Longitude (required)
            radius: Search radius in km (default: 50)
            limit: Maximum results (default: 200)

        Example:
            GET /api/services/nearby/?lat=45.5017&lng=-73.5673&radius=50
        """
        lat = request.query_params.get('lat')
        lng = request.query_params.get('lng')

        if not lat or not lng:
            return Response(
                {'error': 'Parameters "lat" and "lng" are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            lat = float(lat)
            lng = float(lng)
            radius_km = int(request.query_params.get('radius', 50))
            limit = int(request.query_params.get('limit', 200))
        except (ValueError, TypeError):
            return Response(
                {'error': 'Invalid parameter values'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user_location = Point(lng, lat, srid=4326)

        queryset = self.get_queryset().filter(
            location__distance_lte=(user_location, D(km=radius_km)),
            location__isnull=False
        ).order_by(
            '-is_featured',
            '-rating_avg'
        )[:limit]

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'], url_path='featured')
    def featured(self, request):
        """
        Get featured services.

        Query Parameters:
            limit: Maximum results (default: 10)

        Example:
            GET /api/services/featured/?limit=5
        """
        limit = int(request.query_params.get('limit', 10))

        queryset = self.get_queryset().filter(
            is_featured=True
        ).order_by('-rating_avg', '-total_reviews')[:limit]

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'], url_path='categories')
    def categories(self, request):
        """
        Get all service categories with counts.

        Example:
            GET /api/services/categories/

        Returns:
            [
                {"category_name": "Design", "category_slug": "design", "count": 25},
                {"category_name": "Development", "category_slug": "development", "count": 30},
                ...
            ]
        """
        categories = (
            self.get_queryset()
            .values('category_name', 'category_slug')
            .annotate(count=Count('id'))
            .order_by('category_name')
        )

        return Response(list(categories))

    @action(detail=True, methods=['get'], url_path='similar')
    def similar(self, request, service_uuid=None):
        """
        Get similar services.

        Finds services in the same category with similar price range.

        Query Parameters:
            limit: Maximum results (default: 4)

        Example:
            GET /api/services/{uuid}/similar/?limit=6
        """
        service = self.get_object()
        limit = int(request.query_params.get('limit', 4))

        # Find similar services: same category, similar price range
        queryset = self.get_queryset().exclude(
            service_uuid=service.service_uuid
        )

        if service.category_slug:
            queryset = queryset.filter(category_slug=service.category_slug)

        if service.price:
            from decimal import Decimal
            min_price = service.price * Decimal('0.5')
            max_price = service.price * Decimal('1.5')
            queryset = queryset.filter(
                price__gte=min_price,
                price__lte=max_price
            )

        queryset = queryset.order_by('-rating_avg', '-total_reviews')[:limit]

        serializer = PublicServiceListSerializer(queryset, many=True)
        return Response(serializer.data)


class PublicServiceImageViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Public Service Images API ViewSet.

    Read-only access to service gallery images.
    """

    queryset = PublicServiceImage.objects.all()
    serializer_class = PublicServiceImageSerializer
    permission_classes = [AllowAny]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['service']


class PublicServicePricingTierViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Public Service Pricing Tiers API ViewSet.

    Read-only access to service pricing packages.
    """

    queryset = PublicServicePricingTier.objects.all()
    serializer_class = PublicServicePricingTierSerializer
    permission_classes = [AllowAny]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['service', 'is_recommended']
    ordering_fields = ['sort_order', 'price']
    ordering = ['sort_order']


class PublicServicePortfolioViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Public Service Portfolio API ViewSet.

    Read-only access to provider portfolio items.
    """

    queryset = PublicServicePortfolio.objects.all()
    serializer_class = PublicServicePortfolioSerializer
    permission_classes = [AllowAny]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['service']
    ordering_fields = ['sort_order']
    ordering = ['sort_order']


class PublicServiceReviewViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Public Service Reviews API ViewSet.

    Read-only access to service reviews.
    """

    queryset = PublicServiceReview.objects.all().order_by('-created_at')
    serializer_class = PublicServiceReviewSerializer
    permission_classes = [AllowAny]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['service', 'rating', 'reviewer_is_verified']
    ordering_fields = ['created_at', 'rating', 'helpful_count']
    ordering = ['-created_at']
