"""
Services API Views

Django REST Framework ViewSets for the services app API.
All ViewSets are tenant-aware and require authentication.

Provides CRUD operations for:
- Service providers
- Services
- Categories, tags, images
- Pricing tiers
- Portfolio items
- Reviews
- Contracts/bookings
"""

from rest_framework import viewsets, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django_filters.rest_framework import DjangoFilterBackend
from django.utils import timezone
from django.db.models import Q, Avg
from django.shortcuts import get_object_or_404

from core.db.mixins import TenantAwareViewSetMixin
from .models import (
    ServiceCategory,
    ServiceTag,
    ServiceImage,
    ProviderSkill,
    ServiceProvider,
    Service,
    ServicePricingTier,
    ProviderPortfolio,
    ServiceReview,
    ServiceContract,
    ContractMessage,
    CrossTenantServiceRequest,
)
from .serializers import (
    ServiceCategorySerializer,
    ServiceTagSerializer,
    ServiceImageSerializer,
    ProviderSkillSerializer,
    ServiceProviderListSerializer,
    ServiceProviderDetailSerializer,
    ServiceProviderUpdateSerializer,
    ServiceListSerializer,
    ServiceDetailSerializer,
    ServiceCreateSerializer,
    ServiceUpdateSerializer,
    ServicePricingTierSerializer,
    ProviderPortfolioSerializer,
    ServiceReviewSerializer,
    ServiceReviewResponseSerializer,
    ServiceContractListSerializer,
    ServiceContractDetailSerializer,
    ServiceContractCreateSerializer,
    ContractMessageSerializer,
    CrossTenantServiceRequestSerializer,
)


# ==================== PERMISSION CLASSES ====================


class IsProviderOwner(IsAuthenticated):
    """
    Permission class: User must be the provider owner.

    Checks if request.user owns the ServiceProvider instance.
    """

    def has_object_permission(self, request, view, obj):
        # For ServiceProvider objects
        if isinstance(obj, ServiceProvider):
            return obj.user == request.user
        # For Service objects
        if isinstance(obj, Service):
            return obj.provider.user == request.user
        # For other provider-related objects
        if hasattr(obj, 'provider'):
            return obj.provider.user == request.user
        return False


class CanManageService(IsAuthenticated):
    """
    Permission class: User must own the service's provider.

    Used for service CRUD operations.
    """

    def has_object_permission(self, request, view, obj):
        if isinstance(obj, Service):
            return obj.provider.user == request.user
        return False


# ==================== CATEGORY & TAG VIEWSETS ====================


class ServiceCategoryViewSet(TenantAwareViewSetMixin, viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for service categories (read-only).

    Categories are managed by admins via Django admin.
    Provides list and retrieve for frontend category browsing.
    """

    queryset = ServiceCategory.objects.all()
    serializer_class = ServiceCategorySerializer
    permission_classes = [AllowAny]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering_fields = ['sort_order', 'name']
    ordering = ['sort_order']

    @action(detail=False, methods=['get'], url_path='tree')
    def tree(self, request):
        """
        Get hierarchical category tree.

        Returns root categories with their subcategories.
        """
        root_categories = self.queryset.filter(parent__isnull=True)
        serializer = self.get_serializer(root_categories, many=True)
        return Response(serializer.data)


class ServiceTagViewSet(TenantAwareViewSetMixin, viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for service tags (read-only).

    Tags are auto-created when services are published.
    Provides list and retrieve for tag filtering.
    """

    queryset = ServiceTag.objects.all()
    serializer_class = ServiceTagSerializer
    permission_classes = [AllowAny]
    filter_backends = [filters.SearchFilter]
    search_fields = ['name']


class ServiceImageViewSet(TenantAwareViewSetMixin, viewsets.ModelViewSet):
    """
    ViewSet for service images.

    Providers can upload/manage images for their services.
    """

    queryset = ServiceImage.objects.all()
    serializer_class = ServiceImageSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['sort_order']
    ordering = ['sort_order']


# ==================== PROVIDER VIEWSETS ====================


class ServiceProviderViewSet(TenantAwareViewSetMixin, viewsets.ModelViewSet):
    """
    ViewSet for service providers.

    Provides CRUD operations for provider profiles.
    Authenticated users can manage their own provider profile.

    Custom actions:
    - me: Get current user's provider profile
    - stats: Get provider statistics
    """

    queryset = ServiceProvider.objects.all()
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = [
        'provider_type', 'is_verified', 'is_featured',
        'availability_status', 'can_work_remotely'
    ]
    search_fields = ['display_name', 'bio', 'tagline', 'city', 'state', 'country']
    ordering_fields = ['rating_avg', 'completed_jobs_count', 'created_at']
    ordering = ['-rating_avg']

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == 'list':
            return ServiceProviderListSerializer
        elif self.action in ['update', 'partial_update']:
            return ServiceProviderUpdateSerializer
        return ServiceProviderDetailSerializer

    def get_queryset(self):
        """Filter queryset based on user permissions."""
        queryset = super().get_queryset()

        # Prefetch related data for performance
        queryset = queryset.select_related('user', 'company').prefetch_related(
            'categories', 'provider_skills__skill', 'portfolio'
        )

        return queryset

    @action(detail=False, methods=['get'], url_path='me')
    def me(self, request):
        """
        Get current user's provider profile.

        Creates provider profile if it doesn't exist.
        """
        provider, created = ServiceProvider.objects.get_or_create(
            user=request.user,
            defaults={'display_name': request.user.get_full_name() or request.user.username}
        )
        serializer = ServiceProviderDetailSerializer(provider, context={'request': request})
        return Response(serializer.data)

    @action(detail=True, methods=['get'], url_path='stats')
    def stats(self, request, pk=None):
        """
        Get provider statistics.

        Returns detailed stats including earnings, reviews breakdown, etc.
        """
        provider = self.get_object()

        # Calculate stats
        stats = {
            'uuid': str(provider.uuid),
            'display_name': provider.display_name,
            'rating_avg': float(provider.rating_avg),
            'total_reviews': provider.total_reviews,
            'completed_jobs_count': provider.completed_jobs_count,
            'total_earnings': float(provider.total_earnings),
            'response_rate': provider.response_rate,
            'avg_response_time_hours': provider.avg_response_time_hours,
            'active_services': provider.services.filter(is_active=True).count(),
            'public_services': provider.services.filter(is_public=True, is_active=True).count(),
            'pending_contracts': provider.provider_contracts.filter(
                status__in=['pending_payment', 'in_progress']
            ).count(),
            'reviews_breakdown': self._get_reviews_breakdown(provider),
        }

        return Response(stats)

    def _get_reviews_breakdown(self, provider):
        """Calculate reviews breakdown by rating."""
        reviews = provider.reviews.all()
        total = reviews.count()

        if total == 0:
            return {'5': 0, '4': 0, '3': 0, '2': 0, '1': 0}

        breakdown = {}
        for rating in range(5, 0, -1):
            count = reviews.filter(rating=rating).count()
            percentage = round((count / total) * 100, 1) if total > 0 else 0
            breakdown[str(rating)] = {
                'count': count,
                'percentage': percentage
            }

        return breakdown


# ==================== SERVICE VIEWSETS ====================


class ServiceViewSet(TenantAwareViewSetMixin, viewsets.ModelViewSet):
    """
    ViewSet for services.

    Provides CRUD operations for services.
    Providers can manage their own services.

    Custom actions:
    - my_services: Get current user's services
    - publish: Publish service to public marketplace
    - unpublish: Remove service from public marketplace
    - duplicate: Create a copy of a service
    """

    queryset = Service.objects.all()
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = [
        'provider', 'category', 'service_type', 'delivery_type',
        'is_active', 'is_featured', 'is_public'
    ]
    search_fields = ['name', 'description', 'short_description']
    ordering_fields = ['created_at', 'price', 'view_count', 'order_count']
    ordering = ['-created_at']
    lookup_field = 'uuid'

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == 'list':
            return ServiceListSerializer
        elif self.action == 'create':
            return ServiceCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return ServiceUpdateSerializer
        return ServiceDetailSerializer

    def get_queryset(self):
        """Filter queryset based on user permissions."""
        queryset = super().get_queryset()

        # Prefetch related data for performance
        queryset = queryset.select_related('provider', 'category').prefetch_related(
            'images', 'tags', 'pricing_tiers'
        )

        # Filter to user's own services for CRUD operations
        if self.action in ['update', 'partial_update', 'destroy']:
            queryset = queryset.filter(provider__user=self.request.user)

        return queryset

    def perform_create(self, serializer):
        """Set provider from current user when creating service."""
        # Get or create provider for current user
        provider, _ = ServiceProvider.objects.get_or_create(
            user=self.request.user,
            defaults={'display_name': self.request.user.get_full_name() or self.request.user.username}
        )
        serializer.save(provider=provider)

    @action(detail=False, methods=['get'], url_path='my-services')
    def my_services(self, request):
        """
        Get current user's services.

        Returns all services owned by the authenticated user.
        """
        provider = get_object_or_404(ServiceProvider, user=request.user)
        services = self.queryset.filter(provider=provider)

        # Apply filters
        queryset = self.filter_queryset(services)

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = ServiceListSerializer(page, many=True, context={'request': request})
            return self.get_paginated_response(serializer.data)

        serializer = ServiceListSerializer(queryset, many=True, context={'request': request})
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='publish')
    def publish(self, request, uuid=None):
        """
        Publish service to public marketplace.

        Sets is_public=True, triggering sync to public catalog.
        """
        service = self.get_object()

        # Check ownership
        if service.provider.user != request.user:
            return Response(
                {'error': 'You do not have permission to publish this service.'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Check if service has required fields
        if not service.name or not service.description:
            return Response(
                {'error': 'Service must have name and description to be published.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Publish
        service.is_public = True
        service.save(update_fields=['is_public'])

        return Response({
            'message': 'Service published to public marketplace.',
            'service_uuid': str(service.uuid),
            'is_public': True
        })

    @action(detail=True, methods=['post'], url_path='unpublish')
    def unpublish(self, request, uuid=None):
        """
        Remove service from public marketplace.

        Sets is_public=False, triggering removal from public catalog.
        """
        service = self.get_object()

        # Check ownership
        if service.provider.user != request.user:
            return Response(
                {'error': 'You do not have permission to unpublish this service.'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Unpublish
        service.is_public = False
        service.published_to_catalog = False
        service.save(update_fields=['is_public', 'published_to_catalog'])

        return Response({
            'message': 'Service removed from public marketplace.',
            'service_uuid': str(service.uuid),
            'is_public': False
        })

    @action(detail=True, methods=['post'], url_path='duplicate')
    def duplicate(self, request, uuid=None):
        """
        Create a duplicate of a service.

        Copies service with new UUID, appends "(Copy)" to name.
        """
        original_service = self.get_object()

        # Check ownership
        if original_service.provider.user != request.user:
            return Response(
                {'error': 'You do not have permission to duplicate this service.'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Duplicate service
        duplicated_service = Service.objects.create(
            provider=original_service.provider,
            category=original_service.category,
            name=f"{original_service.name} (Copy)",
            description=original_service.description,
            short_description=original_service.short_description,
            service_type=original_service.service_type,
            price=original_service.price,
            price_min=original_service.price_min,
            price_max=original_service.price_max,
            currency=original_service.currency,
            delivery_type=original_service.delivery_type,
            duration_days=original_service.duration_days,
            revisions_included=original_service.revisions_included,
            video_url=original_service.video_url,
            is_active=False,  # Start as inactive
            is_public=False,  # Don't publish copy automatically
        )

        # Copy tags and images (many-to-many)
        duplicated_service.tags.set(original_service.tags.all())
        duplicated_service.images.set(original_service.images.all())

        # Copy pricing tiers
        for tier in original_service.pricing_tiers.all():
            ServicePricingTier.objects.create(
                service=duplicated_service,
                name=tier.name,
                price=tier.price,
                delivery_time_days=tier.delivery_time_days,
                revisions=tier.revisions,
                features=tier.features,
                sort_order=tier.sort_order,
                is_recommended=tier.is_recommended,
            )

        serializer = ServiceDetailSerializer(duplicated_service, context={'request': request})
        return Response(serializer.data, status=status.HTTP_201_CREATED)


# ==================== PRICING TIER & PORTFOLIO VIEWSETS ====================


class ServicePricingTierViewSet(TenantAwareViewSetMixin, viewsets.ModelViewSet):
    """
    ViewSet for service pricing tiers.

    Providers can create/manage pricing packages for their services.
    """

    queryset = ServicePricingTier.objects.all()
    serializer_class = ServicePricingTierSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['service', 'is_recommended']
    ordering_fields = ['sort_order', 'price']
    ordering = ['sort_order']

    def get_queryset(self):
        """Filter to user's own pricing tiers."""
        queryset = super().get_queryset()
        return queryset.filter(service__provider__user=self.request.user)

    def perform_create(self, serializer):
        """Validate user owns the service."""
        service = serializer.validated_data.get('service')
        if service.provider.user != self.request.user:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("You do not have permission to add pricing tiers to this service.")
        serializer.save()


class ProviderPortfolioViewSet(TenantAwareViewSetMixin, viewsets.ModelViewSet):
    """
    ViewSet for provider portfolio items.

    Providers can upload/manage portfolio images.
    """

    queryset = ProviderPortfolio.objects.all()
    serializer_class = ProviderPortfolioSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['sort_order', 'created_at']
    ordering = ['sort_order']

    def get_queryset(self):
        """Filter to user's own portfolio items."""
        queryset = super().get_queryset()
        return queryset.filter(provider__user=self.request.user)

    def perform_create(self, serializer):
        """Set provider from current user."""
        provider = get_object_or_404(ServiceProvider, user=self.request.user)
        serializer.save(provider=provider)


# ==================== REVIEW VIEWSETS ====================


class ServiceReviewViewSet(TenantAwareViewSetMixin, viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for service reviews (read-only for most users).

    Providers can respond to reviews via custom action.
    """

    queryset = ServiceReview.objects.all()
    serializer_class = ServiceReviewSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['provider', 'rating']
    ordering_fields = ['created_at', 'rating']
    ordering = ['-created_at']

    def get_queryset(self):
        """Prefetch related data for performance."""
        queryset = super().get_queryset()
        return queryset.select_related('provider', 'reviewer', 'contract')

    @action(detail=True, methods=['post'], url_path='respond')
    def respond(self, request, pk=None):
        """
        Provider responds to a review.

        Only the provider being reviewed can respond.
        """
        review = self.get_object()

        # Check if user is the provider
        if review.provider.user != request.user:
            return Response(
                {'error': 'You can only respond to reviews of your own services.'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate response
        serializer = ServiceReviewResponseSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Save response
        review.provider_response = serializer.validated_data['provider_response']
        review.provider_responded_at = timezone.now()
        review.save(update_fields=['provider_response', 'provider_responded_at'])

        return Response({
            'message': 'Response posted successfully.',
            'review_id': review.id,
            'provider_response': review.provider_response,
            'provider_responded_at': review.provider_responded_at
        })


# ==================== CONTRACT/BOOKING VIEWSETS ====================


class ServiceContractViewSet(TenantAwareViewSetMixin, viewsets.ModelViewSet):
    """
    ViewSet for service contracts/bookings.

    Clients can create bookings, providers can manage contracts.

    Custom actions:
    - my_contracts: Get user's contracts (as client or provider)
    - deliver: Provider marks contract as delivered
    - complete: Client marks contract as complete
    - request_revision: Client requests revision
    """

    queryset = ServiceContract.objects.all()
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['status', 'rate_type']
    ordering_fields = ['created_at', 'agreed_deadline', 'agreed_rate']
    ordering = ['-created_at']
    lookup_field = 'uuid'

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == 'list':
            return ServiceContractListSerializer
        elif self.action == 'create':
            return ServiceContractCreateSerializer
        return ServiceContractDetailSerializer

    def get_queryset(self):
        """Filter to contracts where user is client or provider."""
        queryset = super().get_queryset()

        # User must be client or provider
        queryset = queryset.filter(
            Q(client=self.request.user) | Q(provider__user=self.request.user)
        )

        # Prefetch related data
        queryset = queryset.select_related(
            'client', 'provider', 'service', 'escrow_transaction'
        )

        return queryset

    def perform_create(self, serializer):
        """Set client and provider when creating contract."""
        service = serializer.validated_data.get('service')
        serializer.save(
            client=self.request.user,
            provider=service.provider
        )

    @action(detail=False, methods=['get'], url_path='my-contracts')
    def my_contracts(self, request):
        """
        Get user's contracts.

        Returns contracts where user is client OR provider.
        """
        contracts = self.get_queryset()

        # Apply filters
        queryset = self.filter_queryset(contracts)

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = ServiceContractListSerializer(page, many=True, context={'request': request})
            return self.get_paginated_response(serializer.data)

        serializer = ServiceContractListSerializer(queryset, many=True, context={'request': request})
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='deliver')
    def deliver(self, request, uuid=None):
        """
        Provider marks contract as delivered.

        Changes status from IN_PROGRESS to DELIVERED.
        """
        contract = self.get_object()

        # Check if user is the provider
        if contract.provider.user != request.user:
            return Response(
                {'error': 'Only the provider can mark contract as delivered.'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Check status
        if contract.status != ServiceContract.ContractStatus.IN_PROGRESS:
            return Response(
                {'error': f'Cannot deliver contract with status: {contract.status}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Mark as delivered
        contract.deliver()

        return Response({
            'message': 'Contract marked as delivered.',
            'contract_uuid': str(contract.uuid),
            'status': contract.status
        })

    @action(detail=True, methods=['post'], url_path='complete')
    def complete(self, request, uuid=None):
        """
        Client marks contract as complete.

        Changes status from DELIVERED to COMPLETED, releases escrow.
        """
        contract = self.get_object()

        # Check if user is the client
        if contract.client != request.user:
            return Response(
                {'error': 'Only the client can mark contract as complete.'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Check status
        if contract.status != ServiceContract.ContractStatus.DELIVERED:
            return Response(
                {'error': f'Cannot complete contract with status: {contract.status}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Mark as complete
        contract.complete()

        return Response({
            'message': 'Contract marked as complete. Escrow funds released.',
            'contract_uuid': str(contract.uuid),
            'status': contract.status
        })

    @action(detail=True, methods=['post'], url_path='request-revision')
    def request_revision(self, request, uuid=None):
        """
        Client requests revision.

        Changes status from DELIVERED to REVISION_REQUESTED.
        """
        contract = self.get_object()

        # Check if user is the client
        if contract.client != request.user:
            return Response(
                {'error': 'Only the client can request revisions.'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Check status
        if contract.status != ServiceContract.ContractStatus.DELIVERED:
            return Response(
                {'error': f'Cannot request revision for contract with status: {contract.status}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check revisions limit
        if contract.revisions_used >= contract.revisions_allowed:
            return Response(
                {'error': 'Revision limit reached.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Request revision
        contract.status = ServiceContract.ContractStatus.REVISION_REQUESTED
        contract.revisions_used += 1
        contract.save(update_fields=['status', 'revisions_used'])

        return Response({
            'message': 'Revision requested.',
            'contract_uuid': str(contract.uuid),
            'status': contract.status,
            'revisions_used': contract.revisions_used,
            'revisions_allowed': contract.revisions_allowed
        })


class ContractMessageViewSet(TenantAwareViewSetMixin, viewsets.ModelViewSet):
    """
    ViewSet for contract messages.

    Clients and providers can exchange messages within a contract.
    """

    queryset = ContractMessage.objects.all()
    serializer_class = ContractMessageSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.OrderingFilter]
    ordering = ['created_at']

    def get_queryset(self):
        """Filter to messages for user's contracts."""
        queryset = super().get_queryset()
        return queryset.filter(
            Q(contract__client=self.request.user) |
            Q(contract__provider__user=self.request.user)
        ).select_related('sender', 'contract')

    def perform_create(self, serializer):
        """Set sender from current user."""
        serializer.save(sender=self.request.user)


# ==================== CROSS-TENANT REQUEST VIEWSETS ====================


class CrossTenantServiceRequestViewSet(TenantAwareViewSetMixin, viewsets.ModelViewSet):
    """
    ViewSet for cross-tenant service requests.

    Allows users to request services from other tenants.
    """

    queryset = CrossTenantServiceRequest.objects.all()
    serializer_class = CrossTenantServiceRequestSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['status', 'hiring_context']
    ordering = ['-created_at']
    lookup_field = 'uuid'

    def get_queryset(self):
        """Filter to user's own requests."""
        queryset = super().get_queryset()
        return queryset.filter(client=self.request.user)

    def perform_create(self, serializer):
        """Set client from current user."""
        serializer.save(client=self.request.user)

        # Send notification to provider (async task)
        instance = serializer.instance
        instance.notify_provider_tenant()
