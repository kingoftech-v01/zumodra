"""
Services API ViewSets - Zumodra Freelance Marketplace.

Provides ViewSets for:
- Service categories and taxonomy
- Provider profiles and management
- Services CRUD
- Client requests and matching
- Proposals and contracts
- Reviews and messaging
- Marketplace analytics
"""

import hashlib
from decimal import Decimal

from django.db.models import Q, Avg, Count, Sum
from django.utils import timezone
from rest_framework import viewsets, permissions, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django_filters import rest_framework as django_filters

from core.cache import TenantCache, RATING_CACHE_TIMEOUT
from core.viewsets import SecureTenantViewSet, SecureReadOnlyViewSet
from accounts.permissions import (
    IsTenantUser,
    IsOwnerOrReadOnly,
    HasKYCVerification,
)

from ..models import (
    ServiceCategory,
    ServiceTag,
    ServiceImage,
    ProviderSkill,
    ServiceProvider,
    Service,
    ServiceLike,
    ClientRequest,
    ProviderMatch,
    ServiceProposal,
    ServiceContract,
    ServiceReview,
    ContractMessage,
)
from ..serializers import (
    ServiceCategorySerializer,
    ServiceCategoryListSerializer,
    ServiceTagSerializer,
    ServiceImageSerializer,
    ProviderSkillSerializer,
    ServiceProviderListSerializer,
    ServiceProviderDetailSerializer,
    ServiceProviderCreateSerializer,
    ServiceListSerializer,
    ServiceDetailSerializer,
    ServiceCreateSerializer,
    ServiceLikeSerializer,
    ClientRequestListSerializer,
    ClientRequestDetailSerializer,
    ClientRequestCreateSerializer,
    ProviderMatchSerializer,
    ServiceProposalListSerializer,
    ServiceProposalDetailSerializer,
    ServiceProposalCreateSerializer,
    ServiceContractListSerializer,
    ServiceContractDetailSerializer,
    ServiceContractCreateSerializer,
    ContractActionSerializer,
    ServiceReviewListSerializer,
    ServiceReviewDetailSerializer,
    ServiceReviewCreateSerializer,
    ReviewResponseSerializer,
    ContractMessageSerializer,
    ContractMessageCreateSerializer,
    ProviderStatsSerializer,
    MarketplaceStatsSerializer,
)


# =============================================================================
# FILTERS
# =============================================================================

class ServiceFilter(django_filters.FilterSet):
    """Filter for services."""
    min_price = django_filters.NumberFilter(field_name='price', lookup_expr='gte')
    max_price = django_filters.NumberFilter(field_name='price', lookup_expr='lte')
    category = django_filters.NumberFilter(field_name='category_id')
    provider = django_filters.NumberFilter(field_name='provider_id')
    service_type = django_filters.CharFilter()
    delivery_type = django_filters.CharFilter()
    is_featured = django_filters.BooleanFilter()

    class Meta:
        model = Service
        fields = ['category', 'provider', 'service_type', 'delivery_type', 'is_featured']


class ProviderFilter(django_filters.FilterSet):
    """Filter for providers."""
    category = django_filters.NumberFilter(field_name='categories')
    min_rate = django_filters.NumberFilter(field_name='hourly_rate', lookup_expr='gte')
    max_rate = django_filters.NumberFilter(field_name='hourly_rate', lookup_expr='lte')
    city = django_filters.CharFilter(lookup_expr='icontains')
    country = django_filters.CharFilter()
    availability_status = django_filters.CharFilter()
    is_verified = django_filters.BooleanFilter()
    is_featured = django_filters.BooleanFilter()
    provider_type = django_filters.CharFilter()

    class Meta:
        model = ServiceProvider
        fields = [
            'category', 'city', 'country', 'availability_status',
            'is_verified', 'is_featured', 'provider_type'
        ]


class ClientRequestFilter(django_filters.FilterSet):
    """Filter for client requests."""
    category = django_filters.NumberFilter(field_name='category_id')
    min_budget = django_filters.NumberFilter(field_name='budget_min', lookup_expr='gte')
    max_budget = django_filters.NumberFilter(field_name='budget_max', lookup_expr='lte')
    status = django_filters.CharFilter()
    remote_allowed = django_filters.BooleanFilter()

    class Meta:
        model = ClientRequest
        fields = ['category', 'status', 'remote_allowed']


class ContractFilter(django_filters.FilterSet):
    """Filter for contracts."""
    status = django_filters.CharFilter()
    client = django_filters.NumberFilter(field_name='client_id')
    provider = django_filters.NumberFilter(field_name='provider_id')
    date_from = django_filters.DateFilter(field_name='created_at', lookup_expr='date__gte')
    date_to = django_filters.DateFilter(field_name='created_at', lookup_expr='date__lte')

    class Meta:
        model = ServiceContract
        fields = ['status', 'client', 'provider']


# =============================================================================
# CATEGORY VIEWSETS
# =============================================================================

class ServiceCategoryViewSet(SecureReadOnlyViewSet):
    """
    ViewSet for service categories (read-only for users, admin can modify).

    Caching:
    - Category list cached for 10 minutes
    - Cache invalidated on category create/update/delete
    """
    queryset = ServiceCategory.objects.all()
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'sort_order']
    ordering = ['sort_order', 'name']

    def get_serializer_class(self):
        if self.action == 'list':
            return ServiceCategoryListSerializer
        return ServiceCategorySerializer

    def get_queryset(self):
        qs = super().get_queryset()
        # Option to get only root categories
        if self.request.query_params.get('root_only') == 'true':
            qs = qs.filter(parent__isnull=True)
        return qs

    def list(self, request, *args, **kwargs):
        """List categories with caching."""
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        root_only = request.query_params.get('root_only', 'false')
        cache_key = f"service_categories:list:root_{root_only}"

        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        response = super().list(request, *args, **kwargs)

        # Cache the response data
        tenant_cache.set(cache_key, response.data, timeout=600)

        return response


class ServiceTagViewSet(SecureReadOnlyViewSet):
    """ViewSet for service tags."""
    queryset = ServiceTag.objects.all()
    serializer_class = ServiceTagSerializer
    search_fields = ['name']
    ordering = ['name']


# =============================================================================
# PROVIDER VIEWSETS
# =============================================================================

class ServiceProviderViewSet(SecureTenantViewSet):
    """
    ViewSet for service provider profiles.
    """
    queryset = ServiceProvider.objects.select_related('user', 'company').prefetch_related('categories')
    filterset_class = ProviderFilter
    search_fields = ['display_name', 'bio', 'tagline', 'city']
    ordering_fields = ['rating_avg', 'completed_jobs_count', 'hourly_rate', 'created_at']
    ordering = ['-rating_avg', '-completed_jobs_count']

    def get_serializer_class(self):
        if self.action == 'list':
            return ServiceProviderListSerializer
        if self.action == 'create':
            return ServiceProviderCreateSerializer
        return ServiceProviderDetailSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        # Hide private profiles unless owner or admin
        if not self.request.user.is_staff:
            qs = qs.filter(Q(is_private=False) | Q(user=self.request.user))
        return qs

    @action(detail=False, methods=['get'])
    def me(self, request):
        """Get current user's provider profile."""
        try:
            provider = ServiceProvider.objects.get(user=request.user)
            serializer = ServiceProviderDetailSerializer(provider)
            return Response(serializer.data)
        except ServiceProvider.DoesNotExist:
            return Response(
                {'error': 'No provider profile found'},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=True, methods=['get'])
    def stats(self, request, pk=None):
        """Get provider statistics with caching."""
        provider = self.get_object()

        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        cache_key = f"provider:{provider.id}:stats"
        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        stats = {
            'total_services': provider.services.count(),
            'active_services': provider.services.filter(is_active=True).count(),
            'total_contracts': provider.provider_contracts.count(),
            'completed_contracts': provider.provider_contracts.filter(status='completed').count(),
            'total_earnings': provider.total_earnings,
            'average_rating': provider.rating_avg,
            'total_reviews': provider.total_reviews,
            'response_rate': provider.response_rate,
        }
        serializer = ProviderStatsSerializer(stats)

        # Cache for 10 minutes
        tenant_cache.set(cache_key, serializer.data, timeout=600)

        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def services(self, request, pk=None):
        """List services offered by this provider."""
        provider = self.get_object()
        services = provider.services.filter(is_active=True)
        serializer = ServiceListSerializer(services, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def reviews(self, request, pk=None):
        """List reviews for this provider."""
        provider = self.get_object()
        reviews = provider.reviews.all()
        serializer = ServiceReviewListSerializer(reviews, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def update_availability(self, request, pk=None):
        """Update provider availability status."""
        provider = self.get_object()
        if provider.user != request.user and not request.user.is_staff:
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )
        new_status = request.data.get('availability_status')
        if new_status not in dict(ServiceProvider.AvailabilityStatus.choices):
            return Response(
                {'error': 'Invalid status'},
                status=status.HTTP_400_BAD_REQUEST
            )
        provider.availability_status = new_status
        provider.save(update_fields=['availability_status'])
        return Response({'status': 'updated', 'availability_status': new_status})


# =============================================================================
# SERVICE VIEWSETS
# =============================================================================

class ServiceViewSet(SecureTenantViewSet):
    """
    ViewSet for services.
    """
    queryset = Service.objects.select_related('provider', 'category').prefetch_related('tags')
    filterset_class = ServiceFilter
    search_fields = ['name', 'description', 'short_description']
    ordering_fields = ['price', 'view_count', 'order_count', 'created_at']
    ordering = ['-is_featured', '-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return ServiceListSerializer
        if self.action == 'create':
            return ServiceCreateSerializer
        return ServiceDetailSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.action == 'list':
            qs = qs.filter(is_active=True)
        return qs

    def retrieve(self, request, *args, **kwargs):
        """Increment view count on retrieve."""
        instance = self.get_object()
        instance.view_count += 1
        instance.save(update_fields=['view_count'])
        return super().retrieve(request, *args, **kwargs)

    @action(detail=True, methods=['post'])
    def like(self, request, pk=None):
        """Like/unlike a service."""
        service = self.get_object()
        like, created = ServiceLike.objects.get_or_create(
            user=request.user,
            service=service,
            defaults={'tenant': request.tenant}
        )
        if not created:
            like.delete()
            return Response({'status': 'unliked'})
        return Response({'status': 'liked'}, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['get'])
    def featured(self, request):
        """Get featured services with caching."""
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        cache_key = "services:featured"
        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        services = self.get_queryset().filter(is_featured=True, is_active=True)[:12]
        serializer = ServiceListSerializer(services, many=True)

        # Cache for 5 minutes
        tenant_cache.set(cache_key, serializer.data, timeout=300)

        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def popular(self, request):
        """Get popular services by order count with caching."""
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        cache_key = "services:popular"
        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        services = self.get_queryset().filter(is_active=True).order_by('-order_count')[:12]
        serializer = ServiceListSerializer(services, many=True)

        # Cache for 5 minutes
        tenant_cache.set(cache_key, serializer.data, timeout=300)

        return Response(serializer.data)


# =============================================================================
# CLIENT REQUEST VIEWSETS
# =============================================================================

class ClientRequestViewSet(SecureTenantViewSet):
    """
    ViewSet for client service requests.
    """
    queryset = ClientRequest.objects.select_related('client', 'category')
    filterset_class = ClientRequestFilter
    search_fields = ['title', 'description']
    ordering_fields = ['budget_max', 'deadline', 'created_at']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return ClientRequestListSerializer
        if self.action == 'create':
            return ClientRequestCreateSerializer
        return ClientRequestDetailSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        # Providers can see open requests, clients see their own
        if self.request.query_params.get('mine') == 'true':
            qs = qs.filter(client=self.request.user)
        elif self.action == 'list':
            # Show open requests to providers
            qs = qs.filter(status='open')
        return qs

    @action(detail=True, methods=['get'])
    def proposals(self, request, pk=None):
        """List proposals for this request."""
        client_request = self.get_object()
        if client_request.client != request.user and not request.user.is_staff:
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )
        proposals = client_request.proposals.all()
        serializer = ServiceProposalListSerializer(proposals, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def matches(self, request, pk=None):
        """List provider matches for this request."""
        client_request = self.get_object()
        if client_request.client != request.user and not request.user.is_staff:
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )
        matches = client_request.matches.select_related('provider')
        serializer = ProviderMatchSerializer(matches, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def close(self, request, pk=None):
        """Close a client request."""
        client_request = self.get_object()
        if client_request.client != request.user:
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )
        client_request.status = 'closed'
        client_request.save(update_fields=['status'])
        return Response({'status': 'closed'})


# =============================================================================
# PROPOSAL VIEWSETS
# =============================================================================

class ServiceProposalViewSet(SecureTenantViewSet):
    """
    ViewSet for service proposals.
    """
    queryset = ServiceProposal.objects.select_related(
        'client_request', 'provider'
    )
    search_fields = ['cover_letter']
    ordering_fields = ['proposed_rate', 'created_at']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return ServiceProposalListSerializer
        if self.action == 'create':
            return ServiceProposalCreateSerializer
        return ServiceProposalDetailSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        # Providers see their proposals, clients see proposals on their requests
        user = self.request.user
        try:
            provider = user.service_provider
            qs = qs.filter(
                Q(provider=provider) |
                Q(client_request__client=user)
            )
        except ServiceProvider.DoesNotExist:
            qs = qs.filter(client_request__client=user)
        return qs

    @action(detail=True, methods=['post'])
    def accept(self, request, pk=None):
        """Accept a proposal (client only)."""
        proposal = self.get_object()
        if proposal.client_request.client != request.user:
            return Response(
                {'error': 'Only the client can accept proposals'},
                status=status.HTTP_403_FORBIDDEN
            )
        if proposal.status != 'pending':
            return Response(
                {'error': 'Proposal is not pending'},
                status=status.HTTP_400_BAD_REQUEST
            )
        proposal.status = 'accepted'
        proposal.save(update_fields=['status'])
        # Close the request
        proposal.client_request.status = 'in_progress'
        proposal.client_request.save(update_fields=['status'])
        return Response({'status': 'accepted'})

    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """Reject a proposal (client only)."""
        proposal = self.get_object()
        if proposal.client_request.client != request.user:
            return Response(
                {'error': 'Only the client can reject proposals'},
                status=status.HTTP_403_FORBIDDEN
            )
        proposal.status = 'rejected'
        proposal.save(update_fields=['status'])
        return Response({'status': 'rejected'})

    @action(detail=True, methods=['post'])
    def withdraw(self, request, pk=None):
        """Withdraw a proposal (provider only)."""
        proposal = self.get_object()
        if proposal.provider.user != request.user:
            return Response(
                {'error': 'Only the provider can withdraw proposals'},
                status=status.HTTP_403_FORBIDDEN
            )
        proposal.status = 'withdrawn'
        proposal.save(update_fields=['status'])
        return Response({'status': 'withdrawn'})


# =============================================================================
# CONTRACT VIEWSETS
# =============================================================================

class ServiceContractViewSet(SecureTenantViewSet):
    """
    ViewSet for service contracts with escrow integration.
    """
    queryset = ServiceContract.objects.select_related('client', 'provider', 'service')
    filterset_class = ContractFilter
    search_fields = ['title', 'description']
    ordering_fields = ['agreed_rate', 'created_at', 'completed_at']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return ServiceContractListSerializer
        if self.action == 'create':
            return ServiceContractCreateSerializer
        return ServiceContractDetailSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        user = self.request.user
        # Users see contracts where they are client or provider
        try:
            provider = user.service_provider
            qs = qs.filter(Q(client=user) | Q(provider=provider))
        except ServiceProvider.DoesNotExist:
            qs = qs.filter(client=user)
        return qs

    @action(detail=True, methods=['post'], url_path='perform-action')
    def perform_action(self, request, pk=None):
        """Perform contract actions (start, deliver, complete, cancel)."""
        contract = self.get_object()
        serializer = ContractActionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        action_type = serializer.validated_data['action']
        reason = serializer.validated_data.get('reason', '')

        user = request.user
        is_client = contract.client == user
        is_provider = hasattr(user, 'service_provider') and contract.provider == user.service_provider

        if action_type == 'start' and is_provider:
            contract.start()
        elif action_type == 'deliver' and is_provider:
            contract.deliver()
        elif action_type == 'complete' and is_client:
            contract.complete()
        elif action_type == 'cancel':
            if is_client or is_provider:
                contract.cancel(reason)
            else:
                return Response(
                    {'error': 'Permission denied'},
                    status=status.HTTP_403_FORBIDDEN
                )
        elif action_type == 'request_revision' and is_client:
            if contract.revisions_used >= contract.revisions_allowed:
                return Response(
                    {'error': 'No revisions remaining'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            contract.status = 'revision_requested'
            contract.revisions_used += 1
            contract.save(update_fields=['status', 'revisions_used'])
        else:
            return Response(
                {'error': 'Invalid action or permission denied'},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response({'status': contract.status})

    @action(detail=True, methods=['get'])
    def messages(self, request, pk=None):
        """List messages in this contract."""
        contract = self.get_object()
        messages = contract.messages.order_by('created_at')
        serializer = ContractMessageSerializer(messages, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def send_message(self, request, pk=None):
        """Send a message in this contract."""
        contract = self.get_object()
        data = request.data.copy()
        data['contract'] = contract.id
        serializer = ContractMessageCreateSerializer(
            data=data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


# =============================================================================
# REVIEW VIEWSETS
# =============================================================================

class ServiceReviewViewSet(SecureTenantViewSet):
    """
    ViewSet for service reviews.
    """
    queryset = ServiceReview.objects.select_related('reviewer', 'provider', 'contract')
    search_fields = ['title', 'content']
    ordering_fields = ['rating', 'created_at']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return ServiceReviewListSerializer
        if self.action == 'create':
            return ServiceReviewCreateSerializer
        return ServiceReviewDetailSerializer

    @action(detail=True, methods=['post'])
    def respond(self, request, pk=None):
        """Provider response to a review."""
        review = self.get_object()
        if review.provider.user != request.user:
            return Response(
                {'error': 'Only the provider can respond'},
                status=status.HTTP_403_FORBIDDEN
            )
        if review.provider_response:
            return Response(
                {'error': 'Already responded'},
                status=status.HTTP_400_BAD_REQUEST
            )
        serializer = ReviewResponseSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        review.provider_response = serializer.validated_data['response']
        review.provider_responded_at = timezone.now()
        review.save(update_fields=['provider_response', 'provider_responded_at'])
        return Response({'status': 'responded'})


# =============================================================================
# MARKETPLACE ANALYTICS
# =============================================================================

class MarketplaceAnalyticsView(APIView):
    """
    Marketplace analytics and statistics with caching.
    """
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        """Get marketplace overview statistics with caching."""
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        cache_key = "marketplace:analytics"
        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        stats = {
            'total_providers': ServiceProvider.objects.filter(
                tenant=request.tenant
            ).count(),
            'verified_providers': ServiceProvider.objects.filter(
                tenant=request.tenant,
                is_verified=True
            ).count(),
            'total_services': Service.objects.filter(
                tenant=request.tenant,
                is_active=True
            ).count(),
            'active_requests': ClientRequest.objects.filter(
                tenant=request.tenant,
                status='open'
            ).count(),
            'completed_contracts': ServiceContract.objects.filter(
                tenant=request.tenant,
                status='completed'
            ).count(),
            'total_gmv': ServiceContract.objects.filter(
                tenant=request.tenant,
                status='completed'
            ).aggregate(total=Sum('agreed_rate'))['total'] or Decimal('0.00'),
        }
        serializer = MarketplaceStatsSerializer(stats)

        # Cache for 5 minutes
        tenant_cache.set(cache_key, serializer.data, timeout=300)

        return Response(serializer.data)
