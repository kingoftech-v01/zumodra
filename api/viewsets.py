"""
API ViewSets - Handle CRUD operations via REST API
"""
from rest_framework import viewsets, permissions, filters, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q, Avg
from .serializers import *
from services.models import (
    DService, DServiceProviderProfile, DServiceCategory,
    DServiceRequest, DServiceProposal, DServiceContract,
    DServiceComment
)
from appointment.models import Appointment
from configurations.models import Skill, Company


class IsOwnerOrReadOnly(permissions.BasePermission):
    """Custom permission: only owners can edit"""
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.user == request.user if hasattr(obj, 'user') else obj == request.user


# ==================== SERVICE VIEWSETS ====================

class DServiceCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for service categories (read-only)
    """
    queryset = DServiceCategory.objects.all()
    serializer_class = DServiceCategorySerializer
    permission_classes = [permissions.AllowAny]


class DServiceProviderProfileViewSet(viewsets.ModelViewSet):
    """
    API endpoint for service provider profiles

    list: Get all providers
    retrieve: Get specific provider
    create: Create provider profile
    update: Update provider profile
    partial_update: Partially update provider profile
    destroy: Delete provider profile
    """
    queryset = DServiceProviderProfile.objects.select_related('user').prefetch_related('categories')
    serializer_class = DServiceProviderProfileSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly, IsOwnerOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['availability_status', 'is_verified', 'is_mobile']
    search_fields = ['bio', 'entity_name', 'city', 'country']
    ordering_fields = ['rating_avg', 'total_reviews', 'completed_jobs_count', 'hourly_rate']

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=True, methods=['get'])
    def services(self, request, pk=None):
        """Get all services offered by this provider"""
        provider = self.get_object()
        services = provider.DServices_offered_by_provider.all()
        serializer = DServiceSerializer(services, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def reviews(self, request, pk=None):
        """Get all reviews for this provider"""
        provider = self.get_object()
        reviews = DServiceComment.objects.filter(provider=provider)
        serializer = DServiceCommentSerializer(reviews, many=True)
        return Response(serializer.data)


class DServiceViewSet(viewsets.ModelViewSet):
    """
    API endpoint for services

    list: Get all services with filters
    retrieve: Get specific service
    create: Create service (provider only)
    update: Update service (owner only)
    destroy: Delete service (owner only)

    Filters: ?category=1&min_price=100&max_price=500&search=web
    """
    queryset = DService.objects.select_related('provider', 'DServiceCategory').prefetch_related('tags')
    serializer_class = DServiceSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['DServiceCategory', 'provider']
    search_fields = ['name', 'description', 'tags__tag']
    ordering_fields = ['price', 'created_at', 'duration_minutes']

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return DServiceDetailSerializer
        return DServiceSerializer

    def get_queryset(self):
        queryset = super().get_queryset()

        # Filter by price range
        min_price = self.request.query_params.get('min_price')
        max_price = self.request.query_params.get('max_price')

        if min_price:
            queryset = queryset.filter(price__gte=min_price)
        if max_price:
            queryset = queryset.filter(price__lte=max_price)

        return queryset

    def perform_create(self, serializer):
        # Get or create provider profile
        try:
            provider = self.request.user.DService_provider_profile
        except DServiceProviderProfile.DoesNotExist:
            return Response(
                {'error': 'You must create a provider profile first'},
                status=status.HTTP_400_BAD_REQUEST
            )
        serializer.save(provider=provider)

    @action(detail=True, methods=['get'])
    def comments(self, request, pk=None):
        """Get all comments for this service"""
        service = self.get_object()
        comments = service.comments_DService.all()
        serializer = DServiceCommentSerializer(comments, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def like(self, request, pk=None):
        """Like/unlike a service"""
        from services.models import DServiceLike
        service = self.get_object()
        like, created = DServiceLike.objects.get_or_create(
            user=request.user,
            DService=service
        )
        if not created:
            like.delete()
            return Response({'liked': False})
        return Response({'liked': True})


class DServiceRequestViewSet(viewsets.ModelViewSet):
    """
    API endpoint for service requests

    list: Get all requests (or my requests)
    retrieve: Get specific request
    create: Create request
    update: Update request (owner only)
    """
    queryset = DServiceRequest.objects.select_related('client').prefetch_related('required_skills')
    serializer_class = DServiceRequestSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['is_open']
    search_fields = ['title', 'description']
    ordering_fields = ['created_at', 'budget_max', 'deadline']

    def get_queryset(self):
        queryset = super().get_queryset()

        # Show only user's requests by default
        if self.request.query_params.get('all') != 'true':
            queryset = queryset.filter(client=self.request.user)

        return queryset

    def perform_create(self, serializer):
        serializer.save(client=self.request.user)

    @action(detail=True, methods=['get'])
    def proposals(self, request, pk=None):
        """Get all proposals for this request"""
        service_request = self.get_object()
        proposals = service_request.proposals.all()
        serializer = DServiceProposalSerializer(proposals, many=True)
        return Response(serializer.data)


class DServiceProposalViewSet(viewsets.ModelViewSet):
    """
    API endpoint for service proposals

    list: Get proposals (filtered by user)
    create: Submit proposal (provider only)
    retrieve: Get specific proposal
    """
    queryset = DServiceProposal.objects.select_related('provider', 'request')
    serializer_class = DServiceProposalSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        queryset = super().get_queryset()

        # Show proposals where user is either provider or client
        if hasattr(self.request.user, 'DService_provider_profile'):
            provider = self.request.user.DService_provider_profile
            queryset = queryset.filter(
                Q(provider=provider) | Q(request__client=self.request.user)
            )
        else:
            queryset = queryset.filter(request__client=self.request.user)

        return queryset

    def perform_create(self, serializer):
        try:
            provider = self.request.user.DService_provider_profile
        except DServiceProviderProfile.DoesNotExist:
            return Response(
                {'error': 'You must create a provider profile first'},
                status=status.HTTP_400_BAD_REQUEST
            )
        serializer.save(provider=provider)

    @action(detail=True, methods=['post'])
    def accept(self, request, pk=None):
        """Accept proposal and create contract"""
        proposal = self.get_object()

        # Only client can accept
        if proposal.request.client != request.user:
            return Response(
                {'error': 'Only the client can accept this proposal'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Mark as accepted
        proposal.is_accepted = True
        proposal.save()

        # Close request
        proposal.request.is_open = False
        proposal.request.save()

        # Create contract
        contract = DServiceContract.objects.create(
            request=proposal.request,
            provider=proposal.provider,
            client=request.user,
            agreed_rate=proposal.proposed_rate,
            agreed_deadline=proposal.request.deadline,
            status='pending'
        )

        serializer = DServiceContractSerializer(contract)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class DServiceContractViewSet(viewsets.ModelViewSet):
    """
    API endpoint for service contracts

    list: Get contracts (filtered by user)
    retrieve: Get specific contract
    """
    queryset = DServiceContract.objects.select_related('provider', 'client')
    serializer_class = DServiceContractSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['status']
    ordering_fields = ['created_at', 'agreed_deadline']

    def get_queryset(self):
        queryset = super().get_queryset()

        # Show contracts where user is either provider or client
        if hasattr(self.request.user, 'DService_provider_profile'):
            provider = self.request.user.DService_provider_profile
            queryset = queryset.filter(
                Q(provider=provider) | Q(client=self.request.user)
            )
        else:
            queryset = queryset.filter(client=self.request.user)

        return queryset

    @action(detail=True, methods=['post'])
    def update_status(self, request, pk=None):
        """Update contract status"""
        contract = self.get_object()
        new_status = request.data.get('status')

        if new_status not in ['active', 'completed', 'cancelled']:
            return Response(
                {'error': 'Invalid status'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Permissions check
        is_client = contract.client == request.user
        is_provider = contract.provider.user == request.user

        if not (is_client or is_provider):
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )

        contract.status = new_status
        if new_status == 'active':
            from django.utils import timezone
            contract.started_at = timezone.now()
        elif new_status == 'completed':
            from django.utils import timezone
            contract.completed_at = timezone.now()
            contract.provider.completed_jobs_count += 1
            contract.provider.save()

        contract.save()

        serializer = self.get_serializer(contract)
        return Response(serializer.data)


class DServiceCommentViewSet(viewsets.ModelViewSet):
    """
    API endpoint for service comments/reviews
    """
    queryset = DServiceComment.objects.select_related('reviewer', 'DService', 'provider')
    serializer_class = DServiceCommentSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(reviewer=self.request.user)


# ==================== APPOINTMENT VIEWSETS ====================

class AppointmentViewSet(viewsets.ModelViewSet):
    """
    API endpoint for appointments
    """
    queryset = Appointment.objects.select_related('user')
    serializer_class = AppointmentSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['status']
    ordering_fields = ['start_time', 'created_at']

    def get_queryset(self):
        return self.queryset.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


# ==================== COMPANY VIEWSETS ====================

class CompanyViewSet(viewsets.ModelViewSet):
    """
    API endpoint for companies
    """
    queryset = Company.objects.select_related('owner')
    serializer_class = CompanySerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly, IsOwnerOrReadOnly]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering_fields = ['created_at', 'name']

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)
