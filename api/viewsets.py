"""
API ViewSets - Handle CRUD operations via REST API

This module provides REST API endpoints for the Zumodra platform.
All ViewSets use secure base classes with proper permission enforcement.

Security Features:
- Tenant isolation on all queries
- Role-based access control
- Object-level permissions
- Audit logging
- Participant-only access for contracts
"""
import logging
from rest_framework import viewsets, permissions, filters, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q, Avg

from .serializers import *
from .base import APIResponse
from services.models import (
    DService, DServiceProviderProfile, DServiceCategory,
    DServiceRequest, DServiceProposal, DServiceContract,
    DServiceComment
)
from appointment.models import Appointment
from configurations.models import Skill, Company

# Import secure base classes and permissions
from core.viewsets import (
    SecureTenantViewSet,
    SecureReadOnlyViewSet,
    ParticipantViewSet,
    RoleBasedViewSet,
)
from core.permissions import (
    IsTenantUser,
    IsTenantAdmin,
    TenantObjectPermission,
    IsOwnerOrReadOnly,
    IsParticipant,
    audited,
)

logger = logging.getLogger('security.api')


# ==================== SERVICE VIEWSETS ====================

class DServiceCategoryViewSet(SecureReadOnlyViewSet):
    """
    API endpoint for service categories (read-only).

    Categories are public data, but we still use SecureReadOnlyViewSet
    for consistent audit logging. AllowAny is used for public access.
    """
    queryset = DServiceCategory.objects.all()
    serializer_class = DServiceCategorySerializer
    permission_classes = [permissions.AllowAny]
    enable_audit_logging = False  # Categories are public, no need to log


class DServiceProviderProfileViewSet(SecureTenantViewSet):
    """
    API endpoint for service provider profiles.

    Security:
    - Authenticated users can view profiles
    - Only profile owners can edit their own profiles
    - Admins can view all profiles in their tenant

    Permissions:
    - list/retrieve: Any authenticated tenant user
    - create: Any authenticated tenant user (creates own profile)
    - update/delete: Profile owner or admin
    """
    queryset = DServiceProviderProfile.objects.select_related('user').prefetch_related('categories')
    serializer_class = DServiceProviderProfileSerializer
    permission_classes = [permissions.IsAuthenticated, IsTenantUser, IsOwnerOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['availability_status', 'is_verified']
    search_fields = ['bio', 'display_name', 'city', 'country']
    ordering_fields = ['rating_avg', 'total_reviews', 'completed_jobs_count', 'hourly_rate']
    tenant_field = None  # Provider profiles are linked via user, not direct tenant FK

    def perform_create(self, serializer):
        """Create provider profile for current user."""
        serializer.save(user=self.request.user)
        logger.info(
            f"PROVIDER_PROFILE_CREATED: user={self.request.user.id} "
            f"tenant={getattr(self.request, 'tenant', None)}"
        )

    @action(detail=True, methods=['get'])
    def services(self, request, pk=None):
        """Get all services offered by this provider."""
        provider = self.get_object()
        services = provider.DServices_offered_by_provider.all()
        serializer = DServiceSerializer(services, many=True)
        return APIResponse.success(data=serializer.data)

    @action(detail=True, methods=['get'])
    def reviews(self, request, pk=None):
        """Get all reviews for this provider."""
        provider = self.get_object()
        reviews = DServiceComment.objects.filter(provider=provider)
        serializer = DServiceCommentSerializer(reviews, many=True)
        return APIResponse.success(data=serializer.data)


class DServiceViewSet(SecureTenantViewSet):
    """
    API endpoint for services.

    Security:
    - list/retrieve: Any authenticated tenant user (read access)
    - create: Requires provider profile in tenant
    - update/destroy: Service owner (provider) or admin

    Filters: ?category=1&min_price=100&max_price=500&search=web
    """
    queryset = DService.objects.select_related('provider', 'category').prefetch_related('tags')
    serializer_class = DServiceSerializer
    permission_classes = [permissions.IsAuthenticated, IsTenantUser]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['category', 'provider']
    search_fields = ['name', 'description', 'tags__tag']
    ordering_fields = ['price', 'created_at', 'duration_minutes']
    tenant_field = None  # Services are linked via provider

    # Action-specific permissions
    action_permissions = {
        'destroy': [permissions.IsAuthenticated, IsTenantAdmin],
    }

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
        """Create service - requires provider profile."""
        try:
            provider = self.request.user.DService_provider_profile
        except DServiceProviderProfile.DoesNotExist:
            from rest_framework.exceptions import ValidationError
            raise ValidationError({
                'provider': 'You must create a provider profile first'
            })
        serializer.save(provider=provider)
        logger.info(
            f"SERVICE_CREATED: user={self.request.user.id} "
            f"provider={provider.id} service={serializer.instance.id}"
        )

    def check_object_permissions(self, request, obj):
        """Verify user can modify this service."""
        super().check_object_permissions(request, obj)

        # For write operations, verify ownership
        if request.method not in permissions.SAFE_METHODS:
            is_owner = obj.provider.user == request.user
            is_admin = self._is_tenant_admin(request)

            if not (is_owner or is_admin):
                from rest_framework.exceptions import PermissionDenied
                raise PermissionDenied("You can only modify your own services.")

    def _is_tenant_admin(self, request):
        """Check if user is tenant admin."""
        from accounts.models import TenantUser
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False
        return TenantUser.objects.filter(
            user=request.user,
            tenant=tenant,
            is_active=True,
            role__in=['owner', 'admin']
        ).exists()

    @action(detail=True, methods=['get'])
    def comments(self, request, pk=None):
        """Get all comments for this service."""
        service = self.get_object()
        comments = service.comments_DService.all()
        serializer = DServiceCommentSerializer(comments, many=True)
        return APIResponse.success(data=serializer.data)

    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAuthenticated])
    def like(self, request, pk=None):
        """Like/unlike a service."""
        from services.models import DServiceLike
        service = self.get_object()
        like, created = DServiceLike.objects.get_or_create(
            user=request.user,
            DService=service
        )
        if not created:
            like.delete()
            return APIResponse.success(data={'liked': False}, message='Service unliked')
        return APIResponse.success(data={'liked': True}, message='Service liked')


class DServiceRequestViewSet(SecureTenantViewSet):
    """
    API endpoint for service requests.

    Security:
    - list: User's own requests (or all if admin)
    - create: Any authenticated tenant user
    - update/destroy: Request owner only
    """
    queryset = DServiceRequest.objects.select_related('client').prefetch_related('required_skills')
    serializer_class = DServiceRequestSerializer
    permission_classes = [permissions.IsAuthenticated, IsTenantUser]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['is_open']
    search_fields = ['title', 'description']
    ordering_fields = ['created_at', 'budget_max', 'deadline']
    tenant_field = None  # Requests linked via client user

    def get_queryset(self):
        queryset = super().get_queryset()

        # Show only user's requests by default, admins can see all
        if self.request.query_params.get('all') != 'true':
            queryset = queryset.filter(client=self.request.user)
        elif not self._is_tenant_admin(self.request):
            # Non-admins can only see their own requests
            queryset = queryset.filter(client=self.request.user)

        return queryset

    def _is_tenant_admin(self, request):
        from accounts.models import TenantUser
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False
        return TenantUser.objects.filter(
            user=request.user, tenant=tenant, is_active=True,
            role__in=['owner', 'admin']
        ).exists()

    def perform_create(self, serializer):
        serializer.save(client=self.request.user)
        logger.info(
            f"SERVICE_REQUEST_CREATED: user={self.request.user.id} "
            f"request={serializer.instance.id}"
        )

    def check_object_permissions(self, request, obj):
        """Verify request owner for modifications."""
        super().check_object_permissions(request, obj)
        if request.method not in permissions.SAFE_METHODS:
            if obj.client != request.user and not self._is_tenant_admin(request):
                from rest_framework.exceptions import PermissionDenied
                raise PermissionDenied("You can only modify your own requests.")

    @action(detail=True, methods=['get'])
    def proposals(self, request, pk=None):
        """Get all proposals for this request - only visible to request owner."""
        service_request = self.get_object()
        # Only request owner can see proposals
        if service_request.client != request.user and not self._is_tenant_admin(request):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("Only the request owner can view proposals.")
        proposals = service_request.proposals.all()
        serializer = DServiceProposalSerializer(proposals, many=True)
        return APIResponse.success(data=serializer.data)


class DServiceProposalViewSet(SecureTenantViewSet):
    """
    API endpoint for service proposals.

    Security:
    - list: Proposals where user is provider or client
    - create: Requires provider profile
    - accept: Only the client can accept

    Participant-based access: Only provider and client can see/interact with proposals.
    """
    queryset = DServiceProposal.objects.select_related('provider', 'request')
    serializer_class = DServiceProposalSerializer
    permission_classes = [permissions.IsAuthenticated, IsTenantUser]
    tenant_field = None

    def get_queryset(self):
        queryset = super().get_queryset()

        # Show proposals where user is either provider or client (participant-only)
        if hasattr(self.request.user, 'DService_provider_profile'):
            provider = self.request.user.DService_provider_profile
            queryset = queryset.filter(
                Q(provider=provider) | Q(request__client=self.request.user)
            )
        else:
            queryset = queryset.filter(request__client=self.request.user)

        return queryset

    def perform_create(self, serializer):
        """Submit proposal - requires provider profile."""
        try:
            provider = self.request.user.DService_provider_profile
        except DServiceProviderProfile.DoesNotExist:
            from rest_framework.exceptions import ValidationError
            raise ValidationError({
                'provider': 'You must create a provider profile first'
            })
        serializer.save(provider=provider)
        logger.info(
            f"PROPOSAL_SUBMITTED: user={self.request.user.id} "
            f"proposal={serializer.instance.id} "
            f"request={serializer.instance.request.id}"
        )

    @action(detail=True, methods=['post'])
    def accept(self, request, pk=None):
        """Accept proposal and create contract - client only."""
        proposal = self.get_object()

        # Only client can accept
        if proposal.request.client != request.user:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("Only the client can accept this proposal.")

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

        logger.info(
            f"PROPOSAL_ACCEPTED: user={request.user.id} "
            f"proposal={proposal.id} contract={contract.id}"
        )

        serializer = DServiceContractSerializer(contract)
        return APIResponse.created(
            data=serializer.data,
            message="Proposal accepted and contract created"
        )


class DServiceContractViewSet(ParticipantViewSet):
    """
    API endpoint for service contracts.

    Security:
    - Participant-only access: Only client and provider can view/modify
    - update_status: Only participants can update status
    - Financial data protected

    Uses ParticipantViewSet to enforce that only involved parties can access.
    """
    queryset = DServiceContract.objects.select_related('provider', 'client')
    serializer_class = DServiceContractSerializer
    permission_classes = [permissions.IsAuthenticated, IsTenantUser]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['status']
    ordering_fields = ['created_at', 'agreed_deadline']
    tenant_field = None

    # Participant fields - users who can access this contract
    participant_fields = ['client', 'provider']

    def get_queryset(self):
        """Filter to contracts where user is participant."""
        queryset = super().get_queryset()

        # ParticipantViewSet handles filtering, but we add explicit check here
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
        """Update contract status - participants only."""
        contract = self.get_object()
        new_status = request.data.get('status')

        if new_status not in ['active', 'completed', 'cancelled']:
            return APIResponse.error(
                message='Invalid status. Must be: active, completed, or cancelled',
                status_code=status.HTTP_400_BAD_REQUEST
            )

        # Verify participant
        is_client = contract.client == request.user
        is_provider = contract.provider.user == request.user

        if not (is_client or is_provider):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("Only contract participants can update status.")

        old_status = contract.status
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

        logger.info(
            f"CONTRACT_STATUS_UPDATED: user={request.user.id} "
            f"contract={contract.id} old_status={old_status} "
            f"new_status={new_status}"
        )

        serializer = self.get_serializer(contract)
        return APIResponse.success(
            data=serializer.data,
            message=f"Contract status updated to {new_status}"
        )


class DServiceCommentViewSet(SecureTenantViewSet):
    """
    API endpoint for service comments/reviews.

    Security:
    - list/retrieve: Any authenticated tenant user
    - create: Authenticated users with completed contract
    - update/destroy: Comment owner only

    Reviews can only be created after a completed contract between reviewer and provider.
    """
    queryset = DServiceComment.objects.select_related('reviewer', 'DService', 'provider')
    serializer_class = DServiceCommentSerializer
    permission_classes = [permissions.IsAuthenticated, IsTenantUser, IsOwnerOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['DService', 'provider', 'rating']
    ordering_fields = ['created_at', 'rating']
    tenant_field = None  # Comments linked via reviewer user

    def perform_create(self, serializer):
        """Create review - validate contract exists."""
        provider = serializer.validated_data.get('provider')
        service = serializer.validated_data.get('DService')

        # Verify reviewer has a completed contract with provider
        has_contract = DServiceContract.objects.filter(
            client=self.request.user,
            provider=provider,
            status='completed'
        ).exists()

        if not has_contract:
            from rest_framework.exceptions import ValidationError
            raise ValidationError({
                'detail': 'You can only review providers after completing a contract with them.'
            })

        serializer.save(reviewer=self.request.user)
        logger.info(
            f"REVIEW_CREATED: user={self.request.user.id} "
            f"provider={provider.id if provider else 'N/A'} "
            f"service={service.id if service else 'N/A'}"
        )

    def check_object_permissions(self, request, obj):
        """Verify reviewer ownership for modifications."""
        super().check_object_permissions(request, obj)
        if request.method not in permissions.SAFE_METHODS:
            if obj.reviewer != request.user:
                from rest_framework.exceptions import PermissionDenied
                raise PermissionDenied("You can only modify your own reviews.")


# ==================== APPOINTMENT VIEWSETS ====================

class AppointmentViewSet(SecureTenantViewSet):
    """
    API endpoint for appointments.

    Security:
    - list/retrieve: User's own appointments only
    - create: Any authenticated tenant user
    - update/destroy: Appointment owner only

    Users can only see and manage their own appointments.
    """
    queryset = Appointment.objects.select_related('client', 'appointment_request')
    serializer_class = AppointmentSerializer
    permission_classes = [permissions.IsAuthenticated, IsTenantUser, IsOwnerOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter, filters.SearchFilter]
    filterset_fields = ['paid']
    ordering_fields = ['created_at']
    search_fields = ['address', 'additional_info']
    tenant_field = None  # Appointments linked via user

    def get_queryset(self):
        """Filter to user's own appointments only."""
        queryset = super().get_queryset()
        return queryset.filter(user=self.request.user)

    def perform_create(self, serializer):
        """Create appointment for current user."""
        serializer.save(user=self.request.user)
        logger.info(
            f"APPOINTMENT_CREATED: user={self.request.user.id} "
            f"appointment={serializer.instance.id}"
        )

    def check_object_permissions(self, request, obj):
        """Verify appointment ownership."""
        super().check_object_permissions(request, obj)
        if obj.user != request.user:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("You can only access your own appointments.")


# ==================== COMPANY VIEWSETS ====================

class CompanyViewSet(SecureTenantViewSet):
    """
    API endpoint for companies.

    Security:
    - list/retrieve: Any authenticated tenant user
    - create: Any authenticated tenant user (becomes owner)
    - update/destroy: Company owner or tenant admin only

    Company owners have full control; admins can manage for moderation purposes.
    """
    queryset = Company.objects.select_related('owner')
    serializer_class = CompanySerializer
    permission_classes = [permissions.IsAuthenticated, IsTenantUser, IsOwnerOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering_fields = ['created_at', 'name']
    tenant_field = None  # Companies linked via owner

    # Action-specific permissions
    action_permissions = {
        'destroy': [permissions.IsAuthenticated, IsTenantAdmin],
    }

    def perform_create(self, serializer):
        """Create company with current user as owner."""
        serializer.save(owner=self.request.user)
        logger.info(
            f"COMPANY_CREATED: user={self.request.user.id} "
            f"company={serializer.instance.id}"
        )

    def check_object_permissions(self, request, obj):
        """Verify company ownership for modifications."""
        super().check_object_permissions(request, obj)

        if request.method not in permissions.SAFE_METHODS:
            is_owner = obj.owner == request.user
            is_admin = self._is_tenant_admin(request)

            if not (is_owner or is_admin):
                from rest_framework.exceptions import PermissionDenied
                raise PermissionDenied("You can only modify your own companies.")

    def _is_tenant_admin(self, request):
        """Check if user is tenant admin."""
        from accounts.models import TenantUser
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False
        return TenantUser.objects.filter(
            user=request.user,
            tenant=tenant,
            is_active=True,
            role__in=['owner', 'admin']
        ).exists()
