"""
Accounts Views - REST API ViewSets and APIViews.

This module provides REST API endpoints for:
- TenantUser management (CRUD with tenant scoping)
- UserProfile management
- KYC verification (submit, verify, reject actions)
- Progressive consent (grant/revoke)
- Data access audit logs (read-only)
- Login history (read-only)
- Authentication (register, login, logout, current user)
"""

from rest_framework import viewsets, views, permissions, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.tokens import RefreshToken
from django_filters.rest_framework import DjangoFilterBackend
from django.contrib.auth import get_user_model, login, logout
from django.utils import timezone
from django.db.models import Q

from .models import (
    TenantUser, UserProfile, KYCVerification,
    ProgressiveConsent, DataAccessLog, LoginHistory,
    TrustScore, EmploymentVerification, EducationVerification,
    Review, CandidateCV, StudentProfile, CoopTerm
)
from .serializers import (
    TenantUserSerializer, TenantUserCreateSerializer,
    UserProfileSerializer,
    KYCVerificationSerializer, KYCSubmissionSerializer,
    KYCVerifyActionSerializer, KYCRejectActionSerializer,
    ProgressiveConsentSerializer, ConsentRequestSerializer,
    ConsentGrantSerializer, ConsentRevokeSerializer,
    DataAccessLogSerializer, LoginHistorySerializer,
    UserRegistrationSerializer, UserLoginSerializer,
    CurrentUserSerializer, PasswordChangeSerializer,
    SecurityQuestionSerializer,
    # New serializers for trust/verification models
    TrustScoreSerializer,
    EmploymentVerificationSerializer, EmploymentVerificationCreateSerializer,
    EmploymentVerificationResponseSerializer,
    EducationVerificationSerializer, EducationVerificationCreateSerializer,
    TranscriptUploadSerializer,
    ReviewSerializer, ReviewCreateSerializer,
    ReviewDisputeSerializer, ReviewResponseSerializer,
    CandidateCVSerializer, CandidateCVCreateSerializer, BestCVMatchSerializer,
    StudentProfileSerializer, StudentProfileCreateSerializer, CoopTermSerializer
)
from .permissions import (
    IsTenantUser, IsTenantAdmin, IsTenantOwner,
    HasKYCVerification, CanAccessUserData, CanManageUsers,
    IsOwnerOrReadOnly
)

User = get_user_model()


# ==================== TENANT USER VIEWSET ====================

class TenantUserViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing tenant user memberships.

    Provides CRUD operations for user-tenant relationships with role management.
    Scoped to the current tenant from request.

    list: Get all members of the current tenant
    retrieve: Get specific tenant user
    create: Add user to tenant (admin only)
    update: Update user role/department (admin only)
    partial_update: Partial update of tenant user
    destroy: Remove user from tenant (admin only)

    Custom actions:
    - deactivate: Soft-delete user from tenant
    - reactivate: Reactivate deactivated user
    - update_role: Change user's role
    """
    serializer_class = TenantUserSerializer
    permission_classes = [permissions.IsAuthenticated, IsTenantUser]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['role', 'is_active', 'department']
    search_fields = ['user__email', 'user__first_name', 'user__last_name', 'job_title']
    ordering_fields = ['joined_at', 'last_active_at', 'role']
    ordering = ['-joined_at']
    lookup_field = 'uuid'

    def get_queryset(self):
        """Filter to current tenant."""
        tenant = getattr(self.request, 'tenant', None)
        if not tenant:
            return TenantUser.objects.none()
        return TenantUser.objects.filter(tenant=tenant).select_related(
            'user', 'department', 'reports_to'
        )

    def get_serializer_class(self):
        if self.action == 'create':
            return TenantUserCreateSerializer
        return TenantUserSerializer

    def get_permissions(self):
        """Require admin permission for write operations."""
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [permissions.IsAuthenticated(), IsTenantAdmin()]
        return super().get_permissions()

    def perform_destroy(self, instance):
        """Soft delete by deactivating instead of hard delete."""
        instance.is_active = False
        instance.deactivated_at = timezone.now()
        instance.save(update_fields=['is_active', 'deactivated_at'])

    @action(detail=True, methods=['post'], permission_classes=[IsTenantAdmin])
    def deactivate(self, request, uuid=None):
        """Deactivate a tenant user (soft delete)."""
        tenant_user = self.get_object()
        tenant_user.is_active = False
        tenant_user.deactivated_at = timezone.now()
        tenant_user.save(update_fields=['is_active', 'deactivated_at'])
        return Response({'status': 'deactivated'})

    @action(detail=True, methods=['post'], permission_classes=[IsTenantAdmin])
    def reactivate(self, request, uuid=None):
        """Reactivate a deactivated tenant user."""
        tenant_user = self.get_object()
        tenant_user.is_active = True
        tenant_user.deactivated_at = None
        tenant_user.save(update_fields=['is_active', 'deactivated_at'])
        return Response({'status': 'reactivated'})

    @action(detail=True, methods=['post'], permission_classes=[IsTenantAdmin])
    def update_role(self, request, uuid=None):
        """Update user's role in the tenant."""
        tenant_user = self.get_object()
        new_role = request.data.get('role')

        if new_role not in dict(TenantUser.UserRole.choices):
            return Response(
                {'error': 'Invalid role'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prevent demoting the last owner
        if tenant_user.role == TenantUser.UserRole.OWNER:
            owner_count = TenantUser.objects.filter(
                tenant=tenant_user.tenant,
                role=TenantUser.UserRole.OWNER,
                is_active=True
            ).count()
            if owner_count <= 1 and new_role != TenantUser.UserRole.OWNER:
                return Response(
                    {'error': 'Cannot demote the last owner'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        tenant_user.role = new_role
        tenant_user.save(update_fields=['role'])
        serializer = self.get_serializer(tenant_user)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def me(self, request):
        """Get current user's tenant membership."""
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return Response(
                {'error': 'No tenant context'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            tenant_user = TenantUser.objects.get(
                user=request.user,
                tenant=tenant
            )
            serializer = self.get_serializer(tenant_user)
            return Response(serializer.data)
        except TenantUser.DoesNotExist:
            return Response(
                {'error': 'Not a member of this tenant'},
                status=status.HTTP_404_NOT_FOUND
            )


# ==================== USER PROFILE VIEWSET ====================

class UserProfileViewSet(viewsets.ModelViewSet):
    """
    ViewSet for user profiles.

    Provides profile management with tenant-scoped access for admins.

    list: Get profiles (admin sees all in tenant, users see own)
    retrieve: Get specific profile
    update: Update profile (owner or admin)
    partial_update: Partial update
    """
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['profile_type', 'country', 'city']
    search_fields = ['user__email', 'user__first_name', 'bio', 'city']
    lookup_field = 'uuid'

    def get_queryset(self):
        """Return appropriate queryset based on user permissions."""
        user = self.request.user
        tenant = getattr(self.request, 'tenant', None)

        # Admins can see all profiles in their tenant
        if tenant:
            try:
                tenant_user = TenantUser.objects.get(
                    user=user, tenant=tenant, is_active=True
                )
                if tenant_user.is_admin:
                    tenant_users = TenantUser.objects.filter(
                        tenant=tenant
                    ).values_list('user_id', flat=True)
                    return UserProfile.objects.filter(
                        user_id__in=tenant_users
                    ).select_related('user')
            except TenantUser.DoesNotExist:
                pass

        # Regular users only see their own profile
        return UserProfile.objects.filter(user=user).select_related('user')

    def get_permissions(self):
        if self.action in ['update', 'partial_update', 'destroy']:
            return [permissions.IsAuthenticated(), IsOwnerOrReadOnly()]
        return super().get_permissions()

    @action(detail=False, methods=['get', 'put', 'patch'])
    def me(self, request):
        """Get or update current user's profile."""
        try:
            profile = request.user.profile
        except UserProfile.DoesNotExist:
            profile = UserProfile.objects.create(user=request.user)

        if request.method == 'GET':
            serializer = self.get_serializer(profile)
            return Response(serializer.data)
        else:
            serializer = self.get_serializer(
                profile, data=request.data,
                partial=(request.method == 'PATCH')
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)


# ==================== KYC VERIFICATION VIEWSET ====================

class KYCVerificationViewSet(viewsets.ModelViewSet):
    """
    ViewSet for KYC verification management.

    Provides submission, viewing, and admin verification actions.

    list: Get verifications (own or admin access)
    retrieve: Get specific verification
    create: Submit new verification request
    verify: Admin action to verify
    reject: Admin action to reject
    """
    serializer_class = KYCVerificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['status', 'verification_type', 'level']
    ordering_fields = ['created_at', 'submitted_at', 'verified_at']
    ordering = ['-created_at']
    lookup_field = 'uuid'

    def get_queryset(self):
        """Filter based on user role."""
        user = self.request.user
        tenant = getattr(self.request, 'tenant', None)

        # Check if user is admin in tenant
        if tenant:
            try:
                tenant_user = TenantUser.objects.get(
                    user=user, tenant=tenant, is_active=True
                )
                if tenant_user.is_admin:
                    # Admins can see all verifications for tenant users
                    tenant_users = TenantUser.objects.filter(
                        tenant=tenant
                    ).values_list('user_id', flat=True)
                    return KYCVerification.objects.filter(
                        user_id__in=tenant_users
                    ).select_related('user', 'verified_by')
            except TenantUser.DoesNotExist:
                pass

        # Regular users see only their own
        return KYCVerification.objects.filter(user=user).select_related('verified_by')

    def get_serializer_class(self):
        if self.action == 'create':
            return KYCSubmissionSerializer
        if self.action == 'verify':
            return KYCVerifyActionSerializer
        if self.action == 'reject':
            return KYCRejectActionSerializer
        return KYCVerificationSerializer

    @action(detail=True, methods=['post'], permission_classes=[IsTenantAdmin])
    def verify(self, request, uuid=None):
        """Admin action to verify a KYC submission."""
        verification = self.get_object()

        if verification.status == KYCVerification.VerificationStatus.VERIFIED:
            return Response(
                {'error': 'Already verified'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = KYCVerifyActionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        verification.mark_verified(
            verified_by=request.user,
            confidence_score=serializer.validated_data.get('confidence_score')
        )

        if serializer.validated_data.get('notes'):
            verification.notes = serializer.validated_data['notes']
        if serializer.validated_data.get('verified_data'):
            verification.verified_data = serializer.validated_data['verified_data']
        verification.save()

        return Response(KYCVerificationSerializer(verification).data)

    @action(detail=True, methods=['post'], permission_classes=[IsTenantAdmin])
    def reject(self, request, uuid=None):
        """Admin action to reject a KYC submission."""
        verification = self.get_object()

        if verification.status == KYCVerification.VerificationStatus.VERIFIED:
            return Response(
                {'error': 'Cannot reject verified submission'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = KYCRejectActionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        verification.mark_rejected(
            reason=serializer.validated_data['rejection_reason']
        )

        if serializer.validated_data.get('notes'):
            verification.notes = serializer.validated_data['notes']
            verification.save(update_fields=['notes'])

        return Response(KYCVerificationSerializer(verification).data)

    @action(detail=False, methods=['get'])
    def my_status(self, request):
        """Get current user's KYC status summary."""
        verifications = KYCVerification.objects.filter(user=request.user)

        verified = verifications.filter(
            status=KYCVerification.VerificationStatus.VERIFIED,
            expires_at__gt=timezone.now()
        )
        pending = verifications.filter(
            status__in=[
                KYCVerification.VerificationStatus.PENDING,
                KYCVerification.VerificationStatus.IN_PROGRESS
            ]
        )

        return Response({
            'total_verifications': verifications.count(),
            'verified_count': verified.count(),
            'pending_count': pending.count(),
            'verified_types': list(verified.values_list('verification_type', flat=True)),
            'verifications': KYCVerificationSerializer(verifications, many=True).data
        })


# ==================== PROGRESSIVE CONSENT VIEWSET ====================

class ProgressiveConsentViewSet(viewsets.ModelViewSet):
    """
    ViewSet for progressive consent management.

    Manages data access consent for progressive revelation.

    list: Get consents (given or received)
    retrieve: Get specific consent
    request_consent: Request consent from another user
    respond: Grant or deny consent
    revoke: Revoke previously granted consent
    """
    serializer_class = ProgressiveConsentSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['status', 'data_category']
    ordering_fields = ['requested_at', 'responded_at', 'expires_at']
    ordering = ['-requested_at']
    lookup_field = 'uuid'

    def get_queryset(self):
        """Get consents where user is grantor or grantee."""
        user = self.request.user
        tenant = getattr(self.request, 'tenant', None)

        queryset = ProgressiveConsent.objects.filter(
            Q(grantor=user) |
            Q(grantee_user=user) |
            Q(grantee_tenant=tenant)
        ).select_related('grantor', 'grantee_user', 'grantee_tenant')

        return queryset.distinct()

    @action(detail=False, methods=['post'])
    def request_consent(self, request):
        """Request consent from another user."""
        serializer = ConsentRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        data_subject_id = serializer.validated_data['data_subject_id']
        try:
            data_subject = User.objects.get(id=data_subject_id)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        tenant = getattr(request, 'tenant', None)
        expires_in_days = serializer.validated_data.get('expires_in_days', 90)

        consent, created = ProgressiveConsent.objects.get_or_create(
            grantor=data_subject,
            grantee_user=request.user,
            grantee_tenant=tenant,
            data_category=serializer.validated_data['data_category'],
            context_type=serializer.validated_data.get('context_type', ''),
            context_id=serializer.validated_data.get('context_id'),
            defaults={
                'purpose': serializer.validated_data['purpose'],
                'status': ProgressiveConsent.ConsentStatus.PENDING,
                'requested_at': timezone.now(),
                'expires_at': timezone.now() + timezone.timedelta(days=expires_in_days)
            }
        )

        if not created:
            # Update existing request
            consent.purpose = serializer.validated_data['purpose']
            consent.status = ProgressiveConsent.ConsentStatus.PENDING
            consent.requested_at = timezone.now()
            consent.save()

        return Response(
            ProgressiveConsentSerializer(consent).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK
        )

    @action(detail=False, methods=['post'])
    def respond(self, request):
        """Grant or deny a consent request."""
        serializer = ConsentGrantSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            consent = ProgressiveConsent.objects.get(
                uuid=serializer.validated_data['consent_uuid'],
                grantor=request.user
            )
        except ProgressiveConsent.DoesNotExist:
            return Response(
                {'error': 'Consent request not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        action = serializer.validated_data['action']
        if action == 'grant':
            consent.grant()
        else:
            consent.deny()

        # Record IP and user agent
        consent.ip_address = self._get_client_ip(request)
        consent.user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]
        consent.save(update_fields=['ip_address', 'user_agent'])

        return Response(ProgressiveConsentSerializer(consent).data)

    @action(detail=False, methods=['post'])
    def revoke(self, request):
        """Revoke a previously granted consent."""
        serializer = ConsentRevokeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            consent = ProgressiveConsent.objects.get(
                uuid=serializer.validated_data['consent_uuid'],
                grantor=request.user,
                status=ProgressiveConsent.ConsentStatus.GRANTED
            )
        except ProgressiveConsent.DoesNotExist:
            return Response(
                {'error': 'Active consent not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        consent.revoke()
        return Response(ProgressiveConsentSerializer(consent).data)

    @action(detail=False, methods=['get'])
    def pending(self, request):
        """Get pending consent requests for current user."""
        pending_consents = ProgressiveConsent.objects.filter(
            grantor=request.user,
            status=ProgressiveConsent.ConsentStatus.PENDING
        )
        serializer = ProgressiveConsentSerializer(pending_consents, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def granted(self, request):
        """Get active consents granted by current user."""
        granted_consents = ProgressiveConsent.objects.filter(
            grantor=request.user,
            status=ProgressiveConsent.ConsentStatus.GRANTED,
            expires_at__gt=timezone.now()
        )
        serializer = ProgressiveConsentSerializer(granted_consents, many=True)
        return Response(serializer.data)

    def _get_client_ip(self, request):
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


# ==================== DATA ACCESS LOG VIEWSET ====================

class DataAccessLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for data access audit logs (read-only).

    Provides read-only access to data access audit trail.

    list: Get access logs (as data subject or accessor)
    retrieve: Get specific log entry
    """
    serializer_class = DataAccessLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['data_category', 'accessor']
    ordering_fields = ['accessed_at']
    ordering = ['-accessed_at']
    lookup_field = 'uuid'

    def get_queryset(self):
        """Get logs where user is subject or accessor."""
        user = self.request.user
        tenant = getattr(self.request, 'tenant', None)

        queryset = DataAccessLog.objects.filter(
            Q(data_subject=user) |
            Q(accessor=user)
        )

        if tenant:
            queryset = queryset.filter(
                Q(accessor_tenant=tenant) | Q(accessor_tenant__isnull=True)
            )

        return queryset.select_related('accessor', 'data_subject', 'consent')

    @action(detail=False, methods=['get'])
    def my_data_accessed(self, request):
        """Get logs of who accessed current user's data."""
        logs = DataAccessLog.objects.filter(
            data_subject=request.user
        ).select_related('accessor', 'consent').order_by('-accessed_at')[:100]

        serializer = self.get_serializer(logs, many=True)
        return Response(serializer.data)


# ==================== LOGIN HISTORY VIEWSET ====================

class LoginHistoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for login history (read-only security log).

    list: Get login history (own or admin view)
    retrieve: Get specific login entry
    """
    serializer_class = LoginHistorySerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['result']
    ordering_fields = ['timestamp']
    ordering = ['-timestamp']

    def get_queryset(self):
        """Get login history for current user or admin view."""
        user = self.request.user
        tenant = getattr(self.request, 'tenant', None)

        # Check if admin
        if tenant:
            try:
                tenant_user = TenantUser.objects.get(
                    user=user, tenant=tenant, is_active=True
                )
                if tenant_user.is_admin:
                    tenant_users = TenantUser.objects.filter(
                        tenant=tenant
                    ).values_list('user_id', flat=True)
                    return LoginHistory.objects.filter(
                        user_id__in=tenant_users
                    ).select_related('user')
            except TenantUser.DoesNotExist:
                pass

        return LoginHistory.objects.filter(user=user)

    @action(detail=False, methods=['get'])
    def recent(self, request):
        """Get recent login attempts for security review."""
        recent_logins = self.get_queryset().filter(
            user=request.user
        )[:20]
        serializer = self.get_serializer(recent_logins, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def failed(self, request):
        """Get failed login attempts for security review."""
        failed_logins = self.get_queryset().filter(
            user=request.user,
            result=LoginHistory.LoginResult.FAILED
        )[:50]
        serializer = self.get_serializer(failed_logins, many=True)
        return Response(serializer.data)


# ==================== AUTHENTICATION VIEWS ====================

class RegisterView(views.APIView):
    """
    User registration endpoint.

    POST: Create new user account with profile.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Generate tokens
        refresh = RefreshToken.for_user(user)

        return Response({
            'user': CurrentUserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }, status=status.HTTP_201_CREATED)


class LoginView(views.APIView):
    """
    User login endpoint.

    POST: Authenticate user and return tokens.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']

        # Log the login attempt
        LoginHistory.objects.create(
            user=user,
            result=LoginHistory.LoginResult.SUCCESS,
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
        )

        # Update tenant user last active
        tenant = getattr(request, 'tenant', None)
        if tenant:
            TenantUser.objects.filter(
                user=user, tenant=tenant
            ).update(last_active_at=timezone.now())

        # Generate tokens
        refresh = RefreshToken.for_user(user)

        return Response({
            'user': CurrentUserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        })

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class LogoutView(views.APIView):
    """
    User logout endpoint.

    POST: Blacklist refresh token.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
        except Exception:
            pass  # Token may already be blacklisted

        return Response({'status': 'logged out'})


class CurrentUserView(views.APIView):
    """
    Current authenticated user endpoint.

    GET: Get current user details with profile and memberships.
    PUT/PATCH: Update current user details.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        serializer = CurrentUserSerializer(request.user, context={'request': request})
        return Response(serializer.data)

    def put(self, request):
        return self._update(request, partial=False)

    def patch(self, request):
        return self._update(request, partial=True)

    def _update(self, request, partial=False):
        serializer = CurrentUserSerializer(
            request.user,
            data=request.data,
            partial=partial,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class PasswordChangeView(views.APIView):
    """
    Password change endpoint.

    POST: Change password for authenticated user.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)

        user = request.user
        user.set_password(serializer.validated_data['new_password'])
        user.save()

        # Optionally invalidate all tokens
        # This would require additional token blacklisting logic

        return Response({'status': 'password changed'})


class SecurityQuestionView(views.APIView):
    """
    Security questions management endpoint.

    GET: Get user's security questions (questions only, not answers)
    POST: Add new security question
    DELETE: Remove security question
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        questions = request.user.security_questions.all()
        serializer = SecurityQuestionSerializer(questions, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = SecurityQuestionSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def delete(self, request):
        question_id = request.data.get('question_id')
        try:
            question = request.user.security_questions.get(id=question_id)
            question.delete()
            return Response({'status': 'deleted'})
        except Exception:
            return Response(
                {'error': 'Question not found'},
                status=status.HTTP_404_NOT_FOUND
            )


# ==================== TRUST SCORE VIEWSET ====================

class TrustScoreViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for trust scores (read-only with recalculate action).

    Provides:
    - GET own trust score
    - Action to recalculate trust score

    list: Get trust scores (admin can see all, users see own)
    retrieve: Get specific trust score
    me: Get current user's trust score
    recalculate: Trigger recalculation of trust score
    """
    serializer_class = TrustScoreSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['trust_level', 'entity_type', 'is_id_verified', 'is_career_verified']
    ordering_fields = ['overall_score', 'trust_level', 'updated_at']
    ordering = ['-overall_score']
    lookup_field = 'uuid'

    def get_queryset(self):
        """Filter based on user role."""
        user = self.request.user
        tenant = getattr(self.request, 'tenant', None)

        # Check if user is admin in tenant
        if tenant:
            try:
                tenant_user = TenantUser.objects.get(
                    user=user, tenant=tenant, is_active=True
                )
                if tenant_user.is_admin:
                    tenant_users = TenantUser.objects.filter(
                        tenant=tenant
                    ).values_list('user_id', flat=True)
                    return TrustScore.objects.filter(
                        user_id__in=tenant_users
                    ).select_related('user')
            except TenantUser.DoesNotExist:
                pass

        # Regular users see only their own
        return TrustScore.objects.filter(user=user).select_related('user')

    @action(detail=False, methods=['get'])
    def me(self, request):
        """Get current user's trust score."""
        try:
            trust_score = TrustScore.objects.get(user=request.user)
        except TrustScore.DoesNotExist:
            # Create trust score if doesn't exist
            trust_score = TrustScore.objects.create(user=request.user)

        serializer = self.get_serializer(trust_score)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def recalculate(self, request):
        """Recalculate current user's trust score."""
        try:
            trust_score = TrustScore.objects.get(user=request.user)
        except TrustScore.DoesNotExist:
            trust_score = TrustScore.objects.create(user=request.user)

        # Update all component scores
        trust_score.update_identity_score()
        trust_score.update_career_score()
        trust_score.update_review_score()
        trust_score.update_dispute_score()
        trust_score.calculate_overall_score()

        serializer = self.get_serializer(trust_score)
        return Response(serializer.data)


# ==================== EMPLOYMENT VERIFICATION VIEWSET ====================

class EmploymentVerificationViewSet(viewsets.ModelViewSet):
    """
    ViewSet for employment verification management.

    Provides CRUD for own verifications with verification workflow actions.

    list: Get employment verifications (own or admin)
    retrieve: Get specific verification
    create: Add new employment entry
    update: Update employment entry
    destroy: Delete unverified employment entry

    Custom actions:
    - request_verification: Send verification request to HR contact
    - handle_response: Public endpoint for HR to respond (token-based)
    """
    serializer_class = EmploymentVerificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status', 'is_current', 'employment_type']
    search_fields = ['company_name', 'job_title']
    ordering_fields = ['start_date', 'end_date', 'created_at', 'verified_at']
    ordering = ['-start_date']
    lookup_field = 'uuid'

    def get_queryset(self):
        """Filter to own verifications or admin access."""
        user = self.request.user
        tenant = getattr(self.request, 'tenant', None)

        if tenant:
            try:
                tenant_user = TenantUser.objects.get(
                    user=user, tenant=tenant, is_active=True
                )
                if tenant_user.is_admin:
                    tenant_users = TenantUser.objects.filter(
                        tenant=tenant
                    ).values_list('user_id', flat=True)
                    return EmploymentVerification.objects.filter(
                        user_id__in=tenant_users
                    ).select_related('user')
            except TenantUser.DoesNotExist:
                pass

        return EmploymentVerification.objects.filter(user=user).select_related('user')

    def get_serializer_class(self):
        if self.action == 'create':
            return EmploymentVerificationCreateSerializer
        return EmploymentVerificationSerializer

    def perform_destroy(self, instance):
        """Only allow deletion of unverified entries."""
        if instance.status == EmploymentVerification.VerificationStatus.VERIFIED:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("Cannot delete verified employment records.")
        instance.delete()

    @action(detail=True, methods=['post'])
    def request_verification(self, request, uuid=None):
        """Send verification request to HR contact."""
        verification = self.get_object()

        if not verification.hr_contact_email:
            return Response(
                {'error': 'HR contact email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if verification.status == EmploymentVerification.VerificationStatus.VERIFIED:
            return Response(
                {'error': 'Already verified'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Regenerate token if expired
        if verification.token_expires_at and verification.token_expires_at < timezone.now():
            import secrets
            verification.verification_token = secrets.token_urlsafe(32)
            verification.token_expires_at = timezone.now() + timezone.timedelta(days=30)

        success = verification.send_verification_request()

        if success:
            serializer = self.get_serializer(verification)
            return Response({
                'status': 'verification_request_sent',
                'data': serializer.data
            })
        else:
            return Response(
                {'error': 'Failed to send verification request'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EmploymentVerificationResponseView(views.APIView):
    """
    Public endpoint for HR contacts to respond to verification requests.

    This endpoint does not require authentication - it uses token-based verification.

    POST: Submit verification response
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = EmploymentVerificationResponseSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data['token']

        try:
            verification = EmploymentVerification.objects.get(
                verification_token=token
            )
        except EmploymentVerification.DoesNotExist:
            return Response(
                {'error': 'Invalid or expired verification token'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check token expiry
        if verification.token_expires_at and verification.token_expires_at < timezone.now():
            return Response(
                {'error': 'Verification token has expired'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if already verified
        if verification.status == EmploymentVerification.VerificationStatus.VERIFIED:
            return Response(
                {'error': 'This employment has already been verified'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Process verification response
        response_data = {
            'dates_confirmed': serializer.validated_data['dates_confirmed'],
            'title_confirmed': serializer.validated_data['title_confirmed'],
            'eligible_for_rehire': serializer.validated_data.get('eligible_for_rehire'),
            'performance_rating': serializer.validated_data.get('performance_rating', ''),
        }

        verification.verified_by_name = serializer.validated_data['verifier_name']
        verification.verified_by_email = serializer.validated_data['verifier_email']
        verification.response_notes = serializer.validated_data.get('notes', '')
        verification.mark_verified(response_data)

        return Response({
            'status': 'verification_submitted',
            'message': 'Thank you for verifying this employment record.'
        })


# ==================== EDUCATION VERIFICATION VIEWSET ====================

class EducationVerificationViewSet(viewsets.ModelViewSet):
    """
    ViewSet for education verification management.

    Provides CRUD for own verifications with verification workflow actions.

    list: Get education verifications (own or admin)
    retrieve: Get specific verification
    create: Add new education entry
    update: Update education entry
    destroy: Delete unverified education entry

    Custom actions:
    - upload_transcript: Upload transcript document
    - request_verification: Send verification request to registrar
    """
    serializer_class = EducationVerificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status', 'is_current', 'degree_type', 'graduated']
    search_fields = ['institution_name', 'field_of_study']
    ordering_fields = ['start_date', 'end_date', 'created_at', 'verified_at']
    ordering = ['-end_date']
    lookup_field = 'uuid'

    def get_queryset(self):
        """Filter to own verifications or admin access."""
        user = self.request.user
        tenant = getattr(self.request, 'tenant', None)

        if tenant:
            try:
                tenant_user = TenantUser.objects.get(
                    user=user, tenant=tenant, is_active=True
                )
                if tenant_user.is_admin:
                    tenant_users = TenantUser.objects.filter(
                        tenant=tenant
                    ).values_list('user_id', flat=True)
                    return EducationVerification.objects.filter(
                        user_id__in=tenant_users
                    ).select_related('user')
            except TenantUser.DoesNotExist:
                pass

        return EducationVerification.objects.filter(user=user).select_related('user')

    def get_serializer_class(self):
        if self.action == 'create':
            return EducationVerificationCreateSerializer
        if self.action == 'upload_transcript':
            return TranscriptUploadSerializer
        return EducationVerificationSerializer

    def perform_destroy(self, instance):
        """Only allow deletion of unverified entries."""
        if instance.status == EducationVerification.VerificationStatus.VERIFIED:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("Cannot delete verified education records.")
        instance.delete()

    @action(detail=True, methods=['post'])
    def upload_transcript(self, request, uuid=None):
        """Upload transcript document for verification."""
        verification = self.get_object()

        serializer = TranscriptUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        verification.transcript_file = serializer.validated_data['transcript_file']
        verification.verification_method = EducationVerification.VerificationMethod.TRANSCRIPT
        verification.save(update_fields=['transcript_file', 'verification_method', 'updated_at'])

        return Response({
            'status': 'transcript_uploaded',
            'data': EducationVerificationSerializer(verification, context={'request': request}).data
        })

    @action(detail=True, methods=['post'])
    def request_verification(self, request, uuid=None):
        """Send verification request to registrar."""
        verification = self.get_object()

        if not verification.registrar_email:
            return Response(
                {'error': 'Registrar email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if verification.status == EducationVerification.VerificationStatus.VERIFIED:
            return Response(
                {'error': 'Already verified'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Regenerate token if expired
        if verification.token_expires_at and verification.token_expires_at < timezone.now():
            import secrets
            verification.verification_token = secrets.token_urlsafe(32)
            verification.token_expires_at = timezone.now() + timezone.timedelta(days=30)

        verification.status = EducationVerification.VerificationStatus.PENDING
        verification.verification_method = EducationVerification.VerificationMethod.EMAIL
        verification.request_sent_at = timezone.now()
        verification.save()

        # Email sending would be handled by Celery task
        serializer = self.get_serializer(verification)
        return Response({
            'status': 'verification_request_sent',
            'data': serializer.data
        })


# ==================== REVIEW VIEWSET ====================

class ReviewViewSet(viewsets.ModelViewSet):
    """
    ViewSet for review management.

    Provides:
    - Create reviews after job/contract completion
    - List reviews for a user
    - Dispute action for reviewees
    - Response action for reviewees

    list: Get reviews (own reviews given/received or admin)
    retrieve: Get specific review
    create: Create new review
    for_user: Get reviews for a specific user

    Custom actions:
    - dispute: Dispute a review (for reviewee)
    - respond: Add response to a review (for reviewee)
    """
    serializer_class = ReviewSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status', 'review_type', 'overall_rating', 'is_negative']
    search_fields = ['title', 'content', 'reviewer__email', 'reviewee__email']
    ordering_fields = ['created_at', 'overall_rating', 'published_at']
    ordering = ['-created_at']
    lookup_field = 'uuid'

    def get_queryset(self):
        """Filter to reviews user is involved in or admin access."""
        user = self.request.user
        tenant = getattr(self.request, 'tenant', None)

        if tenant:
            try:
                tenant_user = TenantUser.objects.get(
                    user=user, tenant=tenant, is_active=True
                )
                if tenant_user.is_admin:
                    tenant_users = TenantUser.objects.filter(
                        tenant=tenant
                    ).values_list('user_id', flat=True)
                    return Review.objects.filter(
                        Q(reviewer_id__in=tenant_users) |
                        Q(reviewee_id__in=tenant_users)
                    ).select_related('reviewer', 'reviewee')
            except TenantUser.DoesNotExist:
                pass

        # Users see reviews they gave or received
        return Review.objects.filter(
            Q(reviewer=user) | Q(reviewee=user)
        ).select_related('reviewer', 'reviewee')

    def get_serializer_class(self):
        if self.action == 'create':
            return ReviewCreateSerializer
        if self.action == 'dispute':
            return ReviewDisputeSerializer
        if self.action == 'respond':
            return ReviewResponseSerializer
        return ReviewSerializer

    @action(detail=False, methods=['get'])
    def for_user(self, request):
        """Get published reviews for a specific user."""
        user_id = request.query_params.get('user_id')
        if not user_id:
            return Response(
                {'error': 'user_id query parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        reviews = Review.objects.filter(
            reviewee_id=user_id,
            status__in=[Review.ReviewStatus.PUBLISHED, Review.ReviewStatus.VALIDATED]
        ).select_related('reviewer', 'reviewee')

        serializer = self.get_serializer(reviews, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def given(self, request):
        """Get reviews given by current user."""
        reviews = Review.objects.filter(reviewer=request.user)
        serializer = self.get_serializer(reviews, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def received(self, request):
        """Get reviews received by current user."""
        reviews = Review.objects.filter(reviewee=request.user)
        serializer = self.get_serializer(reviews, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def dispute(self, request, uuid=None):
        """Dispute a review (for reviewee only)."""
        review = self.get_object()

        # Only reviewee can dispute
        if review.reviewee != request.user:
            return Response(
                {'error': 'Only the reviewee can dispute a review'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Can only dispute pending or published reviews
        if review.status not in [Review.ReviewStatus.PENDING, Review.ReviewStatus.PUBLISHED]:
            return Response(
                {'error': 'This review cannot be disputed'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = ReviewDisputeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        review.dispute(
            response=serializer.validated_data['response'],
            evidence=serializer.validated_data.get('evidence', [])
        )

        return Response({
            'status': 'review_disputed',
            'data': ReviewSerializer(review, context={'request': request}).data
        })

    @action(detail=True, methods=['post'])
    def respond(self, request, uuid=None):
        """Add response to a review (for reviewee only)."""
        review = self.get_object()

        # Only reviewee can respond
        if review.reviewee != request.user:
            return Response(
                {'error': 'Only the reviewee can respond to a review'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Can only respond to published reviews
        if review.status != Review.ReviewStatus.PUBLISHED:
            return Response(
                {'error': 'Can only respond to published reviews'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if already responded
        if review.reviewee_response:
            return Response(
                {'error': 'Already responded to this review'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = ReviewResponseSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        review.reviewee_response = serializer.validated_data['response']
        review.save(update_fields=['reviewee_response', 'updated_at'])

        return Response({
            'status': 'response_added',
            'data': ReviewSerializer(review, context={'request': request}).data
        })


# ==================== CANDIDATE CV VIEWSET ====================

class CandidateCVViewSet(viewsets.ModelViewSet):
    """
    ViewSet for candidate CV management.

    Provides CRUD for own CVs with multi-CV management features.

    list: Get CVs (own only)
    retrieve: Get specific CV
    create: Create new CV
    update: Update CV
    destroy: Delete CV

    Custom actions:
    - set_primary: Set a CV as primary
    - best_match: Get best matching CV for a job description
    """
    serializer_class = CandidateCVSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status', 'is_primary']
    search_fields = ['name', 'headline', 'summary']
    ordering_fields = ['created_at', 'updated_at', 'times_used', 'is_primary']
    ordering = ['-is_primary', '-updated_at']
    lookup_field = 'uuid'

    def get_queryset(self):
        """Filter to own CVs only."""
        return CandidateCV.objects.filter(user=self.request.user)

    def get_serializer_class(self):
        if self.action == 'create':
            return CandidateCVCreateSerializer
        if self.action == 'best_match':
            return BestCVMatchSerializer
        return CandidateCVSerializer

    @action(detail=True, methods=['post'])
    def set_primary(self, request, uuid=None):
        """Set this CV as the primary CV."""
        cv = self.get_object()

        # Unset other primary CVs
        CandidateCV.objects.filter(
            user=request.user,
            is_primary=True
        ).exclude(pk=cv.pk).update(is_primary=False)

        cv.is_primary = True
        cv.save(update_fields=['is_primary', 'updated_at'])

        serializer = self.get_serializer(cv)
        return Response({
            'status': 'primary_set',
            'data': serializer.data
        })

    @action(detail=False, methods=['post'])
    def best_match(self, request):
        """Get the best matching CV for a job description."""
        serializer = BestCVMatchSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        job_description = serializer.validated_data['job_description']
        job_keywords = serializer.validated_data.get('job_keywords', [])

        best_cv = CandidateCV.get_best_match_for_job(
            user=request.user,
            job_description=job_description,
            job_keywords=job_keywords
        )

        if best_cv:
            return Response({
                'match_found': True,
                'cv': CandidateCVSerializer(best_cv, context={'request': request}).data
            })
        else:
            return Response({
                'match_found': False,
                'cv': None,
                'message': 'No CVs found. Please create a CV first.'
            })

    @action(detail=False, methods=['get'])
    def primary(self, request):
        """Get the primary CV."""
        try:
            cv = CandidateCV.objects.get(user=request.user, is_primary=True)
            serializer = self.get_serializer(cv)
            return Response(serializer.data)
        except CandidateCV.DoesNotExist:
            # Return first CV if no primary
            cv = CandidateCV.objects.filter(user=request.user).first()
            if cv:
                serializer = self.get_serializer(cv)
                return Response(serializer.data)
            return Response(
                {'error': 'No CVs found'},
                status=status.HTTP_404_NOT_FOUND
            )


# ==================== STUDENT PROFILE VIEWSET ====================

class StudentProfileViewSet(viewsets.ModelViewSet):
    """
    ViewSet for student profile management.

    Provides CRUD for own student profile with co-op term listing.

    list: Get student profiles (admin sees all, users see own)
    retrieve: Get specific student profile
    create: Create student profile
    update: Update student profile
    destroy: Delete student profile

    Custom actions:
    - me: Get or create current user's student profile
    - coop_terms: List co-op terms for a student profile
    """
    serializer_class = StudentProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = [
        'student_type', 'program_type', 'enrollment_status',
        'enrollment_verified', 'work_authorization'
    ]
    search_fields = ['institution_name', 'program_name', 'major', 'user__email']
    ordering_fields = ['created_at', 'expected_graduation', 'current_year']
    ordering = ['-created_at']
    lookup_field = 'uuid'

    def get_queryset(self):
        """Filter based on user role."""
        user = self.request.user
        tenant = getattr(self.request, 'tenant', None)

        # Check if user is admin in tenant
        if tenant:
            try:
                tenant_user = TenantUser.objects.get(
                    user=user, tenant=tenant, is_active=True
                )
                if tenant_user.is_admin or tenant_user.can_hire:
                    # Admins and hiring roles can see student profiles
                    return StudentProfile.objects.all().select_related('user')
            except TenantUser.DoesNotExist:
                pass

        # Regular users see only their own
        return StudentProfile.objects.filter(user=user).select_related('user')

    def get_serializer_class(self):
        if self.action == 'create':
            return StudentProfileCreateSerializer
        return StudentProfileSerializer

    @action(detail=False, methods=['get', 'post', 'put', 'patch'])
    def me(self, request):
        """Get, create, or update current user's student profile."""
        try:
            profile = StudentProfile.objects.get(user=request.user)
        except StudentProfile.DoesNotExist:
            if request.method == 'GET':
                return Response(
                    {'error': 'No student profile found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            profile = None

        if request.method == 'GET':
            serializer = StudentProfileSerializer(profile, context={'request': request})
            return Response(serializer.data)

        elif request.method == 'POST':
            if profile:
                return Response(
                    {'error': 'Student profile already exists'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            serializer = StudentProfileCreateSerializer(
                data=request.data,
                context={'request': request}
            )
            serializer.is_valid(raise_exception=True)
            profile = serializer.save()
            return Response(
                StudentProfileSerializer(profile, context={'request': request}).data,
                status=status.HTTP_201_CREATED
            )

        else:  # PUT or PATCH
            if not profile:
                return Response(
                    {'error': 'No student profile found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            serializer = StudentProfileSerializer(
                profile,
                data=request.data,
                partial=(request.method == 'PATCH'),
                context={'request': request}
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def coop_terms(self, request, uuid=None):
        """List co-op terms for a student profile."""
        profile = self.get_object()

        # Only allow access to own profile's terms unless admin
        if profile.user != request.user:
            tenant = getattr(request, 'tenant', None)
            if tenant:
                try:
                    tenant_user = TenantUser.objects.get(
                        user=request.user, tenant=tenant, is_active=True
                    )
                    if not (tenant_user.is_admin or tenant_user.can_hire):
                        return Response(
                            {'error': 'Access denied'},
                            status=status.HTTP_403_FORBIDDEN
                        )
                except TenantUser.DoesNotExist:
                    return Response(
                        {'error': 'Access denied'},
                        status=status.HTTP_403_FORBIDDEN
                    )

        terms = CoopTerm.objects.filter(student=profile).order_by('term_number')
        serializer = CoopTermSerializer(terms, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def my_coop_terms(self, request):
        """List current user's co-op terms."""
        try:
            profile = StudentProfile.objects.get(user=request.user)
        except StudentProfile.DoesNotExist:
            return Response(
                {'error': 'No student profile found'},
                status=status.HTTP_404_NOT_FOUND
            )

        terms = CoopTerm.objects.filter(student=profile).order_by('term_number')
        serializer = CoopTermSerializer(terms, many=True)
        return Response(serializer.data)
