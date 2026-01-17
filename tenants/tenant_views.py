"""
Tenants Views - REST API ViewSets and APIViews for tenant management.

This module provides:
- PlanViewSet: Public read-only plans
- TenantViewSet: Owner-only tenant management
- TenantSettingsViewSet: Settings management
- DomainViewSet: Custom domain management
- TenantInvitationViewSet: Invite/resend/revoke
- TenantUsageView: Usage statistics
- AuditLogViewSet: Read-only audit logs
- TenantOnboardingView: Setup wizard
- SubscriptionView: Subscription management
- Stripe webhook endpoints
"""

import logging
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from rest_framework import viewsets, views, status, filters
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django_filters.rest_framework import DjangoFilterBackend

from .models import (
    Plan, Tenant, TenantSettings, Domain,
    TenantInvitation, TenantUsage, AuditLog
)
from .serializers import (
    PlanSerializer, PlanDetailSerializer,
    TenantSerializer, TenantUpdateSerializer, TenantPublicSerializer,
    TenantSettingsSerializer, TenantSettingsUpdateSerializer,
    TenantSecuritySettingsSerializer, TenantIntegrationSettingsSerializer,
    DomainSerializer, DomainCreateSerializer,
    TenantInvitationSerializer, TenantInvitationCreateSerializer,
    TenantInvitationAcceptSerializer,
    TenantUsageSerializer,
    AuditLogSerializer, AuditLogListSerializer,
    TenantOnboardingSerializer, TenantOnboardingStatusSerializer,
    SubscriptionSerializer, SubscriptionStatusSerializer,
    SubscriptionUpgradeSerializer, SubscriptionCancelSerializer,
    StripeCheckoutSessionSerializer, StripeBillingPortalSerializer
)
from .permissions import (
    IsTenantOwner, IsTenantAdmin, IsTenantMember,
    CanManageBilling, CanInviteUsers, CanManageSettings,
    CanViewAnalytics, HasTenantFeature, IsTenantAdminOrReadOnly
)
from .services import TenantService, InvitationService, AuditService

logger = logging.getLogger(__name__)


# ==================== PLAN VIEWSET ====================

class PlanViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for subscription plans.
    Public read-only access for pricing pages.

    list: Get all active plans
    retrieve: Get specific plan details
    compare: Compare multiple plans
    """

    queryset = Plan.objects.filter(is_active=True).order_by('sort_order', 'price_monthly')
    serializer_class = PlanSerializer
    permission_classes = [AllowAny]
    lookup_field = 'slug'

    def get_serializer_class(self):
        # Admin users get full details including Stripe IDs
        if self.request.user.is_authenticated and self.request.user.is_staff:
            return PlanDetailSerializer
        return PlanSerializer

    @action(detail=False, methods=['get'])
    def compare(self, request):
        """
        Compare features across plans.
        Returns a feature matrix for comparison tables.
        """
        plans = self.get_queryset()
        serializer = self.get_serializer(plans, many=True)

        # Build feature comparison matrix
        feature_fields = [f for f in Plan._meta.get_fields() if f.name.startswith('feature_')]
        feature_matrix = []

        for field in feature_fields:
            feature_name = field.name.replace('feature_', '').replace('_', ' ').title()
            feature_data = {
                'name': feature_name,
                'key': field.name.replace('feature_', ''),
                'plans': {}
            }
            for plan in plans:
                feature_data['plans'][plan.slug] = getattr(plan, field.name)
            feature_matrix.append(feature_data)

        return Response({
            'plans': serializer.data,
            'features': feature_matrix
        })

    @action(detail=True, methods=['get'])
    def features(self, request, slug=None):
        """Get detailed features for a specific plan."""
        plan = self.get_object()
        serializer = self.get_serializer(plan)
        return Response(serializer.data['features'])


# ==================== TENANT VIEWSET ====================

class TenantViewSet(viewsets.ModelViewSet):
    """
    API endpoint for tenant management.
    Owner-only access for most operations.

    retrieve: Get tenant details
    update: Update tenant info
    partial_update: Partial update
    activate: Activate tenant
    suspend: Suspend tenant
    """

    serializer_class = TenantSerializer
    permission_classes = [IsAuthenticated, IsTenantOwner]
    lookup_field = 'uuid'

    def get_queryset(self):
        """Return only the current tenant."""
        tenant = getattr(self.request, 'tenant', None)
        if tenant:
            return Tenant.objects.filter(pk=tenant.pk)
        return Tenant.objects.none()

    def get_serializer_class(self):
        if self.action in ['update', 'partial_update']:
            return TenantUpdateSerializer
        return TenantSerializer

    def get_object(self):
        """Get the current tenant from request context."""
        tenant = getattr(self.request, 'tenant', None)
        if not tenant:
            from rest_framework.exceptions import NotFound
            raise NotFound("No tenant context found.")
        return tenant

    def retrieve(self, request, *args, **kwargs):
        """Get current tenant details."""
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        """Update tenant details."""
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        # Log the change
        old_data = TenantSerializer(instance).data
        self.perform_update(serializer)
        new_data = TenantSerializer(instance).data

        AuditService.log(
            tenant=instance,
            user=request.user,
            action=AuditLog.ActionType.UPDATE,
            resource_type='Tenant',
            resource_id=str(instance.uuid),
            description=f"Updated tenant settings",
            old_values=old_data,
            new_values=new_data,
            request=request
        )

        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def public(self, request):
        """Get public tenant information (for career pages)."""
        tenant = self.get_object()
        serializer = TenantPublicSerializer(tenant)
        return Response(serializer.data)


# ==================== TENANT SETTINGS VIEWSET ====================

class TenantSettingsViewSet(viewsets.ModelViewSet):
    """
    API endpoint for tenant settings management.

    retrieve: Get tenant settings
    update: Update settings
    partial_update: Partial update
    security: Update security settings
    integrations: Update integration settings
    """

    serializer_class = TenantSettingsSerializer
    permission_classes = [IsAuthenticated, CanManageSettings]
    http_method_names = ['get', 'put', 'patch']

    def get_queryset(self):
        """Return settings for current tenant."""
        tenant = getattr(self.request, 'tenant', None)
        if tenant:
            return TenantSettings.objects.filter(tenant=tenant)
        return TenantSettings.objects.none()

    def get_object(self):
        """Get or create settings for current tenant."""
        tenant = getattr(self.request, 'tenant', None)
        if not tenant:
            from rest_framework.exceptions import NotFound
            raise NotFound("No tenant context found.")

        settings_obj, created = TenantSettings.objects.get_or_create(tenant=tenant)
        return settings_obj

    def get_serializer_class(self):
        if self.action in ['update', 'partial_update']:
            return TenantSettingsUpdateSerializer
        return TenantSettingsSerializer

    def update(self, request, *args, **kwargs):
        """Update tenant settings."""
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        # Log the change
        old_data = TenantSettingsSerializer(instance).data
        self.perform_update(serializer)
        new_data = TenantSettingsSerializer(instance).data

        AuditService.log(
            tenant=instance.tenant,
            user=request.user,
            action=AuditLog.ActionType.SETTING_CHANGE,
            resource_type='TenantSettings',
            resource_id=str(instance.pk),
            description="Updated tenant settings",
            old_values=old_data,
            new_values=new_data,
            request=request
        )

        return Response(TenantSettingsSerializer(instance).data)

    @action(detail=False, methods=['get', 'patch'], permission_classes=[IsAuthenticated, IsTenantAdmin])
    def security(self, request):
        """Manage security-specific settings (admin only)."""
        instance = self.get_object()

        if request.method == 'PATCH':
            serializer = TenantSecuritySettingsSerializer(instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            AuditService.log(
                tenant=instance.tenant,
                user=request.user,
                action=AuditLog.ActionType.SETTING_CHANGE,
                resource_type='TenantSettings',
                resource_id=str(instance.pk),
                description="Updated security settings",
                new_values=serializer.data,
                request=request
            )

        serializer = TenantSecuritySettingsSerializer(instance)
        return Response(serializer.data)

    @action(detail=False, methods=['get', 'patch'])
    def integrations(self, request):
        """Manage integration settings."""
        instance = self.get_object()

        if request.method == 'PATCH':
            serializer = TenantIntegrationSettingsSerializer(instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()

        serializer = TenantIntegrationSettingsSerializer(instance)
        return Response(serializer.data)


# ==================== DOMAIN VIEWSET ====================

class DomainViewSet(viewsets.ModelViewSet):
    """
    API endpoint for custom domain management.

    list: Get all domains for tenant
    create: Add new domain
    destroy: Remove domain
    set_primary: Set domain as primary
    verify: Verify domain ownership
    """

    serializer_class = DomainSerializer
    permission_classes = [IsAuthenticated, IsTenantAdmin]

    def get_queryset(self):
        """Return domains for current tenant."""
        tenant = getattr(self.request, 'tenant', None)
        if tenant:
            return Domain.objects.filter(tenant=tenant)
        return Domain.objects.none()

    def get_serializer_class(self):
        if self.action == 'create':
            return DomainCreateSerializer
        return DomainSerializer

    def perform_create(self, serializer):
        """Create domain for current tenant."""
        tenant = getattr(self.request, 'tenant', None)

        # Check plan limits
        plan = tenant.plan
        current_count = Domain.objects.filter(tenant=tenant).count()

        # Enterprise plans typically allow more domains
        max_domains = 3 if plan and plan.plan_type in ['professional', 'enterprise'] else 1

        if current_count >= max_domains:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied(f"Your plan allows a maximum of {max_domains} domains.")

        serializer.save(tenant=tenant)

        AuditService.log(
            tenant=tenant,
            user=self.request.user,
            action=AuditLog.ActionType.CREATE,
            resource_type='Domain',
            resource_id=serializer.instance.domain,
            description=f"Added domain: {serializer.instance.domain}",
            request=self.request
        )

    def perform_destroy(self, instance):
        """Delete domain."""
        if instance.is_primary:
            from rest_framework.exceptions import ValidationError
            raise ValidationError("Cannot delete the primary domain.")

        AuditService.log(
            tenant=instance.tenant,
            user=self.request.user,
            action=AuditLog.ActionType.DELETE,
            resource_type='Domain',
            resource_id=instance.domain,
            description=f"Removed domain: {instance.domain}",
            request=self.request
        )

        instance.delete()

    @action(detail=True, methods=['post'])
    def set_primary(self, request, pk=None):
        """Set domain as primary."""
        domain = self.get_object()
        tenant = getattr(request, 'tenant', None)

        # Remove primary from all other domains
        Domain.objects.filter(tenant=tenant, is_primary=True).update(is_primary=False)

        # Set this as primary
        domain.is_primary = True
        domain.save()

        AuditService.log(
            tenant=tenant,
            user=request.user,
            action=AuditLog.ActionType.UPDATE,
            resource_type='Domain',
            resource_id=domain.domain,
            description=f"Set primary domain to: {domain.domain}",
            request=request
        )

        return Response(DomainSerializer(domain).data)

    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        """
        Verify domain ownership.
        Returns DNS records that need to be configured.
        """
        domain = self.get_object()

        # In production, this would check DNS records
        # For now, return the verification requirements
        verification_records = [
            {
                'type': 'CNAME',
                'name': f'zumodra-verify.{domain.domain}',
                'value': f'{domain.tenant.slug}.verify.zumodra.com'
            },
            {
                'type': 'TXT',
                'name': domain.domain,
                'value': f'zumodra-verification={domain.tenant.uuid}'
            }
        ]

        return Response({
            'domain': domain.domain,
            'is_verified': domain.verified_at is not None,
            'verification_records': verification_records,
            'message': 'Add these DNS records to verify domain ownership.'
        })


# ==================== INVITATION VIEWSET ====================

class TenantInvitationViewSet(viewsets.ModelViewSet):
    """
    API endpoint for tenant invitations.

    list: Get all invitations for tenant
    create: Send new invitation
    resend: Resend invitation email
    revoke: Cancel invitation
    accept: Accept invitation (public endpoint)
    """

    serializer_class = TenantInvitationSerializer
    permission_classes = [IsAuthenticated, CanInviteUsers]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['status', 'role']
    ordering_fields = ['created_at', 'expires_at']
    ordering = ['-created_at']

    def get_queryset(self):
        """Return invitations for current tenant."""
        tenant = getattr(self.request, 'tenant', None)
        if tenant:
            return TenantInvitation.objects.filter(tenant=tenant)
        return TenantInvitation.objects.none()

    def get_serializer_class(self):
        if self.action == 'create':
            return TenantInvitationCreateSerializer
        return TenantInvitationSerializer

    def get_serializer_context(self):
        """Add tenant to serializer context."""
        context = super().get_serializer_context()
        context['tenant'] = getattr(self.request, 'tenant', None)
        return context

    def perform_create(self, serializer):
        """Create and send invitation."""
        tenant = getattr(self.request, 'tenant', None)

        # Check plan limits for users
        if not TenantService.check_limit(tenant, 'users'):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("User limit reached. Please upgrade your plan.")

        invitation = InvitationService.create_invitation(
            tenant=tenant,
            email=serializer.validated_data['email'],
            invited_by=self.request.user,
            role=serializer.validated_data.get('role', 'member')
        )

        AuditService.log(
            tenant=tenant,
            user=self.request.user,
            action=AuditLog.ActionType.CREATE,
            resource_type='TenantInvitation',
            resource_id=str(invitation.uuid),
            description=f"Invited {invitation.email} as {invitation.role}",
            request=self.request
        )

    @action(detail=True, methods=['post'])
    def resend(self, request, pk=None):
        """Resend invitation email."""
        invitation = self.get_object()

        if invitation.status != TenantInvitation.InvitationStatus.PENDING:
            return Response(
                {'error': 'Can only resend pending invitations.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Refresh expiration
        invitation.expires_at = timezone.now() + timedelta(days=7)
        invitation.save()

        # Resend email
        InvitationService.send_invitation_email(invitation)

        AuditService.log(
            tenant=invitation.tenant,
            user=request.user,
            action=AuditLog.ActionType.UPDATE,
            resource_type='TenantInvitation',
            resource_id=str(invitation.uuid),
            description=f"Resent invitation to {invitation.email}",
            request=request
        )

        return Response({'message': 'Invitation resent successfully.'})

    @action(detail=True, methods=['post'])
    def revoke(self, request, pk=None):
        """Revoke/cancel invitation."""
        invitation = self.get_object()

        if invitation.status != TenantInvitation.InvitationStatus.PENDING:
            return Response(
                {'error': 'Can only revoke pending invitations.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        invitation.status = TenantInvitation.InvitationStatus.REVOKED
        invitation.save()

        AuditService.log(
            tenant=invitation.tenant,
            user=request.user,
            action=AuditLog.ActionType.DELETE,
            resource_type='TenantInvitation',
            resource_id=str(invitation.uuid),
            description=f"Revoked invitation for {invitation.email}",
            request=request
        )

        return Response({'message': 'Invitation revoked.'})

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def accept(self, request):
        """Accept an invitation (authenticated users)."""
        serializer = TenantInvitationAcceptSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        invitation = InvitationService.accept_invitation(
            token=serializer.validated_data['token'],
            user=request.user
        )

        if not invitation:
            return Response(
                {'error': 'Invalid or expired invitation.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response({
            'message': 'Invitation accepted successfully.',
            'tenant': TenantPublicSerializer(invitation.tenant).data
        })


# ==================== USAGE VIEW ====================

class TenantUsageView(views.APIView):
    """
    API endpoint for tenant usage statistics.

    get: Get current usage vs plan limits
    refresh: Force refresh usage calculations
    """

    permission_classes = [IsAuthenticated, IsTenantMember]

    def get(self, request):
        """Get current tenant usage statistics."""
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return Response(
                {'error': 'No tenant context found.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        usage, created = TenantUsage.objects.get_or_create(tenant=tenant)
        serializer = TenantUsageSerializer(usage)
        return Response(serializer.data)

    def post(self, request):
        """Force refresh usage calculations."""
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return Response(
                {'error': 'No tenant context found.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        usage = TenantService.update_usage(tenant)
        serializer = TenantUsageSerializer(usage)
        return Response(serializer.data)


# ==================== AUDIT LOG VIEWSET ====================

class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for tenant audit logs.
    Read-only with filtering capabilities.

    list: Get audit logs with filters
    retrieve: Get specific log entry
    export: Export logs to CSV
    """

    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated, CanViewAnalytics]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['action', 'resource_type', 'user']
    search_fields = ['description', 'resource_id']
    ordering_fields = ['created_at']
    ordering = ['-created_at']

    def get_queryset(self):
        """Return audit logs for current tenant."""
        tenant = getattr(self.request, 'tenant', None)
        if tenant:
            queryset = AuditLog.objects.filter(tenant=tenant)

            # Date range filtering
            start_date = self.request.query_params.get('start_date')
            end_date = self.request.query_params.get('end_date')

            if start_date:
                queryset = queryset.filter(created_at__gte=start_date)
            if end_date:
                queryset = queryset.filter(created_at__lte=end_date)

            return queryset
        return AuditLog.objects.none()

    def get_serializer_class(self):
        if self.action == 'list':
            return AuditLogListSerializer
        return AuditLogSerializer

    @action(detail=False, methods=['get'])
    def export(self, request):
        """Export audit logs to CSV."""
        # Check feature access
        tenant = getattr(request, 'tenant', None)
        if not tenant or not tenant.plan or not tenant.plan.feature_audit_logs:
            return Response(
                {'error': 'Audit log export requires a plan with audit logs feature.'},
                status=status.HTTP_403_FORBIDDEN
            )

        queryset = self.filter_queryset(self.get_queryset())

        # Build CSV response
        import csv
        from django.http import HttpResponse

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="audit_logs_{timezone.now().strftime("%Y%m%d")}.csv"'

        writer = csv.writer(response)
        writer.writerow(['Timestamp', 'User', 'Action', 'Resource Type', 'Resource ID', 'Description', 'IP Address'])

        for log in queryset[:10000]:  # Limit export size
            writer.writerow([
                log.created_at.isoformat(),
                log.user.email if log.user else 'System',
                log.action,
                log.resource_type,
                log.resource_id,
                log.description,
                log.ip_address
            ])

        return response


# ==================== ONBOARDING VIEW ====================

class TenantOnboardingView(views.APIView):
    """
    API endpoint for tenant onboarding wizard.

    get: Get onboarding status
    post: Submit onboarding step
    """

    permission_classes = [IsAuthenticated, IsTenantOwner]

    def get(self, request):
        """Get onboarding status and progress."""
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return Response(
                {'error': 'No tenant context found.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Define onboarding steps
        steps = [
            {
                'id': 1,
                'name': 'Company Info',
                'completed': bool(tenant.name and tenant.industry)
            },
            {
                'id': 2,
                'name': 'Branding',
                'completed': bool(tenant.logo)
            },
            {
                'id': 3,
                'name': 'Settings',
                'completed': hasattr(tenant, 'settings')
            },
            {
                'id': 4,
                'name': 'Team',
                'completed': TenantInvitation.objects.filter(tenant=tenant).exists()
            }
        ]

        completed_count = sum(1 for s in steps if s['completed'])
        current_step = next((s['id'] for s in steps if not s['completed']), len(steps) + 1)

        return Response({
            'is_complete': completed_count == len(steps),
            'current_step': current_step,
            'total_steps': len(steps),
            'steps': steps,
            'completion_percentage': int((completed_count / len(steps)) * 100)
        })

    @transaction.atomic
    def post(self, request):
        """Submit onboarding data."""
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return Response(
                {'error': 'No tenant context found.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = TenantOnboardingSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # Update tenant info
        if 'company_name' in data:
            tenant.name = data['company_name']
        if 'industry' in data:
            tenant.industry = data['industry']
        if 'company_size' in data:
            tenant.company_size = data['company_size']
        if 'website' in data:
            tenant.website = data['website']
        if 'logo' in data:
            tenant.logo = data['logo']

        tenant.save()

        # Update/create settings
        settings_obj, _ = TenantSettings.objects.get_or_create(tenant=tenant)
        if 'primary_color' in data:
            settings_obj.primary_color = data['primary_color']
        if 'default_timezone' in data:
            settings_obj.default_timezone = data['default_timezone']
        if 'default_language' in data:
            settings_obj.default_language = data['default_language']

        settings_obj.save()

        # Process invitations
        invitations = data.get('invitations', [])
        for inv in invitations:
            if 'email' in inv:
                InvitationService.create_invitation(
                    tenant=tenant,
                    email=inv['email'],
                    invited_by=request.user,
                    role=inv.get('role', 'member')
                )

        return Response({
            'message': 'Onboarding data saved successfully.',
            'tenant': TenantSerializer(tenant).data
        })


# ==================== SUBSCRIPTION VIEW ====================

class SubscriptionView(views.APIView):
    """
    API endpoint for subscription management.

    get: Get current subscription status
    post: Create/upgrade subscription
    put: Update subscription
    delete: Cancel subscription
    """

    permission_classes = [IsAuthenticated, CanManageBilling]

    def get(self, request):
        """Get current subscription status."""
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return Response(
                {'error': 'No tenant context found.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response({
            'status': tenant.status,
            'plan': PlanSerializer(tenant.plan).data if tenant.plan else None,
            'on_trial': tenant.is_on_trial,
            'trial_ends_at': tenant.trial_ends_at,
            'trial_days_remaining': tenant.trial_days_remaining,
            'paid_until': tenant.paid_until,
            'stripe_customer_id': tenant.stripe_customer_id,
            'stripe_subscription_id': tenant.stripe_subscription_id
        })

    def post(self, request):
        """Create checkout session for subscription."""
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return Response(
                {'error': 'No tenant context found.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = StripeCheckoutSessionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # Get plan
        try:
            plan = Plan.objects.get(pk=data['plan_id'], is_active=True)
        except Plan.DoesNotExist:
            return Response(
                {'error': 'Invalid plan selected.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get appropriate Stripe price ID
        billing_cycle = data['billing_cycle']
        price_id = plan.stripe_price_id_yearly if billing_cycle == 'yearly' else plan.stripe_price_id_monthly

        if not price_id:
            return Response(
                {'error': 'Stripe pricing not configured for this plan.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            import stripe
            stripe.api_key = settings.STRIPE_SECRET_KEY

            # Create or get Stripe customer
            if not tenant.stripe_customer_id:
                customer = stripe.Customer.create(
                    email=tenant.owner_email,
                    name=tenant.name,
                    metadata={'tenant_uuid': str(tenant.uuid)}
                )
                tenant.stripe_customer_id = customer.id
                tenant.save(update_fields=['stripe_customer_id'])

            # Create checkout session
            checkout_session = stripe.checkout.Session.create(
                customer=tenant.stripe_customer_id,
                payment_method_types=['card'],
                line_items=[{
                    'price': price_id,
                    'quantity': 1
                }],
                mode='subscription',
                success_url=data['success_url'],
                cancel_url=data['cancel_url'],
                metadata={
                    'tenant_uuid': str(tenant.uuid),
                    'plan_id': plan.id
                }
            )

            AuditService.log(
                tenant=tenant,
                user=request.user,
                action=AuditLog.ActionType.CREATE,
                resource_type='Subscription',
                description=f"Initiated subscription checkout for {plan.name}",
                request=request
            )

            return Response({
                'checkout_url': checkout_session.url,
                'session_id': checkout_session.id
            })

        except Exception as e:
            logger.error(f"Stripe checkout error: {e}")
            return Response(
                {'error': 'Failed to create checkout session.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request):
        """Upgrade/downgrade subscription."""
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return Response(
                {'error': 'No tenant context found.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not tenant.stripe_subscription_id:
            return Response(
                {'error': 'No active subscription to modify.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = SubscriptionUpgradeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            plan = Plan.objects.get(pk=data['plan_id'], is_active=True)
        except Plan.DoesNotExist:
            return Response(
                {'error': 'Invalid plan selected.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            import stripe
            stripe.api_key = settings.STRIPE_SECRET_KEY

            # Get current subscription
            subscription = stripe.Subscription.retrieve(tenant.stripe_subscription_id)

            # Update subscription with new price
            stripe.Subscription.modify(
                tenant.stripe_subscription_id,
                items=[{
                    'id': subscription['items']['data'][0].id,
                    'price': plan.stripe_price_id_monthly
                }],
                proration_behavior='create_prorations' if data.get('prorate', True) else 'none'
            )

            # Update tenant plan
            tenant.plan = plan
            tenant.save(update_fields=['plan'])

            AuditService.log(
                tenant=tenant,
                user=request.user,
                action=AuditLog.ActionType.UPDATE,
                resource_type='Subscription',
                description=f"Changed plan to {plan.name}",
                request=request
            )

            return Response({
                'message': 'Subscription updated successfully.',
                'plan': PlanSerializer(plan).data
            })

        except Exception as e:
            logger.error(f"Stripe subscription update error: {e}")
            return Response(
                {'error': 'Failed to update subscription.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def delete(self, request):
        """Cancel subscription."""
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return Response(
                {'error': 'No tenant context found.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not tenant.stripe_subscription_id:
            return Response(
                {'error': 'No active subscription to cancel.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = SubscriptionCancelSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            import stripe
            stripe.api_key = settings.STRIPE_SECRET_KEY

            if data.get('cancel_immediately', False):
                stripe.Subscription.delete(tenant.stripe_subscription_id)
            else:
                stripe.Subscription.modify(
                    tenant.stripe_subscription_id,
                    cancel_at_period_end=True
                )

            AuditService.log(
                tenant=tenant,
                user=request.user,
                action=AuditLog.ActionType.DELETE,
                resource_type='Subscription',
                description=f"Cancelled subscription (immediate: {data.get('cancel_immediately', False)})",
                new_values={'feedback': data.get('feedback', '')},
                request=request
            )

            return Response({
                'message': 'Subscription cancelled.',
                'cancel_at_period_end': not data.get('cancel_immediately', False)
            })

        except Exception as e:
            logger.error(f"Stripe subscription cancel error: {e}")
            return Response(
                {'error': 'Failed to cancel subscription.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BillingPortalView(views.APIView):
    """
    API endpoint to create Stripe billing portal session.
    """

    permission_classes = [IsAuthenticated, CanManageBilling]

    def post(self, request):
        """Create Stripe billing portal session."""
        tenant = getattr(request, 'tenant', None)
        if not tenant or not tenant.stripe_customer_id:
            return Response(
                {'error': 'No billing information found.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = StripeBillingPortalSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            import stripe
            stripe.api_key = settings.STRIPE_SECRET_KEY

            session = stripe.billing_portal.Session.create(
                customer=tenant.stripe_customer_id,
                return_url=serializer.validated_data['return_url']
            )

            return Response({'portal_url': session.url})

        except Exception as e:
            logger.error(f"Stripe billing portal error: {e}")
            return Response(
                {'error': 'Failed to create billing portal session.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ==================== STRIPE WEBHOOK VIEW ====================

@method_decorator(csrf_exempt, name='dispatch')
class StripeWebhookView(views.APIView):
    """
    Stripe webhook endpoint for subscription events.

    Handles:
    - checkout.session.completed
    - customer.subscription.created
    - customer.subscription.updated
    - customer.subscription.deleted
    - invoice.paid
    - invoice.payment_failed
    """

    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        """Process Stripe webhook event."""
        import stripe
        stripe.api_key = settings.STRIPE_SECRET_KEY

        payload = request.body
        sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
        webhook_secret = getattr(settings, 'STRIPE_WEBHOOK_SECRET', None)

        try:
            if webhook_secret:
                event = stripe.Webhook.construct_event(
                    payload, sig_header, webhook_secret
                )
            else:
                # For testing without webhook signature verification
                import json
                event = stripe.Event.construct_from(
                    json.loads(payload), stripe.api_key
                )
        except ValueError as e:
            logger.error(f"Invalid webhook payload: {e}")
            return Response(status=status.HTTP_400_BAD_REQUEST)
        except stripe.error.SignatureVerificationError as e:
            logger.error(f"Invalid webhook signature: {e}")
            return Response(status=status.HTTP_400_BAD_REQUEST)

        # Handle the event
        event_type = event['type']
        event_data = event['data']['object']

        logger.info(f"Processing Stripe webhook: {event_type}")

        try:
            if event_type == 'checkout.session.completed':
                self._handle_checkout_completed(event_data)

            elif event_type == 'customer.subscription.created':
                self._handle_subscription_created(event_data)

            elif event_type == 'customer.subscription.updated':
                self._handle_subscription_updated(event_data)

            elif event_type == 'customer.subscription.deleted':
                self._handle_subscription_deleted(event_data)

            elif event_type == 'invoice.paid':
                self._handle_invoice_paid(event_data)

            elif event_type == 'invoice.payment_failed':
                self._handle_invoice_failed(event_data)

        except Exception as e:
            logger.error(f"Webhook processing error: {e}")
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'status': 'success'})

    def _get_tenant_from_customer(self, customer_id):
        """Get tenant from Stripe customer ID."""
        try:
            return Tenant.objects.get(stripe_customer_id=customer_id)
        except Tenant.DoesNotExist:
            logger.warning(f"Tenant not found for Stripe customer: {customer_id}")
            return None

    def _handle_checkout_completed(self, session):
        """Handle successful checkout."""
        tenant_uuid = session.get('metadata', {}).get('tenant_uuid')
        if not tenant_uuid:
            return

        try:
            tenant = Tenant.objects.get(uuid=tenant_uuid)
            tenant.stripe_subscription_id = session.get('subscription')
            tenant.save(update_fields=['stripe_subscription_id'])
            logger.info(f"Checkout completed for tenant: {tenant.name}")
        except Tenant.DoesNotExist:
            logger.warning(f"Tenant not found: {tenant_uuid}")

    def _handle_subscription_created(self, subscription):
        """Handle new subscription."""
        tenant = self._get_tenant_from_customer(subscription['customer'])
        if not tenant:
            return

        tenant.stripe_subscription_id = subscription['id']
        tenant.status = Tenant.TenantStatus.ACTIVE
        tenant.on_trial = False
        tenant.activated_at = timezone.now()
        tenant.save()

        logger.info(f"Subscription created for tenant: {tenant.name}")

    def _handle_subscription_updated(self, subscription):
        """Handle subscription update."""
        tenant = self._get_tenant_from_customer(subscription['customer'])
        if not tenant:
            return

        # Update paid_until from current_period_end
        if subscription.get('current_period_end'):
            from datetime import datetime
            tenant.paid_until = datetime.fromtimestamp(
                subscription['current_period_end'],
                tz=timezone.utc
            )
            tenant.save(update_fields=['paid_until'])

        logger.info(f"Subscription updated for tenant: {tenant.name}")

    def _handle_subscription_deleted(self, subscription):
        """Handle subscription cancellation."""
        tenant = self._get_tenant_from_customer(subscription['customer'])
        if not tenant:
            return

        tenant.status = Tenant.TenantStatus.CANCELLED
        tenant.stripe_subscription_id = ''
        tenant.save(update_fields=['status', 'stripe_subscription_id'])

        logger.info(f"Subscription cancelled for tenant: {tenant.name}")

    def _handle_invoice_paid(self, invoice):
        """Handle successful payment."""
        tenant = self._get_tenant_from_customer(invoice['customer'])
        if not tenant:
            return

        # Extend paid_until
        if invoice.get('period_end'):
            from datetime import datetime
            tenant.paid_until = datetime.fromtimestamp(
                invoice['period_end'],
                tz=timezone.utc
            )
            tenant.status = Tenant.TenantStatus.ACTIVE
            tenant.save(update_fields=['paid_until', 'status'])

        logger.info(f"Invoice paid for tenant: {tenant.name}")

    def _handle_invoice_failed(self, invoice):
        """Handle failed payment."""
        tenant = self._get_tenant_from_customer(invoice['customer'])
        if not tenant:
            return

        # Could suspend after multiple failures
        # For now, just log
        logger.warning(f"Invoice payment failed for tenant: {tenant.name}")


# ==================== FEATURE FLAG VIEW ====================

class FeatureFlagView(views.APIView):
    """
    API endpoint to check feature availability.

    get: Check if tenant has access to specific features
    """

    permission_classes = [IsAuthenticated, IsTenantMember]

    def get(self, request):
        """Check feature availability for current tenant."""
        tenant = getattr(request, 'tenant', None)
        if not tenant or not tenant.plan:
            return Response(
                {'error': 'No active plan found.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        plan = tenant.plan

        # Build feature map
        features = {}
        for field in plan._meta.get_fields():
            if field.name.startswith('feature_'):
                key = field.name.replace('feature_', '')
                features[key] = getattr(plan, field.name)

        return Response({
            'plan': plan.name,
            'plan_type': plan.plan_type,
            'features': features,
            'limits': {
                'max_users': plan.max_users,
                'max_job_postings': plan.max_job_postings,
                'max_candidates_per_month': plan.max_candidates_per_month,
                'max_circusales': plan.max_circusales,
                'storage_limit_gb': plan.storage_limit_gb
            }
        })

    def post(self, request):
        """Check specific feature availability."""
        tenant = getattr(request, 'tenant', None)
        if not tenant or not tenant.plan:
            return Response({'has_access': False})

        feature = request.data.get('feature')
        if not feature:
            return Response(
                {'error': 'Feature name required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        feature_attr = f'feature_{feature}'
        has_access = getattr(tenant.plan, feature_attr, False)

        return Response({
            'feature': feature,
            'has_access': has_access,
            'plan': tenant.plan.name
        })


# ==================== EIN VERIFICATION API ENDPOINTS ====================

def _verify_ein_with_external_service(ein_number):
    """
    Verify EIN with external service (IRS or third-party provider).

    This function is a placeholder for actual API integration.
    When an external EIN verification API becomes available, implement the
    API call here.

    Args:
        ein_number: EIN in format XX-XXXXXXX

    Returns:
        dict: {
            'status': 'verified' | 'pending' | 'invalid',
            'message': str,
            'details': dict (optional)
        }
    """
    # See TODO-TENANTS-001 in tenants/TODO.md for EIN verification API integration
    # Example implementation:
    #
    # import requests
    # API_KEY = settings.EIN_VERIFICATION_API_KEY
    # API_URL = settings.EIN_VERIFICATION_API_URL
    #
    # try:
    #     response = requests.post(
    #         f"{API_URL}/verify",
    #         json={'ein': ein_number},
    #         headers={'Authorization': f'Bearer {API_KEY}'},
    #         timeout=10
    #     )
    #     if response.status_code == 200:
    #         data = response.json()
    #         return {
    #             'status': 'verified' if data['valid'] else 'invalid',
    #             'message': data.get('message', 'EIN verified'),
    #             'details': data
    #         }
    # except Exception as e:
    #     logger.error(f"EIN verification API error: {e}")
    #     return {
    #         'status': 'pending',
    #         'message': 'EIN verification is pending. We will notify you once complete.'
    #     }

    # For now, return pending status
    return {
        'status': 'pending',
        'message': _('EIN submitted for verification. We will verify and notify you once complete.')
    }


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def submit_ein_verification(request):
    """
    Submit EIN for business verification.

    POST /api/verify/ein/

    Request body:
    - ein_number: EIN in format XX-XXXXXXX

    Requires: User must be part of a tenant
    """
    from .serializers import EINVerificationSerializer

    # Must be part of a tenant
    if not hasattr(request, 'tenant') or not request.tenant:
        return Response(
            {'error': _('You must be part of a tenant to verify EIN.')},
            status=status.HTTP_403_FORBIDDEN
        )

    serializer = EINVerificationSerializer(data=request.data)

    if serializer.is_valid():
        ein_number = serializer.validated_data['ein_number']

        # Update tenant with EIN
        tenant = request.tenant
        tenant.ein_number = ein_number

        # Verify EIN through external service
        verification_result = _verify_ein_with_external_service(ein_number)

        # Update tenant verification status based on result
        if verification_result['status'] == 'verified':
            tenant.ein_verified = True
            tenant.ein_verified_at = timezone.now()
        elif verification_result['status'] == 'pending':
            tenant.ein_verified = False

        tenant.save(update_fields=['ein_number', 'ein_verified', 'ein_verified_at'])

        return Response({
            'status': verification_result['status'],
            'message': verification_result['message'],
            'ein_number': ein_number,
        }, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_ein_verification_status(request):
    """
    Get EIN verification status for tenant.

    GET /api/verify/ein/status/

    Requires: User must be part of a tenant
    """
    if not hasattr(request, 'tenant') or not request.tenant:
        return Response(
            {'error': _('You must be part of a tenant.')},
            status=status.HTTP_403_FORBIDDEN
        )

    tenant = request.tenant

    return Response({
        'ein_number': tenant.ein_number,
        'ein_verified': tenant.ein_verified,
        'ein_verified_at': tenant.ein_verified_at,
    })
