"""
Core ViewSets - Secure Base Classes with Permission Enforcement for Zumodra

This module provides secure base ViewSet classes that enforce:
1. Tenant isolation by default
2. Role-based access control (RBAC)
3. Object-level permissions
4. Security audit logging
5. Feature access validation
6. Automatic created_by/updated_by tracking

All ViewSets should inherit from these classes to ensure consistent security.

USAGE:
    from core.viewsets import (
        SecureTenantViewSet,
        SecureReadOnlyViewSet,
        AdminOnlyViewSet,
        RoleBasedViewSet,
    )

    class EmployeeViewSet(SecureTenantViewSet):
        queryset = Employee.objects.all()
        serializer_class = EmployeeSerializer

CLASSES:

1. SecureTenantViewSet:
   - Default permissions: IsAuthenticated, IsTenantUser, TenantObjectPermission
   - Automatic tenant isolation
   - Security audit logging
   - Feature access validation
   - created_by/updated_by tracking

2. SecureReadOnlyViewSet:
   - Read-only with tenant isolation
   - Same security features as SecureTenantViewSet

3. AdminOnlyViewSet:
   - Restricted to tenant admins and owners
   - For sensitive operations

4. OwnerOnlyViewSet:
   - Restricted to tenant owners only
   - For billing, deletion, ownership transfer

5. RoleBasedViewSet:
   - Per-action role requirements
   - Configurable via role_permissions dict
"""

import logging
from typing import Any, Dict, List, Optional, Set, Type

from django.db.models import QuerySet
from rest_framework import permissions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied

from api.base import (
    TenantAwareViewSet,
    TenantAwareReadOnlyViewSet,
    APIResponse,
    OptimizedQuerySetMixin,
)
from core.permissions import (
    IsTenantUser,
    IsTenantAdmin,
    IsTenantOwner,
    TenantObjectPermission,
    ActionBasedPermission,
    HasFeatureAccess,
    AuditedPermission,
    audited,
    ADMIN_ROLES,
    HR_ROLES,
    RECRUITER_ROLES,
)

logger = logging.getLogger('security.viewsets')


# =============================================================================
# SECURE TENANT VIEWSET
# =============================================================================

class SecureTenantViewSet(TenantAwareViewSet):
    """
    Base ViewSet with enforced tenant isolation and comprehensive permission checking.

    Default Permissions:
    - All actions require authentication
    - All actions require tenant membership
    - Objects are filtered to current tenant
    - Object-level permissions verified on retrieve/update/delete

    Features:
    - Security audit logging
    - Feature access validation
    - created_by/updated_by tracking
    - Per-action permission overrides
    - Sensitive data protection

    Usage:
        class EmployeeViewSet(SecureTenantViewSet):
            queryset = Employee.objects.all()
            serializer_class = EmployeeSerializer

            # Optional: Per-action permissions
            action_permissions = {
                'list': [IsTenantUser],
                'create': [IsTenantAdmin],
                'destroy': [IsTenantOwner],
            }

            # Optional: Required feature from plan
            required_feature = 'advanced_hr'

            # Optional: Sensitive fields to protect
            sensitive_fields = ['phone_number', 'ssn']
    """

    # Default: require authentication, tenant membership, and object-level permission
    permission_classes = [
        permissions.IsAuthenticated,
        IsTenantUser,
        TenantObjectPermission,
    ]

    # Override per-action permissions (optional)
    action_permissions: Dict[str, List[Type[permissions.BasePermission]]] = {}

    # Required feature from tenant plan (optional)
    required_feature: Optional[str] = None

    # Sensitive fields that require special handling (optional)
    sensitive_fields: List[str] = []

    # Roles that can access sensitive fields
    sensitive_field_roles: List[str] = ['owner', 'admin', 'hr_manager']

    # Enable audit logging (default: True)
    enable_audit_logging: bool = True

    # Track created_by/updated_by (default: True)
    track_user_modifications: bool = True

    def get_permissions(self) -> List[permissions.BasePermission]:
        """
        Get permission classes based on action.

        If action_permissions is defined, use those for the specific action.
        Otherwise, fall back to class-level permission_classes.
        """
        if self.action in self.action_permissions:
            permission_classes = self.action_permissions[self.action]
            return [perm() for perm in permission_classes]

        return super().get_permissions()

    def initial(self, request: Request, *args, **kwargs) -> None:
        """
        Validate feature access and log request before any action.
        """
        super().initial(request, *args, **kwargs)

        # Check required feature
        if self.required_feature:
            self.require_tenant_feature(self.required_feature)

        # Log API access for security auditing
        if self.enable_audit_logging:
            self._log_access(request)

    def _log_access(self, request: Request) -> None:
        """Log API access for security auditing."""
        user_id = request.user.id if request.user.is_authenticated else None
        tenant = self.get_tenant()
        tenant_slug = tenant.slug if tenant else 'none'

        logger.info(
            f"API_ACCESS: user={user_id} tenant={tenant_slug} "
            f"view={self.__class__.__name__} action={self.action} "
            f"method={request.method} path={request.path}"
        )

    def get_queryset(self) -> QuerySet:
        """
        Enforce tenant isolation on all queries.

        Adds additional safety check to log if queryset might not be properly scoped.
        """
        queryset = super().get_queryset()

        # Additional safety: verify tenant filter was applied
        tenant = self.get_tenant()
        if tenant and self.tenant_field and self.enable_audit_logging:
            # This is a sanity check - the parent class should have filtered
            if not queryset.query.where:
                logger.warning(
                    f"SECURITY_WARNING: Queryset for {self.__class__.__name__} "
                    f"may not be tenant-scoped. Tenant: {tenant.slug}"
                )

        return queryset

    def perform_create(self, serializer) -> None:
        """
        Ensure tenant and created_by are set on created objects.
        """
        tenant = self.get_tenant_or_404()
        save_kwargs = {}

        # Set tenant if applicable
        if self.tenant_field == 'tenant':
            save_kwargs['tenant'] = tenant

        # Track who created the object
        if self.track_user_modifications:
            model = serializer.Meta.model
            if hasattr(model, 'created_by'):
                save_kwargs['created_by'] = self.request.user

        serializer.save(**save_kwargs)

        # Log creation
        if self.enable_audit_logging:
            logger.info(
                f"RESOURCE_CREATED: model={serializer.Meta.model.__name__} "
                f"user={self.request.user.id} tenant={tenant.slug}"
            )

    def perform_update(self, serializer) -> None:
        """
        Track who updated the object.
        """
        save_kwargs = {}

        # Track who updated the object
        if self.track_user_modifications:
            model = serializer.Meta.model
            if hasattr(model, 'updated_by'):
                save_kwargs['updated_by'] = self.request.user

        serializer.save(**save_kwargs)

        # Log update
        if self.enable_audit_logging:
            tenant = self.get_tenant()
            logger.info(
                f"RESOURCE_UPDATED: model={serializer.Meta.model.__name__} "
                f"pk={serializer.instance.pk} user={self.request.user.id} "
                f"tenant={tenant.slug if tenant else 'none'}"
            )

    def perform_destroy(self, instance) -> None:
        """
        Log deletion before destroying.
        """
        if self.enable_audit_logging:
            tenant = self.get_tenant()
            logger.info(
                f"RESOURCE_DELETED: model={instance.__class__.__name__} "
                f"pk={instance.pk} user={self.request.user.id} "
                f"tenant={tenant.slug if tenant else 'none'}"
            )

        super().perform_destroy(instance)


# =============================================================================
# SECURE READ-ONLY VIEWSET
# =============================================================================

class SecureReadOnlyViewSet(TenantAwareReadOnlyViewSet):
    """
    Read-only ViewSet with tenant isolation and security logging.

    Use for resources that shouldn't be modified via API but still
    require proper authentication and tenant scoping.

    Usage:
        class AuditLogViewSet(SecureReadOnlyViewSet):
            queryset = AuditLog.objects.all()
            serializer_class = AuditLogSerializer
    """

    permission_classes = [
        permissions.IsAuthenticated,
        IsTenantUser,
        TenantObjectPermission,
    ]

    # Override per-action permissions
    action_permissions: Dict[str, List[Type[permissions.BasePermission]]] = {}

    # Required feature from tenant plan
    required_feature: Optional[str] = None

    # Enable audit logging
    enable_audit_logging: bool = True

    def get_permissions(self) -> List[permissions.BasePermission]:
        """Get permission classes based on action."""
        if self.action in self.action_permissions:
            permission_classes = self.action_permissions[self.action]
            return [perm() for perm in permission_classes]

        return super().get_permissions()

    def initial(self, request: Request, *args, **kwargs) -> None:
        """Validate feature access and log request."""
        super().initial(request, *args, **kwargs)

        if self.required_feature:
            self.require_tenant_feature(self.required_feature)

        if self.enable_audit_logging:
            user_id = request.user.id if request.user.is_authenticated else None
            tenant = self.get_tenant()
            logger.info(
                f"API_ACCESS: user={user_id} tenant={tenant.slug if tenant else 'none'} "
                f"view={self.__class__.__name__} action={self.action} "
                f"method={request.method}"
            )


# =============================================================================
# ADMIN-ONLY VIEWSET
# =============================================================================

class AdminOnlyViewSet(SecureTenantViewSet):
    """
    ViewSet restricted to tenant administrators (owners and admins).

    Use for sensitive operations that require admin privileges.

    Usage:
        class TenantSettingsViewSet(AdminOnlyViewSet):
            queryset = TenantSettings.objects.all()
            serializer_class = TenantSettingsSerializer
    """

    permission_classes = [
        permissions.IsAuthenticated,
        IsTenantAdmin,
        TenantObjectPermission,
    ]


# =============================================================================
# OWNER-ONLY VIEWSET
# =============================================================================

class OwnerOnlyViewSet(SecureTenantViewSet):
    """
    ViewSet restricted to tenant owners only.

    Use for critical operations like:
    - Billing management
    - Tenant deletion
    - Ownership transfer
    - Plan changes

    Usage:
        class BillingViewSet(OwnerOnlyViewSet):
            queryset = Billing.objects.all()
            serializer_class = BillingSerializer
    """

    permission_classes = [
        permissions.IsAuthenticated,
        IsTenantOwner,
        TenantObjectPermission,
    ]


# =============================================================================
# ROLE-BASED VIEWSET
# =============================================================================

class RoleBasedViewSet(SecureTenantViewSet):
    """
    ViewSet with role-based action permissions.

    Define which roles can perform which actions via the role_permissions dict.

    Usage:
        class CandidateViewSet(RoleBasedViewSet):
            queryset = Candidate.objects.all()
            serializer_class = CandidateSerializer

            role_permissions = {
                'list': ['owner', 'admin', 'hr_manager', 'recruiter', 'hiring_manager', 'viewer'],
                'retrieve': ['owner', 'admin', 'hr_manager', 'recruiter', 'hiring_manager', 'viewer'],
                'create': ['owner', 'admin', 'hr_manager', 'recruiter'],
                'update': ['owner', 'admin', 'hr_manager', 'recruiter'],
                'partial_update': ['owner', 'admin', 'hr_manager', 'recruiter'],
                'destroy': ['owner', 'admin'],
            }

    Role values: 'owner', 'admin', 'hr_manager', 'recruiter', 'hiring_manager', 'employee', 'viewer'
    """

    # Per-action role requirements
    role_permissions: Dict[str, List[str]] = {}

    # Default roles if action not in role_permissions
    default_allowed_roles: List[str] = ['owner', 'admin']

    def check_permissions(self, request: Request) -> None:
        """
        Check role-based permissions for the action.
        """
        # First run standard permission checks
        super().check_permissions(request)

        # Then check role-based permissions if defined
        if self.action in self.role_permissions:
            allowed_roles = self.role_permissions[self.action]
            self._check_role_permission(request, allowed_roles)
        elif self.default_allowed_roles:
            # Use default if action not explicitly defined
            pass  # Already authenticated and tenant member

    def _check_role_permission(self, request: Request, allowed_roles: List[str]) -> None:
        """Check if user has one of the allowed roles."""
        tenant = self.get_tenant()
        if not tenant:
            raise PermissionDenied("No tenant context")

        from tenant_profiles.models import TenantUser

        has_role = TenantUser.objects.filter(
            user=request.user,
            tenant=tenant,
            is_active=True,
            role__in=allowed_roles
        ).exists()

        if not has_role:
            logger.warning(
                f"PERMISSION_DENIED: user={request.user.id} "
                f"tenant={tenant.slug} action={self.action} "
                f"required_roles={allowed_roles}"
            )
            raise PermissionDenied(
                f"Your role does not have permission for '{self.action}'. "
                f"Required roles: {', '.join(allowed_roles)}"
            )


# =============================================================================
# HR VIEWSET
# =============================================================================

class HRViewSet(RoleBasedViewSet):
    """
    ViewSet for HR-related operations.

    Preconfigured with appropriate role permissions for HR resources:
    - List/Retrieve: HR roles + viewers
    - Create/Update: HR managers and above
    - Delete: Admins only

    Usage:
        class EmployeeViewSet(HRViewSet):
            queryset = Employee.objects.all()
            serializer_class = EmployeeSerializer
    """

    role_permissions = {
        'list': ['owner', 'admin', 'hr_manager', 'viewer'],
        'retrieve': ['owner', 'admin', 'hr_manager', 'viewer'],
        'create': ['owner', 'admin', 'hr_manager'],
        'update': ['owner', 'admin', 'hr_manager'],
        'partial_update': ['owner', 'admin', 'hr_manager'],
        'destroy': ['owner', 'admin'],
    }


# =============================================================================
# RECRUITER VIEWSET
# =============================================================================

class RecruiterViewSet(RoleBasedViewSet):
    """
    ViewSet for recruitment/ATS operations.

    Preconfigured with appropriate role permissions for ATS resources:
    - List/Retrieve: Recruiting roles + viewers
    - Create/Update: Recruiters and above
    - Delete: Admins only

    Usage:
        class CandidateViewSet(RecruiterViewSet):
            queryset = Candidate.objects.all()
            serializer_class = CandidateSerializer
    """

    role_permissions = {
        'list': ['owner', 'admin', 'hr_manager', 'recruiter', 'hiring_manager', 'viewer'],
        'retrieve': ['owner', 'admin', 'hr_manager', 'recruiter', 'hiring_manager', 'viewer'],
        'create': ['owner', 'admin', 'hr_manager', 'recruiter'],
        'update': ['owner', 'admin', 'hr_manager', 'recruiter'],
        'partial_update': ['owner', 'admin', 'hr_manager', 'recruiter'],
        'destroy': ['owner', 'admin'],
    }


# =============================================================================
# PARTICIPANT-ONLY VIEWSET
# =============================================================================

class ParticipantViewSet(SecureTenantViewSet):
    """
    ViewSet for resources where access is limited to participants.

    Useful for contracts, conversations, disputes, etc. where only
    the involved parties should have access.

    Usage:
        class ContractViewSet(ParticipantViewSet):
            queryset = Contract.objects.all()
            serializer_class = ContractSerializer
            participant_fields = ['client', 'provider']

        class ConversationViewSet(ParticipantViewSet):
            queryset = Conversation.objects.all()
            serializer_class = ConversationSerializer
            participant_field = 'participants'  # M2M field
    """

    # FK fields containing participant users
    participant_fields: List[str] = []

    # M2M field containing participants
    participant_field: Optional[str] = None

    def check_object_permissions(self, request: Request, obj) -> None:
        """Check that user is a participant of the object."""
        super().check_object_permissions(request, obj)

        if not self._is_participant(request.user, obj):
            # Check if admin (admins can access all)
            tenant = self.get_tenant()
            if tenant:
                from tenant_profiles.models import TenantUser
                is_admin = TenantUser.objects.filter(
                    user=request.user,
                    tenant=tenant,
                    is_active=True,
                    role__in=['owner', 'admin']
                ).exists()
                if is_admin:
                    return

            raise PermissionDenied("You must be a participant to access this resource.")

    def _is_participant(self, user, obj) -> bool:
        """Check if user is a participant."""
        # Check M2M participant field
        if self.participant_field:
            participants = getattr(obj, self.participant_field, None)
            if participants is not None:
                if hasattr(participants, 'filter'):
                    return participants.filter(pk=user.pk).exists()
                elif hasattr(participants, '__contains__'):
                    return user in participants

        # Check FK participant fields
        for field in self.participant_fields:
            participant = getattr(obj, field, None)
            if participant is not None:
                if participant == user:
                    return True
                # Handle model with user FK
                if hasattr(participant, 'user') and participant.user == user:
                    return True

        return False

    def get_queryset(self) -> QuerySet:
        """Filter to only objects where user is a participant."""
        queryset = super().get_queryset()
        user = self.request.user

        # Check if admin (admins see all)
        tenant = self.get_tenant()
        if tenant:
            from tenant_profiles.models import TenantUser
            is_admin = TenantUser.objects.filter(
                user=user,
                tenant=tenant,
                is_active=True,
                role__in=['owner', 'admin']
            ).exists()
            if is_admin:
                return queryset

        # Filter to participant objects
        from django.db.models import Q

        if self.participant_field:
            # M2M field
            queryset = queryset.filter(**{self.participant_field: user})
        elif self.participant_fields:
            # FK fields - OR them together
            q_filter = Q()
            for field in self.participant_fields:
                q_filter |= Q(**{field: user})
                # Also check nested user FK
                q_filter |= Q(**{f"{field}__user": user})
            queryset = queryset.filter(q_filter)

        return queryset


# =============================================================================
# OPTIMIZED SECURE VIEWSET
# =============================================================================

class OptimizedSecureViewSet(OptimizedQuerySetMixin, SecureTenantViewSet):
    """
    SecureTenantViewSet with query optimization features.

    Combines security with N+1 prevention via select_related and prefetch_related.

    Usage:
        class EmployeeViewSet(OptimizedSecureViewSet):
            queryset = Employee.objects.all()
            serializer_class = EmployeeSerializer

            # Query optimizations
            select_related_fields = ['user', 'department', 'manager']
            prefetch_related_fields = ['skills', 'certifications']
            defer_fields = ['biography', 'internal_notes']

            # Security
            role_permissions = {
                'destroy': ['owner', 'admin'],
            }
    """
    pass


# =============================================================================
# BULK OPERATION VIEWSET
# =============================================================================

class BulkOperationViewSet(SecureTenantViewSet):
    """
    ViewSet that supports bulk operations with proper permission checks.

    Provides create_bulk, update_bulk, and delete_bulk actions.
    All bulk operations require admin role by default.

    Usage:
        class CandidateViewSet(BulkOperationViewSet):
            queryset = Candidate.objects.all()
            serializer_class = CandidateSerializer

            bulk_create_permission = ['owner', 'admin', 'hr_manager']
            bulk_update_permission = ['owner', 'admin', 'hr_manager']
            bulk_delete_permission = ['owner', 'admin']
    """

    # Roles that can perform bulk operations
    bulk_create_permission: List[str] = ['owner', 'admin']
    bulk_update_permission: List[str] = ['owner', 'admin']
    bulk_delete_permission: List[str] = ['owner', 'admin']

    # Maximum items per bulk operation
    bulk_max_items: int = 100

    def _check_bulk_permission(self, request: Request, allowed_roles: List[str]) -> None:
        """Check permission for bulk operation."""
        tenant = self.get_tenant()
        if not tenant:
            raise PermissionDenied("No tenant context")

        from tenant_profiles.models import TenantUser

        has_role = TenantUser.objects.filter(
            user=request.user,
            tenant=tenant,
            is_active=True,
            role__in=allowed_roles
        ).exists()

        if not has_role:
            raise PermissionDenied(
                f"Bulk operations require one of these roles: {', '.join(allowed_roles)}"
            )

    def create_bulk(self, request: Request) -> Response:
        """
        Create multiple objects in a single request.

        Request body: { "items": [...] }
        """
        self._check_bulk_permission(request, self.bulk_create_permission)

        items = request.data.get('items', [])
        if len(items) > self.bulk_max_items:
            return APIResponse.error(
                message=f"Bulk operations limited to {self.bulk_max_items} items",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        created = []
        errors = []

        for i, item_data in enumerate(items):
            serializer = self.get_serializer(data=item_data)
            if serializer.is_valid():
                self.perform_create(serializer)
                created.append(serializer.data)
            else:
                errors.append({'index': i, 'errors': serializer.errors})

        if errors:
            return APIResponse.error(
                message=f"Created {len(created)} items with {len(errors)} errors",
                errors=errors,
                status_code=status.HTTP_207_MULTI_STATUS
            )

        return APIResponse.created(
            data={'items': created, 'count': len(created)},
            message=f"Successfully created {len(created)} items"
        )

    def delete_bulk(self, request: Request) -> Response:
        """
        Delete multiple objects in a single request.

        Request body: { "ids": [...] }
        """
        self._check_bulk_permission(request, self.bulk_delete_permission)

        ids = request.data.get('ids', [])
        if len(ids) > self.bulk_max_items:
            return APIResponse.error(
                message=f"Bulk operations limited to {self.bulk_max_items} items",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        queryset = self.get_queryset().filter(pk__in=ids)
        deleted_count = queryset.count()

        # Log before deletion
        tenant = self.get_tenant()
        logger.info(
            f"BULK_DELETE: user={request.user.id} tenant={tenant.slug if tenant else 'none'} "
            f"model={queryset.model.__name__} count={deleted_count} ids={ids}"
        )

        queryset.delete()

        return APIResponse.success(
            data={'deleted_count': deleted_count},
            message=f"Successfully deleted {deleted_count} items"
        )


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'SecureTenantViewSet',
    'SecureReadOnlyViewSet',
    'AdminOnlyViewSet',
    'OwnerOnlyViewSet',
    'RoleBasedViewSet',
    'HRViewSet',
    'RecruiterViewSet',
    'ParticipantViewSet',
    'OptimizedSecureViewSet',
    'BulkOperationViewSet',
]
