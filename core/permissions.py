"""
Core Permissions - Unified RBAC and Object-Level Permission Module for Zumodra

This module consolidates all permission classes from across the codebase into
a single importable module, adding audit logging and security enhancements.

USAGE:
    from core.permissions import (
        IsTenantUser, IsTenantAdmin, IsTenantOwner,
        SecureTenantViewSet, require_tenant_user,
        AuditedPermission, SensitiveDataPermission
    )

PERMISSION CATEGORIES:

1. BASIC TENANT PERMISSIONS (from tenant_profiles.permissions):
   - IsTenantUser: Basic tenant membership
   - IsTenantAdmin: Admin or Owner role
   - IsTenantOwner: Owner-only access
   - IsOwnerOrReadOnly: Object ownership

2. KYC & VERIFICATION:
   - HasKYCVerification: Verified KYC required
   - HasMinimumKYCLevel: Specific KYC level required

3. DATA ACCESS:
   - CanAccessUserData: Consent-based data access
   - CanManageUsers: User management permissions
   - IsVerifiedRecruiter: Recruiter verification

4. ROLE-BASED:
   - HasTenantPermission: Dynamic permission check
   - HasTenantRole: Single role required
   - HasAnyTenantRole: Any of specified roles

5. OBJECT-LEVEL:
   - ObjectOwnerPermission: Object ownership
   - TenantObjectPermission: Tenant-scoped objects
   - DepartmentScopedPermission: Department-based access
   - HierarchyScopedPermission: Org hierarchy access

6. FEATURE FLAGS:
   - HasFeatureAccess: Plan-based feature access
   - HasPlanPermission: Subscription tier check
   - TenantUsageLimitPermission: Usage limits

7. COMPOSITE:
   - AllOfPermissions: Require all permissions
   - AnyOfPermissions: Require any permission
   - ActionBasedPermission: Per-action permissions
   - MethodBasedPermission: Per-HTTP-method permissions

8. SECURITY:
   - Requires2FA: Two-factor authentication required
   - RequiresRecentLogin: Recent authentication required
   - IPWhitelistPermission: IP-based access control

9. TENANT-SPECIFIC (from tenants.permissions):
   - TenantPermissionMixin: Utility mixin
   - IsTenantMember: Basic membership
   - CanManageBilling: Billing permissions
   - CanInviteUsers: User invitation
   - CanManageSettings: Settings management
   - CanViewAnalytics: Analytics access
   - CanExportData: Data export
   - HasTenantFeature: Feature flags
   - IsTenantOwnerOrReadOnly: Read-only except owner
   - IsTenantAdminOrReadOnly: Read-only except admin
   - IsInvitationOwner: Invitation management

10. NEW SECURITY ENHANCEMENTS:
    - AuditedPermission: Wrapper for audit logging
    - SensitiveDataPermission: PII field protection
    - audited(): Factory for creating audited permissions
"""

import logging
from typing import Any, Dict, List, Optional, Set, Type

from rest_framework import permissions
from rest_framework.request import Request
from rest_framework.views import APIView
from django.utils import timezone

logger = logging.getLogger('security.permissions')

# =============================================================================
# RE-EXPORT FROM tenant_profiles.permissions
# =============================================================================

from tenant_profiles.permissions import (
    # Basic tenant permissions
    IsTenantUser,
    IsTenantAdmin,
    IsTenantOwner,
    IsOwnerOrReadOnly,

    # KYC permissions
    HasKYCVerification,
    HasMinimumKYCLevel,

    # Data access permissions
    CanAccessUserData,
    CanManageUsers,
    IsVerifiedRecruiter,

    # Role-based permissions
    HasTenantPermission,
    HasTenantRole,
    HasAnyTenantRole,
    IsRecruiter,
    IsHiringManager,
    IsHRManager,

    # Object-level permissions
    ObjectOwnerPermission,
    TenantObjectPermission,
    DepartmentScopedPermission,
    HierarchyScopedPermission,

    # Feature/Plan permissions
    HasFeatureAccess,
    HasPlanPermission,
    TenantUsageLimitPermission,

    # Composite permissions
    AllOfPermissions,
    AnyOfPermissions,
    ActionBasedPermission,
    MethodBasedPermission,

    # Security permissions
    Requires2FA,
    RequiresRecentLogin,
    IPWhitelistPermission,

    # Utilities
    get_user_permissions,
    check_permission,
    PermissionCache,
)

# =============================================================================
# RE-EXPORT FROM tenants.permissions
# =============================================================================

from tenants.permissions import (
    TenantPermissionMixin,
    IsTenantMember,
    CanManageBilling,
    CanInviteUsers,
    CanManageSettings,
    CanViewAnalytics,
    CanExportData,
    HasTenantFeature,
    IsTenantOwnerOrReadOnly,
    IsTenantAdminOrReadOnly,
    IsInvitationOwner,
)

# =============================================================================
# NEW: AUDITED PERMISSION WRAPPER
# =============================================================================

class AuditedPermission(permissions.BasePermission):
    """
    Wrapper permission class that logs all permission checks for security auditing.

    This wrapper logs both view-level and object-level permission checks,
    recording the user, tenant, view, action, and result.

    Usage:
        # Create an audited version of any permission class
        AuditedIsTenantAdmin = audited(IsTenantAdmin)

        class MyView(APIView):
            permission_classes = [AuditedIsTenantAdmin]

    Logs are written to the 'security.permissions' logger at INFO level for
    successful checks and WARNING level for denied checks.
    """

    wrapped_permission_class: Type[permissions.BasePermission] = None

    def __init__(self):
        if self.wrapped_permission_class:
            self.wrapped = self.wrapped_permission_class()
        else:
            self.wrapped = None

    def has_permission(self, request: Request, view: APIView) -> bool:
        if not self.wrapped:
            return True

        result = self.wrapped.has_permission(request, view)
        self._log_check(request, view, None, result, 'view')
        return result

    def has_object_permission(self, request: Request, view: APIView, obj: Any) -> bool:
        if not self.wrapped:
            return True

        # Use wrapped method if it exists, otherwise fall back to view permission
        if hasattr(self.wrapped, 'has_object_permission'):
            result = self.wrapped.has_object_permission(request, view, obj)
        else:
            result = self.wrapped.has_permission(request, view)

        self._log_check(request, view, obj, result, 'object')
        return result

    @property
    def message(self) -> str:
        if self.wrapped and hasattr(self.wrapped, 'message'):
            return self.wrapped.message
        return "Permission denied."

    def _log_check(
        self,
        request: Request,
        view: APIView,
        obj: Any,
        result: bool,
        check_type: str
    ) -> None:
        """Log the permission check for security auditing."""
        user_id = getattr(request.user, 'id', None) if request.user else None
        tenant = getattr(request, 'tenant', None)
        tenant_slug = getattr(tenant, 'slug', None) if tenant else None
        view_name = view.__class__.__name__
        action = getattr(view, 'action', request.method)
        object_id = getattr(obj, 'pk', None) if obj else None
        object_type = obj.__class__.__name__ if obj else None
        permission_name = (
            self.wrapped_permission_class.__name__
            if self.wrapped_permission_class
            else 'Unknown'
        )

        log_data = {
            'event': 'PERMISSION_CHECK',
            'user_id': user_id,
            'tenant': tenant_slug,
            'permission': permission_name,
            'view': view_name,
            'action': action,
            'check_type': check_type,
            'object_type': object_type,
            'object_id': object_id,
            'result': 'GRANTED' if result else 'DENIED',
            'ip_address': self._get_client_ip(request),
        }

        log_message = (
            f"PERMISSION_CHECK: user={user_id} tenant={tenant_slug} "
            f"permission={permission_name} view={view_name} action={action} "
            f"type={check_type} object={object_type}:{object_id} "
            f"result={'GRANTED' if result else 'DENIED'}"
        )

        if result:
            logger.info(log_message, extra=log_data)
        else:
            logger.warning(log_message, extra=log_data)

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


def audited(permission_class: Type[permissions.BasePermission]) -> Type[AuditedPermission]:
    """
    Factory function to create an audited version of any permission class.

    Usage:
        AuditedIsTenantAdmin = audited(IsTenantAdmin)

        class MyViewSet(viewsets.ModelViewSet):
            permission_classes = [AuditedIsTenantAdmin]

    Args:
        permission_class: The permission class to wrap with audit logging

    Returns:
        A new permission class that wraps the original with audit logging
    """
    return type(
        f'Audited{permission_class.__name__}',
        (AuditedPermission,),
        {'wrapped_permission_class': permission_class}
    )


# =============================================================================
# NEW: SENSITIVE DATA PERMISSION
# =============================================================================

class SensitiveDataPermission(permissions.BasePermission):
    """
    Permission for controlling access to sensitive data fields (PII).

    This permission class works with views/viewsets that define sensitive fields
    and the roles that can access them. It's typically used alongside serializers
    that mask sensitive data.

    Usage:
        class EmployeeViewSet(viewsets.ModelViewSet):
            permission_classes = [IsAuthenticated, IsTenantUser, SensitiveDataPermission]
            sensitive_fields = ['phone_number', 'ssn', 'bank_account']
            sensitive_field_roles = ['owner', 'admin', 'hr_manager']

    How it works:
    - For list/retrieve operations, this permission always allows the request
    - The actual field masking happens in the serializer
    - This permission logs when sensitive data is accessed for auditing
    - For update operations on sensitive fields, it validates the user has the role
    """

    message = "You do not have permission to access or modify sensitive data."

    # Default roles that can access sensitive data
    DEFAULT_SENSITIVE_ROLES = ['owner', 'admin', 'hr_manager']

    def has_permission(self, request: Request, view: APIView) -> bool:
        """View-level permission - always allow, filtering happens at serializer level."""
        return True

    def has_object_permission(self, request: Request, view: APIView, obj: Any) -> bool:
        """
        Object-level permission for sensitive data.

        For safe methods (GET, HEAD, OPTIONS), always returns True.
        For unsafe methods, checks if any sensitive fields are being modified.
        """
        # Safe methods are always allowed - serializer handles masking
        if request.method in permissions.SAFE_METHODS:
            self._log_sensitive_access(request, view, obj, 'read')
            return True

        # For writes, check if sensitive fields are being modified
        sensitive_fields = getattr(view, 'sensitive_fields', [])
        if not sensitive_fields:
            return True

        # Check if request data contains sensitive fields
        request_data = getattr(request, 'data', {})
        modifying_sensitive = any(
            field in request_data
            for field in sensitive_fields
        )

        if not modifying_sensitive:
            return True

        # User is modifying sensitive data - check role
        can_access = self._check_sensitive_access(request, view)

        if can_access:
            self._log_sensitive_access(request, view, obj, 'write')
        else:
            logger.warning(
                f"SENSITIVE_DATA_DENIED: user={request.user.id} "
                f"attempted to modify sensitive fields on {obj.__class__.__name__}:{obj.pk}"
            )

        return can_access

    def _check_sensitive_access(self, request: Request, view: APIView) -> bool:
        """Check if user has role to access sensitive data."""
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False

        # Get allowed roles from view or use defaults
        allowed_roles = getattr(
            view,
            'sensitive_field_roles',
            self.DEFAULT_SENSITIVE_ROLES
        )

        # Import here to avoid circular imports
        from tenant_profiles.models import TenantUser

        return TenantUser.objects.filter(
            user=request.user,
            tenant=tenant,
            is_active=True,
            role__in=allowed_roles
        ).exists()

    def _log_sensitive_access(
        self,
        request: Request,
        view: APIView,
        obj: Any,
        access_type: str
    ) -> None:
        """Log access to sensitive data for compliance auditing."""
        sensitive_fields = getattr(view, 'sensitive_fields', [])
        if not sensitive_fields:
            return

        user_id = getattr(request.user, 'id', None)
        tenant = getattr(request, 'tenant', None)
        tenant_slug = getattr(tenant, 'slug', None) if tenant else None

        logger.info(
            f"SENSITIVE_DATA_ACCESS: user={user_id} tenant={tenant_slug} "
            f"object={obj.__class__.__name__}:{obj.pk} "
            f"access_type={access_type} fields={sensitive_fields}"
        )


# =============================================================================
# NEW: PARTICIPANT PERMISSION
# =============================================================================

class IsParticipant(permissions.BasePermission):
    """
    Object-level permission for resources with multiple participants.

    Useful for contracts, conversations, disputes, etc. where multiple
    users have access but are neither the owner nor the tenant admin.

    Usage:
        class ContractViewSet(viewsets.ModelViewSet):
            permission_classes = [IsAuthenticated, IsParticipant]
            participant_fields = ['client', 'provider']  # Fields containing users

        class ConversationViewSet(viewsets.ModelViewSet):
            permission_classes = [IsAuthenticated, IsParticipant]
            participant_field = 'participants'  # M2M field
    """

    message = "You must be a participant to access this resource."

    def has_permission(self, request: Request, view: APIView) -> bool:
        """View-level permission - require authentication."""
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request: Request, view: APIView, obj: Any) -> bool:
        """Check if user is a participant."""
        if not request.user or not request.user.is_authenticated:
            return False

        # Check M2M participant field
        participant_field = getattr(view, 'participant_field', None)
        if participant_field:
            participants = getattr(obj, participant_field, None)
            if participants is not None:
                if hasattr(participants, 'all'):
                    # M2M relationship
                    return participants.filter(pk=request.user.pk).exists()
                elif hasattr(participants, '__iter__'):
                    # List of users
                    return request.user in participants

        # Check multiple FK participant fields
        participant_fields = getattr(view, 'participant_fields', [])
        for field in participant_fields:
            participant = getattr(obj, field, None)
            if participant is not None:
                # Handle nested user fields (e.g., 'provider.user')
                if '.' in str(field):
                    parts = str(field).split('.')
                    current = obj
                    for part in parts:
                        current = getattr(current, part, None)
                        if current is None:
                            break
                    participant = current

                if participant == request.user:
                    return True
                # Handle model with user FK
                if hasattr(participant, 'user') and participant.user == request.user:
                    return True

        # Admins always have access
        tenant = getattr(request, 'tenant', None)
        if tenant:
            from tenant_profiles.models import TenantUser
            is_admin = TenantUser.objects.filter(
                user=request.user,
                tenant=tenant,
                is_active=True,
                role__in=[TenantUser.UserRole.OWNER, TenantUser.UserRole.ADMIN]
            ).exists()
            if is_admin:
                return True

        return False


# =============================================================================
# NEW: RATE LIMITED PERMISSION
# =============================================================================

class IsNotRateLimited(permissions.BasePermission):
    """
    Permission that enforces rate limiting via permission system.

    This is complementary to DRF's throttling but allows for more complex
    rate limiting scenarios, like per-feature or per-action limits.

    Usage:
        class BulkImportViewSet(viewsets.ModelViewSet):
            permission_classes = [IsAuthenticated, IsNotRateLimited]
            rate_limit_scope = 'bulk_import'
            rate_limit = '10/hour'
    """

    message = "You have exceeded the rate limit for this action. Please try again later."

    def has_permission(self, request: Request, view: APIView) -> bool:
        from django.core.cache import cache

        scope = getattr(view, 'rate_limit_scope', None)
        limit_str = getattr(view, 'rate_limit', None)

        if not scope or not limit_str:
            return True

        # Parse rate limit string (e.g., "10/hour")
        try:
            num_requests, period = limit_str.split('/')
            num_requests = int(num_requests)
        except (ValueError, AttributeError):
            return True

        # Calculate period in seconds
        period_seconds = {
            'second': 1,
            'minute': 60,
            'hour': 3600,
            'day': 86400,
        }.get(period, 3600)

        # Build cache key
        user_id = request.user.id if request.user.is_authenticated else 'anon'
        tenant = getattr(request, 'tenant', None)
        tenant_id = tenant.id if tenant else 'none'
        cache_key = f'rate_limit:{scope}:{tenant_id}:{user_id}'

        # Check current count
        current_count = cache.get(cache_key, 0)

        if current_count >= num_requests:
            logger.warning(
                f"RATE_LIMIT_EXCEEDED: user={user_id} tenant={tenant_id} "
                f"scope={scope} limit={limit_str} count={current_count}"
            )
            return False

        # Increment counter
        if current_count == 0:
            cache.set(cache_key, 1, timeout=period_seconds)
        else:
            cache.incr(cache_key)

        return True


# =============================================================================
# CONVENIENCE ALIASES
# =============================================================================

# Common permission combinations as shortcuts
IsAdminOrOwner = IsTenantAdmin  # Admin includes Owner
IsHROrAbove = CanManageUsers  # HR managers, admins, owners

# Pre-created audited versions of common permissions
AuditedIsTenantUser = audited(IsTenantUser)
AuditedIsTenantAdmin = audited(IsTenantAdmin)
AuditedIsTenantOwner = audited(IsTenantOwner)
AuditedCanManageUsers = audited(CanManageUsers)
AuditedTenantObjectPermission = audited(TenantObjectPermission)


# =============================================================================
# ROLE CONSTANTS FOR CONVENIENCE
# =============================================================================

# Import role definitions for easy access
try:
    from tenant_profiles.models import TenantUser

    ROLE_OWNER = TenantUser.UserRole.OWNER
    ROLE_ADMIN = TenantUser.UserRole.ADMIN
    ROLE_HR_MANAGER = TenantUser.UserRole.HR_MANAGER
    ROLE_RECRUITER = TenantUser.UserRole.RECRUITER
    ROLE_HIRING_MANAGER = TenantUser.UserRole.HIRING_MANAGER
    ROLE_EMPLOYEE = TenantUser.UserRole.EMPLOYEE
    ROLE_VIEWER = TenantUser.UserRole.VIEWER

    # Role groups for common use cases
    ADMIN_ROLES = [ROLE_OWNER, ROLE_ADMIN]
    HR_ROLES = [ROLE_OWNER, ROLE_ADMIN, ROLE_HR_MANAGER]
    RECRUITER_ROLES = [ROLE_OWNER, ROLE_ADMIN, ROLE_HR_MANAGER, ROLE_RECRUITER, ROLE_HIRING_MANAGER]
    ALL_ROLES = [ROLE_OWNER, ROLE_ADMIN, ROLE_HR_MANAGER, ROLE_RECRUITER, ROLE_HIRING_MANAGER, ROLE_EMPLOYEE, ROLE_VIEWER]
except ImportError:
    # Handle case where accounts app isn't available yet
    pass


# =============================================================================
# __all__ EXPORT
# =============================================================================

__all__ = [
    # From tenant_profiles.permissions
    'IsTenantUser',
    'IsTenantAdmin',
    'IsTenantOwner',
    'IsOwnerOrReadOnly',
    'HasKYCVerification',
    'HasMinimumKYCLevel',
    'CanAccessUserData',
    'CanManageUsers',
    'IsVerifiedRecruiter',
    'HasTenantPermission',
    'HasTenantRole',
    'HasAnyTenantRole',
    'IsRecruiter',
    'IsHiringManager',
    'IsHRManager',
    'ObjectOwnerPermission',
    'TenantObjectPermission',
    'DepartmentScopedPermission',
    'HierarchyScopedPermission',
    'HasFeatureAccess',
    'HasPlanPermission',
    'TenantUsageLimitPermission',
    'AllOfPermissions',
    'AnyOfPermissions',
    'ActionBasedPermission',
    'MethodBasedPermission',
    'Requires2FA',
    'RequiresRecentLogin',
    'IPWhitelistPermission',
    'get_user_permissions',
    'check_permission',
    'PermissionCache',

    # From tenants.permissions
    'TenantPermissionMixin',
    'IsTenantMember',
    'CanManageBilling',
    'CanInviteUsers',
    'CanManageSettings',
    'CanViewAnalytics',
    'CanExportData',
    'HasTenantFeature',
    'IsTenantOwnerOrReadOnly',
    'IsTenantAdminOrReadOnly',
    'IsInvitationOwner',

    # New security enhancements
    'AuditedPermission',
    'audited',
    'SensitiveDataPermission',
    'IsParticipant',
    'IsNotRateLimited',

    # Pre-created audited versions
    'AuditedIsTenantUser',
    'AuditedIsTenantAdmin',
    'AuditedIsTenantOwner',
    'AuditedCanManageUsers',
    'AuditedTenantObjectPermission',

    # Aliases
    'IsAdminOrOwner',
    'IsHROrAbove',

    # Role constants
    'ROLE_OWNER',
    'ROLE_ADMIN',
    'ROLE_HR_MANAGER',
    'ROLE_RECRUITER',
    'ROLE_HIRING_MANAGER',
    'ROLE_EMPLOYEE',
    'ROLE_VIEWER',
    'ADMIN_ROLES',
    'HR_ROLES',
    'RECRUITER_ROLES',
    'ALL_ROLES',
]
