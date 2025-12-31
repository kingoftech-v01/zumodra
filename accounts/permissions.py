"""
Accounts Permissions - Comprehensive RBAC Permission Classes for Multi-Tenant SaaS

This module provides a complete Role-Based Access Control (RBAC) system:

BASIC PERMISSIONS:
- IsTenantUser: Basic tenant membership check
- IsTenantAdmin: Admin or Owner role check
- IsTenantOwner: Owner-only access
- IsOwnerOrReadOnly: Object ownership check

KYC & VERIFICATION:
- HasKYCVerification: Verified KYC status required
- HasMinimumKYCLevel: Specific KYC level requirement

DATA ACCESS:
- CanAccessUserData: Consent-based data access
- CanManageUsers: User management permissions
- IsVerifiedRecruiter: Recruiter verification check

ROLE-BASED:
- HasTenantPermission: Dynamic permission check
- HasTenantRole: Role-based access
- HasAnyTenantRole: Any of specified roles

OBJECT-LEVEL:
- ObjectOwnerPermission: Object-level ownership
- TenantObjectPermission: Tenant-scoped objects
- DepartmentScopedPermission: Department-based access

FEATURE FLAGS:
- HasFeatureAccess: Plan-based feature access
- HasPlanPermission: Subscription tier check

COMPOSITE:
- CompositePermission: Combine multiple permissions
- AllOfPermissions: Require all permissions
- AnyOfPermissions: Require any permission
"""

from typing import List, Set, Optional, Type
from functools import wraps

from rest_framework import permissions
from rest_framework.request import Request
from rest_framework.views import APIView
from django.utils import timezone
from django.db import models
from django.core.cache import cache

from .models import TenantUser, KYCVerification, ProgressiveConsent


class IsTenantUser(permissions.BasePermission):
    """
    Permission check for users who are members of the current tenant.

    Requires:
    - User to be authenticated
    - User to have an active TenantUser membership for request.tenant
    """
    message = "You must be a member of this organization to access this resource."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        # Check if tenant context exists
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False

        # Check if user is a member of the tenant
        return TenantUser.objects.filter(
            user=request.user,
            tenant=tenant,
            is_active=True
        ).exists()

    def has_object_permission(self, request, view, obj):
        # For object-level permissions, also verify tenant scoping
        if hasattr(obj, 'tenant'):
            tenant = getattr(request, 'tenant', None)
            return obj.tenant == tenant
        return self.has_permission(request, view)


class IsTenantAdmin(permissions.BasePermission):
    """
    Permission check for tenant administrators.

    Requires user to have 'admin' or 'owner' role in the current tenant.
    """
    message = "You must be an administrator of this organization to perform this action."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False

        return TenantUser.objects.filter(
            user=request.user,
            tenant=tenant,
            is_active=True,
            role__in=[TenantUser.UserRole.ADMIN, TenantUser.UserRole.OWNER]
        ).exists()


class IsTenantOwner(permissions.BasePermission):
    """
    Permission check for tenant owners only.

    Most restrictive tenant permission - only the owner can access.
    Used for billing, plan changes, and tenant deletion.
    """
    message = "Only the organization owner can perform this action."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False

        return TenantUser.objects.filter(
            user=request.user,
            tenant=tenant,
            is_active=True,
            role=TenantUser.UserRole.OWNER
        ).exists()


class HasKYCVerification(permissions.BasePermission):
    """
    Permission check for users with verified KYC status.

    Requires at least one verified and non-expired KYC verification.
    Optional: Specify minimum verification level in view.
    """
    message = "KYC verification is required to access this resource."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        # Get minimum verification level from view (optional)
        min_level = getattr(view, 'kyc_level_required', None)

        # Check for valid KYC verification
        verifications = KYCVerification.objects.filter(
            user=request.user,
            status=KYCVerification.VerificationStatus.VERIFIED
        )

        # Filter by level if specified
        if min_level:
            verifications = verifications.filter(level=min_level)

        # Check if any verification is still valid (not expired)
        for verification in verifications:
            if verification.is_valid:
                return True

        return False


class CanAccessUserData(permissions.BasePermission):
    """
    Permission check for accessing user data based on progressive consent.

    Verifies that the requester has been granted consent by the data subject
    to access the specific data category.

    Usage in views:
        class MyView(APIView):
            permission_classes = [CanAccessUserData]
            data_category = 'contact'  # From ProgressiveConsent.DataCategory
    """
    message = "You do not have consent to access this user's data."

    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False

        # Safe methods may have different requirements
        if request.method in permissions.SAFE_METHODS:
            # For read operations, check if user is accessing their own data
            if hasattr(obj, 'user') and obj.user == request.user:
                return True
            if obj == request.user:
                return True

        # Get the data category from view
        data_category = getattr(view, 'data_category', None)
        if not data_category:
            return True  # No specific category required

        # Determine the data subject
        data_subject = None
        if hasattr(obj, 'user'):
            data_subject = obj.user
        elif hasattr(obj, 'grantor'):
            data_subject = obj.grantor
        else:
            data_subject = obj

        # Check if requester has consent
        tenant = getattr(request, 'tenant', None)

        consent_query = ProgressiveConsent.objects.filter(
            grantor=data_subject,
            data_category=data_category,
            status=ProgressiveConsent.ConsentStatus.GRANTED
        )

        # Check consent granted to user or tenant
        if tenant:
            consent_query = consent_query.filter(
                models.Q(grantee_user=request.user) |
                models.Q(grantee_tenant=tenant)
            )
        else:
            consent_query = consent_query.filter(grantee_user=request.user)

        # Check if any consent is active (not expired)
        for consent in consent_query:
            if consent.is_active:
                return True

        return False


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Object-level permission to only allow owners of an object to edit it.
    Assumes the model instance has a `user` attribute.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions only to owner
        if hasattr(obj, 'user'):
            return obj.user == request.user
        return obj == request.user


class CanManageUsers(permissions.BasePermission):
    """
    Permission for user management operations.

    Allows HR managers, admins, and owners to manage users.
    """
    message = "You do not have permission to manage users."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False

        allowed_roles = [
            TenantUser.UserRole.OWNER,
            TenantUser.UserRole.ADMIN,
            TenantUser.UserRole.HR_MANAGER
        ]

        return TenantUser.objects.filter(
            user=request.user,
            tenant=tenant,
            is_active=True,
            role__in=allowed_roles
        ).exists()


class HasTenantPermission(permissions.BasePermission):
    """
    Dynamic permission check based on specific permission codename.

    Usage in views:
        class MyView(APIView):
            permission_classes = [HasTenantPermission]
            required_permission = 'view_candidates'
    """
    message = "You do not have the required permission for this action."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False

        required_perm = getattr(view, 'required_permission', None)
        if not required_perm:
            return True  # No specific permission required

        try:
            tenant_user = TenantUser.objects.get(
                user=request.user,
                tenant=tenant,
                is_active=True
            )
            return tenant_user.has_permission(required_perm)
        except TenantUser.DoesNotExist:
            return False


class IsVerifiedRecruiter(permissions.BasePermission):
    """
    Permission for verified recruiters to access candidate data.

    Requires:
    - Tenant membership with recruiter/hiring manager role
    - Valid KYC verification (bidirectional trust)
    """
    message = "You must be a verified recruiter to access this resource."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False

        # Check role
        recruiter_roles = [
            TenantUser.UserRole.OWNER,
            TenantUser.UserRole.ADMIN,
            TenantUser.UserRole.HR_MANAGER,
            TenantUser.UserRole.RECRUITER,
            TenantUser.UserRole.HIRING_MANAGER
        ]

        has_role = TenantUser.objects.filter(
            user=request.user,
            tenant=tenant,
            is_active=True,
            role__in=recruiter_roles
        ).exists()

        if not has_role:
            return False

        # Check KYC verification
        has_kyc = KYCVerification.objects.filter(
            user=request.user,
            status=KYCVerification.VerificationStatus.VERIFIED,
            expires_at__gt=timezone.now()
        ).exists()

        return has_kyc


# =============================================================================
# ADVANCED ROLE-BASED PERMISSIONS
# =============================================================================

class HasTenantRole(permissions.BasePermission):
    """
    Permission check for specific tenant role.

    Usage:
        class MyView(APIView):
            permission_classes = [HasTenantRole]
            required_role = TenantUser.UserRole.HR_MANAGER
    """
    message = "You do not have the required role for this action."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False

        required_role = getattr(view, 'required_role', None)
        if not required_role:
            return True

        return TenantUser.objects.filter(
            user=request.user,
            tenant=tenant,
            is_active=True,
            role=required_role
        ).exists()


class HasAnyTenantRole(permissions.BasePermission):
    """
    Permission check for any of the specified roles.

    Usage:
        class MyView(APIView):
            permission_classes = [HasAnyTenantRole]
            allowed_roles = [TenantUser.UserRole.ADMIN, TenantUser.UserRole.HR_MANAGER]
    """
    message = "You do not have one of the required roles for this action."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False

        allowed_roles = getattr(view, 'allowed_roles', [])
        if not allowed_roles:
            return True

        return TenantUser.objects.filter(
            user=request.user,
            tenant=tenant,
            is_active=True,
            role__in=allowed_roles
        ).exists()


class HasMinimumKYCLevel(permissions.BasePermission):
    """
    Permission check for minimum KYC verification level.

    Usage:
        class MyView(APIView):
            permission_classes = [HasMinimumKYCLevel]
            minimum_kyc_level = 'enhanced'
    """
    message = "Your KYC verification level is insufficient for this action."

    # KYC levels in order of increasing verification
    KYC_LEVEL_ORDER = ['basic', 'standard', 'enhanced', 'complete']

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        minimum_level = getattr(view, 'minimum_kyc_level', None)
        if not minimum_level:
            return True

        # Get user's highest verified KYC level
        verification = KYCVerification.objects.filter(
            user=request.user,
            status=KYCVerification.VerificationStatus.VERIFIED,
            expires_at__gt=timezone.now()
        ).order_by('-level').first()

        if not verification:
            return False

        # Compare levels
        try:
            user_level_index = self.KYC_LEVEL_ORDER.index(verification.level)
            required_level_index = self.KYC_LEVEL_ORDER.index(minimum_level)
            return user_level_index >= required_level_index
        except ValueError:
            return False


# =============================================================================
# OBJECT-LEVEL PERMISSIONS
# =============================================================================

class ObjectOwnerPermission(permissions.BasePermission):
    """
    Object-level permission for object owners.

    Checks if the requesting user owns the object via specified field.

    Usage:
        class MyView(APIView):
            permission_classes = [ObjectOwnerPermission]
            owner_field = 'created_by'  # Default is 'user'
    """
    message = "You do not own this resource."

    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False

        owner_field = getattr(view, 'owner_field', 'user')

        # Handle nested field access (e.g., 'profile.user')
        owner = obj
        for field in owner_field.split('.'):
            owner = getattr(owner, field, None)
            if owner is None:
                return False

        return owner == request.user


class TenantObjectPermission(permissions.BasePermission):
    """
    Object-level permission for tenant-scoped objects.

    Ensures objects belong to the current tenant context.

    Usage:
        class MyView(APIView):
            permission_classes = [TenantObjectPermission]
            tenant_field = 'tenant'  # Default
    """
    message = "This resource does not belong to your organization."

    def has_object_permission(self, request, view, obj):
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False

        tenant_field = getattr(view, 'tenant_field', 'tenant')

        # Handle nested field access
        obj_tenant = obj
        for field in tenant_field.split('.'):
            obj_tenant = getattr(obj_tenant, field, None)
            if obj_tenant is None:
                return False

        return obj_tenant == tenant or obj_tenant.id == tenant.id


class DepartmentScopedPermission(permissions.BasePermission):
    """
    Permission for department-scoped access.

    Users can only access resources in their department unless they are admins.

    Usage:
        class MyView(APIView):
            permission_classes = [DepartmentScopedPermission]
            department_field = 'department'
    """
    message = "You do not have access to resources outside your department."

    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False

        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False

        # Get user's tenant membership
        try:
            tenant_user = TenantUser.objects.get(
                user=request.user,
                tenant=tenant,
                is_active=True
            )
        except TenantUser.DoesNotExist:
            return False

        # Admins can access all departments
        if tenant_user.is_admin:
            return True

        department_field = getattr(view, 'department_field', 'department')
        obj_department = getattr(obj, department_field, None)

        # If object has no department, allow access
        if obj_department is None:
            return True

        # Check if user is in the same department
        return tenant_user.department == obj_department


class HierarchyScopedPermission(permissions.BasePermission):
    """
    Permission based on organizational hierarchy.

    Users can access resources of their direct and indirect reports.

    Usage:
        class MyView(APIView):
            permission_classes = [HierarchyScopedPermission]
            user_field = 'assigned_to'
    """
    message = "You do not have access to this resource based on organizational hierarchy."

    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False

        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False

        # Get user's tenant membership
        try:
            tenant_user = TenantUser.objects.get(
                user=request.user,
                tenant=tenant,
                is_active=True
            )
        except TenantUser.DoesNotExist:
            return False

        # Admins can access all
        if tenant_user.is_admin:
            return True

        user_field = getattr(view, 'user_field', 'user')
        obj_user = getattr(obj, user_field, None)

        if obj_user is None:
            return True

        # Check if requesting user and object owner are same
        if obj_user == request.user:
            return True

        # Check if object owner reports to requesting user
        return self._is_in_hierarchy(tenant_user, obj_user, tenant)

    def _is_in_hierarchy(self, manager_tenant_user, subordinate_user, tenant, max_depth=10):
        """
        Check if subordinate is in manager's hierarchy.
        """
        try:
            subordinate_tenant_user = TenantUser.objects.get(
                user=subordinate_user,
                tenant=tenant,
                is_active=True
            )
        except TenantUser.DoesNotExist:
            return False

        current = subordinate_tenant_user
        depth = 0

        while current and depth < max_depth:
            if current.reports_to == manager_tenant_user:
                return True
            current = current.reports_to
            depth += 1

        return False


# =============================================================================
# FEATURE FLAG PERMISSIONS
# =============================================================================

class HasFeatureAccess(permissions.BasePermission):
    """
    Permission based on tenant plan features.

    Usage:
        class MyView(APIView):
            permission_classes = [HasFeatureAccess]
            required_feature = 'feature_ai_matching'
    """
    message = "Your subscription plan does not include this feature."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        tenant = getattr(request, 'tenant', None)
        if not tenant or not tenant.plan:
            return False

        required_feature = getattr(view, 'required_feature', None)
        if not required_feature:
            return True

        # Check if tenant plan has the feature
        return getattr(tenant.plan, required_feature, False)


class HasPlanPermission(permissions.BasePermission):
    """
    Permission based on subscription plan tier.

    Usage:
        class MyView(APIView):
            permission_classes = [HasPlanPermission]
            minimum_plan = 'professional'  # or ['professional', 'enterprise']
    """
    message = "Your subscription plan tier is insufficient for this action."

    PLAN_HIERARCHY = ['free', 'starter', 'professional', 'enterprise']

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        tenant = getattr(request, 'tenant', None)
        if not tenant or not tenant.plan:
            return False

        minimum_plan = getattr(view, 'minimum_plan', None)
        if not minimum_plan:
            return True

        # Handle list of allowed plans
        if isinstance(minimum_plan, (list, tuple)):
            return tenant.plan.plan_type in minimum_plan

        # Handle minimum tier comparison
        try:
            tenant_plan_index = self.PLAN_HIERARCHY.index(tenant.plan.plan_type)
            required_plan_index = self.PLAN_HIERARCHY.index(minimum_plan)
            return tenant_plan_index >= required_plan_index
        except ValueError:
            return False


class TenantUsageLimitPermission(permissions.BasePermission):
    """
    Permission based on tenant usage limits.

    Usage:
        class MyView(APIView):
            permission_classes = [TenantUsageLimitPermission]
            usage_type = 'user_count'  # Matches TenantUsage fields
    """
    message = "Your organization has reached its usage limit for this resource."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False

        usage_type = getattr(view, 'usage_type', None)
        if not usage_type:
            return True

        # Get tenant usage
        if not hasattr(tenant, 'usage'):
            return True

        usage = tenant.usage
        plan = tenant.plan

        if not plan:
            return False

        # Map usage types to plan limits
        limit_mapping = {
            'user_count': 'max_users',
            'active_job_count': 'max_job_postings',
            'candidate_count_this_month': 'max_candidates_per_month',
            'circusale_count': 'max_circusales',
        }

        if usage_type not in limit_mapping:
            return True

        current_usage = getattr(usage, usage_type, 0)
        limit = getattr(plan, limit_mapping[usage_type], float('inf'))

        # For creation actions, check if adding one more would exceed limit
        if request.method in ['POST', 'PUT']:
            return current_usage < limit

        return current_usage <= limit


# =============================================================================
# COMPOSITE PERMISSIONS
# =============================================================================

class AllOfPermissions(permissions.BasePermission):
    """
    Composite permission requiring ALL specified permissions.

    Usage:
        class MyView(APIView):
            permission_classes = [AllOfPermissions]
            required_permissions = [IsTenantUser, HasKYCVerification, HasFeatureAccess]
    """
    message = "You do not meet all required permission criteria."

    def has_permission(self, request, view):
        required_permissions = getattr(view, 'required_permissions', [])

        for permission_class in required_permissions:
            permission = permission_class()
            if not permission.has_permission(request, view):
                self.message = getattr(permission, 'message', self.message)
                return False

        return True

    def has_object_permission(self, request, view, obj):
        required_permissions = getattr(view, 'required_permissions', [])

        for permission_class in required_permissions:
            permission = permission_class()
            if hasattr(permission, 'has_object_permission'):
                if not permission.has_object_permission(request, view, obj):
                    self.message = getattr(permission, 'message', self.message)
                    return False

        return True


class AnyOfPermissions(permissions.BasePermission):
    """
    Composite permission requiring ANY of specified permissions.

    Usage:
        class MyView(APIView):
            permission_classes = [AnyOfPermissions]
            allowed_permissions = [IsTenantAdmin, IsTenantOwner]
    """
    message = "You do not meet any of the required permission criteria."

    def has_permission(self, request, view):
        allowed_permissions = getattr(view, 'allowed_permissions', [])

        if not allowed_permissions:
            return True

        for permission_class in allowed_permissions:
            permission = permission_class()
            if permission.has_permission(request, view):
                return True

        return False

    def has_object_permission(self, request, view, obj):
        allowed_permissions = getattr(view, 'allowed_permissions', [])

        if not allowed_permissions:
            return True

        for permission_class in allowed_permissions:
            permission = permission_class()
            if hasattr(permission, 'has_object_permission'):
                if permission.has_object_permission(request, view, obj):
                    return True

        return False


# =============================================================================
# ACTION-BASED PERMISSIONS
# =============================================================================

class ActionBasedPermission(permissions.BasePermission):
    """
    Permission based on view action (for ViewSets).

    Usage:
        class MyViewSet(viewsets.ModelViewSet):
            permission_classes = [ActionBasedPermission]
            action_permissions = {
                'list': [IsTenantUser],
                'create': [IsTenantAdmin],
                'update': [IsTenantAdmin],
                'destroy': [IsTenantOwner],
            }
    """
    message = "You do not have permission for this action."

    def has_permission(self, request, view):
        action = getattr(view, 'action', None)
        action_permissions = getattr(view, 'action_permissions', {})

        # Get permissions for this action
        permission_classes = action_permissions.get(action, [])

        if not permission_classes:
            return True

        for permission_class in permission_classes:
            permission = permission_class()
            if not permission.has_permission(request, view):
                self.message = getattr(permission, 'message', self.message)
                return False

        return True


class MethodBasedPermission(permissions.BasePermission):
    """
    Permission based on HTTP method.

    Usage:
        class MyView(APIView):
            permission_classes = [MethodBasedPermission]
            method_permissions = {
                'GET': [IsTenantUser],
                'POST': [IsTenantAdmin],
                'PUT': [IsTenantAdmin],
                'DELETE': [IsTenantOwner],
            }
    """
    message = "You do not have permission for this HTTP method."

    def has_permission(self, request, view):
        method_permissions = getattr(view, 'method_permissions', {})

        # Get permissions for this method
        permission_classes = method_permissions.get(request.method, [])

        if not permission_classes:
            return True

        for permission_class in permission_classes:
            permission = permission_class()
            if not permission.has_permission(request, view):
                self.message = getattr(permission, 'message', self.message)
                return False

        return True


# =============================================================================
# SECURITY PERMISSIONS
# =============================================================================

class Requires2FA(permissions.BasePermission):
    """
    Permission requiring 2FA to be enabled and verified.

    Usage:
        class MyView(APIView):
            permission_classes = [Requires2FA]
    """
    message = "Two-factor authentication is required for this action."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        # Check if 2FA is enabled for user
        try:
            from django_otp import devices_for_user
            has_device = any(devices_for_user(request.user, confirmed=True))
            if not has_device:
                return False
        except ImportError:
            return True  # If django_otp not installed, skip check

        # Check if session has verified 2FA
        if hasattr(request.user, 'is_verified'):
            return request.user.is_verified()

        return True


class RequiresRecentLogin(permissions.BasePermission):
    """
    Permission requiring recent authentication.

    Used for sensitive actions that require re-authentication.

    Usage:
        class MyView(APIView):
            permission_classes = [RequiresRecentLogin]
            recent_login_minutes = 15  # Default: 30
    """
    message = "Please re-authenticate to perform this sensitive action."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        recent_minutes = getattr(view, 'recent_login_minutes', 30)

        # Check token claims for iat (issued at)
        token = getattr(request, 'auth', None)
        if token and hasattr(token, 'payload'):
            iat = token.payload.get('iat')
            if iat:
                from datetime import datetime, timedelta
                issued_at = datetime.fromtimestamp(iat)
                if datetime.utcnow() - issued_at > timedelta(minutes=recent_minutes):
                    return False

        # Check session-based last login
        last_login = request.user.last_login
        if last_login:
            from datetime import timedelta
            if timezone.now() - last_login > timedelta(minutes=recent_minutes):
                return False

        return True


class IPWhitelistPermission(permissions.BasePermission):
    """
    Permission based on IP whitelist.

    Usage:
        class MyView(APIView):
            permission_classes = [IPWhitelistPermission]
            ip_whitelist = ['192.168.1.0/24', '10.0.0.1']
    """
    message = "Your IP address is not authorized for this action."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        ip_whitelist = getattr(view, 'ip_whitelist', None)

        # Also check tenant settings
        tenant = getattr(request, 'tenant', None)
        if tenant and hasattr(tenant, 'settings'):
            tenant_whitelist = tenant.settings.ip_whitelist or []
            if ip_whitelist:
                ip_whitelist = list(ip_whitelist) + tenant_whitelist
            else:
                ip_whitelist = tenant_whitelist

        if not ip_whitelist:
            return True

        client_ip = self._get_client_ip(request)
        return self._ip_in_whitelist(client_ip, ip_whitelist)

    def _get_client_ip(self, request) -> str:
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')

    def _ip_in_whitelist(self, ip: str, whitelist: list) -> bool:
        import ipaddress

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False

        for allowed in whitelist:
            try:
                if '/' in allowed:
                    network = ipaddress.ip_network(allowed, strict=False)
                    if ip_obj in network:
                        return True
                else:
                    if ip_obj == ipaddress.ip_address(allowed):
                        return True
            except ValueError:
                continue

        return False


# =============================================================================
# PERMISSION UTILITIES
# =============================================================================

def get_user_permissions(user, tenant=None) -> Set[str]:
    """
    Get all permissions for a user in a tenant context.

    Args:
        user: The user to check
        tenant: Optional tenant context

    Returns:
        Set of permission codenames
    """
    permissions_set = set()

    # Django model permissions
    permissions_set.update(user.get_all_permissions())

    # Tenant role permissions
    if tenant:
        try:
            tenant_user = TenantUser.objects.get(
                user=user,
                tenant=tenant,
                is_active=True
            )
            permissions_set.update(tenant_user.get_all_permissions())
        except TenantUser.DoesNotExist:
            pass

    return permissions_set


def check_permission(user, permission: str, tenant=None, obj=None) -> bool:
    """
    Check if user has a specific permission.

    Args:
        user: The user to check
        permission: Permission codename
        tenant: Optional tenant context
        obj: Optional object for object-level permissions

    Returns:
        bool indicating if user has permission
    """
    if not user or not user.is_authenticated:
        return False

    # Superusers have all permissions
    if user.is_superuser:
        return True

    # Check tenant permissions
    if tenant:
        try:
            tenant_user = TenantUser.objects.get(
                user=user,
                tenant=tenant,
                is_active=True
            )
            return tenant_user.has_permission(permission)
        except TenantUser.DoesNotExist:
            return False

    # Fall back to Django permissions
    return user.has_perm(permission)


class PermissionCache:
    """
    Caching layer for permission checks to improve performance.
    """

    CACHE_PREFIX = 'user_permissions:'
    CACHE_TIMEOUT = 300  # 5 minutes

    @classmethod
    def get_permissions(cls, user, tenant=None) -> Optional[Set[str]]:
        """
        Get cached permissions for user.
        """
        cache_key = cls._get_cache_key(user, tenant)
        return cache.get(cache_key)

    @classmethod
    def set_permissions(cls, user, tenant, permissions: Set[str]):
        """
        Cache permissions for user.
        """
        cache_key = cls._get_cache_key(user, tenant)
        cache.set(cache_key, permissions, timeout=cls.CACHE_TIMEOUT)

    @classmethod
    def invalidate(cls, user, tenant=None):
        """
        Invalidate cached permissions for user.
        """
        cache_key = cls._get_cache_key(user, tenant)
        cache.delete(cache_key)

    @classmethod
    def _get_cache_key(cls, user, tenant=None) -> str:
        tenant_id = tenant.id if tenant else 'none'
        return f"{cls.CACHE_PREFIX}{user.id}:{tenant_id}"
