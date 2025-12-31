"""
Tenants Permissions - Custom DRF permissions for tenant-scoped access control.

This module defines permission classes for:
- IsTenantOwner: Only tenant owners can perform action
- IsTenantAdmin: Owners and admins can perform action
- CanManageBilling: Users with billing permissions
- CanInviteUsers: Users who can invite new members
"""

from rest_framework import permissions
from accounts.models import TenantUser, ROLE_PERMISSIONS


class TenantPermissionMixin:
    """
    Mixin to get tenant user from request.
    Assumes request.tenant is set by tenant middleware.
    """

    def get_tenant_user(self, request):
        """Get the TenantUser for the current user and tenant."""
        if not request.user.is_authenticated:
            return None

        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return None

        try:
            return TenantUser.objects.get(
                user=request.user,
                tenant=tenant,
                is_active=True
            )
        except TenantUser.DoesNotExist:
            return None


class IsTenantOwner(TenantPermissionMixin, permissions.BasePermission):
    """
    Permission class: Only tenant owners can access.
    Tenant owners have full control over the tenant.
    """

    message = "Only the tenant owner can perform this action."

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        tenant_user = self.get_tenant_user(request)
        if not tenant_user:
            return False

        return tenant_user.role == TenantUser.UserRole.OWNER

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)


class IsTenantAdmin(TenantPermissionMixin, permissions.BasePermission):
    """
    Permission class: Tenant owners and admins can access.
    Admins have most permissions except billing and ownership transfer.
    """

    message = "Only tenant administrators can perform this action."

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        tenant_user = self.get_tenant_user(request)
        if not tenant_user:
            return False

        return tenant_user.role in [
            TenantUser.UserRole.OWNER,
            TenantUser.UserRole.ADMIN
        ]

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)


class IsTenantMember(TenantPermissionMixin, permissions.BasePermission):
    """
    Permission class: Any active tenant member can access.
    Basic permission for authenticated tenant users.
    """

    message = "You must be a member of this tenant to perform this action."

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        tenant_user = self.get_tenant_user(request)
        return tenant_user is not None and tenant_user.is_active

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)


class CanManageBilling(TenantPermissionMixin, permissions.BasePermission):
    """
    Permission class: Users with billing management permission.
    Typically only owners can manage billing.
    """

    message = "You do not have permission to manage billing."

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        tenant_user = self.get_tenant_user(request)
        if not tenant_user:
            return False

        # Check for manage_billing permission
        return tenant_user.has_permission('manage_billing')

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)


class CanInviteUsers(TenantPermissionMixin, permissions.BasePermission):
    """
    Permission class: Users who can invite new members.
    Owners, admins, and HR managers typically have this permission.
    """

    message = "You do not have permission to invite users."

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        tenant_user = self.get_tenant_user(request)
        if not tenant_user:
            return False

        # Check for manage_users permission
        return tenant_user.has_permission('manage_users')

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)


class CanManageSettings(TenantPermissionMixin, permissions.BasePermission):
    """
    Permission class: Users who can manage tenant settings.
    """

    message = "You do not have permission to manage settings."

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        tenant_user = self.get_tenant_user(request)
        if not tenant_user:
            return False

        return tenant_user.has_permission('manage_settings')

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)


class CanViewAnalytics(TenantPermissionMixin, permissions.BasePermission):
    """
    Permission class: Users who can view analytics and reports.
    """

    message = "You do not have permission to view analytics."

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        tenant_user = self.get_tenant_user(request)
        if not tenant_user:
            return False

        return tenant_user.has_permission('view_analytics')

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)


class CanExportData(TenantPermissionMixin, permissions.BasePermission):
    """
    Permission class: Users who can export data.
    """

    message = "You do not have permission to export data."

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        tenant_user = self.get_tenant_user(request)
        if not tenant_user:
            return False

        return tenant_user.has_permission('export_data')

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)


class HasTenantFeature(TenantPermissionMixin, permissions.BasePermission):
    """
    Permission class: Check if tenant plan has a specific feature.
    Usage: Override required_feature in the view or pass in kwargs.
    """

    message = "Your plan does not include this feature."
    required_feature = None

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        tenant = getattr(request, 'tenant', None)
        if not tenant or not tenant.plan:
            return False

        # Get feature name from view or class attribute
        feature = getattr(view, 'required_feature', None) or self.required_feature
        if not feature:
            return True

        # Check if plan has the feature
        feature_attr = f'feature_{feature}'
        return getattr(tenant.plan, feature_attr, False)

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)


class IsTenantOwnerOrReadOnly(TenantPermissionMixin, permissions.BasePermission):
    """
    Permission class: Read-only for all, write for owner only.
    """

    message = "Only the tenant owner can modify this resource."

    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True

        if not request.user.is_authenticated:
            return False

        tenant_user = self.get_tenant_user(request)
        if not tenant_user:
            return False

        return tenant_user.role == TenantUser.UserRole.OWNER

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True

        return self.has_permission(request, view)


class IsTenantAdminOrReadOnly(TenantPermissionMixin, permissions.BasePermission):
    """
    Permission class: Read-only for members, write for admins.
    """

    message = "Only tenant administrators can modify this resource."

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        tenant_user = self.get_tenant_user(request)
        if not tenant_user:
            return False

        if request.method in permissions.SAFE_METHODS:
            return True

        return tenant_user.role in [
            TenantUser.UserRole.OWNER,
            TenantUser.UserRole.ADMIN
        ]

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)


class IsInvitationOwner(permissions.BasePermission):
    """
    Permission class: Only the user who sent the invitation can manage it.
    """

    message = "You can only manage invitations you sent."

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True

        return obj.invited_by == request.user
