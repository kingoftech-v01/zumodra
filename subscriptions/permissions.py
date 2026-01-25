"""
subscriptions Permissions

Role-based access control for subscriptions functionality.
"""

from rest_framework import permissions


class IsSubscriptionsAdmin(permissions.BasePermission):
    """
    Permission check: User must be PDG, supervisor, or HR manager.
    """

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        if request.user.is_staff or request.user.is_superuser:
            return True

        # Check tenant role
        try:
            tenant_membership = request.user.memberships.filter(
                tenant=request.tenant,
                is_active=True
            ).first()
            return tenant_membership and tenant_membership.role in ['pdg', 'supervisor', 'hr_manager']
        except AttributeError:
            return False


class CanViewRecord(permissions.BasePermission):
    """
    Permission check: User can perform action on model.
    """

    def has_permission(self, request, view):
        # All authenticated users can view
        if request.method in permissions.SAFE_METHODS:
            return request.user.is_authenticated

        # Write permissions require admin or object ownership
        return request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        # Safe methods (GET, HEAD, OPTIONS) allowed for all authenticated
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions: owner or admin
        if hasattr(obj, 'created_by'):
            if obj.created_by == request.user:
                return True

        # Check if user is admin
        try:
            tenant_membership = request.user.memberships.filter(
                tenant=request.tenant,
                is_active=True
            ).first()
            return tenant_membership and tenant_membership.role in ['pdg', 'supervisor', 'hr_manager']
        except AttributeError:
            return False
