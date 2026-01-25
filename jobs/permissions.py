"""
jobs Permissions

Role-based access control for jobs functionality.
"""

from rest_framework import permissions


class IsJobsAdmin(permissions.BasePermission):
    """
    Permission check: User must be PDG, supervisor, or HR manager.
    """

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        if request.user.is_staff or request.user.is_superuser:
            return True

        try:
            tenant_membership = request.user.memberships.filter(
                tenant=request.tenant,
                is_active=True
            ).first()
            return tenant_membership and tenant_membership.role in ['pdg', 'supervisor', 'hr_manager']
        except AttributeError:
            return False


class CanManageResource(permissions.BasePermission):
    """
    Permission for managing resources.
    """

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions require appropriate role
        try:
            tenant_membership = request.user.memberships.filter(
                tenant=request.tenant,
                is_active=True
            ).first()
            return tenant_membership and tenant_membership.role in [
                'pdg', 'supervisor', 'hr_manager', 'recruiter'
            ]
        except AttributeError:
            return False

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True

        # Check ownership or admin
        if hasattr(obj, 'created_by') and obj.created_by == request.user:
            return True

        try:
            tenant_membership = request.user.memberships.filter(
                tenant=request.tenant,
                is_active=True
            ).first()
            return tenant_membership and tenant_membership.role in ['pdg', 'supervisor', 'hr_manager']
        except AttributeError:
            return False
