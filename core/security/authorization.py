"""
Authorization Security Module for Zumodra

Provides comprehensive authorization features including:
- Permission Checker with caching
- Resource Access Validator (object-level permissions)
- Tenant Boundary Enforcer
- Cross-Tenant Access Preventer
- Privilege Escalation Detector

All components are tenant-aware and integrate with the security logging system.
"""

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type, Union

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.db.models import Model, Q
from django.http import HttpRequest
from django.utils import timezone

from .owasp import SecurityEvent, SecurityEventLogger, SecurityEventType

logger = logging.getLogger('security.authorization')
User = get_user_model()


# =============================================================================
# Permission Definitions
# =============================================================================

class Permission(Enum):
    """Standard permission types."""
    VIEW = 'view'
    CREATE = 'create'
    UPDATE = 'update'
    DELETE = 'delete'
    MANAGE = 'manage'  # Full CRUD + settings
    ADMIN = 'admin'    # Full access


class ResourceType(Enum):
    """Resource types for permission checking."""
    # ATS Resources
    JOB_POSTING = 'job_posting'
    APPLICATION = 'application'
    CANDIDATE = 'candidate'
    INTERVIEW = 'interview'
    OFFER = 'offer'

    # HR Resources
    EMPLOYEE = 'employee'
    TIME_OFF = 'time_off'
    DOCUMENT = 'document'
    ONBOARDING = 'onboarding'

    # Tenant Resources
    TENANT = 'tenant'
    USER = 'user'
    ROLE = 'role'
    CIRCUSALE = 'circusale'

    # Service Resources
    SERVICE = 'service'
    APPOINTMENT = 'appointment'
    MESSAGE = 'message'
    PAYMENT = 'payment'

    # System Resources
    SETTINGS = 'settings'
    AUDIT_LOG = 'audit_log'
    ANALYTICS = 'analytics'


@dataclass
class PermissionGrant:
    """Represents a permission grant for a resource."""
    resource_type: ResourceType
    permission: Permission
    resource_id: Optional[str] = None  # None = all resources of type
    conditions: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Role Definitions
# =============================================================================

class RoleType(Enum):
    """Standard role types."""
    PDG = 'pdg'  # Full tenant access
    SUPERVISOR = 'supervisor'  # Circusale + subordinates
    HR_MANAGER = 'hr_manager'  # HR operations
    RECRUITER = 'recruiter'  # ATS operations
    HIRING_MANAGER = 'hiring_manager'  # Department hiring
    EMPLOYEE = 'employee'  # Basic access
    MARKETER = 'marketer'  # Marketing operations
    FINANCE = 'finance'  # Finance operations
    VIEWER = 'viewer'  # Read-only


# Default role permissions (can be customized per tenant)
DEFAULT_ROLE_PERMISSIONS: Dict[RoleType, List[PermissionGrant]] = {
    RoleType.PDG: [
        PermissionGrant(ResourceType.TENANT, Permission.ADMIN),
        PermissionGrant(ResourceType.USER, Permission.ADMIN),
        PermissionGrant(ResourceType.SETTINGS, Permission.ADMIN),
    ],
    RoleType.HR_MANAGER: [
        PermissionGrant(ResourceType.EMPLOYEE, Permission.MANAGE),
        PermissionGrant(ResourceType.TIME_OFF, Permission.MANAGE),
        PermissionGrant(ResourceType.DOCUMENT, Permission.MANAGE),
        PermissionGrant(ResourceType.ONBOARDING, Permission.MANAGE),
    ],
    RoleType.RECRUITER: [
        PermissionGrant(ResourceType.JOB_POSTING, Permission.MANAGE),
        PermissionGrant(ResourceType.APPLICATION, Permission.MANAGE),
        PermissionGrant(ResourceType.CANDIDATE, Permission.MANAGE),
        PermissionGrant(ResourceType.INTERVIEW, Permission.MANAGE),
    ],
    RoleType.HIRING_MANAGER: [
        PermissionGrant(ResourceType.JOB_POSTING, Permission.VIEW),
        PermissionGrant(ResourceType.APPLICATION, Permission.VIEW),
        PermissionGrant(ResourceType.CANDIDATE, Permission.VIEW),
        PermissionGrant(ResourceType.INTERVIEW, Permission.CREATE),
    ],
    RoleType.EMPLOYEE: [
        PermissionGrant(ResourceType.EMPLOYEE, Permission.VIEW, conditions={'self_only': True}),
        PermissionGrant(ResourceType.TIME_OFF, Permission.CREATE, conditions={'self_only': True}),
        PermissionGrant(ResourceType.DOCUMENT, Permission.VIEW, conditions={'self_only': True}),
    ],
    RoleType.VIEWER: [
        PermissionGrant(ResourceType.JOB_POSTING, Permission.VIEW),
        PermissionGrant(ResourceType.EMPLOYEE, Permission.VIEW, conditions={'self_only': True}),
    ],
}


# =============================================================================
# Permission Checker
# =============================================================================

class PermissionChecker:
    """
    Permission checking with caching for performance.

    Provides efficient permission validation with multi-level caching.
    """

    CACHE_PREFIX = 'permissions:'
    CACHE_TIMEOUT = 300  # 5 minutes

    def __init__(self):
        self.logger = SecurityEventLogger()

    def has_permission(
        self,
        user,
        resource_type: Union[ResourceType, str],
        permission: Union[Permission, str],
        resource_id: str = None,
        request: HttpRequest = None
    ) -> bool:
        """
        Check if a user has a specific permission.

        Args:
            user: The user to check
            resource_type: Type of resource
            permission: Required permission
            resource_id: Optional specific resource ID
            request: Optional request for context

        Returns:
            True if permission is granted
        """
        if not user or not user.is_authenticated:
            return False

        # Superusers bypass permission checks
        if getattr(user, 'is_superuser', False):
            return True

        # Normalize types
        if isinstance(resource_type, str):
            try:
                resource_type = ResourceType(resource_type)
            except ValueError:
                return False

        if isinstance(permission, str):
            try:
                permission = Permission(permission)
            except ValueError:
                return False

        # Check cache
        cache_key = self._get_cache_key(user.id, resource_type, permission, resource_id)
        cached_result = cache.get(cache_key)

        if cached_result is not None:
            return cached_result

        # Check permissions
        has_perm = self._check_permission(user, resource_type, permission, resource_id, request)

        # Cache result
        cache.set(cache_key, has_perm, self.CACHE_TIMEOUT)

        return has_perm

    def require_permission(
        self,
        resource_type: Union[ResourceType, str],
        permission: Union[Permission, str],
        resource_id_param: str = None
    ) -> Callable:
        """
        Decorator to require permission for a view.

        Args:
            resource_type: Type of resource
            permission: Required permission
            resource_id_param: URL parameter name for resource ID

        Returns:
            Decorator function
        """
        def decorator(view_func: Callable) -> Callable:
            @wraps(view_func)
            def wrapper(request, *args, **kwargs):
                resource_id = kwargs.get(resource_id_param) if resource_id_param else None

                if not self.has_permission(
                    request.user, resource_type, permission, resource_id, request
                ):
                    self._log_access_denied(
                        request.user, resource_type, permission, resource_id, request
                    )
                    raise PermissionDenied('You do not have permission to perform this action.')

                return view_func(request, *args, **kwargs)
            return wrapper
        return decorator

    def get_user_permissions(
        self,
        user,
        resource_type: ResourceType = None
    ) -> List[PermissionGrant]:
        """
        Get all permissions for a user.

        Args:
            user: The user
            resource_type: Optional filter by resource type

        Returns:
            List of permission grants
        """
        permissions = []

        # Get role-based permissions
        user_role = self._get_user_role(user)
        if user_role:
            role_perms = DEFAULT_ROLE_PERMISSIONS.get(user_role, [])
            permissions.extend(role_perms)

        # Get custom permissions
        custom_perms = self._get_custom_permissions(user)
        permissions.extend(custom_perms)

        # Filter by resource type if specified
        if resource_type:
            permissions = [p for p in permissions if p.resource_type == resource_type]

        return permissions

    def invalidate_user_cache(self, user_id: int):
        """
        Invalidate all cached permissions for a user.

        Args:
            user_id: The user ID
        """
        # Pattern-based deletion (implementation depends on cache backend)
        pattern = f"{self.CACHE_PREFIX}user:{user_id}:*"
        try:
            # For Redis
            cache.delete_pattern(pattern)
        except AttributeError:
            # For other backends, we can't do pattern deletion
            # Fall back to clearing specific known keys
            pass

    def _check_permission(
        self,
        user,
        resource_type: ResourceType,
        permission: Permission,
        resource_id: str = None,
        request: HttpRequest = None
    ) -> bool:
        """Perform actual permission check."""
        # Get user's role
        user_role = self._get_user_role(user)

        if not user_role:
            return False

        # PDG has full access within tenant
        if user_role == RoleType.PDG:
            return True

        # Check role permissions
        role_perms = DEFAULT_ROLE_PERMISSIONS.get(user_role, [])

        for grant in role_perms:
            if self._matches_grant(grant, resource_type, permission, resource_id, user):
                return True

        # Check custom permissions
        custom_perms = self._get_custom_permissions(user)
        for grant in custom_perms:
            if self._matches_grant(grant, resource_type, permission, resource_id, user):
                return True

        return False

    def _matches_grant(
        self,
        grant: PermissionGrant,
        resource_type: ResourceType,
        permission: Permission,
        resource_id: str,
        user
    ) -> bool:
        """Check if a permission grant matches the request."""
        # Resource type must match
        if grant.resource_type != resource_type:
            return False

        # Check permission level (ADMIN > MANAGE > UPDATE > CREATE > VIEW)
        permission_hierarchy = [
            Permission.VIEW, Permission.CREATE, Permission.UPDATE,
            Permission.DELETE, Permission.MANAGE, Permission.ADMIN
        ]

        grant_level = permission_hierarchy.index(grant.permission)
        required_level = permission_hierarchy.index(permission)

        if grant_level < required_level:
            return False

        # Check resource ID constraint
        if grant.resource_id and resource_id and grant.resource_id != resource_id:
            return False

        # Check conditions
        if grant.conditions:
            if not self._check_conditions(grant.conditions, user, resource_id):
                return False

        return True

    def _check_conditions(
        self,
        conditions: Dict[str, Any],
        user,
        resource_id: str = None
    ) -> bool:
        """Check permission conditions."""
        for condition, value in conditions.items():
            if condition == 'self_only' and value:
                # User can only access their own resources
                if resource_id and str(user.id) != str(resource_id):
                    return False

            elif condition == 'circusale_only' and value:
                # User can only access resources in their circusale
                # Implementation depends on your model structure
                pass

            elif condition == 'department' and value:
                # User can only access resources in specific department
                user_dept = getattr(user, 'department', None)
                if user_dept != value:
                    return False

        return True

    def _get_user_role(self, user) -> Optional[RoleType]:
        """Get the user's role."""
        # Try different attribute names
        role_attr = getattr(user, 'role', None)
        if role_attr:
            if isinstance(role_attr, str):
                try:
                    return RoleType(role_attr.lower())
                except ValueError:
                    pass

        # Check for tenant user role
        tenant_user = getattr(user, 'tenantuser', None)
        if tenant_user:
            role = getattr(tenant_user, 'role', None)
            if role:
                try:
                    return RoleType(role.lower())
                except ValueError:
                    pass

        return None

    def _get_custom_permissions(self, user) -> List[PermissionGrant]:
        """Get custom permissions for a user (from database)."""
        # This would query your permission model
        # Example implementation:
        custom_perms = []

        if hasattr(user, 'custom_permissions'):
            for perm in user.custom_permissions.all():
                grant = PermissionGrant(
                    resource_type=ResourceType(perm.resource_type),
                    permission=Permission(perm.permission),
                    resource_id=perm.resource_id,
                    conditions=perm.conditions or {},
                )
                custom_perms.append(grant)

        return custom_perms

    def _get_cache_key(
        self,
        user_id: int,
        resource_type: ResourceType,
        permission: Permission,
        resource_id: str = None
    ) -> str:
        """Generate cache key for permission."""
        key_parts = [
            self.CACHE_PREFIX,
            f"user:{user_id}",
            f"resource:{resource_type.value}",
            f"perm:{permission.value}",
        ]
        if resource_id:
            key_parts.append(f"id:{resource_id}")

        return ':'.join(key_parts)

    def _log_access_denied(
        self,
        user,
        resource_type: ResourceType,
        permission: Permission,
        resource_id: str,
        request: HttpRequest
    ):
        """Log access denied event."""
        event = SecurityEvent(
            event_type=SecurityEventType.ACCESS_DENIED,
            severity='medium',
            message=f'Permission denied: {permission.value} on {resource_type.value}',
            user_id=str(user.id) if user else None,
            tenant_id=self._get_tenant_id(request),
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', ''),
            request_path=request.path,
            request_method=request.method,
            details={
                'resource_type': resource_type.value,
                'permission': permission.value,
                'resource_id': resource_id,
            }
        )
        self.logger.log(event)

    def _get_tenant_id(self, request: HttpRequest) -> Optional[str]:
        """Extract tenant ID from request."""
        if hasattr(request, 'tenant'):
            return str(getattr(request.tenant, 'id', None))
        return None


# =============================================================================
# Resource Access Validator
# =============================================================================

class ResourceAccessValidator:
    """
    Validates object-level permissions for resources.

    Provides fine-grained access control at the individual resource level.
    """

    def __init__(self):
        self.logger = SecurityEventLogger()
        self.permission_checker = PermissionChecker()

    def can_access(
        self,
        user,
        resource: Model,
        permission: Permission = Permission.VIEW,
        request: HttpRequest = None
    ) -> bool:
        """
        Check if user can access a specific resource.

        Args:
            user: The user requesting access
            resource: The resource model instance
            permission: Required permission level
            request: Optional request for context

        Returns:
            True if access is allowed
        """
        if not user or not user.is_authenticated:
            return False

        if getattr(user, 'is_superuser', False):
            return True

        # Get resource type from model
        resource_type = self._get_resource_type(resource)
        if not resource_type:
            return False

        # Check base permission
        if not self.permission_checker.has_permission(
            user, resource_type, permission, str(resource.pk), request
        ):
            return False

        # Check ownership
        if self._check_ownership(user, resource):
            return True

        # Check tenant boundary
        if not self._check_tenant_access(user, resource):
            return False

        # Check circusale boundary (if applicable)
        if not self._check_circusale_access(user, resource):
            return False

        return True

    def filter_queryset(
        self,
        user,
        queryset,
        permission: Permission = Permission.VIEW
    ):
        """
        Filter a queryset to only include accessible resources.

        Args:
            user: The user requesting access
            queryset: The queryset to filter
            permission: Required permission level

        Returns:
            Filtered queryset
        """
        if not user or not user.is_authenticated:
            return queryset.none()

        if getattr(user, 'is_superuser', False):
            return queryset

        # Build filter conditions
        filters = Q()

        # Tenant filter
        tenant_id = self._get_user_tenant_id(user)
        if tenant_id:
            if hasattr(queryset.model, 'tenant_id'):
                filters &= Q(tenant_id=tenant_id)
            elif hasattr(queryset.model, 'tenant'):
                filters &= Q(tenant_id=tenant_id)

        # Role-based filters
        user_role = self._get_user_role(user)

        if user_role == RoleType.PDG:
            # PDG sees everything in tenant
            pass
        elif user_role == RoleType.SUPERVISOR:
            # Supervisor sees their circusale
            circusale_id = self._get_user_circusale_id(user)
            if circusale_id and hasattr(queryset.model, 'circusale_id'):
                filters &= Q(circusale_id=circusale_id)
        else:
            # Others might only see their own resources
            role_perms = DEFAULT_ROLE_PERMISSIONS.get(user_role, [])
            resource_type = self._get_resource_type_from_model(queryset.model)

            for grant in role_perms:
                if grant.resource_type == resource_type:
                    if grant.conditions.get('self_only'):
                        # Only own resources
                        owner_field = self._get_owner_field(queryset.model)
                        if owner_field:
                            filters &= Q(**{owner_field: user})

        return queryset.filter(filters)

    def _check_ownership(self, user, resource: Model) -> bool:
        """Check if user owns the resource."""
        # Check common owner fields
        owner_fields = ['owner', 'user', 'created_by', 'author']

        for field in owner_fields:
            if hasattr(resource, field):
                owner = getattr(resource, field)
                if owner and (owner == user or getattr(owner, 'id', None) == user.id):
                    return True

        # Check if resource IS the user
        if isinstance(resource, User) and resource.id == user.id:
            return True

        return False

    def _check_tenant_access(self, user, resource: Model) -> bool:
        """Check if resource is in user's tenant."""
        user_tenant = self._get_user_tenant_id(user)
        if not user_tenant:
            return True  # No tenant context

        resource_tenant = None
        if hasattr(resource, 'tenant_id'):
            resource_tenant = str(resource.tenant_id)
        elif hasattr(resource, 'tenant'):
            resource_tenant = str(getattr(resource.tenant, 'id', None))

        if resource_tenant and resource_tenant != user_tenant:
            return False

        return True

    def _check_circusale_access(self, user, resource: Model) -> bool:
        """Check if resource is in user's circusale (if applicable)."""
        user_role = self._get_user_role(user)

        # PDG has access to all circusales
        if user_role == RoleType.PDG:
            return True

        user_circusale = self._get_user_circusale_id(user)
        if not user_circusale:
            return True  # No circusale context

        resource_circusale = None
        if hasattr(resource, 'circusale_id'):
            resource_circusale = str(resource.circusale_id)
        elif hasattr(resource, 'circusale'):
            resource_circusale = str(getattr(resource.circusale, 'id', None))

        if resource_circusale and resource_circusale != user_circusale:
            return False

        return True

    def _get_resource_type(self, resource: Model) -> Optional[ResourceType]:
        """Get ResourceType from model instance."""
        model_name = resource.__class__.__name__.lower()
        return self._get_resource_type_from_model(resource.__class__)

    def _get_resource_type_from_model(self, model: Type[Model]) -> Optional[ResourceType]:
        """Get ResourceType from model class."""
        model_name = model.__name__.lower()

        # Map model names to resource types
        model_mapping = {
            'jobposting': ResourceType.JOB_POSTING,
            'job': ResourceType.JOB_POSTING,
            'application': ResourceType.APPLICATION,
            'candidate': ResourceType.CANDIDATE,
            'interview': ResourceType.INTERVIEW,
            'offer': ResourceType.OFFER,
            'employee': ResourceType.EMPLOYEE,
            'timeoff': ResourceType.TIME_OFF,
            'document': ResourceType.DOCUMENT,
            'user': ResourceType.USER,
            'service': ResourceType.SERVICE,
            'appointment': ResourceType.APPOINTMENT,
            'message': ResourceType.MESSAGE,
            'payment': ResourceType.PAYMENT,
        }

        return model_mapping.get(model_name)

    def _get_owner_field(self, model: Type[Model]) -> Optional[str]:
        """Get the owner field name for a model."""
        owner_fields = ['owner', 'user', 'created_by', 'author']

        for field in owner_fields:
            if hasattr(model, field):
                return field

        return None

    def _get_user_tenant_id(self, user) -> Optional[str]:
        """Get user's tenant ID."""
        if hasattr(user, 'tenant_id'):
            return str(user.tenant_id)
        if hasattr(user, 'tenant'):
            return str(getattr(user.tenant, 'id', None))
        if hasattr(user, 'tenantuser'):
            return str(getattr(user.tenantuser, 'tenant_id', None))
        return None

    def _get_user_circusale_id(self, user) -> Optional[str]:
        """Get user's circusale ID."""
        if hasattr(user, 'circusale_id'):
            return str(user.circusale_id)
        if hasattr(user, 'circusale'):
            return str(getattr(user.circusale, 'id', None))
        if hasattr(user, 'tenantuser'):
            return str(getattr(user.tenantuser, 'circusale_id', None))
        return None

    def _get_user_role(self, user) -> Optional[RoleType]:
        """Get user's role."""
        role_attr = getattr(user, 'role', None)
        if role_attr:
            try:
                return RoleType(role_attr.lower() if isinstance(role_attr, str) else role_attr)
            except ValueError:
                pass
        return None


# =============================================================================
# Tenant Boundary Enforcer
# =============================================================================

class TenantBoundaryEnforcer:
    """
    Enforces tenant boundaries to prevent cross-tenant data access.

    Ensures strict data isolation between tenants.
    """

    def __init__(self):
        self.logger = SecurityEventLogger()

    def enforce(self, user, request: HttpRequest) -> bool:
        """
        Enforce tenant boundary for the current request.

        Args:
            user: The authenticated user
            request: The HTTP request

        Returns:
            True if within boundary, raises PermissionDenied otherwise
        """
        if not user or not user.is_authenticated:
            return True  # Anonymous users handled elsewhere

        if getattr(user, 'is_superuser', False):
            return True

        user_tenant = self._get_user_tenant_id(user)
        request_tenant = self._get_request_tenant_id(request)

        if user_tenant and request_tenant and user_tenant != request_tenant:
            self._log_boundary_violation(user, user_tenant, request_tenant, request)
            raise PermissionDenied('Access denied: tenant boundary violation')

        return True

    def enforce_queryset(self, user, queryset):
        """
        Apply tenant filtering to a queryset.

        Args:
            user: The user
            queryset: The queryset to filter

        Returns:
            Filtered queryset
        """
        if getattr(user, 'is_superuser', False):
            return queryset

        tenant_id = self._get_user_tenant_id(user)
        if not tenant_id:
            return queryset

        model = queryset.model

        # Apply tenant filter
        if hasattr(model, 'tenant_id'):
            return queryset.filter(tenant_id=tenant_id)
        elif hasattr(model, 'tenant'):
            return queryset.filter(tenant_id=tenant_id)

        return queryset

    def validate_foreign_key(
        self,
        user,
        model: Type[Model],
        pk: Any,
        request: HttpRequest = None
    ) -> bool:
        """
        Validate that a foreign key reference is within tenant boundary.

        Args:
            user: The user making the reference
            model: The model class being referenced
            pk: The primary key of the referenced object
            request: Optional request for logging

        Returns:
            True if valid, False otherwise
        """
        user_tenant = self._get_user_tenant_id(user)
        if not user_tenant:
            return True

        try:
            obj = model.objects.get(pk=pk)

            obj_tenant = None
            if hasattr(obj, 'tenant_id'):
                obj_tenant = str(obj.tenant_id)
            elif hasattr(obj, 'tenant'):
                obj_tenant = str(getattr(obj.tenant, 'id', None))

            if obj_tenant and obj_tenant != user_tenant:
                self._log_fk_violation(user, model, pk, user_tenant, obj_tenant, request)
                return False

            return True

        except model.DoesNotExist:
            return False

    def _get_user_tenant_id(self, user) -> Optional[str]:
        """Get user's tenant ID."""
        if hasattr(user, 'tenant_id'):
            return str(user.tenant_id)
        if hasattr(user, 'tenant'):
            return str(getattr(user.tenant, 'id', None))
        if hasattr(user, 'tenantuser'):
            return str(getattr(user.tenantuser, 'tenant_id', None))
        return None

    def _get_request_tenant_id(self, request: HttpRequest) -> Optional[str]:
        """Get tenant ID from request context."""
        if hasattr(request, 'tenant'):
            return str(getattr(request.tenant, 'id', None) or
                       getattr(request.tenant, 'schema_name', None))
        return None

    def _log_boundary_violation(
        self,
        user,
        user_tenant: str,
        request_tenant: str,
        request: HttpRequest
    ):
        """Log a tenant boundary violation."""
        event = SecurityEvent(
            event_type=SecurityEventType.TENANT_BOUNDARY_VIOLATION,
            severity='high',
            message='Cross-tenant access attempt detected',
            user_id=str(user.id),
            tenant_id=request_tenant,
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', ''),
            request_path=request.path,
            request_method=request.method,
            details={
                'user_tenant': user_tenant,
                'target_tenant': request_tenant,
            }
        )
        self.logger.log(event)

    def _log_fk_violation(
        self,
        user,
        model: Type[Model],
        pk: Any,
        user_tenant: str,
        obj_tenant: str,
        request: HttpRequest = None
    ):
        """Log a foreign key violation."""
        event = SecurityEvent(
            event_type=SecurityEventType.TENANT_BOUNDARY_VIOLATION,
            severity='high',
            message=f'Cross-tenant FK reference: {model.__name__}',
            user_id=str(user.id),
            tenant_id=user_tenant,
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', '') if request else None,
            details={
                'model': model.__name__,
                'pk': str(pk),
                'user_tenant': user_tenant,
                'object_tenant': obj_tenant,
            }
        )
        self.logger.log(event)


# =============================================================================
# Cross-Tenant Access Preventer
# =============================================================================

class CrossTenantAccessPreventer:
    """
    Middleware-like component to prevent cross-tenant access attempts.

    Provides comprehensive protection against data leakage between tenants.
    """

    PROTECTED_PATHS = [
        '/api/',
        '/dashboard/',
        '/admin/',
        '/settings/',
        '/finance/',
        '/hr/',
        '/ats/',
    ]

    def __init__(self):
        self.logger = SecurityEventLogger()
        self.boundary_enforcer = TenantBoundaryEnforcer()

    def process_request(self, request: HttpRequest) -> Optional[bool]:
        """
        Process incoming request for cross-tenant violations.

        Args:
            request: The HTTP request

        Returns:
            True if allowed, raises PermissionDenied otherwise
        """
        # Skip for unprotected paths
        if not self._is_protected_path(request.path):
            return True

        user = getattr(request, 'user', None)
        if not user or not user.is_authenticated:
            return True

        # Enforce tenant boundary
        return self.boundary_enforcer.enforce(user, request)

    def validate_query_params(
        self,
        request: HttpRequest,
        tenant_param_names: List[str] = None
    ) -> bool:
        """
        Validate query parameters don't contain cross-tenant references.

        Args:
            request: The HTTP request
            tenant_param_names: Parameter names that reference tenants

        Returns:
            True if valid
        """
        if not tenant_param_names:
            tenant_param_names = ['tenant_id', 'tenant', 'organization_id', 'org_id']

        user = getattr(request, 'user', None)
        if not user or not user.is_authenticated:
            return True

        if getattr(user, 'is_superuser', False):
            return True

        user_tenant = self._get_user_tenant_id(user)
        if not user_tenant:
            return True

        # Check GET and POST parameters
        params = {**request.GET.dict(), **request.POST.dict()}

        for param_name in tenant_param_names:
            if param_name in params:
                param_tenant = str(params[param_name])
                if param_tenant != user_tenant:
                    self._log_param_violation(user, param_name, param_tenant, request)
                    return False

        return True

    def validate_request_body(
        self,
        request: HttpRequest,
        data: Dict[str, Any],
        tenant_fields: List[str] = None
    ) -> bool:
        """
        Validate request body doesn't contain cross-tenant references.

        Args:
            request: The HTTP request
            data: Parsed request body
            tenant_fields: Field names that reference tenants

        Returns:
            True if valid
        """
        if not tenant_fields:
            tenant_fields = ['tenant_id', 'tenant', 'organization_id']

        user = getattr(request, 'user', None)
        if not user or not user.is_authenticated:
            return True

        if getattr(user, 'is_superuser', False):
            return True

        user_tenant = self._get_user_tenant_id(user)
        if not user_tenant:
            return True

        for field in tenant_fields:
            if field in data:
                data_tenant = str(data[field])
                if data_tenant != user_tenant:
                    self._log_body_violation(user, field, data_tenant, request)
                    return False

        return True

    def _is_protected_path(self, path: str) -> bool:
        """Check if a path should be protected."""
        return any(path.startswith(p) for p in self.PROTECTED_PATHS)

    def _get_user_tenant_id(self, user) -> Optional[str]:
        """Get user's tenant ID."""
        if hasattr(user, 'tenant_id'):
            return str(user.tenant_id)
        if hasattr(user, 'tenant'):
            return str(getattr(user.tenant, 'id', None))
        return None

    def _log_param_violation(
        self,
        user,
        param_name: str,
        param_tenant: str,
        request: HttpRequest
    ):
        """Log a query parameter violation."""
        event = SecurityEvent(
            event_type=SecurityEventType.TENANT_BOUNDARY_VIOLATION,
            severity='high',
            message=f'Cross-tenant query parameter: {param_name}',
            user_id=str(user.id),
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', ''),
            request_path=request.path,
            details={
                'param_name': param_name,
                'param_tenant': param_tenant,
            }
        )
        self.logger.log(event)

    def _log_body_violation(
        self,
        user,
        field: str,
        data_tenant: str,
        request: HttpRequest
    ):
        """Log a request body violation."""
        event = SecurityEvent(
            event_type=SecurityEventType.TENANT_BOUNDARY_VIOLATION,
            severity='high',
            message=f'Cross-tenant body field: {field}',
            user_id=str(user.id),
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', ''),
            request_path=request.path,
            details={
                'field': field,
                'data_tenant': data_tenant,
            }
        )
        self.logger.log(event)


# =============================================================================
# Privilege Escalation Detector
# =============================================================================

class PrivilegeEscalationDetector:
    """
    Detects and prevents privilege escalation attempts.

    Monitors for unauthorized attempts to gain higher privileges.
    """

    # Actions that could indicate privilege escalation
    SENSITIVE_ACTIONS = [
        'change_role', 'grant_permission', 'create_user', 'delete_user',
        'change_password', 'enable_superuser', 'modify_tenant', 'create_tenant',
        'access_admin', 'modify_settings', 'export_data', 'api_key_create',
    ]

    def __init__(self):
        self.logger = SecurityEventLogger()
        self.permission_checker = PermissionChecker()

    def check_escalation(
        self,
        user,
        action: str,
        target_role: str = None,
        target_user=None,
        request: HttpRequest = None
    ) -> Tuple[bool, str]:
        """
        Check for privilege escalation in an action.

        Args:
            user: The user performing the action
            action: The action being performed
            target_role: If changing role, the target role
            target_user: If modifying a user, the target user
            request: Optional request for context

        Returns:
            Tuple of (is_allowed, reason if denied)
        """
        if not user or not user.is_authenticated:
            return False, 'Authentication required'

        # Superusers can perform all actions
        if getattr(user, 'is_superuser', False):
            return True, ''

        user_role = self._get_role_level(user)

        # Check role change escalation
        if action == 'change_role' and target_role:
            target_level = self._get_role_level_by_name(target_role)
            if target_level >= user_role:
                self._log_escalation_attempt(user, action, 'role_escalation', request)
                return False, 'Cannot assign role equal or higher than your own'

        # Check user modification
        if target_user and action in ['change_role', 'grant_permission', 'enable_superuser']:
            target_level = self._get_role_level(target_user)

            # Can't modify users of equal or higher level
            if target_level >= user_role:
                self._log_escalation_attempt(user, action, 'user_hierarchy', request)
                return False, 'Cannot modify users at or above your level'

        # Check for superuser creation/modification
        if action == 'enable_superuser':
            if not getattr(user, 'is_superuser', False):
                self._log_escalation_attempt(user, action, 'superuser_creation', request)
                return False, 'Only superusers can create other superusers'

        # Check sensitive action permissions
        if action in self.SENSITIVE_ACTIONS:
            resource_type = self._action_to_resource(action)
            if resource_type:
                has_perm = self.permission_checker.has_permission(
                    user, resource_type, Permission.ADMIN, request=request
                )
                if not has_perm:
                    self._log_escalation_attempt(user, action, 'insufficient_permission', request)
                    return False, f'Insufficient permission for {action}'

        return True, ''

    def validate_permission_grant(
        self,
        granting_user,
        target_user,
        permission: PermissionGrant,
        request: HttpRequest = None
    ) -> Tuple[bool, str]:
        """
        Validate that a permission grant is not an escalation.

        Args:
            granting_user: User granting the permission
            target_user: User receiving the permission
            permission: The permission being granted
            request: Optional request for context

        Returns:
            Tuple of (is_valid, reason if invalid)
        """
        # Check if granting user has the permission they're trying to grant
        if not self.permission_checker.has_permission(
            granting_user,
            permission.resource_type,
            permission.permission,
            permission.resource_id,
            request
        ):
            self._log_escalation_attempt(
                granting_user, 'grant_permission', 'no_permission_to_grant', request
            )
            return False, 'Cannot grant permissions you do not have'

        # Check if target would exceed granting user's level
        granting_level = self._get_role_level(granting_user)
        target_level = self._get_role_level(target_user)

        # ADMIN permission can only be granted by higher level users
        if permission.permission == Permission.ADMIN:
            if target_level >= granting_level:
                self._log_escalation_attempt(
                    granting_user, 'grant_permission', 'admin_grant', request
                )
                return False, 'Cannot grant ADMIN to users at or above your level'

        return True, ''

    def _get_role_level(self, user) -> int:
        """Get numeric role level for comparison."""
        role_levels = {
            RoleType.PDG: 100,
            RoleType.SUPERVISOR: 80,
            RoleType.HR_MANAGER: 60,
            RoleType.FINANCE: 60,
            RoleType.RECRUITER: 50,
            RoleType.HIRING_MANAGER: 50,
            RoleType.MARKETER: 40,
            RoleType.EMPLOYEE: 20,
            RoleType.VIEWER: 10,
        }

        role = self._get_user_role(user)
        return role_levels.get(role, 0)

    def _get_role_level_by_name(self, role_name: str) -> int:
        """Get role level by role name."""
        try:
            role = RoleType(role_name.lower())
            return self._get_role_level_from_type(role)
        except ValueError:
            return 0

    def _get_role_level_from_type(self, role: RoleType) -> int:
        """Get role level from RoleType."""
        role_levels = {
            RoleType.PDG: 100,
            RoleType.SUPERVISOR: 80,
            RoleType.HR_MANAGER: 60,
            RoleType.FINANCE: 60,
            RoleType.RECRUITER: 50,
            RoleType.HIRING_MANAGER: 50,
            RoleType.MARKETER: 40,
            RoleType.EMPLOYEE: 20,
            RoleType.VIEWER: 10,
        }
        return role_levels.get(role, 0)

    def _get_user_role(self, user) -> Optional[RoleType]:
        """Get user's role."""
        role_attr = getattr(user, 'role', None)
        if role_attr:
            try:
                return RoleType(role_attr.lower() if isinstance(role_attr, str) else role_attr)
            except ValueError:
                pass
        return None

    def _action_to_resource(self, action: str) -> Optional[ResourceType]:
        """Map action to resource type."""
        action_mapping = {
            'change_role': ResourceType.ROLE,
            'grant_permission': ResourceType.ROLE,
            'create_user': ResourceType.USER,
            'delete_user': ResourceType.USER,
            'change_password': ResourceType.USER,
            'modify_tenant': ResourceType.TENANT,
            'create_tenant': ResourceType.TENANT,
            'modify_settings': ResourceType.SETTINGS,
            'export_data': ResourceType.AUDIT_LOG,
        }
        return action_mapping.get(action)

    def _log_escalation_attempt(
        self,
        user,
        action: str,
        reason: str,
        request: HttpRequest = None
    ):
        """Log a privilege escalation attempt."""
        event = SecurityEvent(
            event_type=SecurityEventType.PRIVILEGE_ESCALATION_ATTEMPT,
            severity='critical',
            message=f'Privilege escalation attempt: {action}',
            user_id=str(user.id) if user else None,
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', '') if request else None,
            request_path=request.path if request else None,
            request_method=request.method if request else None,
            details={
                'action': action,
                'reason': reason,
                'user_role': str(self._get_user_role(user)),
            }
        )
        self.logger.log(event)
