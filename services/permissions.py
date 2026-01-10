"""
Service Marketplace Permissions

Permission checks for cross-tenant marketplace operations.
Enforces security rules for publishing services, accepting requests, etc.
"""

from django.core.exceptions import PermissionDenied
from django.db import connection
import logging

logger = logging.getLogger(__name__)


def can_publish_to_marketplace(user, service):
    """
    Check if user can publish a service to public marketplace.

    Requirements:
    - User must be in the service's tenant
    - User must have 'manager' or 'owner' role (ADMIN or OWNER)
    - Provider must have marketplace_enabled=True
    - Tenant must not be suspended or inactive

    Args:
        user: CustomUser instance
        service: Service instance

    Returns:
        bool: True if allowed

    Raises:
        PermissionDenied: If user lacks permission (with specific message)
    """
    from accounts.models import TenantUser

    # Check tenant membership
    try:
        tenant_user = TenantUser.objects.get(
            user=user,
            tenant=service.tenant,
            is_active=True
        )
    except TenantUser.DoesNotExist:
        logger.warning(
            f"User {user.id} attempted to publish service {service.uuid} "
            f"but is not a member of tenant {service.tenant.schema_name}"
        )
        raise PermissionDenied("You are not a member of this organization.")

    # Check role - only OWNER and ADMIN can publish to marketplace
    if tenant_user.role not in [TenantUser.UserRole.OWNER, TenantUser.UserRole.ADMIN]:
        logger.warning(
            f"User {user.id} (role: {tenant_user.role}) attempted to publish service {service.uuid} "
            f"but lacks required role"
        )
        raise PermissionDenied(
            "Only organization owners and admins can publish services to the public marketplace."
        )

    # Check provider marketplace status
    if not service.provider.marketplace_enabled:
        logger.warning(
            f"User {user.id} attempted to publish service {service.uuid} "
            f"but provider {service.provider.uuid} marketplace is disabled"
        )
        raise PermissionDenied(
            "This service provider does not have marketplace access enabled."
        )

    # Check tenant status
    if service.tenant.status != service.tenant.TenantStatus.ACTIVE:
        logger.warning(
            f"User {user.id} attempted to publish service {service.uuid} "
            f"but tenant {service.tenant.schema_name} status is {service.tenant.status}"
        )
        raise PermissionDenied(
            "Your organization must be in active status to publish services to the marketplace."
        )

    return True


def can_enable_provider_marketplace(user, provider):
    """
    Check if user can enable marketplace for a service provider.

    Only tenant owners can enable/disable marketplace access for providers.

    Args:
        user: CustomUser instance
        provider: ServiceProvider instance

    Returns:
        bool: True if allowed

    Raises:
        PermissionDenied: If user lacks permission
    """
    from accounts.models import TenantUser

    try:
        tenant_user = TenantUser.objects.get(
            user=user,
            tenant=provider.tenant,
            is_active=True
        )
    except TenantUser.DoesNotExist:
        raise PermissionDenied("You are not a member of this organization.")

    # Only OWNER can change marketplace settings
    if tenant_user.role != TenantUser.UserRole.OWNER:
        raise PermissionDenied(
            "Only organization owners can enable marketplace access for providers."
        )

    return True


def can_view_cross_tenant_request(user, cross_request):
    """
    Check if user can view a cross-tenant service request.

    Allowed:
    - Request creator (client)
    - Members of requesting tenant with appropriate role (ADMIN, HR_MANAGER, OWNER)

    Args:
        user: CustomUser instance
        cross_request: CrossTenantServiceRequest instance

    Returns:
        bool: True if allowed

    Raises:
        PermissionDenied: If user lacks permission
    """
    from accounts.models import TenantUser

    # Creator can always view
    if cross_request.client == user:
        return True

    # Tenant managers can view
    try:
        tenant_user = TenantUser.objects.get(
            user=user,
            tenant=cross_request.tenant,
            is_active=True
        )

        # OWNER, ADMIN, HR_MANAGER can view
        if tenant_user.role in [
            TenantUser.UserRole.OWNER,
            TenantUser.UserRole.ADMIN,
            TenantUser.UserRole.HR_MANAGER
        ]:
            return True

    except TenantUser.DoesNotExist:
        pass

    logger.warning(
        f"User {user.id} attempted to view cross-tenant request {cross_request.uuid} "
        f"but lacks permission"
    )
    raise PermissionDenied("You do not have permission to view this request.")


def can_respond_to_cross_tenant_request(user, cross_request):
    """
    Check if user can respond to a cross-tenant service request.

    Only admins/owners in the TARGET tenant (provider) can respond.
    The request lives in the requesting tenant's schema, but the target
    schema name is stored in target_tenant_schema field.

    Args:
        user: CustomUser instance
        cross_request: CrossTenantServiceRequest instance

    Returns:
        bool: True if allowed

    Raises:
        PermissionDenied: If user lacks permission
    """
    from accounts.models import TenantUser
    from tenants.models import Tenant

    # Get target tenant (provider's tenant)
    try:
        target_tenant = Tenant.objects.get(schema_name=cross_request.target_tenant_schema)
    except Tenant.DoesNotExist:
        raise PermissionDenied("Target organization not found.")

    # Check if user is member of target tenant with appropriate role
    try:
        tenant_user = TenantUser.objects.get(
            user=user,
            tenant=target_tenant,
            is_active=True
        )

        # OWNER and ADMIN can respond
        if tenant_user.role in [TenantUser.UserRole.OWNER, TenantUser.UserRole.ADMIN]:
            return True

    except TenantUser.DoesNotExist:
        pass

    logger.warning(
        f"User {user.id} attempted to respond to cross-tenant request {cross_request.uuid} "
        f"for target tenant {cross_request.target_tenant_schema} but lacks permission"
    )
    raise PermissionDenied(
        "Only admins/owners of the service provider organization can respond to this request."
    )


def can_create_cross_tenant_request(user, catalog_service):
    """
    Check if user can create a cross-tenant service request.

    Requirements:
    - User must be authenticated
    - User must be in a tenant (or we could allow public users in future)
    - Cannot request from own tenant (must use internal service booking)

    Args:
        user: CustomUser instance
        catalog_service: PublicServiceCatalog instance

    Returns:
        bool: True if allowed

    Raises:
        PermissionDenied: If user lacks permission
    """
    if not user.is_authenticated:
        raise PermissionDenied("You must be logged in to request services.")

    # Check if user is in a tenant
    from accounts.models import TenantUser
    user_tenants = TenantUser.objects.filter(user=user, is_active=True)

    if not user_tenants.exists():
        # Future: could allow public users to request services
        raise PermissionDenied(
            "You must be part of an organization to request services. "
            "Please join or create an organization first."
        )

    # Get user's primary tenant (or any active tenant)
    user_tenant = user_tenants.first().tenant

    # Cannot request from own tenant
    if user_tenant.schema_name == catalog_service.tenant_schema_name:
        raise PermissionDenied(
            "Use the internal services page to book services from your own company."
        )

    return True
