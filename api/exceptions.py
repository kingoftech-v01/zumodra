"""
API Exceptions - Custom Exception Classes for Zumodra API

This module provides custom exception classes for standardized error handling:
- Tenant-specific exceptions
- Business logic exceptions
- Rate limiting exceptions
- Feature access exceptions
- Standardized error responses

All exceptions follow a consistent format:
{
    "success": false,
    "message": "Human-readable message",
    "error_code": "MACHINE_READABLE_CODE",
    "errors": [...],
    "meta": {...}
}
"""

import logging
from typing import Any, Dict, List, Optional

from django.utils.translation import gettext_lazy as _

from rest_framework import status
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.views import exception_handler
from rest_framework.response import Response
from django.utils import timezone

logger = logging.getLogger(__name__)


# =============================================================================
# BASE EXCEPTIONS
# =============================================================================

class ZumodraAPIException(APIException):
    """
    Base exception for all Zumodra API errors.

    Attributes:
        status_code: HTTP status code
        default_detail: Default error message
        default_code: Machine-readable error code
        error_code: Specific error code for this instance
        extra_data: Additional data to include in response
    """

    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = _("An unexpected error occurred.")
    default_code = "ERROR"

    def __init__(
        self,
        detail: str = None,
        code: str = None,
        extra_data: Dict = None,
        **kwargs
    ):
        self.error_code = code or self.default_code
        self.extra_data = extra_data or {}

        if detail is None:
            detail = str(self.default_detail)

        super().__init__(detail=detail, code=code)

    def get_full_details(self) -> Dict:
        """Get full error details for response."""
        return {
            'message': str(self.detail),
            'error_code': self.error_code,
            'extra_data': self.extra_data,
        }


# =============================================================================
# TENANT EXCEPTIONS
# =============================================================================

class TenantNotFoundError(ZumodraAPIException):
    """Raised when no tenant context is found."""

    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = _("No organization context found. Please access via your organization domain.")
    default_code = "TENANT_NOT_FOUND"


class TenantInactiveError(ZumodraAPIException):
    """Raised when tenant is not active (suspended, cancelled, etc.)."""

    status_code = status.HTTP_403_FORBIDDEN
    default_detail = _("Your organization account is currently inactive.")
    default_code = "TENANT_INACTIVE"

    def __init__(self, reason: str = None, **kwargs):
        detail = str(self.default_detail)
        if reason:
            detail = f"{detail} Reason: {reason}"
        super().__init__(detail=detail, **kwargs)


class TenantSuspendedError(TenantInactiveError):
    """Raised when tenant is suspended (usually payment issues)."""

    default_detail = _("Your organization account has been suspended.")
    default_code = "TENANT_SUSPENDED"


class TenantTrialExpiredError(ZumodraAPIException):
    """Raised when tenant's trial period has expired."""

    status_code = status.HTTP_402_PAYMENT_REQUIRED
    default_detail = _("Your trial period has expired. Please subscribe to continue.")
    default_code = "TRIAL_EXPIRED"


class TenantAccessDeniedError(ZumodraAPIException):
    """Raised when user doesn't have access to the tenant."""

    status_code = status.HTTP_403_FORBIDDEN
    default_detail = _("You do not have access to this organization.")
    default_code = "TENANT_ACCESS_DENIED"


class TenantMismatchError(ZumodraAPIException):
    """Raised when trying to access resources from a different tenant."""

    status_code = status.HTTP_403_FORBIDDEN
    default_detail = _("Cannot access resources from another organization.")
    default_code = "TENANT_MISMATCH"


# =============================================================================
# FEATURE & PLAN EXCEPTIONS
# =============================================================================

class FeatureNotAvailableError(ZumodraAPIException):
    """Raised when trying to use a feature not included in plan."""

    status_code = status.HTTP_403_FORBIDDEN
    default_detail = _("This feature is not available in your current plan.")
    default_code = "FEATURE_NOT_AVAILABLE"

    def __init__(self, feature_name: str = None, required_plan: str = None, **kwargs):
        detail = str(self.default_detail)
        extra_data = kwargs.pop('extra_data', {})

        if feature_name:
            detail = f"The '{feature_name}' feature is not available in your current plan."
            extra_data['feature'] = feature_name

        if required_plan:
            detail = f"{detail} Upgrade to {required_plan} to access this feature."
            extra_data['required_plan'] = required_plan

        super().__init__(detail=detail, extra_data=extra_data, **kwargs)


class PlanLimitExceededError(ZumodraAPIException):
    """Raised when a plan limit is exceeded."""

    status_code = status.HTTP_403_FORBIDDEN
    default_detail = _("You have reached the limit for your current plan.")
    default_code = "PLAN_LIMIT_EXCEEDED"

    def __init__(
        self,
        limit_name: str = None,
        current_usage: int = None,
        max_allowed: int = None,
        **kwargs
    ):
        detail = str(self.default_detail)
        extra_data = kwargs.pop('extra_data', {})

        if limit_name:
            extra_data['limit_name'] = limit_name
            detail = f"You have reached the {limit_name} limit for your current plan."

        if current_usage is not None and max_allowed is not None:
            extra_data['current_usage'] = current_usage
            extra_data['max_allowed'] = max_allowed
            detail = f"{detail} Current: {current_usage}/{max_allowed}."

        super().__init__(detail=detail, extra_data=extra_data, **kwargs)


class UpgradeRequiredError(ZumodraAPIException):
    """Raised when an action requires a plan upgrade."""

    status_code = status.HTTP_402_PAYMENT_REQUIRED
    default_detail = _("Please upgrade your plan to perform this action.")
    default_code = "UPGRADE_REQUIRED"

    def __init__(self, suggested_plan: str = None, **kwargs):
        extra_data = kwargs.pop('extra_data', {})
        if suggested_plan:
            extra_data['suggested_plan'] = suggested_plan
        super().__init__(extra_data=extra_data, **kwargs)


# =============================================================================
# RESOURCE EXCEPTIONS
# =============================================================================

class ResourceNotFoundError(ZumodraAPIException):
    """Raised when a requested resource is not found."""

    status_code = status.HTTP_404_NOT_FOUND
    default_detail = _("The requested resource was not found.")
    default_code = "NOT_FOUND"

    def __init__(self, resource_type: str = None, resource_id: Any = None, **kwargs):
        detail = str(self.default_detail)
        extra_data = kwargs.pop('extra_data', {})

        if resource_type:
            extra_data['resource_type'] = resource_type
            detail = f"{resource_type} not found."

        if resource_id:
            extra_data['resource_id'] = str(resource_id)
            detail = f"{resource_type or 'Resource'} with ID '{resource_id}' not found."

        super().__init__(detail=detail, extra_data=extra_data, **kwargs)


class ResourceAlreadyExistsError(ZumodraAPIException):
    """Raised when trying to create a duplicate resource."""

    status_code = status.HTTP_409_CONFLICT
    default_detail = _("A resource with these details already exists.")
    default_code = "ALREADY_EXISTS"

    def __init__(
        self,
        resource_type: str = None,
        conflicting_fields: List[str] = None,
        **kwargs
    ):
        detail = str(self.default_detail)
        extra_data = kwargs.pop('extra_data', {})

        if resource_type:
            extra_data['resource_type'] = resource_type
            detail = f"A {resource_type} with these details already exists."

        if conflicting_fields:
            extra_data['conflicting_fields'] = conflicting_fields

        super().__init__(detail=detail, extra_data=extra_data, **kwargs)


class ResourceLockedError(ZumodraAPIException):
    """Raised when trying to modify a locked resource."""

    status_code = status.HTTP_423_LOCKED
    default_detail = _("This resource is currently locked and cannot be modified.")
    default_code = "RESOURCE_LOCKED"

    def __init__(self, locked_by: str = None, locked_until: str = None, **kwargs):
        extra_data = kwargs.pop('extra_data', {})
        if locked_by:
            extra_data['locked_by'] = locked_by
        if locked_until:
            extra_data['locked_until'] = locked_until
        super().__init__(extra_data=extra_data, **kwargs)


class ResourceStateError(ZumodraAPIException):
    """Raised when a resource is in an invalid state for the operation."""

    status_code = status.HTTP_409_CONFLICT
    default_detail = _("This operation cannot be performed on the resource in its current state.")
    default_code = "INVALID_STATE"

    def __init__(
        self,
        current_state: str = None,
        required_state: str = None,
        allowed_states: List[str] = None,
        **kwargs
    ):
        detail = str(self.default_detail)
        extra_data = kwargs.pop('extra_data', {})

        if current_state:
            extra_data['current_state'] = current_state
            detail = f"Resource is in '{current_state}' state."

        if required_state:
            extra_data['required_state'] = required_state
            detail = f"{detail} Required state: '{required_state}'."

        if allowed_states:
            extra_data['allowed_states'] = allowed_states
            detail = f"{detail} Allowed states: {', '.join(allowed_states)}."

        super().__init__(detail=detail, extra_data=extra_data, **kwargs)


# =============================================================================
# PERMISSION EXCEPTIONS
# =============================================================================

class PermissionDeniedError(ZumodraAPIException):
    """Raised when user doesn't have permission for an action."""

    status_code = status.HTTP_403_FORBIDDEN
    default_detail = _("You do not have permission to perform this action.")
    default_code = "PERMISSION_DENIED"

    def __init__(self, required_permission: str = None, **kwargs):
        extra_data = kwargs.pop('extra_data', {})
        if required_permission:
            extra_data['required_permission'] = required_permission
        super().__init__(extra_data=extra_data, **kwargs)


class InsufficientRoleError(ZumodraAPIException):
    """Raised when user's role is insufficient for an action."""

    status_code = status.HTTP_403_FORBIDDEN
    default_detail = _("Your role does not have permission for this action.")
    default_code = "INSUFFICIENT_ROLE"

    def __init__(
        self,
        current_role: str = None,
        required_role: str = None,
        **kwargs
    ):
        detail = str(self.default_detail)
        extra_data = kwargs.pop('extra_data', {})

        if current_role:
            extra_data['current_role'] = current_role

        if required_role:
            extra_data['required_role'] = required_role
            detail = f"This action requires the '{required_role}' role or higher."

        super().__init__(detail=detail, extra_data=extra_data, **kwargs)


class OwnershipRequiredError(ZumodraAPIException):
    """Raised when only the owner can perform an action."""

    status_code = status.HTTP_403_FORBIDDEN
    default_detail = _("Only the owner can perform this action.")
    default_code = "OWNERSHIP_REQUIRED"


# =============================================================================
# RATE LIMITING EXCEPTIONS
# =============================================================================

class RateLimitExceededError(ZumodraAPIException):
    """Raised when API rate limit is exceeded."""

    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    default_detail = _("Rate limit exceeded. Please wait before making more requests.")
    default_code = "RATE_LIMIT_EXCEEDED"

    def __init__(
        self,
        retry_after: int = None,
        limit: int = None,
        period: str = None,
        **kwargs
    ):
        extra_data = kwargs.pop('extra_data', {})

        if retry_after:
            extra_data['retry_after_seconds'] = retry_after

        if limit and period:
            extra_data['limit'] = limit
            extra_data['period'] = period

        super().__init__(extra_data=extra_data, **kwargs)


class BurstLimitExceededError(RateLimitExceededError):
    """Raised when short-term burst limit is exceeded."""

    default_detail = _("Too many requests in a short time. Please slow down.")
    default_code = "BURST_LIMIT_EXCEEDED"


class DailyLimitExceededError(RateLimitExceededError):
    """Raised when daily API limit is exceeded."""

    default_detail = _("Daily API limit exceeded. Limit resets at midnight UTC.")
    default_code = "DAILY_LIMIT_EXCEEDED"


# =============================================================================
# VALIDATION EXCEPTIONS
# =============================================================================

class InvalidInputError(ZumodraAPIException):
    """Raised for general invalid input."""

    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = _("Invalid input provided.")
    default_code = "INVALID_INPUT"


class MissingRequiredFieldError(ZumodraAPIException):
    """Raised when a required field is missing."""

    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = _("Required field is missing.")
    default_code = "MISSING_REQUIRED_FIELD"

    def __init__(self, field_name: str = None, **kwargs):
        detail = str(self.default_detail)
        extra_data = kwargs.pop('extra_data', {})

        if field_name:
            extra_data['field'] = field_name
            detail = f"Required field '{field_name}' is missing."

        super().__init__(detail=detail, extra_data=extra_data, **kwargs)


class InvalidFieldValueError(ZumodraAPIException):
    """Raised when a field value is invalid."""

    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = _("Invalid field value.")
    default_code = "INVALID_FIELD_VALUE"

    def __init__(
        self,
        field_name: str = None,
        value: Any = None,
        allowed_values: List = None,
        **kwargs
    ):
        detail = str(self.default_detail)
        extra_data = kwargs.pop('extra_data', {})

        if field_name:
            extra_data['field'] = field_name
            detail = f"Invalid value for field '{field_name}'."

        if value is not None:
            extra_data['provided_value'] = str(value)

        if allowed_values:
            extra_data['allowed_values'] = allowed_values
            detail = f"{detail} Allowed values: {', '.join(map(str, allowed_values))}."

        super().__init__(detail=detail, extra_data=extra_data, **kwargs)


class BusinessRuleViolationError(ZumodraAPIException):
    """Raised when a business rule is violated."""

    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_detail = _("This action violates business rules.")
    default_code = "BUSINESS_RULE_VIOLATION"

    def __init__(self, rule_name: str = None, rule_description: str = None, **kwargs):
        extra_data = kwargs.pop('extra_data', {})

        if rule_name:
            extra_data['rule'] = rule_name

        detail = rule_description if rule_description else str(self.default_detail)

        super().__init__(detail=detail, extra_data=extra_data, **kwargs)


# =============================================================================
# EXTERNAL SERVICE EXCEPTIONS
# =============================================================================

class ExternalServiceError(ZumodraAPIException):
    """Raised when an external service fails."""

    status_code = status.HTTP_502_BAD_GATEWAY
    default_detail = _("An external service is temporarily unavailable.")
    default_code = "EXTERNAL_SERVICE_ERROR"

    def __init__(self, service_name: str = None, **kwargs):
        extra_data = kwargs.pop('extra_data', {})

        if service_name:
            extra_data['service'] = service_name

        super().__init__(extra_data=extra_data, **kwargs)


class PaymentError(ExternalServiceError):
    """Raised when a payment operation fails."""

    default_detail = _("Payment processing failed.")
    default_code = "PAYMENT_ERROR"


class EmailDeliveryError(ExternalServiceError):
    """Raised when email delivery fails."""

    default_detail = _("Failed to send email.")
    default_code = "EMAIL_DELIVERY_ERROR"


class StorageError(ExternalServiceError):
    """Raised when file storage operation fails."""

    default_detail = _("File storage operation failed.")
    default_code = "STORAGE_ERROR"


# =============================================================================
# AUTHENTICATION EXCEPTIONS
# =============================================================================

class AuthenticationFailedError(ZumodraAPIException):
    """Raised when authentication fails."""

    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = _("Authentication failed.")
    default_code = "AUTHENTICATION_FAILED"


class TokenExpiredError(AuthenticationFailedError):
    """Raised when authentication token has expired."""

    default_detail = _("Authentication token has expired. Please log in again.")
    default_code = "TOKEN_EXPIRED"


class InvalidTokenError(AuthenticationFailedError):
    """Raised when authentication token is invalid."""

    default_detail = _("Invalid authentication token.")
    default_code = "INVALID_TOKEN"


class SessionExpiredError(AuthenticationFailedError):
    """Raised when user session has expired."""

    default_detail = _("Your session has expired. Please log in again.")
    default_code = "SESSION_EXPIRED"


class TwoFactorRequiredError(ZumodraAPIException):
    """Raised when 2FA is required but not provided."""

    status_code = status.HTTP_403_FORBIDDEN
    default_detail = _("Two-factor authentication is required.")
    default_code = "2FA_REQUIRED"


# =============================================================================
# EXCEPTION HANDLER
# =============================================================================

def zumodra_exception_handler(exc, context):
    """
    Custom exception handler for standardized error responses.

    All errors are formatted as:
    {
        "success": false,
        "data": null,
        "message": "Error description",
        "error_code": "MACHINE_CODE",
        "errors": [...],
        "meta": {
            "timestamp": "ISO8601",
            "tenant": "tenant_slug"
        }
    }
    """
    # Get the standard DRF response
    response = exception_handler(exc, context)

    # Handle unhandled exceptions
    if response is None:
        logger.exception(f"Unhandled exception: {exc}")
        response = Response(
            {
                "success": False,
                "data": None,
                "message": "An unexpected error occurred.",
                "error_code": "INTERNAL_ERROR",
                "errors": [],
                "meta": {
                    "timestamp": timezone.now().isoformat(),
                }
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        return response

    # Format the response
    error_data = {
        "success": False,
        "data": None,
        "message": "",
        "error_code": "ERROR",
        "errors": [],
        "meta": {
            "timestamp": timezone.now().isoformat(),
        }
    }

    # Handle our custom exceptions
    if isinstance(exc, ZumodraAPIException):
        error_data["message"] = str(exc.detail)
        error_data["error_code"] = exc.error_code
        if exc.extra_data:
            error_data["meta"].update(exc.extra_data)

    # Handle DRF ValidationError
    elif isinstance(exc, ValidationError):
        error_data["error_code"] = "VALIDATION_ERROR"
        if isinstance(exc.detail, dict):
            error_data["errors"] = [
                {"field": field, "messages": msgs if isinstance(msgs, list) else [str(msgs)]}
                for field, msgs in exc.detail.items()
            ]
            error_data["message"] = "Validation failed."
        elif isinstance(exc.detail, list):
            error_data["errors"] = [{"field": "non_field_errors", "messages": [str(e) for e in exc.detail]}]
            error_data["message"] = str(exc.detail[0]) if exc.detail else "Validation failed."
        else:
            error_data["message"] = str(exc.detail)

    # Handle other DRF exceptions
    else:
        error_data["message"] = str(exc.detail) if hasattr(exc, 'detail') else str(exc)
        error_data["error_code"] = getattr(exc, 'default_code', 'ERROR')

    # Add tenant context if available
    request = context.get('request')
    if request:
        tenant = getattr(request, 'tenant', None)
        if tenant:
            error_data["meta"]["tenant"] = tenant.slug

    response.data = error_data
    return response


# =============================================================================
# EXCEPTION UTILITIES
# =============================================================================

def raise_for_tenant(tenant) -> None:
    """
    Raise appropriate exception based on tenant status.

    Usage:
        raise_for_tenant(request.tenant)
    """
    if not tenant:
        raise TenantNotFoundError()

    if hasattr(tenant, 'status'):
        if tenant.status == 'suspended':
            raise TenantSuspendedError()
        elif tenant.status == 'cancelled':
            raise TenantInactiveError(reason="Account has been cancelled.")
        elif tenant.status != 'active' and tenant.status != 'trial':
            raise TenantInactiveError()

    if hasattr(tenant, 'is_on_trial') and hasattr(tenant, 'trial_ends_at'):
        if not tenant.is_on_trial and not hasattr(tenant, 'paid_until'):
            raise TenantTrialExpiredError()


def raise_for_feature(tenant, feature_name: str, required_plan: str = None) -> None:
    """
    Raise FeatureNotAvailableError if tenant doesn't have the feature.

    Usage:
        raise_for_feature(request.tenant, 'ai_matching', 'Professional')
    """
    if not tenant or not tenant.plan:
        raise FeatureNotAvailableError(feature_name=feature_name, required_plan=required_plan)

    feature_attr = f'feature_{feature_name}'
    if not getattr(tenant.plan, feature_attr, False):
        raise FeatureNotAvailableError(feature_name=feature_name, required_plan=required_plan)


def raise_for_limit(
    tenant,
    limit_name: str,
    current_count: int,
    resource_name: str = None
) -> None:
    """
    Raise PlanLimitExceededError if tenant has exceeded a limit.

    Usage:
        raise_for_limit(request.tenant, 'users', current_user_count, 'team members')
    """
    if not tenant or not tenant.plan:
        raise PlanLimitExceededError(limit_name=resource_name or limit_name)

    limit_attr = f'max_{limit_name}'
    max_allowed = getattr(tenant.plan, limit_attr, 0)

    if current_count >= max_allowed:
        raise PlanLimitExceededError(
            limit_name=resource_name or limit_name,
            current_usage=current_count,
            max_allowed=max_allowed
        )
