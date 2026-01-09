"""
Secure Celery Task Base Classes with Permission Validation

This module provides Celery task base classes that enforce permission checks
before executing tasks that operate on user or tenant data.

USAGE:
    from core.tasks.secure_task import SecureTenantTask, secure_task

    # Using base class directly
    @celery_app.task(bind=True, base=SecureTenantTask)
    def bulk_delete_candidates(self, candidate_ids, user_id=None, tenant_id=None):
        self.require_permission('edit_candidates')
        # ... task logic

    # Using decorator
    @secure_task(required_permission='edit_candidates')
    def another_task(self, data, user_id=None, tenant_id=None):
        # Permission automatically validated
        # ... task logic

CLASSES:

1. SecureTenantTask:
   - Validates user_id and tenant_id before execution
   - Checks required_permission and required_roles
   - Provides require_permission() and require_role() methods
   - verify_object_ownership() for object-level checks
   - Audit logging of task execution

2. PermissionValidatedTask:
   - Combines SecureTenantTask with AutoRetry
   - Full-featured secure task with retry logic

DECORATORS:

1. @secure_task(required_permission=None, required_roles=None):
   Creates a task with built-in permission validation
"""

import logging
from typing import Any, Dict, List, Optional, Type

from celery import Task
from django.core.exceptions import PermissionDenied, ObjectDoesNotExist
from django.db import connection

from zumodra.celery_tasks_base import TenantAwareTask, AutoRetryTask

logger = logging.getLogger('security.tasks')


# =============================================================================
# SECURE TENANT TASK
# =============================================================================

class SecureTenantTask(TenantAwareTask):
    """
    Celery task with permission validation for multi-tenant operations.

    All tasks operating on user data should inherit from this class to ensure
    proper authorization checks before execution.

    Features:
    - Validates user_id and tenant_id permissions before execution
    - Checks required_permission attribute if defined
    - Checks required_roles attribute if defined
    - Provides require_permission() for explicit permission checks
    - Provides require_role() for explicit role checks
    - verify_object_ownership() for object-level permissions
    - Comprehensive audit logging

    Usage:
        @celery_app.task(bind=True, base=SecureTenantTask)
        def bulk_move_applications(self, application_ids, user_id=None, tenant_id=None):
            self.require_permission('edit_candidates')

            for app_id in application_ids:
                self.verify_object_ownership(Application, app_id, owner_field='job__tenant')

            # ... task logic

    Class Attributes:
        required_permission: Permission codename required for this task
        required_roles: List of roles that can execute this task
        log_execution: Whether to log task execution (default: True)
        validate_on_execute: Auto-validate permissions on execute (default: True)
    """

    abstract = True

    # Permission requirements (override in subclass)
    required_permission: Optional[str] = None
    required_roles: Optional[List[str]] = None

    # Audit logging settings
    log_execution: bool = True

    # Auto-validate permissions when task is called
    validate_on_execute: bool = True

    # Store user context
    _user_id: Optional[int] = None
    _tenant_id: Optional[int] = None
    _tenant_user: Optional[Any] = None

    def __call__(self, *args, **kwargs):
        """
        Execute task with permission validation.

        Extracts user_id and tenant_id from kwargs, validates permissions
        if required, then executes the task with tenant context.
        """
        # Extract security context from kwargs
        self._user_id = kwargs.pop('user_id', None)
        self._tenant_id = kwargs.pop('tenant_id', None)
        tenant_schema = kwargs.get('tenant_schema', None)

        # Validate permissions if required
        if self.validate_on_execute and (self.required_permission or self.required_roles):
            self._validate_permissions()

        # Log task execution
        if self.log_execution:
            self._log_task_start(kwargs)

        try:
            # Execute with tenant context via parent class
            result = super().__call__(*args, **kwargs)

            if self.log_execution:
                self._log_task_success()

            return result

        except PermissionDenied as e:
            self._log_permission_denied(str(e))
            raise

        except Exception as e:
            if self.log_execution:
                self._log_task_failure(e)
            raise

    def _validate_permissions(self) -> None:
        """
        Validate user has required permissions before task execution.

        Raises:
            PermissionDenied: If user lacks required permissions
        """
        if not self._user_id or not self._tenant_id:
            raise PermissionDenied(
                f"Task {self.name} requires user_id and tenant_id for authorization. "
                "Pass these as kwargs when calling the task."
            )

        # Get tenant user
        from accounts.models import TenantUser

        try:
            self._tenant_user = TenantUser.objects.get(
                user_id=self._user_id,
                tenant_id=self._tenant_id,
                is_active=True
            )
        except TenantUser.DoesNotExist:
            raise PermissionDenied(
                f"User {self._user_id} is not a member of tenant {self._tenant_id}"
            )

        # Check role requirement
        if self.required_roles:
            if self._tenant_user.role not in self.required_roles:
                raise PermissionDenied(
                    f"User role '{self._tenant_user.role}' not in required roles "
                    f"{self.required_roles} for task {self.name}"
                )

        # Check permission requirement
        if self.required_permission:
            if not self._tenant_user.has_permission(self.required_permission):
                raise PermissionDenied(
                    f"User lacks permission '{self.required_permission}' "
                    f"required for task {self.name}"
                )

    def require_permission(self, permission_codename: str) -> None:
        """
        Explicitly check for a permission within the task.

        Use this for conditional permission checks based on task logic.

        Usage:
            def run(self, data, user_id=None, tenant_id=None):
                if data.get('bulk_delete'):
                    self.require_permission('delete_candidates')
                # ... rest of task

        Args:
            permission_codename: The permission codename to check

        Raises:
            PermissionDenied: If user lacks the permission
        """
        if not self._user_id:
            raise PermissionDenied(f"user_id required for permission check: {permission_codename}")

        # Get or refresh tenant user
        if not self._tenant_user and self._tenant_id:
            from accounts.models import TenantUser
            try:
                self._tenant_user = TenantUser.objects.get(
                    user_id=self._user_id,
                    tenant_id=self._tenant_id,
                    is_active=True
                )
            except TenantUser.DoesNotExist:
                raise PermissionDenied(f"User {self._user_id} not found in tenant")

        if self._tenant_user and not self._tenant_user.has_permission(permission_codename):
            logger.warning(
                f"TASK_PERMISSION_DENIED: task={self.name} user={self._user_id} "
                f"tenant={self._tenant_id} permission={permission_codename}"
            )
            raise PermissionDenied(
                f"User lacks permission '{permission_codename}' for this operation"
            )

    def require_role(self, allowed_roles: List[str]) -> None:
        """
        Explicitly check for role within the task.

        Usage:
            def run(self, data, user_id=None, tenant_id=None):
                if data.get('is_bulk_operation'):
                    self.require_role(['owner', 'admin'])
                # ... rest of task

        Args:
            allowed_roles: List of role names that are allowed

        Raises:
            PermissionDenied: If user doesn't have an allowed role
        """
        if not self._user_id:
            raise PermissionDenied(f"user_id required for role check")

        from accounts.models import TenantUser

        has_role = TenantUser.objects.filter(
            user_id=self._user_id,
            tenant_id=self._tenant_id,
            is_active=True,
            role__in=allowed_roles
        ).exists()

        if not has_role:
            logger.warning(
                f"TASK_ROLE_DENIED: task={self.name} user={self._user_id} "
                f"tenant={self._tenant_id} required_roles={allowed_roles}"
            )
            raise PermissionDenied(
                f"User role not in allowed roles {allowed_roles}"
            )

    def verify_object_ownership(
        self,
        model_class: Type,
        object_id: Any,
        owner_field: str = 'user',
        admin_bypass: bool = True
    ) -> bool:
        """
        Verify the acting user owns or can access the object.

        Use this to ensure users can only operate on their own objects
        or objects they have access to.

        Usage:
            def run(self, candidate_ids, user_id=None, tenant_id=None):
                for cid in candidate_ids:
                    self.verify_object_ownership(
                        Candidate, cid,
                        owner_field='assigned_recruiter__user'
                    )

        Args:
            model_class: The Django model class
            object_id: The primary key of the object
            owner_field: Field path to the owner (supports __ traversal)
            admin_bypass: Allow admins to access all objects

        Returns:
            True if user has access

        Raises:
            PermissionDenied: If user doesn't have access
            ObjectDoesNotExist: If object not found
        """
        try:
            obj = model_class.objects.get(pk=object_id)
        except model_class.DoesNotExist:
            raise ObjectDoesNotExist(f"{model_class.__name__} with pk={object_id} not found")

        # Get the owner from the object
        owner = obj
        for field in owner_field.split('__'):
            owner = getattr(owner, field, None)
            if owner is None:
                break

        # Check if user owns the object
        if owner and getattr(owner, 'id', None) == self._user_id:
            return True

        # Check for admin bypass
        if admin_bypass and self._tenant_user:
            if self._tenant_user.is_admin:
                return True

        logger.warning(
            f"TASK_OWNERSHIP_DENIED: task={self.name} user={self._user_id} "
            f"object={model_class.__name__}:{object_id} owner_field={owner_field}"
        )
        raise PermissionDenied(
            f"User does not have access to {model_class.__name__} with id {object_id}"
        )

    def verify_tenant_ownership(
        self,
        model_class: Type,
        object_id: Any,
        tenant_field: str = 'tenant'
    ) -> bool:
        """
        Verify the object belongs to the current tenant.

        Usage:
            def run(self, document_id, user_id=None, tenant_id=None):
                self.verify_tenant_ownership(Document, document_id)

        Args:
            model_class: The Django model class
            object_id: The primary key of the object
            tenant_field: Field path to the tenant

        Returns:
            True if object belongs to tenant

        Raises:
            PermissionDenied: If object doesn't belong to tenant
        """
        try:
            obj = model_class.objects.get(pk=object_id)
        except model_class.DoesNotExist:
            raise ObjectDoesNotExist(f"{model_class.__name__} with pk={object_id} not found")

        # Get the tenant from the object
        obj_tenant = obj
        for field in tenant_field.split('__'):
            obj_tenant = getattr(obj_tenant, field, None)
            if obj_tenant is None:
                break

        if obj_tenant is None:
            raise PermissionDenied(
                f"{model_class.__name__} with id {object_id} has no tenant"
            )

        if getattr(obj_tenant, 'id', None) != self._tenant_id:
            logger.warning(
                f"TASK_TENANT_MISMATCH: task={self.name} expected_tenant={self._tenant_id} "
                f"object_tenant={getattr(obj_tenant, 'id', None)} "
                f"object={model_class.__name__}:{object_id}"
            )
            raise PermissionDenied(
                f"{model_class.__name__} with id {object_id} belongs to a different tenant"
            )

        return True

    def _log_task_start(self, kwargs: Dict) -> None:
        """Log task execution start."""
        # Sanitize kwargs for logging (remove sensitive data)
        safe_kwargs = {
            k: v for k, v in kwargs.items()
            if not any(s in k.lower() for s in ['password', 'token', 'secret', 'key'])
        }

        logger.info(
            f"TASK_STARTED: task={self.name} id={self.request.id} "
            f"user={self._user_id} tenant={self._tenant_id} "
            f"params={list(safe_kwargs.keys())}"
        )

    def _log_task_success(self) -> None:
        """Log task successful completion."""
        logger.info(
            f"TASK_COMPLETED: task={self.name} id={self.request.id} "
            f"user={self._user_id} tenant={self._tenant_id}"
        )

    def _log_task_failure(self, exc: Exception) -> None:
        """Log task failure."""
        logger.error(
            f"TASK_FAILED: task={self.name} id={self.request.id} "
            f"user={self._user_id} tenant={self._tenant_id} "
            f"error={str(exc)}"
        )

    def _log_permission_denied(self, message: str) -> None:
        """Log permission denial."""
        logger.warning(
            f"TASK_PERMISSION_DENIED: task={self.name} id={self.request.id} "
            f"user={self._user_id} tenant={self._tenant_id} "
            f"message={message}"
        )


# =============================================================================
# PERMISSION VALIDATED TASK (with AutoRetry)
# =============================================================================

class PermissionValidatedTask(SecureTenantTask, AutoRetryTask):
    """
    Secure task that combines permission validation with automatic retry.

    Inherits from both SecureTenantTask (permission checks) and
    AutoRetryTask (exponential backoff retry logic).

    Usage:
        @celery_app.task(bind=True, base=PermissionValidatedTask)
        def important_operation(self, data, user_id=None, tenant_id=None):
            self.require_permission('perform_important_operation')
            # If task fails with transient error, it will retry
            # with exponential backoff
    """

    abstract = True

    # Don't retry on permission errors
    dont_autoretry_for = (
        PermissionDenied,
        ObjectDoesNotExist,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    )


# =============================================================================
# SECURE TASK DECORATOR
# =============================================================================

def secure_task(
    required_permission: Optional[str] = None,
    required_roles: Optional[List[str]] = None,
    **task_kwargs
):
    """
    Decorator to create a secure task with permission validation.

    Usage:
        from zumodra.celery import app as celery_app

        @secure_task(required_permission='edit_candidates')
        def bulk_update_candidates(self, candidate_ids, updates, user_id=None, tenant_id=None):
            # Permission is automatically validated before execution
            for cid in candidate_ids:
                # ... update logic

        @secure_task(required_roles=['owner', 'admin'])
        def admin_only_task(self, data, user_id=None, tenant_id=None):
            # Only owners and admins can execute
            ...

    Args:
        required_permission: Permission codename required to execute
        required_roles: List of roles allowed to execute
        **task_kwargs: Additional kwargs passed to @celery_app.task

    Returns:
        Decorated task function
    """
    def decorator(func):
        # Import celery app
        from zumodra.celery import app as celery_app

        # Create dynamic task class with permission requirements
        task_class = type(
            f'Secure{func.__name__.title()}Task',
            (SecureTenantTask,),
            {
                'required_permission': required_permission,
                'required_roles': required_roles,
            }
        )

        # Apply celery decorator with our secure base class
        return celery_app.task(
            bind=True,
            base=task_class,
            **task_kwargs
        )(func)

    return decorator


def permission_validated_task(
    required_permission: Optional[str] = None,
    required_roles: Optional[List[str]] = None,
    **task_kwargs
):
    """
    Decorator for secure tasks with automatic retry logic.

    Combines permission validation with exponential backoff retries.

    Usage:
        @permission_validated_task(
            required_permission='process_payments',
            max_retries=5
        )
        def process_payment(self, payment_id, user_id=None, tenant_id=None):
            # Permission validated + auto-retry on transient failures
            ...
    """
    def decorator(func):
        from zumodra.celery import app as celery_app

        task_class = type(
            f'PermissionValidated{func.__name__.title()}Task',
            (PermissionValidatedTask,),
            {
                'required_permission': required_permission,
                'required_roles': required_roles,
            }
        )

        return celery_app.task(
            bind=True,
            base=task_class,
            **task_kwargs
        )(func)

    return decorator


# =============================================================================
# ADMIN TASK DECORATOR
# =============================================================================

def admin_task(**task_kwargs):
    """
    Decorator for tasks that require admin role.

    Shortcut for @secure_task(required_roles=['owner', 'admin'])

    Usage:
        @admin_task()
        def cleanup_tenant_data(self, user_id=None, tenant_id=None):
            # Only admins can execute
            ...
    """
    return secure_task(required_roles=['owner', 'admin'], **task_kwargs)


def hr_task(**task_kwargs):
    """
    Decorator for tasks that require HR roles.

    Shortcut for @secure_task(required_roles=['owner', 'admin', 'hr_manager'])

    Usage:
        @hr_task()
        def sync_employee_data(self, user_id=None, tenant_id=None):
            ...
    """
    return secure_task(required_roles=['owner', 'admin', 'hr_manager'], **task_kwargs)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'SecureTenantTask',
    'PermissionValidatedTask',
    'secure_task',
    'permission_validated_task',
    'admin_task',
    'hr_task',
]
