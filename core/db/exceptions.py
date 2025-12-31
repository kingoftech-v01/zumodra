"""
Custom Database Exceptions for Zumodra

This module provides custom exception classes for database operations:
- ConcurrentModificationError: Raised when optimistic locking fails

These exceptions help handle concurrency and data integrity issues
in a multi-user, multi-tenant environment.
"""

from django.core.exceptions import ObjectDoesNotExist


class ConcurrentModificationError(Exception):
    """
    Exception raised when optimistic locking detects a concurrent modification.

    This occurs when two processes attempt to update the same record
    simultaneously, and the version number has changed since the record
    was read.

    Attributes:
        model_name: The name of the model class.
        object_id: The primary key of the object.
        expected_version: The version number expected by the updater.
        actual_version: The current version number in the database.

    Example:
        try:
            instance.save()
        except ConcurrentModificationError as e:
            # Handle the conflict - reload and retry, or inform the user
            instance.refresh_from_db()
            # Merge changes or notify user of conflict
    """

    def __init__(
        self,
        model_name: str = None,
        object_id=None,
        expected_version: int = None,
        actual_version: int = None,
        message: str = None
    ):
        self.model_name = model_name
        self.object_id = object_id
        self.expected_version = expected_version
        self.actual_version = actual_version

        if message:
            self.message = message
        else:
            self.message = (
                f"Concurrent modification detected for {model_name} "
                f"(id={object_id}). Expected version {expected_version}, "
                f"but found version {actual_version}. "
                "The record was modified by another process."
            )

        super().__init__(self.message)

    def __str__(self):
        return self.message


class StaleObjectError(ConcurrentModificationError):
    """
    Alias for ConcurrentModificationError for compatibility.

    Some ORMs use StaleObjectError terminology, so this alias
    provides familiarity for developers from those backgrounds.
    """
    pass


class TenantMismatchError(Exception):
    """
    Exception raised when an operation is attempted across tenant boundaries.

    This helps maintain tenant isolation in a multi-tenant environment.

    Example:
        if obj.tenant_id != current_tenant.id:
            raise TenantMismatchError(
                "Cannot access object from a different tenant"
            )
    """

    def __init__(self, message: str = None, object_tenant=None, current_tenant=None):
        self.object_tenant = object_tenant
        self.current_tenant = current_tenant

        if message:
            self.message = message
        else:
            self.message = (
                f"Tenant mismatch: Object belongs to tenant {object_tenant}, "
                f"but current tenant is {current_tenant}."
            )

        super().__init__(self.message)


class SoftDeletedObjectError(ObjectDoesNotExist):
    """
    Exception raised when attempting to access a soft-deleted object.

    This exception extends ObjectDoesNotExist to provide more context
    about why the object appears to be missing.

    Example:
        if obj.is_deleted:
            raise SoftDeletedObjectError(
                "This record has been deleted and is no longer accessible."
            )
    """

    def __init__(self, message: str = None, model_name: str = None, object_id=None):
        self.model_name = model_name
        self.object_id = object_id

        if message:
            self.message = message
        else:
            self.message = (
                f"The {model_name or 'object'} (id={object_id}) has been "
                "soft-deleted and is not accessible through the default manager."
            )

        super().__init__(self.message)
