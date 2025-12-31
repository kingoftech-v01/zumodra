"""
Custom Database Managers for Zumodra

This module provides specialized QuerySet managers:
- TenantAwareManager: Auto-filters by current tenant for multi-tenancy
- SoftDeleteManager: Handles soft-deleted records with is_deleted flag
- AuditManager: Includes audit trail fields and operations

These managers ensure data isolation, safe deletion, and compliance-ready auditing
across the entire application.
"""

import logging
from typing import TYPE_CHECKING, Optional, Any

from django.db import models
from django.db.models import QuerySet, Q
from django.utils import timezone

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractUser

logger = logging.getLogger(__name__)


# =============================================================================
# TENANT-AWARE QUERYSET AND MANAGER
# =============================================================================

class TenantAwareQuerySet(QuerySet):
    """
    QuerySet that automatically filters by the current tenant.

    Ensures data isolation in a multi-tenant environment by restricting
    queries to the current tenant's data only.
    """

    def for_tenant(self, tenant):
        """
        Filter queryset for a specific tenant.

        Args:
            tenant: The tenant instance or tenant ID to filter by.

        Returns:
            QuerySet: Filtered queryset for the specified tenant.
        """
        if tenant is None:
            return self.none()

        if hasattr(tenant, 'pk'):
            return self.filter(tenant_id=tenant.pk)
        return self.filter(tenant_id=tenant)

    def for_current_tenant(self):
        """
        Filter queryset for the current tenant from thread-local storage.

        This method retrieves the current tenant from django-tenants
        connection and filters accordingly.

        SECURITY: Returns an empty queryset on error to prevent data leakage.
        If tenant cannot be determined, no records are returned rather than
        returning unfiltered results.

        Returns:
            QuerySet: Filtered queryset for the current tenant, or empty
                queryset if tenant cannot be determined.
        """
        try:
            from django.db import connection
            tenant = getattr(connection, 'tenant', None)
            if tenant:
                return self.for_tenant(tenant)
            else:
                # No tenant set - return empty queryset for security
                logger.warning(
                    "for_current_tenant() called but no tenant is set on connection. "
                    "Returning empty queryset to prevent data leakage."
                )
                return self.none()
        except Exception as e:
            # On any error, return empty queryset for security
            logger.error(
                "Error getting current tenant in for_current_tenant(): %s. "
                "Returning empty queryset to prevent data leakage.",
                str(e)
            )
            return self.none()

    def active(self):
        """Filter to only active records (is_active=True)."""
        return self.filter(is_active=True)

    def inactive(self):
        """Filter to only inactive records (is_active=False)."""
        return self.filter(is_active=False)

    def created_after(self, date):
        """Filter records created after the specified date."""
        return self.filter(created_at__gte=date)

    def created_before(self, date):
        """Filter records created before the specified date."""
        return self.filter(created_at__lte=date)

    def created_between(self, start_date, end_date):
        """Filter records created between two dates."""
        return self.filter(created_at__range=(start_date, end_date))

    def updated_after(self, date):
        """Filter records updated after the specified date."""
        return self.filter(updated_at__gte=date)

    def order_by_created(self, descending=True):
        """Order by creation date."""
        order = '-created_at' if descending else 'created_at'
        return self.order_by(order)

    def order_by_updated(self, descending=True):
        """Order by last update date."""
        order = '-updated_at' if descending else 'updated_at'
        return self.order_by(order)


class TenantAwareManager(models.Manager):
    """
    Manager that automatically filters by tenant.

    Use this manager for models that belong to a specific tenant.
    It provides automatic tenant filtering and useful query methods.

    Usage:
        class MyModel(models.Model):
            tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE)
            objects = TenantAwareManager()
    """

    def get_queryset(self) -> TenantAwareQuerySet:
        """Return a TenantAwareQuerySet."""
        return TenantAwareQuerySet(self.model, using=self._db)

    def for_tenant(self, tenant):
        """Filter for a specific tenant."""
        return self.get_queryset().for_tenant(tenant)

    def for_current_tenant(self):
        """Filter for the current tenant."""
        return self.get_queryset().for_current_tenant()

    def active(self):
        """Get only active records."""
        return self.get_queryset().active()

    def created_after(self, date):
        """Get records created after date."""
        return self.get_queryset().created_after(date)

    def created_between(self, start_date, end_date):
        """Get records created between dates."""
        return self.get_queryset().created_between(start_date, end_date)


# =============================================================================
# SOFT DELETE QUERYSET AND MANAGER
# =============================================================================

class SoftDeleteQuerySet(QuerySet):
    """
    QuerySet for handling soft-deleted records.

    Provides methods to work with both active and deleted records,
    supporting soft deletion patterns for data recovery and auditing.
    """

    def delete(self):
        """
        Soft delete all records in the queryset.

        Instead of actually deleting records, this sets is_deleted=True
        and records the deletion timestamp.

        Returns:
            tuple: (count, {model_label: count})
        """
        count = self.update(
            is_deleted=True,
            deleted_at=timezone.now()
        )
        return count, {self.model._meta.label: count}

    def hard_delete(self):
        """
        Permanently delete all records in the queryset.

        WARNING: This is irreversible. Use with caution.

        Returns:
            tuple: (count, {model_label: count})
        """
        return super().delete()

    def undelete(self):
        """
        Restore soft-deleted records.

        Returns:
            int: Number of records restored.
        """
        return self.update(
            is_deleted=False,
            deleted_at=None
        )

    def alive(self):
        """Filter to only non-deleted records."""
        return self.filter(is_deleted=False)

    def dead(self):
        """Filter to only soft-deleted records."""
        return self.filter(is_deleted=True)

    def with_deleted(self):
        """Return all records including soft-deleted ones."""
        return self.all()

    def deleted_after(self, date):
        """Filter records deleted after the specified date."""
        return self.filter(deleted_at__gte=date)

    def deleted_before(self, date):
        """Filter records deleted before the specified date."""
        return self.filter(deleted_at__lte=date)

    def deleted_by(self, user):
        """Filter records deleted by a specific user."""
        if hasattr(self.model, 'deleted_by'):
            return self.filter(deleted_by=user)
        return self


class SoftDeleteManager(models.Manager):
    """
    Manager that excludes soft-deleted records by default.

    Provides an interface for working with soft-deleted records,
    including restoration and permanent deletion.

    Usage:
        class MyModel(models.Model):
            is_deleted = models.BooleanField(default=False)
            deleted_at = models.DateTimeField(null=True, blank=True)

            objects = SoftDeleteManager()
            all_objects = SoftDeleteManager(alive_only=False)
    """

    def __init__(self, *args, alive_only: bool = True, **kwargs):
        """
        Initialize the manager.

        Args:
            alive_only: If True, exclude soft-deleted records by default.
        """
        self.alive_only = alive_only
        super().__init__(*args, **kwargs)

    def get_queryset(self) -> SoftDeleteQuerySet:
        """Return a SoftDeleteQuerySet, optionally filtering out deleted records."""
        qs = SoftDeleteQuerySet(self.model, using=self._db)
        if self.alive_only:
            return qs.alive()
        return qs

    def alive(self):
        """Get only non-deleted records."""
        return self.get_queryset().alive()

    def dead(self):
        """Get only soft-deleted records."""
        return SoftDeleteQuerySet(self.model, using=self._db).dead()

    def with_deleted(self):
        """Get all records including soft-deleted."""
        return SoftDeleteQuerySet(self.model, using=self._db).all()

    def hard_delete(self):
        """Permanently delete records."""
        return self.get_queryset().hard_delete()

    def undelete(self):
        """Restore soft-deleted records."""
        return SoftDeleteQuerySet(self.model, using=self._db).dead().undelete()


# =============================================================================
# AUDIT MANAGER
# =============================================================================

class AuditQuerySet(QuerySet):
    """
    QuerySet with audit-related query methods.

    Provides filtering and tracking for auditable records,
    supporting compliance and security requirements.
    """

    def created_by(self, user):
        """Filter records created by a specific user."""
        return self.filter(created_by=user)

    def modified_by(self, user):
        """Filter records last modified by a specific user."""
        return self.filter(modified_by=user)

    def modified_since(self, date):
        """Filter records modified since a date."""
        return self.filter(updated_at__gte=date)

    def recently_modified(self, days: int = 7):
        """Filter records modified in the last N days."""
        cutoff = timezone.now() - timezone.timedelta(days=days)
        return self.filter(updated_at__gte=cutoff)

    def stale(self, days: int = 90):
        """Filter records not modified in N days."""
        cutoff = timezone.now() - timezone.timedelta(days=days)
        return self.filter(updated_at__lt=cutoff)

    def with_audit_info(self):
        """
        Select related audit fields for efficient loading.

        Returns:
            QuerySet: QuerySet with related created_by and modified_by prefetched.
        """
        return self.select_related('created_by', 'modified_by')

    def by_ip_address(self, ip_address: str):
        """Filter records created from a specific IP address."""
        if hasattr(self.model, 'created_from_ip'):
            return self.filter(created_from_ip=ip_address)
        return self

    def changes_by_user(self, user, since=None):
        """
        Get all records touched by a user (created or modified).

        Args:
            user: The user to filter by.
            since: Optional date to filter changes after.

        Returns:
            QuerySet: Records created or modified by the user.
        """
        q = Q(created_by=user) | Q(modified_by=user)
        qs = self.filter(q)
        if since:
            qs = qs.filter(updated_at__gte=since)
        return qs


class AuditManager(models.Manager):
    """
    Manager that includes audit trail operations.

    Provides methods for tracking who created and modified records,
    supporting compliance, security auditing, and accountability.

    Usage:
        class MyModel(models.Model):
            created_by = models.ForeignKey(User, related_name='+')
            modified_by = models.ForeignKey(User, related_name='+')

            objects = AuditManager()
    """

    def get_queryset(self) -> AuditQuerySet:
        """Return an AuditQuerySet."""
        return AuditQuerySet(self.model, using=self._db)

    def created_by(self, user):
        """Get records created by a user."""
        return self.get_queryset().created_by(user)

    def modified_by(self, user):
        """Get records modified by a user."""
        return self.get_queryset().modified_by(user)

    def recently_modified(self, days: int = 7):
        """Get recently modified records."""
        return self.get_queryset().recently_modified(days)

    def stale(self, days: int = 90):
        """Get stale records not modified in N days."""
        return self.get_queryset().stale(days)

    def with_audit_info(self):
        """Get queryset with audit info prefetched."""
        return self.get_queryset().with_audit_info()

    def changes_by_user(self, user, since=None):
        """Get all records touched by a user."""
        return self.get_queryset().changes_by_user(user, since)

    def create_with_audit(
        self,
        user: Optional['AbstractUser'] = None,
        ip_address: Optional[str] = None,
        **kwargs
    ):
        """
        Create a new record with audit information populated.

        Args:
            user: The user creating the record.
            ip_address: The IP address of the request.
            **kwargs: Additional fields for the record.

        Returns:
            Model instance: The newly created record.
        """
        if user:
            kwargs['created_by'] = user
            kwargs['modified_by'] = user

        if ip_address and hasattr(self.model, 'created_from_ip'):
            kwargs['created_from_ip'] = ip_address

        return self.create(**kwargs)


# =============================================================================
# COMBINED MANAGERS
# =============================================================================

class TenantSoftDeleteQuerySet(TenantAwareQuerySet, SoftDeleteQuerySet):
    """Combined QuerySet with both tenant-aware and soft-delete functionality."""
    pass


class TenantSoftDeleteManager(models.Manager):
    """
    Combined manager with tenant-aware and soft-delete functionality.

    Use this for tenant-scoped models that also need soft deletion.

    Usage:
        class MyModel(models.Model):
            tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE)
            is_deleted = models.BooleanField(default=False)
            deleted_at = models.DateTimeField(null=True, blank=True)

            objects = TenantSoftDeleteManager()
    """

    def __init__(self, *args, alive_only: bool = True, **kwargs):
        self.alive_only = alive_only
        super().__init__(*args, **kwargs)

    def get_queryset(self) -> TenantSoftDeleteQuerySet:
        qs = TenantSoftDeleteQuerySet(self.model, using=self._db)
        if self.alive_only:
            return qs.alive()
        return qs

    def for_tenant(self, tenant):
        return self.get_queryset().for_tenant(tenant)

    def for_current_tenant(self):
        return self.get_queryset().for_current_tenant()

    def alive(self):
        return self.get_queryset().alive()

    def dead(self):
        return TenantSoftDeleteQuerySet(self.model, using=self._db).dead()

    def with_deleted(self):
        return TenantSoftDeleteQuerySet(self.model, using=self._db).all()


class FullAuditQuerySet(TenantAwareQuerySet, SoftDeleteQuerySet, AuditQuerySet):
    """Combined QuerySet with tenant-aware, soft-delete, and audit functionality."""
    pass


class FullAuditManager(models.Manager):
    """
    Comprehensive manager combining all features.

    Provides tenant isolation, soft deletion, and audit tracking
    in a single manager for maximum flexibility.

    Usage:
        class MyModel(models.Model):
            tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE)
            is_deleted = models.BooleanField(default=False)
            deleted_at = models.DateTimeField(null=True, blank=True)
            created_by = models.ForeignKey(User, related_name='+')
            modified_by = models.ForeignKey(User, related_name='+')

            objects = FullAuditManager()
            all_objects = FullAuditManager(alive_only=False)
    """

    def __init__(self, *args, alive_only: bool = True, **kwargs):
        self.alive_only = alive_only
        super().__init__(*args, **kwargs)

    def get_queryset(self) -> FullAuditQuerySet:
        qs = FullAuditQuerySet(self.model, using=self._db)
        if self.alive_only:
            return qs.alive()
        return qs

    def for_tenant(self, tenant):
        return self.get_queryset().for_tenant(tenant)

    def for_current_tenant(self):
        return self.get_queryset().for_current_tenant()

    def alive(self):
        return self.get_queryset().alive()

    def dead(self):
        return FullAuditQuerySet(self.model, using=self._db).dead()

    def with_deleted(self):
        return FullAuditQuerySet(self.model, using=self._db).all()

    def with_audit_info(self):
        return self.get_queryset().with_audit_info()

    def create_with_audit(
        self,
        user: Optional['AbstractUser'] = None,
        ip_address: Optional[str] = None,
        tenant=None,
        **kwargs
    ):
        """Create a record with full audit information."""
        if user:
            kwargs['created_by'] = user
            kwargs['modified_by'] = user

        if ip_address and hasattr(self.model, 'created_from_ip'):
            kwargs['created_from_ip'] = ip_address

        if tenant:
            kwargs['tenant'] = tenant

        return self.create(**kwargs)
