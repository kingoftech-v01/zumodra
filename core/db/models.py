"""
Base Models for Zumodra

This module provides abstract base model classes:
- BaseModel: UUID primary key, timestamps, soft delete
- TenantAwareModel: Multi-tenant isolation base
- AuditableModel: Full audit trail with user tracking
- SoftDeleteModel: Soft deletion with recovery support

These models standardize data patterns across the application,
ensuring consistency, security, and maintainability.
"""

import uuid
from typing import TYPE_CHECKING, Optional

from django.conf import settings
from django.db import models
from django.db.models import F
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from core.db.managers import (
    TenantAwareManager,
    SoftDeleteManager,
    AuditManager,
    TenantSoftDeleteManager,
    FullAuditManager,
)
from core.db.exceptions import ConcurrentModificationError

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractUser


# =============================================================================
# BASE MODEL
# =============================================================================

class BaseModel(models.Model):
    """
    Abstract base model with UUID primary key and timestamps.

    Provides:
    - UUID primary key for security and distributed systems
    - Automatic created_at and updated_at timestamps
    - is_active flag for soft disabling records

    All models should inherit from this class for consistency.

    Example:
        class MyModel(BaseModel):
            name = models.CharField(max_length=100)
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        verbose_name=_('ID')
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        verbose_name=_('Created at')
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        db_index=True,
        verbose_name=_('Updated at')
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        verbose_name=_('Is active'),
        help_text=_('Designates whether this record is active.')
    )

    class Meta:
        abstract = True
        ordering = ['-created_at']
        get_latest_by = 'created_at'

    def __str__(self):
        return str(self.id)

    @property
    def created_at_display(self) -> str:
        """Return human-readable creation date."""
        if self.created_at:
            return self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        return ''

    @property
    def updated_at_display(self) -> str:
        """Return human-readable update date."""
        if self.updated_at:
            return self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        return ''

    def activate(self):
        """Activate this record."""
        self.is_active = True
        self.save(update_fields=['is_active', 'updated_at'])

    def deactivate(self):
        """Deactivate this record."""
        self.is_active = False
        self.save(update_fields=['is_active', 'updated_at'])

    def touch(self):
        """Update the updated_at timestamp without changing other fields."""
        self.updated_at = timezone.now()
        self.save(update_fields=['updated_at'])


# =============================================================================
# SOFT DELETE MODEL
# =============================================================================

class SoftDeleteModel(BaseModel):
    """
    Abstract model with soft deletion support.

    Records are never physically deleted; instead, they are marked
    as deleted with a timestamp. This allows for data recovery
    and audit compliance.

    Provides:
    - is_deleted flag for soft deletion
    - deleted_at timestamp
    - deleted_by user tracking
    - Automatic filtering of deleted records via manager

    Example:
        class MyModel(SoftDeleteModel):
            name = models.CharField(max_length=100)

            objects = SoftDeleteManager()
            all_objects = SoftDeleteManager(alive_only=False)
    """

    is_deleted = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name=_('Is deleted'),
        help_text=_('Soft deletion flag.')
    )
    deleted_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Deleted at'),
        help_text=_('Timestamp when the record was soft-deleted.')
    )
    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(class)s_deleted',
        verbose_name=_('Deleted by'),
        help_text=_('User who deleted this record.')
    )

    objects = SoftDeleteManager()
    all_objects = SoftDeleteManager(alive_only=False)

    class Meta:
        abstract = True

    def delete(self, using=None, keep_parents=False, user: Optional['AbstractUser'] = None):
        """
        Soft delete the record.

        Instead of physically deleting, marks the record as deleted
        and records the deletion timestamp and user.

        Args:
            using: Database alias to use.
            keep_parents: Unused, kept for API compatibility.
            user: The user performing the deletion.
        """
        self.is_deleted = True
        self.deleted_at = timezone.now()
        if user:
            self.deleted_by = user
        self.save(update_fields=['is_deleted', 'deleted_at', 'deleted_by', 'updated_at'])

    def hard_delete(self, using=None, keep_parents=False):
        """
        Permanently delete the record.

        WARNING: This is irreversible. Use only when absolutely necessary.
        """
        super().delete(using=using, keep_parents=keep_parents)

    def restore(self):
        """
        Restore a soft-deleted record.

        Clears the deletion flag and related fields.
        """
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None
        self.save(update_fields=['is_deleted', 'deleted_at', 'deleted_by', 'updated_at'])

    @property
    def is_alive(self) -> bool:
        """Check if the record is not deleted."""
        return not self.is_deleted


# =============================================================================
# TENANT-AWARE MODEL
# =============================================================================

class TenantAwareModel(BaseModel):
    """
    Abstract model for tenant-scoped data.

    Provides automatic tenant association and filtering.
    All tenant-specific data should inherit from this model.

    The tenant field creates a foreign key to the Tenant model,
    ensuring data isolation in a multi-tenant environment.

    Example:
        class MyModel(TenantAwareModel):
            name = models.CharField(max_length=100)

        # Queries are automatically filtered by tenant
        MyModel.objects.for_current_tenant().all()
    """

    tenant = models.ForeignKey(
        'tenants.Tenant',
        on_delete=models.CASCADE,
        related_name='%(app_label)s_%(class)s_set',
        verbose_name=_('Tenant'),
        help_text=_('The tenant this record belongs to.')
    )

    objects = TenantAwareManager()

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        """
        Save the model, auto-populating tenant if not set.

        Attempts to get the current tenant from the connection
        if no tenant is explicitly set.
        """
        if not self.tenant_id:
            try:
                from django.db import connection
                tenant = getattr(connection, 'tenant', None)
                if tenant:
                    self.tenant = tenant
            except Exception:
                pass
        super().save(*args, **kwargs)


# =============================================================================
# AUDITABLE MODEL
# =============================================================================

class AuditableModel(BaseModel):
    """
    Abstract model with full audit trail.

    Tracks who created and modified records, along with
    optional IP address tracking for security compliance.

    Provides:
    - created_by: User who created the record
    - modified_by: User who last modified the record
    - created_from_ip: IP address of creation request
    - version: Optimistic locking counter

    Example:
        class MyModel(AuditableModel):
            name = models.CharField(max_length=100)

        # Create with audit info
        MyModel.objects.create_with_audit(
            user=request.user,
            ip_address=get_client_ip(request),
            name='Test'
        )
    """

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(class)s_created',
        verbose_name=_('Created by'),
        help_text=_('User who created this record.')
    )
    modified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(class)s_modified',
        verbose_name=_('Modified by'),
        help_text=_('User who last modified this record.')
    )
    created_from_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name=_('Created from IP'),
        help_text=_('IP address of the creation request.')
    )
    version = models.PositiveIntegerField(
        default=1,
        verbose_name=_('Version'),
        help_text=_('Record version for optimistic locking.')
    )

    objects = AuditManager()

    class Meta:
        abstract = True

    def save(self, *args, user: Optional['AbstractUser'] = None, **kwargs):
        """
        Save the model with audit tracking and optimistic locking.

        Uses atomic version increment with F() expression to prevent
        race conditions. Verifies version hasn't changed since read.

        Args:
            user: The user making the change. If provided, updates modified_by.
            *args: Positional arguments for parent save.
            **kwargs: Keyword arguments for parent save.

        Raises:
            ConcurrentModificationError: If the record was modified by another
                process since it was read.
        """
        if user:
            self.modified_by = user
            if not self.pk:
                self.created_by = user

        # Optimistic locking for existing records
        if self.pk:
            expected_version = self.version
            # Check if the record still has the expected version
            model_class = self.__class__
            current_version = model_class.objects.filter(pk=self.pk).values_list(
                'version', flat=True
            ).first()

            if current_version is not None and current_version != expected_version:
                raise ConcurrentModificationError(
                    model_name=model_class.__name__,
                    object_id=self.pk,
                    expected_version=expected_version,
                    actual_version=current_version
                )

            # Use atomic increment with update() and F() expression
            update_fields = kwargs.get('update_fields')
            if update_fields is None:
                # Full save - use atomic update for version
                model_class.objects.filter(pk=self.pk, version=expected_version).update(
                    version=F('version') + 1
                )
                # Refresh the version number
                self.version = expected_version + 1

        super().save(*args, **kwargs)

    def set_audit_user(self, user: 'AbstractUser'):
        """Set the audit user for subsequent save."""
        self._audit_user = user

    @property
    def audit_summary(self) -> dict:
        """Return a summary of audit information."""
        return {
            'created_by': str(self.created_by) if self.created_by else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'modified_by': str(self.modified_by) if self.modified_by else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_from_ip': self.created_from_ip,
            'version': self.version,
        }


# =============================================================================
# TENANT-AWARE SOFT DELETE MODEL
# =============================================================================

class TenantSoftDeleteModel(SoftDeleteModel):
    """
    Abstract model combining tenant awareness and soft deletion.

    Use this for tenant-scoped data that requires soft deletion
    for compliance and data recovery.

    Example:
        class MyModel(TenantSoftDeleteModel):
            name = models.CharField(max_length=100)

            objects = TenantSoftDeleteManager()
            all_objects = TenantSoftDeleteManager(alive_only=False)
    """

    tenant = models.ForeignKey(
        'tenants.Tenant',
        on_delete=models.CASCADE,
        related_name='%(app_label)s_%(class)s_set',
        verbose_name=_('Tenant'),
        help_text=_('The tenant this record belongs to.')
    )

    objects = TenantSoftDeleteManager()
    all_objects = TenantSoftDeleteManager(alive_only=False)

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        """Save with auto-tenant population."""
        if not self.tenant_id:
            try:
                from django.db import connection
                tenant = getattr(connection, 'tenant', None)
                if tenant:
                    self.tenant = tenant
            except Exception:
                pass
        super().save(*args, **kwargs)


# =============================================================================
# FULL AUDIT MODEL (TENANT + SOFT DELETE + AUDIT)
# =============================================================================

class FullAuditModel(SoftDeleteModel):
    """
    Comprehensive model with tenant awareness, soft deletion, and audit trail.

    This is the most feature-complete base model, providing:
    - UUID primary key and timestamps (from BaseModel)
    - Soft deletion with recovery (from SoftDeleteModel)
    - Tenant isolation (tenant field)
    - Full audit trail (created_by, modified_by, IP, version)

    Use this for critical business data requiring full tracking.

    Example:
        class Contract(FullAuditModel):
            title = models.CharField(max_length=200)
            value = models.DecimalField(max_digits=12, decimal_places=2)

            objects = FullAuditManager()
            all_objects = FullAuditManager(alive_only=False)
    """

    tenant = models.ForeignKey(
        'tenants.Tenant',
        on_delete=models.CASCADE,
        related_name='%(app_label)s_%(class)s_set',
        verbose_name=_('Tenant'),
        help_text=_('The tenant this record belongs to.')
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(class)s_created',
        verbose_name=_('Created by')
    )
    modified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(class)s_modified',
        verbose_name=_('Modified by')
    )
    created_from_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name=_('Created from IP')
    )
    version = models.PositiveIntegerField(
        default=1,
        verbose_name=_('Version')
    )

    objects = FullAuditManager()
    all_objects = FullAuditManager(alive_only=False)

    class Meta:
        abstract = True

    def save(self, *args, user: Optional['AbstractUser'] = None, **kwargs):
        """
        Save with tenant, audit, and version tracking with optimistic locking.

        Uses atomic version increment with F() expression to prevent
        race conditions. Verifies version hasn't changed since read.

        Args:
            user: The user making the change. If provided, updates modified_by.
            *args: Positional arguments for parent save.
            **kwargs: Keyword arguments for parent save.

        Raises:
            ConcurrentModificationError: If the record was modified by another
                process since it was read.
        """
        # Auto-populate tenant
        if not self.tenant_id:
            try:
                from django.db import connection
                tenant = getattr(connection, 'tenant', None)
                if tenant:
                    self.tenant = tenant
            except Exception:
                pass

        # Handle audit user
        if user:
            self.modified_by = user
            if not self.pk:
                self.created_by = user

        # Optimistic locking for existing records
        if self.pk:
            expected_version = self.version
            # Check if the record still has the expected version
            model_class = self.__class__
            current_version = model_class.objects.filter(pk=self.pk).values_list(
                'version', flat=True
            ).first()

            if current_version is not None and current_version != expected_version:
                raise ConcurrentModificationError(
                    model_name=model_class.__name__,
                    object_id=self.pk,
                    expected_version=expected_version,
                    actual_version=current_version
                )

            # Use atomic increment with update() and F() expression
            update_fields = kwargs.get('update_fields')
            if update_fields is None:
                # Full save - use atomic update for version
                model_class.objects.filter(pk=self.pk, version=expected_version).update(
                    version=F('version') + 1
                )
                # Refresh the version number
                self.version = expected_version + 1

        super().save(*args, **kwargs)

    @property
    def audit_summary(self) -> dict:
        """Return comprehensive audit information."""
        return {
            'id': str(self.id),
            'tenant_id': str(self.tenant_id) if self.tenant_id else None,
            'created_by': str(self.created_by) if self.created_by else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'modified_by': str(self.modified_by) if self.modified_by else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_from_ip': self.created_from_ip,
            'is_deleted': self.is_deleted,
            'deleted_at': self.deleted_at.isoformat() if self.deleted_at else None,
            'deleted_by': str(self.deleted_by) if self.deleted_by else None,
            'version': self.version,
        }


# =============================================================================
# MIXIN CLASSES (For flexible composition)
# =============================================================================

class TimestampMixin(models.Model):
    """
    Mixin adding only timestamp fields.

    Use when you need timestamps but not UUID primary keys.
    """

    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        verbose_name=_('Created at')
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name=_('Updated at')
    )

    class Meta:
        abstract = True


class UUIDMixin(models.Model):
    """
    Mixin adding UUID field (not as primary key).

    Use when you need a public UUID but want to keep integer primary keys.
    """

    uuid = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        unique=True,
        verbose_name=_('UUID')
    )

    class Meta:
        abstract = True


class SlugMixin(models.Model):
    """
    Mixin adding a slug field for SEO-friendly URLs.

    For tenant-aware models, slug uniqueness is scoped to the tenant,
    allowing the same slug to exist across different tenants.
    """

    slug = models.SlugField(
        max_length=255,
        blank=True,
        verbose_name=_('Slug'),
        help_text=_('URL-friendly identifier. Unique within tenant scope.')
    )

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        """
        Auto-generate slug if not provided.

        For tenant-aware models, ensures slug uniqueness within the tenant.
        For non-tenant models, ensures global uniqueness.
        """
        if not self.slug and hasattr(self, 'name'):
            from django.utils.text import slugify
            base_slug = slugify(self.name)[:240]
            slug = base_slug
            counter = 1
            model_class = self.__class__

            # Build base queryset for uniqueness check
            queryset = model_class.objects.exclude(pk=self.pk)

            # Scope to tenant if this model is tenant-aware
            if hasattr(self, 'tenant_id') and self.tenant_id:
                queryset = queryset.filter(tenant_id=self.tenant_id)

            while queryset.filter(slug=slug).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1
            self.slug = slug
        super().save(*args, **kwargs)

    @classmethod
    def get_unique_slug_constraints(cls):
        """
        Return the unique constraint for slugs.

        Override this in concrete models to specify tenant-scoped uniqueness:

        class Meta:
            constraints = [
                models.UniqueConstraint(
                    fields=['tenant', 'slug'],
                    name='%(app_label)s_%(class)s_unique_tenant_slug'
                )
            ]
        """
        return []


class OrderableMixin(models.Model):
    """
    Mixin for models that need manual ordering.
    """

    order = models.PositiveIntegerField(
        default=0,
        db_index=True,
        verbose_name=_('Order'),
        help_text=_('Display order (lower numbers appear first).')
    )

    class Meta:
        abstract = True
        ordering = ['order']

    def move_up(self):
        """Move this item up in the order."""
        if self.order > 0:
            self.order -= 1
            self.save(update_fields=['order'])

    def move_down(self):
        """Move this item down in the order."""
        self.order += 1
        self.save(update_fields=['order'])


class MetadataMixin(models.Model):
    """
    Mixin for storing arbitrary metadata as JSON.
    """

    metadata = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_('Metadata'),
        help_text=_('Additional metadata stored as JSON.')
    )
    extra_data = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_('Extra data'),
        help_text=_('Additional data for extensions.')
    )

    class Meta:
        abstract = True

    def get_meta(self, key: str, default=None):
        """Get a metadata value by key."""
        return self.metadata.get(key, default)

    def set_meta(self, key: str, value):
        """Set a metadata value by key."""
        self.metadata[key] = value
        self.save(update_fields=['metadata'])

    def update_meta(self, data: dict):
        """Update multiple metadata values."""
        self.metadata.update(data)
        self.save(update_fields=['metadata'])
