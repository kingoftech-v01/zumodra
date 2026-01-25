"""
Core Models - Base classes for all apps

This module provides reusable base model classes used across the application:
- TenantAwareModel: Adds tenant field and tenant-aware functionality
- TimestampedModel: Adds created_at/updated_at timestamps
- PasswordHistory: Tracks password change history for security
"""

from django.db import models
from django.utils import timezone
from django.conf import settings


class TenantAwareModel(models.Model):
    """
    Abstract base class for tenant-aware models.

    Provides:
    - Foreign key to Tenant model
    - Automatic tenant context awareness
    - Common fields for tenant-scoped models

    All models in TENANT_APPS should inherit from this.
    """

    tenant = models.ForeignKey(
        'tenants.Tenant',
        on_delete=models.CASCADE,
        related_name='%(class)s_set',
        db_index=True,
        help_text='Tenant that owns this record'
    )

    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=['tenant']),
        ]

    def save(self, *args, **kwargs):
        """Ensure tenant is set on save"""
        # Tenant should be set by the calling code
        # This is just a safety check
        if not self.tenant_id:
            from django_tenants.utils import get_tenant_model
            from tenants.middleware import get_current_tenant

            # Try to get current tenant from thread-local storage
            current_tenant = get_current_tenant()
            if current_tenant:
                self.tenant = current_tenant

        super().save(*args, **kwargs)


class TimestampedModel(models.Model):
    """
    Abstract base class that adds timestamp fields.

    Provides:
    - created_at: Automatically set on creation
    - updated_at: Automatically updated on save

    Usage:
        class MyModel(TimestampedModel):
            # your fields here
            pass
    """

    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text='Timestamp when record was created'
    )

    updated_at = models.DateTimeField(
        auto_now=True,
        help_text='Timestamp when record was last updated'
    )

    class Meta:
        abstract = True
        get_latest_by = 'created_at'
        ordering = ['-created_at']


class PasswordHistory(models.Model):
    """
    Track password change history for security.

    Used by password validators to prevent password reuse.
    Stores hashed passwords only (never plaintext).
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='password_history'
    )

    password = models.CharField(
        max_length=255,
        help_text='Hashed password (NEVER plaintext)'
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True
    )

    class Meta:
        verbose_name = 'Password History'
        verbose_name_plural = 'Password Histories'
        ordering = ['-created_at']
        get_latest_by = 'created_at'

    def __str__(self):
        return f"Password history for {self.user} at {self.created_at}"
