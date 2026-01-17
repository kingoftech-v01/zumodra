"""
Base service for syncing tenant data to public schema.

Provides the foundation for bidirectional sync between tenant-isolated schemas
and the public schema for marketplace/browse functionality.

Pattern:
    Tenant Schema (private) → Public Schema (public catalog)
    - When item marked public: sync_to_public()
    - When item updated: sync_to_public() (idempotent)
    - When item marked private/deleted: remove_from_public()

Security:
    - Field-level exclusions for sensitive data
    - Schema isolation validation
    - HTML sanitization
    - Tenant verification
"""

import logging
from typing import Dict, List, Callable, Any, Optional
from decimal import Decimal

from django.db import connection, models
from django.utils import timezone
from django.core.exceptions import ValidationError

from tenants.context import public_schema_context

logger = logging.getLogger(__name__)


class PublicSyncService:
    """
    Base class for syncing tenant models to public catalog models.

    Subclasses must define:
        - public_model: Model class in public schema (e.g., PublicJobCatalog)
        - tenant_model: Model class in tenant schema (e.g., JobPosting)
        - field_mapping: Dict mapping public fields to tenant fields/callables
        - sync_conditions: List of lambda functions that must return True to sync

    Example:
        class JobPublicSyncService(PublicSyncService):
            public_model = PublicJobCatalog
            tenant_model = JobPosting

            field_mapping = {
                'uuid': 'uuid',
                'title': 'title',
                'company_name': lambda job: job.tenant.name,
            }

            sync_conditions = [
                lambda job: job.published_on_career_page == True,
                lambda job: job.is_internal_only == False,
            ]
    """

    # Subclass must override these
    public_model: models.Model = None
    tenant_model: models.Model = None
    field_mapping: Dict[str, Any] = {}
    sync_conditions: List[Callable] = []

    # Sensitive field patterns - never sync fields matching these
    SENSITIVE_PATTERNS = [
        'password', 'token', 'secret', 'key', 'credential',
        'sin_', 'ssn_', 'bank_', 'stripe_', 'account_',
        'encrypted', '_private', 'confidential',
        'ip_address', 'user_agent', 'session',
    ]

    def __init__(self):
        """Initialize sync service with validation."""
        # See TODO-CORE-001 in core/TODO.md (abstract base class by design)
        if self.public_model is None or self.tenant_model is None:
            raise NotImplementedError(
                f"{self.__class__.__name__} must define public_model and tenant_model"
            )

        if not self.field_mapping:
            raise NotImplementedError(
                f"{self.__class__.__name__} must define field_mapping"
            )

    def should_sync(self, instance: models.Model) -> bool:
        """
        Check if instance meets all sync conditions.

        Args:
            instance: Tenant model instance to evaluate

        Returns:
            True if all sync_conditions pass, False otherwise
        """
        if not self.sync_conditions:
            # No conditions defined means always sync
            return True

        for condition in self.sync_conditions:
            try:
                if not condition(instance):
                    logger.debug(
                        f"Sync condition failed for {instance}: {condition.__name__ if hasattr(condition, '__name__') else condition}"
                    )
                    return False
            except Exception as e:
                logger.error(
                    f"Error evaluating sync condition for {instance}: {e}",
                    exc_info=True
                )
                return False

        return True

    def validate_field_safety(self, field_name: str) -> bool:
        """
        Ensure field name doesn't match sensitive patterns.

        Args:
            field_name: Name of field to validate

        Returns:
            True if field is safe to sync, False if potentially sensitive
        """
        field_lower = field_name.lower()
        return not any(pattern in field_lower for pattern in self.SENSITIVE_PATTERNS)

    def get_mapped_data(self, instance: models.Model) -> Dict[str, Any]:
        """
        Extract and map fields from tenant instance to public catalog format.

        Args:
            instance: Tenant model instance

        Returns:
            Dictionary of field_name: value for public catalog model

        Raises:
            ValidationError: If required mapping fails or produces invalid data
        """
        mapped_data = {}

        for public_field, source in self.field_mapping.items():
            try:
                # Safety check - ensure field doesn't match sensitive patterns
                if not self.validate_field_safety(public_field):
                    logger.warning(
                        f"Skipping potentially sensitive field: {public_field}"
                    )
                    continue

                # Get value from tenant instance
                if callable(source):
                    # Source is a lambda/function
                    value = source(instance)
                elif isinstance(source, str):
                    # Source is a field name string
                    value = getattr(instance, source, None)
                else:
                    # Direct value
                    value = source

                # Handle None values
                if value is None:
                    mapped_data[public_field] = None
                    continue

                # Type conversions and sanitization
                if isinstance(value, str):
                    # Sanitize HTML content for description fields
                    if 'description' in public_field.lower() or 'html' in public_field.lower():
                        value = self.sanitize_html(value)
                    # Limit string length to prevent abuse
                    max_length = self.get_field_max_length(public_field)
                    if max_length and len(value) > max_length:
                        logger.warning(
                            f"Truncating {public_field} from {len(value)} to {max_length} chars"
                        )
                        value = value[:max_length]

                mapped_data[public_field] = value

            except AttributeError as e:
                logger.error(
                    f"Field mapping error for {public_field}: {e}. "
                    f"Source: {source}, Instance: {instance}"
                )
                # Continue with other fields instead of failing entirely
                mapped_data[public_field] = None
            except Exception as e:
                logger.error(
                    f"Unexpected error mapping {public_field}: {e}",
                    exc_info=True
                )
                mapped_data[public_field] = None

        return mapped_data

    def get_field_max_length(self, field_name: str) -> Optional[int]:
        """
        Get max_length constraint from public model field if it exists.

        Args:
            field_name: Name of field in public model

        Returns:
            Max length integer or None if no constraint
        """
        try:
            field = self.public_model._meta.get_field(field_name)
            return getattr(field, 'max_length', None)
        except Exception:
            return None

    def sanitize_html(self, html_content: str) -> str:
        """
        Sanitize HTML content to prevent XSS attacks.

        Uses nh3 (Rust-based HTML sanitizer) for security.
        Allows safe tags only: p, br, strong, em, ul, ol, li, a

        Args:
            html_content: Raw HTML string

        Returns:
            Sanitized HTML string with only safe tags
        """
        try:
            import nh3

            # Define allowed tags and attributes
            allowed_tags = {
                'p', 'br', 'strong', 'em', 'b', 'i', 'u',
                'ul', 'ol', 'li', 'a', 'h1', 'h2', 'h3',
                'blockquote', 'code', 'pre'
            }

            allowed_attributes = {
                'a': {'href', 'title'},
            }

            return nh3.clean(
                html_content,
                tags=allowed_tags,
                attributes=allowed_attributes,
                link_rel='nofollow noopener noreferrer',  # Security for links
            )

        except ImportError:
            # Fallback to bleach if nh3 not available
            logger.warning("nh3 not available, using bleach for HTML sanitization")
            try:
                import bleach
                return bleach.clean(
                    html_content,
                    tags=['p', 'br', 'strong', 'em', 'b', 'i', 'ul', 'ol', 'li', 'a'],
                    attributes={'a': ['href', 'title']},
                    strip=True,
                )
            except ImportError:
                # Last resort: strip all HTML
                import re
                return re.sub(r'<[^>]+>', '', html_content)

    def validate_schema_context(self, instance: models.Model) -> bool:
        """
        Validate that we're operating in a tenant schema (not public).

        Security check to prevent:
        - SSRF attacks
        - Cross-schema pollution
        - Invalid sync operations

        Args:
            instance: Tenant model instance to validate

        Returns:
            True if schema context is valid, False otherwise
        """
        # Check current schema is not public
        if connection.schema_name == 'public':
            logger.error(
                "Cannot sync from public schema - invalid operation. "
                "Sync must originate from tenant schema."
            )
            return False

        # Validate tenant exists and matches
        from tenants.models import Tenant

        try:
            tenant = Tenant.objects.get(schema_name=connection.schema_name)

            # Verify instance's tenant matches current schema
            if hasattr(instance, 'tenant_id') and instance.tenant_id != tenant.id:
                logger.error(
                    f"Tenant mismatch: instance.tenant_id={instance.tenant_id}, "
                    f"connection.tenant={tenant.id}. Possible security violation."
                )
                return False

            return True

        except Tenant.DoesNotExist:
            logger.error(f"Invalid tenant schema: {connection.schema_name}")
            return False

    def sync_to_public(self, instance: models.Model, created: bool = False) -> Optional[models.Model]:
        """
        Main sync operation: create or update entry in public catalog.

        Workflow:
            1. Validate schema context (security)
            2. Check sync conditions
            3. Extract mapped data
            4. Switch to public schema
            5. Update or create catalog entry
            6. Update source instance sync metadata

        Args:
            instance: Tenant model instance to sync
            created: Whether this is a new record (from post_save signal)

        Returns:
            Public catalog model instance if successful, None otherwise
        """
        # Security validation
        if not self.validate_schema_context(instance):
            return None

        # Check sync conditions
        if not self.should_sync(instance):
            logger.debug(
                f"Sync conditions not met for {self.tenant_model.__name__} "
                f"{instance.uuid if hasattr(instance, 'uuid') else instance.pk}"
            )
            # Remove from catalog if exists
            self.remove_from_public(instance)
            return None

        # Extract mapped data
        try:
            catalog_data = self.get_mapped_data(instance)
        except Exception as e:
            logger.error(
                f"Failed to map data for {instance}: {e}",
                exc_info=True
            )
            return None

        # Add required sync metadata
        catalog_data.update({
            'tenant_id': instance.tenant_id,
            'tenant_schema_name': connection.schema_name,
            'synced_at': timezone.now(),
        })

        # Get unique lookup fields for update_or_create
        lookup_fields = {
            'tenant_schema_name': connection.schema_name,
        }

        # Add UUID lookup if instance has uuid field
        if hasattr(instance, 'uuid'):
            uuid_field_name = f"{self.tenant_model.__name__.lower()}_uuid"
            if uuid_field_name in catalog_data:
                lookup_fields[uuid_field_name] = instance.uuid

        # Switch to public schema and perform sync
        try:
            with public_schema_context():
                catalog_entry, was_created = self.public_model.objects.update_or_create(
                    **lookup_fields,
                    defaults=catalog_data
                )

                action = 'Created' if was_created else 'Updated'
                logger.info(
                    f"{action} {self.public_model.__name__} entry for "
                    f"{self.tenant_model.__name__} {instance.uuid if hasattr(instance, 'uuid') else instance.pk} "
                    f"from {connection.schema_name}"
                )

                return catalog_entry

        except Exception as e:
            logger.error(
                f"Failed to sync {instance} to public catalog: {e}",
                exc_info=True
            )
            return None

    def remove_from_public(self, instance: models.Model) -> int:
        """
        Remove instance from public catalog.

        Called when:
        - Item is deleted
        - Item is marked private
        - Sync conditions no longer met

        Args:
            instance: Tenant model instance to remove

        Returns:
            Number of catalog entries deleted (should be 0 or 1)
        """
        # Build lookup filters
        filters = {
            'tenant_schema_name': connection.schema_name,
        }

        # Add UUID filter if available
        if hasattr(instance, 'uuid'):
            uuid_field_name = f"{self.tenant_model.__name__.lower()}_uuid"
            filters[uuid_field_name] = instance.uuid

        # Delete from public schema
        try:
            with public_schema_context():
                deleted_count, _ = self.public_model.objects.filter(**filters).delete()

                if deleted_count > 0:
                    logger.info(
                        f"Removed {deleted_count} {self.public_model.__name__} "
                        f"entries for {instance}"
                    )

                return deleted_count

        except Exception as e:
            logger.error(
                f"Failed to remove {instance} from public catalog: {e}",
                exc_info=True
            )
            return 0
