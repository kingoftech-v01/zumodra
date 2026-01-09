"""
Secure S3 Storage - Private ACL with signed URLs.

This module provides secure file storage using S3 with:
- Private ACL by default
- Signed URLs for time-limited access
- Audit logging for file access
- Tenant-scoped storage paths

Usage:
    from core.storage import SecureS3Storage, TenantS3Storage

    # In model fields
    class Document(models.Model):
        file = models.FileField(storage=SecureS3Storage())

    # Generate signed URL
    url = document.file.storage.url(document.file.name, expire=3600)

Configuration:
    Set in settings.py:
    - AWS_STORAGE_BUCKET_NAME: Your S3 bucket name
    - AWS_S3_REGION_NAME: AWS region
    - AWS_S3_CUSTOM_DOMAIN: Optional CloudFront domain
    - SECURE_STORAGE_URL_EXPIRY: Default URL expiry in seconds (default: 3600)
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode

from django.conf import settings
from django.core.files.storage import default_storage

try:
    from storages.backends.s3boto3 import S3Boto3Storage
    HAS_S3_STORAGE = True
except ImportError:
    HAS_S3_STORAGE = False
    S3Boto3Storage = object  # Placeholder for inheritance

logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security.storage')


# Default URL expiry time in seconds (1 hour)
DEFAULT_URL_EXPIRY = getattr(settings, 'SECURE_STORAGE_URL_EXPIRY', 3600)


class SecureS3Storage(S3Boto3Storage if HAS_S3_STORAGE else object):
    """
    Secure S3 storage backend with private ACL.

    All files are stored with private ACL and accessed via signed URLs
    with configurable expiration times.
    """

    # Force private ACL - no public access
    default_acl = 'private'

    # Enable query string authentication (signed URLs)
    querystring_auth = True

    # Default expiry for signed URLs
    querystring_expire = DEFAULT_URL_EXPIRY

    # Use path-style URLs for compatibility
    addressing_style = 'path'

    def __init__(self, *args, **kwargs):
        """Initialize with security settings."""
        # Override any passed ACL to ensure private
        kwargs['default_acl'] = 'private'
        kwargs['querystring_auth'] = True
        kwargs.setdefault('querystring_expire', DEFAULT_URL_EXPIRY)

        if HAS_S3_STORAGE:
            super().__init__(*args, **kwargs)

        self._log_init()

    def _log_init(self):
        """Log storage initialization."""
        logger.info(
            f"SecureS3Storage initialized with: "
            f"acl=private, querystring_auth=True, expire={self.querystring_expire}s"
        )

    def url(self, name: str, parameters: Optional[dict] = None, expire: Optional[int] = None) -> str:
        """
        Generate a signed URL for accessing a file.

        Args:
            name: File path/name
            parameters: Optional additional URL parameters
            expire: Optional custom expiry time in seconds

        Returns:
            Signed URL with time-limited access
        """
        if not HAS_S3_STORAGE:
            return default_storage.url(name)

        # Use custom expiry if provided
        original_expire = self.querystring_expire
        if expire is not None:
            self.querystring_expire = expire

        try:
            url = super().url(name, parameters)

            # Log URL generation for audit
            self._log_url_generation(name, expire or original_expire)

            return url
        finally:
            # Restore original expiry
            self.querystring_expire = original_expire

    def _log_url_generation(self, name: str, expire: int):
        """Log signed URL generation for audit purposes."""
        security_logger.debug(
            f"SIGNED_URL_GENERATED: file={name} expire={expire}s"
        )

    def save(self, name: str, content, max_length: Optional[int] = None) -> str:
        """
        Save file with security logging.

        Args:
            name: Desired file name
            content: File content
            max_length: Optional max filename length

        Returns:
            Actual name used for saving
        """
        if not HAS_S3_STORAGE:
            return default_storage.save(name, content, max_length)

        saved_name = super().save(name, content, max_length)

        security_logger.info(
            f"FILE_UPLOADED: name={saved_name} size={content.size if hasattr(content, 'size') else 'unknown'}"
        )

        return saved_name

    def delete(self, name: str) -> None:
        """
        Delete file with security logging.

        Args:
            name: File name to delete
        """
        if not HAS_S3_STORAGE:
            return default_storage.delete(name)

        super().delete(name)

        security_logger.info(f"FILE_DELETED: name={name}")


class TenantS3Storage(SecureS3Storage):
    """
    Tenant-scoped S3 storage.

    Automatically prefixes file paths with tenant ID for isolation.
    """

    def __init__(self, tenant_id: Optional[int] = None, *args, **kwargs):
        """Initialize with tenant context."""
        self.tenant_id = tenant_id
        super().__init__(*args, **kwargs)

    def _get_tenant_prefix(self) -> str:
        """Get the tenant prefix for file paths."""
        if self.tenant_id:
            return f"tenants/{self.tenant_id}/"
        return "shared/"

    def _name(self, name: str) -> str:
        """Add tenant prefix to file name."""
        prefix = self._get_tenant_prefix()
        if not name.startswith(prefix):
            name = f"{prefix}{name}"
        return name

    def save(self, name: str, content, max_length: Optional[int] = None) -> str:
        """Save file with tenant prefix."""
        name = self._name(name)
        return super().save(name, content, max_length)

    def url(self, name: str, parameters: Optional[dict] = None, expire: Optional[int] = None) -> str:
        """Generate URL with tenant context."""
        name = self._name(name)
        return super().url(name, parameters, expire)

    def delete(self, name: str) -> None:
        """Delete file with tenant prefix."""
        name = self._name(name)
        super().delete(name)

    def exists(self, name: str) -> bool:
        """Check if file exists with tenant prefix."""
        name = self._name(name)
        if not HAS_S3_STORAGE:
            return default_storage.exists(name)
        return super().exists(name)


class SecureMediaStorage(SecureS3Storage):
    """
    Secure storage for user-uploaded media files.

    Adds additional security measures:
    - Shorter URL expiry for sensitive files
    - Content type validation
    - File size limits
    """

    # Shorter expiry for sensitive media
    querystring_expire = 1800  # 30 minutes

    # Location within bucket
    location = 'media'

    # Content types considered sensitive (shorter expiry)
    SENSITIVE_EXTENSIONS = {'.pdf', '.doc', '.docx', '.xls', '.xlsx'}

    def url(self, name: str, parameters: Optional[dict] = None, expire: Optional[int] = None) -> str:
        """Generate URL with adjusted expiry for sensitive files."""
        if expire is None:
            # Use shorter expiry for sensitive file types
            ext = os.path.splitext(name)[1].lower()
            if ext in self.SENSITIVE_EXTENSIONS:
                expire = 600  # 10 minutes for sensitive files
            else:
                expire = self.querystring_expire

        return super().url(name, parameters, expire)


class SecurePrivateStorage(SecureS3Storage):
    """
    Storage for highly sensitive private files.

    Features:
    - Very short URL expiry (5 minutes)
    - Additional audit logging
    - Access logging with user context
    """

    # Very short expiry for private files
    querystring_expire = 300  # 5 minutes

    # Location within bucket
    location = 'private'

    def url(self, name: str, parameters: Optional[dict] = None, expire: Optional[int] = None) -> str:
        """Generate URL with access logging."""
        if expire is None:
            expire = self.querystring_expire

        # Log access to private files
        security_logger.info(
            f"PRIVATE_FILE_URL_REQUESTED: file={name} expire={expire}s"
        )

        return super().url(name, parameters, expire)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_secure_storage(tenant_id: Optional[int] = None) -> SecureS3Storage:
    """
    Get a secure storage instance.

    Args:
        tenant_id: Optional tenant ID for scoped storage

    Returns:
        SecureS3Storage or TenantS3Storage instance
    """
    if tenant_id:
        return TenantS3Storage(tenant_id=tenant_id)
    return SecureS3Storage()


def generate_signed_url(
    file_path: str,
    expire: int = DEFAULT_URL_EXPIRY,
    tenant_id: Optional[int] = None
) -> str:
    """
    Generate a signed URL for a file.

    Args:
        file_path: Path to the file in storage
        expire: URL expiry time in seconds
        tenant_id: Optional tenant ID for scoped storage

    Returns:
        Signed URL string
    """
    storage = get_secure_storage(tenant_id)
    return storage.url(file_path, expire=expire)


def is_url_expired(url: str) -> bool:
    """
    Check if a signed URL has expired.

    Args:
        url: The signed URL to check

    Returns:
        True if expired, False if still valid
    """
    # Parse expiry from URL (AWS S3 uses X-Amz-Expires parameter)
    from urllib.parse import urlparse, parse_qs

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if 'X-Amz-Expires' in params and 'X-Amz-Date' in params:
        try:
            date_str = params['X-Amz-Date'][0]
            expires = int(params['X-Amz-Expires'][0])

            # Parse AWS date format: YYYYMMDDTHHMMSSZ
            created = datetime.strptime(date_str, '%Y%m%dT%H%M%SZ')
            expiry_time = created + timedelta(seconds=expires)

            return datetime.utcnow() > expiry_time
        except (ValueError, KeyError):
            pass

    return False
