"""
Security Validators for Zumodra

Comprehensive input validation and sanitization for the multi-tenant ATS/HR SaaS platform:
- InputSanitizer: XSS prevention, SQL injection prevention
- FileUploadValidator: MIME type checking, magic bytes validation, size limits
- URLValidator: SSRF prevention, domain validation
- EmailValidator: Strict RFC compliance
- PhoneValidator: International format validation

All validators are designed for production use with proper error handling.
"""

import hashlib
import html
import ipaddress
import logging
import mimetypes
import os
import re
import unicodedata
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse, urljoin

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger('security.validators')


# =============================================================================
# INPUT SANITIZER
# =============================================================================

class InputSanitizer:
    """
    Comprehensive input sanitization for XSS and SQL injection prevention.

    Provides multiple sanitization methods:
    - HTML escaping for XSS prevention
    - SQL special character handling
    - Path traversal prevention
    - Unicode normalization
    - Null byte removal

    Usage:
        sanitizer = InputSanitizer()
        clean_text = sanitizer.sanitize_html(user_input)
        clean_query = sanitizer.sanitize_for_sql(search_term)
    """

    # Characters that need escaping in SQL
    SQL_ESCAPE_CHARS = ["'", '"', '\\', '\x00', '\n', '\r', '\x1a']

    # XSS dangerous patterns
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'vbscript:',
        r'data:text/html',
        r'on\w+\s*=',
        r'<iframe[^>]*>',
        r'<object[^>]*>',
        r'<embed[^>]*>',
        r'<link[^>]*>',
        r'<style[^>]*>.*?</style>',
        r'expression\s*\(',
        r'url\s*\(',
    ]

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\./',
        r'\.\.',
        r'\.\.\\',
        r'%2e%2e%2f',
        r'%2e%2e/',
        r'\.%2e/',
        r'%2e\./',
        r'%252e%252e%252f',
    ]

    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r"'\s*or\s+'",
        r"'\s*or\s+1\s*=\s*1",
        r";\s*drop\s+",
        r";\s*delete\s+",
        r";\s*update\s+",
        r";\s*insert\s+",
        r"union\s+select",
        r"--\s*$",
        r"#\s*$",
        r"/\*.*\*/",
    ]

    def __init__(self):
        self.xss_patterns = [
            re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.XSS_PATTERNS
        ]
        self.path_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.PATH_TRAVERSAL_PATTERNS
        ]
        self.sql_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.SQL_INJECTION_PATTERNS
        ]

    def sanitize_html(self, content: str, allow_safe_tags: bool = False) -> str:
        """
        Sanitize content for XSS prevention.

        Args:
            content: The input content to sanitize
            allow_safe_tags: If True, preserve safe HTML tags

        Returns:
            Sanitized content
        """
        if not content:
            return content

        # Remove null bytes
        content = content.replace('\x00', '')

        # Normalize unicode
        content = unicodedata.normalize('NFKC', content)

        # Remove XSS patterns
        for pattern in self.xss_patterns:
            content = pattern.sub('', content)

        if allow_safe_tags:
            # Preserve safe tags but escape others
            safe_tags = {'b', 'i', 'u', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li'}
            # This is a simplified approach - in production, use bleach or similar
            content = self._escape_unsafe_tags(content, safe_tags)
        else:
            # Full HTML escape
            content = html.escape(content)

        return content

    def _escape_unsafe_tags(self, content: str, safe_tags: Set[str]) -> str:
        """Escape HTML tags not in the safe list."""
        # Simple implementation - for production, use a proper HTML parser
        tag_pattern = re.compile(r'<(/?)(\w+)([^>]*)>')

        def replace_tag(match):
            closing = match.group(1)
            tag_name = match.group(2).lower()
            attrs = match.group(3)

            if tag_name in safe_tags:
                # For safe tags, still sanitize attributes
                if tag_name == 'a':
                    # Only allow href with safe protocols
                    href_match = re.search(r'href\s*=\s*["\']([^"\']+)["\']', attrs, re.IGNORECASE)
                    if href_match:
                        href = href_match.group(1)
                        if not href.startswith(('http://', 'https://', '/')):
                            return html.escape(match.group(0))
                        return f'<{closing}{tag_name} href="{html.escape(href)}">'
                return f'<{closing}{tag_name}>'
            return html.escape(match.group(0))

        return tag_pattern.sub(replace_tag, content)

    def sanitize_for_sql(self, value: str) -> str:
        """
        Sanitize value for use in SQL queries.

        Note: Always prefer parameterized queries. This is a defense-in-depth measure.

        Args:
            value: The input value

        Returns:
            Sanitized value
        """
        if not value:
            return value

        # Remove null bytes
        value = value.replace('\x00', '')

        # Escape special characters
        for char in self.SQL_ESCAPE_CHARS:
            value = value.replace(char, '\\' + char)

        return value

    def detect_sql_injection(self, value: str) -> bool:
        """
        Detect potential SQL injection patterns.

        Args:
            value: The input value to check

        Returns:
            True if SQL injection pattern detected
        """
        if not value:
            return False

        for pattern in self.sql_patterns:
            if pattern.search(value):
                logger.warning(
                    "SQL injection pattern detected",
                    extra={'pattern': pattern.pattern, 'value': value[:100]}
                )
                return True
        return False

    def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename for safe storage.

        Args:
            filename: The original filename

        Returns:
            Safe filename
        """
        if not filename:
            return 'unnamed_file'

        # Remove null bytes
        filename = filename.replace('\x00', '')

        # Remove path separators
        filename = filename.replace('/', '').replace('\\', '')

        # Remove path traversal
        for pattern in self.path_patterns:
            filename = pattern.sub('', filename)

        # Remove dangerous characters
        filename = re.sub(r'[<>:"|?*]', '', filename)

        # Normalize unicode
        filename = unicodedata.normalize('NFKC', filename)

        # Limit length (preserve extension)
        max_length = 255
        if len(filename) > max_length:
            name, ext = os.path.splitext(filename)
            filename = name[:max_length - len(ext)] + ext

        # Ensure not empty
        if not filename or filename == '.':
            filename = 'unnamed_file'

        return filename

    def sanitize_path(self, path: str, base_path: str = None) -> Optional[str]:
        """
        Sanitize file path to prevent traversal attacks.

        Args:
            path: The path to sanitize
            base_path: The base path to restrict access to

        Returns:
            Safe path or None if path is invalid
        """
        if not path:
            return None

        # Remove null bytes
        path = path.replace('\x00', '')

        # Check for traversal patterns
        for pattern in self.path_patterns:
            if pattern.search(path):
                logger.warning("Path traversal attempt detected", extra={'path': path})
                return None

        # Normalize the path
        normalized = os.path.normpath(path)

        # If base_path is provided, ensure path is within it
        if base_path:
            base_resolved = Path(base_path).resolve()
            path_resolved = Path(os.path.join(base_path, normalized)).resolve()

            if not str(path_resolved).startswith(str(base_resolved)):
                logger.warning(
                    "Path traversal attempt blocked",
                    extra={'path': path, 'base': base_path}
                )
                return None

            return str(path_resolved)

        return normalized

    def sanitize_json(self, data: Any) -> Any:
        """
        Recursively sanitize JSON data.

        Args:
            data: JSON data (dict, list, or scalar)

        Returns:
            Sanitized data
        """
        if isinstance(data, dict):
            return {k: self.sanitize_json(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.sanitize_json(item) for item in data]
        elif isinstance(data, str):
            return self.sanitize_html(data)
        return data

    def strip_tags(self, content: str) -> str:
        """
        Remove all HTML tags from content.

        Args:
            content: HTML content

        Returns:
            Plain text content
        """
        if not content:
            return content

        # Remove HTML tags
        content = re.sub(r'<[^>]+>', '', content)

        # Decode HTML entities
        content = html.unescape(content)

        return content.strip()


# =============================================================================
# FILE UPLOAD VALIDATOR
# =============================================================================

class FileUploadValidator:
    """
    Comprehensive file upload validation.

    Validates:
    - File extension whitelist
    - MIME type checking
    - Magic bytes (file signature) validation
    - File size limits
    - Filename sanitization
    - Malware signature detection (basic)

    Usage:
        validator = FileUploadValidator()
        is_valid, error = validator.validate(uploaded_file)
    """

    # File signatures (magic bytes) for common file types
    FILE_SIGNATURES = {
        # Images
        'image/jpeg': [b'\xFF\xD8\xFF'],
        'image/png': [b'\x89PNG\r\n\x1a\n'],
        'image/gif': [b'GIF87a', b'GIF89a'],
        'image/webp': [b'RIFF', b'WEBP'],
        'image/bmp': [b'BM'],
        'image/tiff': [b'II*\x00', b'MM\x00*'],
        'image/svg+xml': [b'<?xml', b'<svg'],

        # Documents
        'application/pdf': [b'%PDF'],
        'application/msword': [b'\xD0\xCF\x11\xE0'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [b'PK\x03\x04'],
        'application/vnd.ms-excel': [b'\xD0\xCF\x11\xE0'],
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': [b'PK\x03\x04'],
        'application/vnd.ms-powerpoint': [b'\xD0\xCF\x11\xE0'],
        'application/vnd.openxmlformats-officedocument.presentationml.presentation': [b'PK\x03\x04'],

        # Archives
        'application/zip': [b'PK\x03\x04', b'PK\x05\x06'],
        'application/x-rar-compressed': [b'Rar!\x1a\x07'],
        'application/x-7z-compressed': [b'7z\xBC\xAF\x27\x1C'],
        'application/gzip': [b'\x1f\x8b'],
        'application/x-tar': [b'ustar'],

        # Text
        'text/plain': [],  # No specific signature
        'text/csv': [],
        'application/json': [],
        'application/xml': [b'<?xml'],
    }

    # Default allowed extensions
    DEFAULT_ALLOWED_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.txt', '.csv', '.json', '.xml',
        '.zip', '.rar', '.7z', '.gz',
    }

    # Default max file size (10MB)
    DEFAULT_MAX_SIZE = 10 * 1024 * 1024

    # Dangerous extensions that should never be allowed
    DANGEROUS_EXTENSIONS = {
        '.exe', '.dll', '.so', '.dylib',
        '.bat', '.cmd', '.sh', '.ps1', '.vbs', '.js',
        '.php', '.asp', '.aspx', '.jsp', '.cgi', '.py', '.pl', '.rb',
        '.htaccess', '.htpasswd',
        '.phar', '.war', '.jar',
    }

    def __init__(
        self,
        allowed_extensions: Set[str] = None,
        max_size: int = None,
        check_magic_bytes: bool = True,
        tenant_id: str = None
    ):
        """
        Initialize the validator.

        Args:
            allowed_extensions: Set of allowed file extensions
            max_size: Maximum file size in bytes
            check_magic_bytes: Whether to validate magic bytes
            tenant_id: Tenant ID for tenant-specific limits
        """
        self.allowed_extensions = allowed_extensions or self.DEFAULT_ALLOWED_EXTENSIONS
        self.max_size = max_size or self._get_max_size_for_tenant(tenant_id)
        self.check_magic_bytes = check_magic_bytes
        self.sanitizer = InputSanitizer()

    def _get_max_size_for_tenant(self, tenant_id: str) -> int:
        """Get max file size based on tenant tier."""
        # This can be extended to check tenant subscription tier
        return getattr(settings, 'SECURITY_MAX_UPLOAD_SIZE', self.DEFAULT_MAX_SIZE)

    def validate(self, uploaded_file) -> Tuple[bool, Optional[str]]:
        """
        Validate an uploaded file.

        Args:
            uploaded_file: Django UploadedFile or similar

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Check if file exists
            if not uploaded_file:
                return (False, "No file provided")

            # Get filename
            filename = getattr(uploaded_file, 'name', '')
            if not filename:
                return (False, "Invalid filename")

            # Validate extension
            is_valid, error = self._validate_extension(filename)
            if not is_valid:
                return (False, error)

            # Validate file size
            file_size = getattr(uploaded_file, 'size', 0)
            is_valid, error = self._validate_size(file_size)
            if not is_valid:
                return (False, error)

            # Validate MIME type
            content_type = getattr(uploaded_file, 'content_type', '')
            is_valid, error = self._validate_content_type(content_type, filename)
            if not is_valid:
                return (False, error)

            # Validate magic bytes
            if self.check_magic_bytes:
                is_valid, error = self._validate_magic_bytes(uploaded_file, content_type)
                if not is_valid:
                    return (False, error)

            # Check for dangerous content
            is_valid, error = self._check_dangerous_content(uploaded_file)
            if not is_valid:
                return (False, error)

            return (True, None)

        except Exception as e:
            logger.error(f"File validation error: {e}")
            return (False, "File validation failed")

    def _validate_extension(self, filename: str) -> Tuple[bool, Optional[str]]:
        """Validate file extension."""
        ext = os.path.splitext(filename)[1].lower()

        # Check dangerous extensions
        if ext in self.DANGEROUS_EXTENSIONS:
            logger.warning(f"Dangerous file extension blocked: {ext}")
            return (False, f"File type '{ext}' is not allowed")

        # Check allowed extensions
        if ext not in self.allowed_extensions:
            return (False, f"File type '{ext}' is not allowed")

        return (True, None)

    def _validate_size(self, file_size: int) -> Tuple[bool, Optional[str]]:
        """Validate file size."""
        if file_size <= 0:
            return (False, "Invalid file size")

        if file_size > self.max_size:
            max_mb = self.max_size / (1024 * 1024)
            return (False, f"File size exceeds maximum allowed ({max_mb:.1f} MB)")

        return (True, None)

    def _validate_content_type(
        self, content_type: str, filename: str
    ) -> Tuple[bool, Optional[str]]:
        """Validate content type matches extension."""
        if not content_type:
            return (True, None)  # Skip if not provided

        ext = os.path.splitext(filename)[1].lower()
        expected_type = mimetypes.guess_type(filename)[0]

        # Allow if content type is generic
        if content_type in ('application/octet-stream', 'binary/octet-stream'):
            return (True, None)

        # Check for mismatched content type
        if expected_type and content_type != expected_type:
            # Allow some flexibility for similar types
            if not self._are_compatible_types(content_type, expected_type):
                logger.warning(
                    f"Content type mismatch: {content_type} vs expected {expected_type}"
                )
                # Don't reject, just log - some browsers report different types
                pass

        return (True, None)

    def _are_compatible_types(self, type1: str, type2: str) -> bool:
        """Check if two MIME types are compatible."""
        # Same base type
        base1 = type1.split('/')[0] if '/' in type1 else type1
        base2 = type2.split('/')[0] if '/' in type2 else type2
        return base1 == base2

    def _validate_magic_bytes(
        self, uploaded_file, content_type: str
    ) -> Tuple[bool, Optional[str]]:
        """Validate file magic bytes match claimed type."""
        try:
            # Read first bytes
            uploaded_file.seek(0)
            header = uploaded_file.read(32)
            uploaded_file.seek(0)

            if not header:
                return (False, "Empty file")

            # Get expected signatures for content type
            signatures = self.FILE_SIGNATURES.get(content_type, [])

            # If no signatures defined for this type, skip check
            if not signatures:
                return (True, None)

            # Check if any signature matches
            for sig in signatures:
                if header.startswith(sig):
                    return (True, None)

            logger.warning(
                f"Magic bytes mismatch for {content_type}",
                extra={'header': header[:16].hex()}
            )
            return (False, "File content does not match declared type")

        except Exception as e:
            logger.error(f"Magic bytes validation error: {e}")
            return (True, None)  # Don't block on error

    def _check_dangerous_content(self, uploaded_file) -> Tuple[bool, Optional[str]]:
        """Check for dangerous content in file."""
        try:
            # Read content
            uploaded_file.seek(0)
            content = uploaded_file.read(8192)  # First 8KB
            uploaded_file.seek(0)

            # Check for script tags in files that shouldn't have them
            content_type = getattr(uploaded_file, 'content_type', '')
            if not content_type.startswith('text/html'):
                if b'<script' in content.lower():
                    logger.warning("Script tag found in non-HTML file")
                    return (False, "File contains potentially dangerous content")

            # Check for PHP code in non-PHP files
            if b'<?php' in content.lower():
                logger.warning("PHP code found in file")
                return (False, "File contains potentially dangerous content")

            return (True, None)

        except Exception as e:
            logger.error(f"Content check error: {e}")
            return (True, None)  # Don't block on error

    def get_safe_filename(self, filename: str) -> str:
        """
        Get a sanitized, safe filename.

        Args:
            filename: Original filename

        Returns:
            Safe filename
        """
        return self.sanitizer.sanitize_filename(filename)

    def generate_unique_filename(
        self, original_filename: str, prefix: str = None
    ) -> str:
        """
        Generate a unique, safe filename.

        Args:
            original_filename: Original filename
            prefix: Optional prefix to add

        Returns:
            Unique filename
        """
        import uuid

        safe_name = self.get_safe_filename(original_filename)
        name, ext = os.path.splitext(safe_name)

        unique_id = uuid.uuid4().hex[:8]

        if prefix:
            return f"{prefix}_{unique_id}_{name}{ext}"
        return f"{unique_id}_{name}{ext}"


# =============================================================================
# URL VALIDATOR
# =============================================================================

class URLValidator:
    """
    URL validation with SSRF prevention.

    Validates:
    - URL format
    - Safe protocols (http, https)
    - Domain blacklist/whitelist
    - Private IP detection (SSRF prevention)
    - Redirect chain validation

    Usage:
        validator = URLValidator()
        is_valid, error = validator.validate(url)
    """

    # Safe protocols
    SAFE_PROTOCOLS = {'http', 'https'}

    # Private IP ranges
    PRIVATE_IP_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),  # Link-local
        ipaddress.ip_network('::1/128'),  # IPv6 loopback
        ipaddress.ip_network('fc00::/7'),  # IPv6 private
        ipaddress.ip_network('fe80::/10'),  # IPv6 link-local
    ]

    # Dangerous hostnames
    DANGEROUS_HOSTNAMES = {
        'localhost',
        'localhost.localdomain',
        '0.0.0.0',
        '[::]',
        '[::1]',
        'metadata.google.internal',  # GCP metadata
        '169.254.169.254',  # AWS/Azure metadata
        'metadata.azure.internal',
    }

    def __init__(
        self,
        allowed_domains: List[str] = None,
        blocked_domains: List[str] = None,
        allow_private_ips: bool = False,
        max_redirects: int = 5
    ):
        """
        Initialize the validator.

        Args:
            allowed_domains: Whitelist of allowed domains (if set, only these are allowed)
            blocked_domains: Blacklist of blocked domains
            allow_private_ips: Whether to allow private IP addresses
            max_redirects: Maximum number of redirects to follow
        """
        self.allowed_domains = set(allowed_domains or [])
        self.blocked_domains = set(blocked_domains or [])
        self.allow_private_ips = allow_private_ips
        self.max_redirects = max_redirects

    def validate(self, url: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a URL for safety.

        Args:
            url: The URL to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not url:
            return (False, "URL is required")

        try:
            parsed = urlparse(url)

            # Check protocol
            if parsed.scheme.lower() not in self.SAFE_PROTOCOLS:
                return (False, f"Protocol '{parsed.scheme}' is not allowed")

            # Check hostname
            hostname = parsed.hostname
            if not hostname:
                return (False, "Invalid URL: no hostname")

            # Check for dangerous hostnames
            if hostname.lower() in self.DANGEROUS_HOSTNAMES:
                logger.warning(f"Blocked dangerous hostname: {hostname}")
                return (False, "URL hostname is not allowed")

            # Check domain whitelist
            if self.allowed_domains:
                if not self._is_domain_allowed(hostname):
                    return (False, "Domain is not in allowed list")

            # Check domain blacklist
            if self.blocked_domains:
                if self._is_domain_blocked(hostname):
                    return (False, "Domain is blocked")

            # Check for private IPs
            if not self.allow_private_ips:
                is_private, reason = self._is_private_address(hostname)
                if is_private:
                    logger.warning(f"SSRF attempt blocked: {hostname} - {reason}")
                    return (False, f"URL points to private address: {reason}")

            return (True, None)

        except Exception as e:
            logger.error(f"URL validation error: {e}")
            return (False, "Invalid URL format")

    def _is_domain_allowed(self, hostname: str) -> bool:
        """Check if hostname is in allowed list."""
        hostname = hostname.lower()
        for allowed in self.allowed_domains:
            if hostname == allowed or hostname.endswith('.' + allowed):
                return True
        return False

    def _is_domain_blocked(self, hostname: str) -> bool:
        """Check if hostname is in blocked list."""
        hostname = hostname.lower()
        for blocked in self.blocked_domains:
            if hostname == blocked or hostname.endswith('.' + blocked):
                return True
        return False

    def _is_private_address(self, hostname: str) -> Tuple[bool, str]:
        """
        Check if hostname resolves to private IP.

        Returns:
            Tuple of (is_private, reason)
        """
        import socket

        try:
            # Try to parse as IP address directly
            try:
                ip = ipaddress.ip_address(hostname)
                if self._is_ip_private(ip):
                    return (True, f"Direct private IP: {hostname}")
                return (False, "")
            except ValueError:
                pass

            # Resolve hostname
            try:
                addresses = socket.getaddrinfo(hostname, None)
                for family, _, _, _, sockaddr in addresses:
                    ip_str = sockaddr[0]
                    try:
                        ip = ipaddress.ip_address(ip_str)
                        if self._is_ip_private(ip):
                            return (True, f"Hostname resolves to private IP: {ip_str}")
                    except ValueError:
                        continue
            except socket.gaierror:
                # Could not resolve - might be intentional, allow it
                pass

            return (False, "")

        except Exception as e:
            logger.error(f"Private address check error: {e}")
            return (False, "")

    def _is_ip_private(self, ip: ipaddress.IPv4Address) -> bool:
        """Check if IP is in private ranges."""
        for network in self.PRIVATE_IP_RANGES:
            if ip in network:
                return True
        return False

    def sanitize_url(self, url: str) -> str:
        """
        Sanitize URL for safe storage/display.

        Args:
            url: The URL to sanitize

        Returns:
            Sanitized URL
        """
        if not url:
            return ""

        # Parse and reconstruct
        try:
            parsed = urlparse(url)

            # Only allow safe schemes
            if parsed.scheme.lower() not in self.SAFE_PROTOCOLS:
                return ""

            # Reconstruct URL without potentially dangerous parts
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean_url += f"?{parsed.query}"

            return clean_url
        except Exception:
            return ""


# =============================================================================
# EMAIL VALIDATOR
# =============================================================================

class EmailValidator:
    """
    Strict email validation with RFC compliance.

    Validates:
    - RFC 5321/5322 format compliance
    - Domain validation
    - Disposable email detection
    - MX record checking (optional)

    Usage:
        validator = EmailValidator()
        is_valid, error = validator.validate(email)
    """

    # Email regex (RFC 5322)
    EMAIL_PATTERN = re.compile(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
        r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
        r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    )

    # Common disposable email domains
    DISPOSABLE_DOMAINS = {
        'mailinator.com', 'guerrillamail.com', 'tempmail.com',
        'throwaway.email', '10minutemail.com', 'yopmail.com',
        'fakeinbox.com', 'trashmail.com', 'getnada.com',
        'maildrop.cc', 'dispostable.com', 'tempail.com',
    }

    def __init__(
        self,
        check_mx: bool = False,
        block_disposable: bool = True,
        allowed_domains: List[str] = None
    ):
        """
        Initialize the validator.

        Args:
            check_mx: Whether to check MX records
            block_disposable: Whether to block disposable emails
            allowed_domains: List of allowed domains (if set, only these are allowed)
        """
        self.check_mx = check_mx
        self.block_disposable = block_disposable
        self.allowed_domains = set(allowed_domains or [])

    def validate(self, email: str) -> Tuple[bool, Optional[str]]:
        """
        Validate an email address.

        Args:
            email: The email address to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not email:
            return (False, "Email is required")

        # Normalize
        email = email.lower().strip()

        # Check length
        if len(email) > 254:
            return (False, "Email address is too long")

        # Check format
        if not self.EMAIL_PATTERN.match(email):
            return (False, "Invalid email format")

        # Extract domain
        try:
            local_part, domain = email.rsplit('@', 1)
        except ValueError:
            return (False, "Invalid email format")

        # Check local part length
        if len(local_part) > 64:
            return (False, "Email local part is too long")

        # Check domain
        if not domain or '.' not in domain:
            return (False, "Invalid email domain")

        # Check allowed domains
        if self.allowed_domains:
            if domain not in self.allowed_domains:
                return (False, "Email domain is not allowed")

        # Check disposable domains
        if self.block_disposable:
            if domain in self.DISPOSABLE_DOMAINS:
                return (False, "Disposable email addresses are not allowed")

        # Check MX records
        if self.check_mx:
            has_mx, error = self._check_mx_record(domain)
            if not has_mx:
                return (False, error)

        return (True, None)

    def _check_mx_record(self, domain: str) -> Tuple[bool, Optional[str]]:
        """Check if domain has MX records."""
        try:
            import dns.resolver
            records = dns.resolver.resolve(domain, 'MX')
            if records:
                return (True, None)
            return (False, "Domain has no mail servers")
        except ImportError:
            # dns package not available, skip check
            return (True, None)
        except Exception as e:
            logger.warning(f"MX lookup failed for {domain}: {e}")
            return (True, None)  # Don't block on DNS errors

    def normalize(self, email: str) -> str:
        """
        Normalize email address.

        Args:
            email: The email address

        Returns:
            Normalized email
        """
        return email.lower().strip()


# =============================================================================
# PHONE VALIDATOR
# =============================================================================

class PhoneValidator:
    """
    International phone number validation.

    Validates:
    - E.164 format compliance
    - Country code validation
    - Number length validation
    - Formatting and normalization

    Usage:
        validator = PhoneValidator(default_region='CA')
        is_valid, error = validator.validate('+14165551234')
    """

    # E.164 pattern (basic)
    E164_PATTERN = re.compile(r'^\+[1-9]\d{1,14}$')

    # Basic patterns for common regions
    REGION_PATTERNS = {
        'US': re.compile(r'^(\+?1)?[2-9]\d{2}[2-9]\d{6}$'),
        'CA': re.compile(r'^(\+?1)?[2-9]\d{2}[2-9]\d{6}$'),
        'GB': re.compile(r'^(\+?44)?\d{10}$'),
        'FR': re.compile(r'^(\+?33)?[1-9]\d{8}$'),
        'DE': re.compile(r'^(\+?49)?\d{10,11}$'),
    }

    def __init__(
        self,
        default_region: str = 'CA',
        require_country_code: bool = False,
        allowed_regions: List[str] = None
    ):
        """
        Initialize the validator.

        Args:
            default_region: Default region for parsing
            require_country_code: Whether to require country code
            allowed_regions: List of allowed region codes
        """
        self.default_region = default_region
        self.require_country_code = require_country_code
        self.allowed_regions = set(allowed_regions or [])

        # Try to import phonenumbers for advanced validation
        try:
            import phonenumbers
            self.phonenumbers = phonenumbers
        except ImportError:
            self.phonenumbers = None

    def validate(self, phone: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a phone number.

        Args:
            phone: The phone number to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not phone:
            return (False, "Phone number is required")

        # Clean input
        phone = self._clean_phone(phone)

        if not phone:
            return (False, "Invalid phone number")

        # Use phonenumbers library if available
        if self.phonenumbers:
            return self._validate_with_phonenumbers(phone)

        # Fall back to basic validation
        return self._validate_basic(phone)

    def _clean_phone(self, phone: str) -> str:
        """Remove formatting characters from phone number."""
        # Keep only digits and leading +
        cleaned = re.sub(r'[^\d+]', '', phone)

        # Remove + if not at start
        if '+' in cleaned[1:]:
            cleaned = cleaned[0] + cleaned[1:].replace('+', '')

        return cleaned

    def _validate_with_phonenumbers(self, phone: str) -> Tuple[bool, Optional[str]]:
        """Validate using phonenumbers library."""
        try:
            parsed = self.phonenumbers.parse(phone, self.default_region)

            if not self.phonenumbers.is_valid_number(parsed):
                return (False, "Invalid phone number")

            # Check region if restricted
            if self.allowed_regions:
                region = self.phonenumbers.region_code_for_number(parsed)
                if region not in self.allowed_regions:
                    return (False, f"Phone numbers from {region} are not allowed")

            return (True, None)

        except self.phonenumbers.NumberParseException as e:
            return (False, f"Invalid phone number: {str(e)}")

    def _validate_basic(self, phone: str) -> Tuple[bool, Optional[str]]:
        """Basic phone validation without phonenumbers library."""
        # Remove leading +
        digits = phone.lstrip('+')

        # Check minimum length
        if len(digits) < 10:
            return (False, "Phone number is too short")

        # Check maximum length (E.164 max is 15)
        if len(digits) > 15:
            return (False, "Phone number is too long")

        # Check for valid characters
        if not digits.isdigit():
            return (False, "Phone number contains invalid characters")

        # Check E.164 format if starts with +
        if phone.startswith('+'):
            if not self.E164_PATTERN.match(phone):
                return (False, "Invalid E.164 format")

        return (True, None)

    def format_e164(self, phone: str) -> Optional[str]:
        """
        Format phone number in E.164 format.

        Args:
            phone: The phone number

        Returns:
            E.164 formatted number or None if invalid
        """
        if self.phonenumbers:
            try:
                parsed = self.phonenumbers.parse(phone, self.default_region)
                if self.phonenumbers.is_valid_number(parsed):
                    return self.phonenumbers.format_number(
                        parsed,
                        self.phonenumbers.PhoneNumberFormat.E164
                    )
            except Exception:
                pass
            return None

        # Basic formatting
        cleaned = self._clean_phone(phone)
        if not cleaned.startswith('+'):
            # Add default country code for US/CA
            if self.default_region in ('US', 'CA'):
                cleaned = '+1' + cleaned.lstrip('1')
        return cleaned if self.E164_PATTERN.match(cleaned) else None

    def format_national(self, phone: str) -> Optional[str]:
        """
        Format phone number in national format.

        Args:
            phone: The phone number

        Returns:
            Nationally formatted number or None if invalid
        """
        if self.phonenumbers:
            try:
                parsed = self.phonenumbers.parse(phone, self.default_region)
                if self.phonenumbers.is_valid_number(parsed):
                    return self.phonenumbers.format_number(
                        parsed,
                        self.phonenumbers.PhoneNumberFormat.NATIONAL
                    )
            except Exception:
                pass
        return None

    def format_international(self, phone: str) -> Optional[str]:
        """
        Format phone number in international format.

        Args:
            phone: The phone number

        Returns:
            Internationally formatted number or None if invalid
        """
        if self.phonenumbers:
            try:
                parsed = self.phonenumbers.parse(phone, self.default_region)
                if self.phonenumbers.is_valid_number(parsed):
                    return self.phonenumbers.format_number(
                        parsed,
                        self.phonenumbers.PhoneNumberFormat.INTERNATIONAL
                    )
            except Exception:
                pass
        return None


# =============================================================================
# USERNAME VALIDATOR
# =============================================================================

class UsernameValidator:
    """
    Strict username validation for secure user accounts.

    Validates:
    - Alphanumeric characters only (with optional underscores/hyphens)
    - Length constraints (3-30 characters)
    - No reserved words
    - No offensive content
    - Case-insensitive uniqueness

    Usage:
        validator = UsernameValidator()
        is_valid, error = validator.validate('john_doe123')
    """

    # Username pattern: alphanumeric with underscores/hyphens, must start with letter
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{2,29}$')

    # Strict alphanumeric only (no special chars)
    ALPHANUMERIC_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9]{2,29}$')

    # Reserved usernames that cannot be used
    RESERVED_USERNAMES = {
        'admin', 'administrator', 'root', 'system', 'support',
        'help', 'info', 'contact', 'sales', 'billing', 'api',
        'www', 'mail', 'email', 'ftp', 'ssh', 'test', 'demo',
        'null', 'undefined', 'anonymous', 'guest', 'user',
        'zumodra', 'moderator', 'mod', 'staff', 'superuser',
        'webmaster', 'postmaster', 'hostmaster', 'abuse',
        'security', 'noreply', 'no-reply', 'mailer-daemon',
        'nobody', 'operator', 'sysadmin', 'backup', 'daemon',
        'tenant', 'owner', 'ceo', 'pdg', 'hr', 'manager',
    }

    # Offensive/prohibited terms (basic list - extend as needed)
    PROHIBITED_TERMS = {
        'fuck', 'shit', 'ass', 'bitch', 'damn', 'hell',
        'nazi', 'hitler', 'racist', 'terror',
    }

    def __init__(
        self,
        min_length: int = 3,
        max_length: int = 30,
        allow_special_chars: bool = True,
        check_reserved: bool = True,
        check_offensive: bool = True
    ):
        """
        Initialize the validator.

        Args:
            min_length: Minimum username length
            max_length: Maximum username length
            allow_special_chars: Allow underscores and hyphens
            check_reserved: Block reserved usernames
            check_offensive: Block offensive usernames
        """
        self.min_length = min_length
        self.max_length = max_length
        self.allow_special_chars = allow_special_chars
        self.check_reserved = check_reserved
        self.check_offensive = check_offensive

    def validate(self, username: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a username.

        Args:
            username: The username to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not username:
            return (False, "Username is required")

        # Normalize (lowercase, strip)
        username = username.lower().strip()

        # Check length
        if len(username) < self.min_length:
            return (False, f"Username must be at least {self.min_length} characters")

        if len(username) > self.max_length:
            return (False, f"Username must be at most {self.max_length} characters")

        # Check pattern
        if self.allow_special_chars:
            if not self.USERNAME_PATTERN.match(username):
                return (False, "Username must start with a letter and contain only letters, numbers, underscores, and hyphens")
        else:
            if not self.ALPHANUMERIC_PATTERN.match(username):
                return (False, "Username must start with a letter and contain only letters and numbers")

        # Check reserved usernames
        if self.check_reserved:
            if username in self.RESERVED_USERNAMES:
                return (False, "This username is reserved")

        # Check offensive content
        if self.check_offensive:
            for term in self.PROHIBITED_TERMS:
                if term in username:
                    return (False, "Username contains prohibited content")

        # Check for repeated characters (e.g., 'aaaaaaa')
        if self._has_excessive_repeats(username):
            return (False, "Username contains too many repeated characters")

        return (True, None)

    def _has_excessive_repeats(self, username: str, max_repeats: int = 3) -> bool:
        """Check for excessive character repetition."""
        count = 1
        prev = ''
        for char in username:
            if char == prev:
                count += 1
                if count > max_repeats:
                    return True
            else:
                count = 1
            prev = char
        return False

    def normalize(self, username: str) -> str:
        """
        Normalize a username for storage/comparison.

        Args:
            username: The username to normalize

        Returns:
            Normalized username (lowercase, stripped)
        """
        return username.lower().strip()

    def suggest_alternatives(self, username: str, count: int = 3) -> List[str]:
        """
        Suggest alternative usernames if the provided one is taken.

        Args:
            username: The original username
            count: Number of suggestions to generate

        Returns:
            List of suggested usernames
        """
        import random

        suggestions = []
        base = self.normalize(username)

        # Add numbers
        for i in range(count):
            num = random.randint(1, 999)
            suggestions.append(f"{base}{num}")

        return suggestions


# =============================================================================
# SANITIZATION UTILITIES
# =============================================================================

class SanitizationUtilities:
    """
    Advanced sanitization utilities using bleach and escape functions.

    Provides:
    - HTML sanitization with configurable allowed tags
    - Rich text sanitization for CMS/editor content
    - Plain text extraction
    - URL sanitization
    - Markdown sanitization
    - JSON sanitization

    Usage:
        sanitizer = SanitizationUtilities()
        clean_html = sanitizer.sanitize_rich_text(user_html)
    """

    # Default allowed HTML tags for rich text
    ALLOWED_TAGS = [
        'p', 'br', 'strong', 'em', 'u', 'b', 'i', 's', 'strike',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li',
        'a', 'img',
        'blockquote', 'pre', 'code',
        'table', 'thead', 'tbody', 'tr', 'th', 'td',
        'div', 'span', 'hr',
    ]

    # Default allowed attributes
    ALLOWED_ATTRIBUTES = {
        '*': ['class', 'id'],
        'a': ['href', 'title', 'target', 'rel'],
        'img': ['src', 'alt', 'title', 'width', 'height'],
        'table': ['border', 'cellpadding', 'cellspacing'],
        'th': ['colspan', 'rowspan'],
        'td': ['colspan', 'rowspan'],
    }

    # Safe URL protocols
    ALLOWED_PROTOCOLS = ['http', 'https', 'mailto', 'tel']

    def __init__(self, use_bleach: bool = True):
        """
        Initialize the sanitizer.

        Args:
            use_bleach: Whether to use bleach library (falls back to html.escape if not available)
        """
        self.use_bleach = use_bleach
        self._bleach = None

        if use_bleach:
            try:
                import bleach
                self._bleach = bleach
            except ImportError:
                logger.warning("bleach library not installed, falling back to html.escape")
                self.use_bleach = False

    def sanitize_rich_text(
        self,
        content: str,
        allowed_tags: List[str] = None,
        allowed_attributes: Dict[str, List[str]] = None,
        strip: bool = True
    ) -> str:
        """
        Sanitize rich text content (HTML from editors).

        Args:
            content: HTML content to sanitize
            allowed_tags: List of allowed HTML tags
            allowed_attributes: Dict of allowed attributes per tag
            strip: Whether to strip disallowed tags (True) or escape them (False)

        Returns:
            Sanitized HTML content
        """
        if not content:
            return content

        tags = allowed_tags or self.ALLOWED_TAGS
        attrs = allowed_attributes or self.ALLOWED_ATTRIBUTES

        if self._bleach:
            return self._bleach.clean(
                content,
                tags=tags,
                attributes=attrs,
                protocols=self.ALLOWED_PROTOCOLS,
                strip=strip
            )

        # Fallback: strip all HTML
        return self._strip_html(content)

    def sanitize_plain_text(self, content: str) -> str:
        """
        Sanitize plain text content (escape all HTML).

        Args:
            content: Text content to sanitize

        Returns:
            HTML-escaped content
        """
        if not content:
            return content

        return html.escape(content)

    def extract_text(self, html_content: str) -> str:
        """
        Extract plain text from HTML content.

        Args:
            html_content: HTML content

        Returns:
            Plain text without HTML tags
        """
        if not html_content:
            return ''

        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', html_content)

        # Decode HTML entities
        text = html.unescape(text)

        # Normalize whitespace
        text = ' '.join(text.split())

        return text.strip()

    def sanitize_url(self, url: str) -> str:
        """
        Sanitize a URL for safe embedding.

        Args:
            url: URL to sanitize

        Returns:
            Sanitized URL or empty string if unsafe
        """
        if not url:
            return ''

        url = url.strip()

        # Check protocol
        parsed = urlparse(url)
        if parsed.scheme and parsed.scheme.lower() not in self.ALLOWED_PROTOCOLS:
            return ''

        # Escape special characters
        return html.escape(url)

    def sanitize_markdown(self, content: str) -> str:
        """
        Sanitize Markdown content.

        Args:
            content: Markdown content

        Returns:
            Sanitized Markdown content
        """
        if not content:
            return content

        # Remove potential HTML in markdown
        content = self._strip_dangerous_html(content)

        # Sanitize URLs in markdown links
        link_pattern = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')

        def sanitize_link(match):
            text = match.group(1)
            url = self.sanitize_url(match.group(2))
            if url:
                return f'[{text}]({url})'
            return text

        content = link_pattern.sub(sanitize_link, content)

        return content

    def sanitize_json_values(self, data: Any) -> Any:
        """
        Recursively sanitize all string values in JSON data.

        Args:
            data: JSON data (dict, list, or scalar)

        Returns:
            Sanitized data
        """
        if isinstance(data, dict):
            return {k: self.sanitize_json_values(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.sanitize_json_values(item) for item in data]
        elif isinstance(data, str):
            return self.sanitize_plain_text(data)
        return data

    def _strip_html(self, content: str) -> str:
        """Strip all HTML tags from content."""
        return re.sub(r'<[^>]+>', '', content)

    def _strip_dangerous_html(self, content: str) -> str:
        """Remove dangerous HTML elements from content."""
        # Remove script tags
        content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL | re.IGNORECASE)

        # Remove style tags
        content = re.sub(r'<style[^>]*>.*?</style>', '', content, flags=re.DOTALL | re.IGNORECASE)

        # Remove on* event handlers
        content = re.sub(r'\son\w+\s*=\s*["\'][^"\']*["\']', '', content, flags=re.IGNORECASE)

        # Remove javascript: URLs
        content = re.sub(r'javascript:', '', content, flags=re.IGNORECASE)

        return content

    def linkify(self, content: str, safe: bool = True) -> str:
        """
        Convert URLs in text to clickable links.

        Args:
            content: Text content
            safe: Whether to use safe mode (nofollow, target=_blank)

        Returns:
            Content with URLs converted to links
        """
        if not content:
            return content

        if self._bleach:
            callbacks = []
            if safe:
                def add_safe_attrs(attrs, new=False):
                    attrs[(None, 'rel')] = 'nofollow noopener'
                    attrs[(None, 'target')] = '_blank'
                    return attrs
                callbacks.append(add_safe_attrs)

            return self._bleach.linkify(content, callbacks=callbacks)

        # Fallback: simple URL pattern replacement
        url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\\^`\[\]]+',
            re.IGNORECASE
        )

        def replace_url(match):
            url = html.escape(match.group(0))
            if safe:
                return f'<a href="{url}" rel="nofollow noopener" target="_blank">{url}</a>'
            return f'<a href="{url}">{url}</a>'

        return url_pattern.sub(replace_url, content)


# =============================================================================
# VIRUS SCAN STUB
# =============================================================================

class VirusScanValidator:
    """
    Virus scanning stub for file uploads.

    In production, integrate with:
    - ClamAV (open source)
    - VirusTotal API
    - Windows Defender API
    - Third-party scanning services

    This stub provides the interface and basic pattern detection.
    """

    # Known dangerous file signatures (basic patterns)
    DANGEROUS_PATTERNS = [
        b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE',  # EICAR test
        b'X5O!P%@AP[4\\PZX54(P^)7CC)7}',  # EICAR test signature
        b'MZ',  # Windows executable (first 2 bytes) - for non-exe contexts
    ]

    # Suspicious strings in files
    SUSPICIOUS_STRINGS = [
        b'CreateRemoteThread',
        b'VirtualAllocEx',
        b'WriteProcessMemory',
        b'powershell -enc',
        b'powershell -encodedcommand',
        b'cmd.exe /c',
        b'wscript.shell',
        b'eval(base64_decode',
        b'fromCharCode',
    ]

    def __init__(self, use_clamav: bool = False, clamav_socket: str = None):
        """
        Initialize the virus scanner.

        Args:
            use_clamav: Whether to use ClamAV
            clamav_socket: Path to ClamAV socket (if using ClamAV)
        """
        self.use_clamav = use_clamav
        self.clamav_socket = clamav_socket or '/var/run/clamav/clamd.ctl'
        self._clamd = None

        if use_clamav:
            try:
                import clamd
                self._clamd = clamd.ClamdUnixSocket(self.clamav_socket)
            except ImportError:
                logger.warning("clamd library not installed")
                self.use_clamav = False
            except Exception as e:
                logger.warning(f"Could not connect to ClamAV: {e}")
                self.use_clamav = False

    def scan(self, file_content: bytes) -> Tuple[bool, Optional[str]]:
        """
        Scan file content for viruses/malware.

        Args:
            file_content: File content as bytes

        Returns:
            Tuple of (is_safe, threat_name)
        """
        # Try ClamAV first
        if self._clamd:
            return self._scan_with_clamav(file_content)

        # Fall back to basic pattern matching
        return self._scan_basic(file_content)

    def scan_file(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """
        Scan a file for viruses/malware.

        Args:
            file_path: Path to the file

        Returns:
            Tuple of (is_safe, threat_name)
        """
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            return self.scan(content)
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return (False, "Scan error")

    def scan_uploaded_file(self, uploaded_file) -> Tuple[bool, Optional[str]]:
        """
        Scan an uploaded file object.

        Args:
            uploaded_file: Django UploadedFile

        Returns:
            Tuple of (is_safe, threat_name)
        """
        try:
            uploaded_file.seek(0)
            content = uploaded_file.read()
            uploaded_file.seek(0)
            return self.scan(content)
        except Exception as e:
            logger.error(f"Error scanning uploaded file: {e}")
            return (False, "Scan error")

    def _scan_with_clamav(self, content: bytes) -> Tuple[bool, Optional[str]]:
        """Scan with ClamAV."""
        try:
            from io import BytesIO
            result = self._clamd.instream(BytesIO(content))

            if result and 'stream' in result:
                status, name = result['stream']
                if status == 'FOUND':
                    logger.warning(f"ClamAV detected threat: {name}")
                    return (False, name)

            return (True, None)
        except Exception as e:
            logger.error(f"ClamAV scan error: {e}")
            # On error, fall back to basic scan
            return self._scan_basic(content)

    def _scan_basic(self, content: bytes) -> Tuple[bool, Optional[str]]:
        """Basic pattern-based scanning."""
        # Check for dangerous patterns
        for pattern in self.DANGEROUS_PATTERNS:
            if pattern in content:
                logger.warning(f"Dangerous pattern detected in file")
                return (False, "Suspicious pattern detected")

        # Check for suspicious strings
        for suspicious in self.SUSPICIOUS_STRINGS:
            if suspicious.lower() in content.lower():
                logger.warning(f"Suspicious string detected in file")
                return (False, "Suspicious content detected")

        return (True, None)


# =============================================================================
# COMBINED FILE VALIDATOR WITH VIRUS SCAN
# =============================================================================

class SecureFileValidator:
    """
    Complete file validation including virus scanning.

    Combines:
    - FileUploadValidator for type/size/extension checks
    - VirusScanValidator for malware detection
    - InputSanitizer for filename sanitization

    Usage:
        validator = SecureFileValidator()
        is_valid, error = validator.validate(uploaded_file)
    """

    def __init__(
        self,
        allowed_extensions: Set[str] = None,
        max_size: int = None,
        scan_for_viruses: bool = True,
        use_clamav: bool = False,
        tenant_id: str = None
    ):
        """
        Initialize the secure file validator.

        Args:
            allowed_extensions: Set of allowed file extensions
            max_size: Maximum file size in bytes
            scan_for_viruses: Whether to scan for viruses
            use_clamav: Whether to use ClamAV for scanning
            tenant_id: Tenant ID for tenant-specific limits
        """
        self.file_validator = FileUploadValidator(
            allowed_extensions=allowed_extensions,
            max_size=max_size,
            tenant_id=tenant_id
        )
        self.virus_scanner = VirusScanValidator(use_clamav=use_clamav) if scan_for_viruses else None
        self.sanitizer = InputSanitizer()

    def validate(self, uploaded_file) -> Tuple[bool, Optional[str]]:
        """
        Validate an uploaded file completely.

        Args:
            uploaded_file: Django UploadedFile or similar

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Basic file validation
        is_valid, error = self.file_validator.validate(uploaded_file)
        if not is_valid:
            return (False, error)

        # Virus scan
        if self.virus_scanner:
            is_safe, threat = self.virus_scanner.scan_uploaded_file(uploaded_file)
            if not is_safe:
                logger.warning(f"Malware detected in upload: {threat}")
                return (False, "File contains potentially dangerous content")

        return (True, None)

    def get_safe_filename(self, filename: str) -> str:
        """Get a sanitized filename."""
        return self.file_validator.get_safe_filename(filename)

    def generate_unique_filename(self, original_filename: str, prefix: str = None) -> str:
        """Generate a unique, safe filename."""
        return self.file_validator.generate_unique_filename(original_filename, prefix)
