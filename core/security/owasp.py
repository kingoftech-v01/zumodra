"""
OWASP Top 10 2021 Security Protections for Zumodra

This module implements comprehensive protections against the OWASP Top 10 vulnerabilities:
- A01:2021 Broken Access Control
- A02:2021 Cryptographic Failures
- A03:2021 Injection
- A04:2021 Insecure Design
- A05:2021 Security Misconfiguration
- A06:2021 Vulnerable and Outdated Components
- A07:2021 Identification and Authentication Failures
- A08:2021 Software and Data Integrity Failures
- A09:2021 Security Logging and Monitoring Failures
- A10:2021 Server-Side Request Forgery (SSRF)

All protections are tenant-aware and log security events for audit compliance.
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import subprocess
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection
from django.http import HttpRequest, HttpResponse, HttpResponseForbidden
from django.utils import timezone
from django.utils.crypto import constant_time_compare, get_random_string

# Security logger configuration
logger = logging.getLogger('security')
audit_logger = logging.getLogger('security.audit')


# =============================================================================
# Security Event Types for Logging
# =============================================================================

class SecurityEventType(Enum):
    """Security event types for standardized logging."""
    # Access Control Events
    ACCESS_DENIED = 'access_denied'
    TENANT_BOUNDARY_VIOLATION = 'tenant_boundary_violation'
    RESOURCE_ACCESS_VIOLATION = 'resource_access_violation'
    PRIVILEGE_ESCALATION_ATTEMPT = 'privilege_escalation_attempt'

    # Authentication Events
    LOGIN_SUCCESS = 'login_success'
    LOGIN_FAILURE = 'login_failure'
    ACCOUNT_LOCKED = 'account_locked'
    PASSWORD_CHANGE = 'password_change'
    MFA_ENABLED = 'mfa_enabled'
    MFA_DISABLED = 'mfa_disabled'
    SESSION_HIJACK_ATTEMPT = 'session_hijack_attempt'

    # Injection Events
    SQL_INJECTION_ATTEMPT = 'sql_injection_attempt'
    COMMAND_INJECTION_ATTEMPT = 'command_injection_attempt'
    LDAP_INJECTION_ATTEMPT = 'ldap_injection_attempt'
    XSS_ATTEMPT = 'xss_attempt'

    # SSRF Events
    SSRF_ATTEMPT = 'ssrf_attempt'
    BLOCKED_URL_ACCESS = 'blocked_url_access'

    # Integrity Events
    CSRF_VIOLATION = 'csrf_violation'
    DATA_TAMPERING = 'data_tampering'
    SIGNATURE_MISMATCH = 'signature_mismatch'

    # Configuration Events
    SECURITY_MISCONFIGURATION = 'security_misconfiguration'
    VULNERABLE_COMPONENT = 'vulnerable_component'

    # Cryptographic Events
    WEAK_ENCRYPTION = 'weak_encryption'
    TLS_FAILURE = 'tls_failure'


@dataclass
class SecurityEvent:
    """Standardized security event for logging and alerting."""
    event_type: SecurityEventType
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    message: str
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_path: Optional[str] = None
    request_method: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=timezone.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for logging/storage."""
        return {
            'event_type': self.event_type.value,
            'severity': self.severity,
            'message': self.message,
            'tenant_id': self.tenant_id,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'request_path': self.request_path,
            'request_method': self.request_method,
            'details': self.details,
            'timestamp': self.timestamp.isoformat(),
        }


# =============================================================================
# A01:2021 - Broken Access Control
# =============================================================================

class TenantAccessControlValidator:
    """
    Validates tenant-level access control to prevent unauthorized cross-tenant access.

    Ensures users can only access resources within their assigned tenant,
    preventing horizontal privilege escalation attacks.
    """

    def __init__(self):
        self.logger = SecurityEventLogger()

    def get_tenant_from_request(self, request: HttpRequest) -> Optional[str]:
        """Extract tenant identifier from request."""
        # Try django-tenants integration first
        if hasattr(request, 'tenant'):
            return str(getattr(request.tenant, 'schema_name', None) or
                       getattr(request.tenant, 'id', None))

        # Fallback to header-based tenant identification
        return request.META.get('HTTP_X_TENANT_ID')

    def get_user_tenant(self, user) -> Optional[str]:
        """Get the tenant associated with a user."""
        if not user or not user.is_authenticated:
            return None

        # Try common tenant relationships
        if hasattr(user, 'tenant'):
            tenant = user.tenant
            return str(getattr(tenant, 'schema_name', None) or
                       getattr(tenant, 'id', None))

        if hasattr(user, 'tenant_id'):
            return str(user.tenant_id)

        # Check for tenant user profile
        if hasattr(user, 'tenantuser'):
            return str(user.tenantuser.tenant_id)

        return None

    def validate_access(
        self,
        request: HttpRequest,
        resource_tenant_id: Optional[str] = None
    ) -> bool:
        """
        Validate that the current user has access to the requested tenant context.

        Args:
            request: The HTTP request object
            resource_tenant_id: The tenant ID of the resource being accessed

        Returns:
            True if access is allowed, False otherwise
        """
        user = getattr(request, 'user', None)
        request_tenant_id = self.get_tenant_from_request(request)
        user_tenant_id = self.get_user_tenant(user)

        # Superusers bypass tenant checks
        if user and getattr(user, 'is_superuser', False):
            return True

        # Anonymous users have no tenant access
        if not user or not user.is_authenticated:
            return False

        # Check tenant boundary
        target_tenant = resource_tenant_id or request_tenant_id

        if target_tenant and user_tenant_id != target_tenant:
            self._log_access_violation(request, user_tenant_id, target_tenant)
            return False

        return True

    def _log_access_violation(
        self,
        request: HttpRequest,
        user_tenant: Optional[str],
        target_tenant: str
    ):
        """Log a tenant boundary violation attempt."""
        event = SecurityEvent(
            event_type=SecurityEventType.TENANT_BOUNDARY_VIOLATION,
            severity='high',
            message=f'Cross-tenant access attempt: user tenant {user_tenant} -> {target_tenant}',
            tenant_id=target_tenant,
            user_id=str(getattr(request.user, 'id', None)),
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            request_path=request.path,
            request_method=request.method,
            details={
                'user_tenant': user_tenant,
                'target_tenant': target_tenant,
            }
        )
        self.logger.log(event)

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


class ResourceOwnershipChecker:
    """
    Validates resource ownership to prevent unauthorized access.

    Implements object-level authorization checking to ensure users
    can only access resources they own or have explicit permissions for.
    """

    def __init__(self):
        self.logger = SecurityEventLogger()

    def check_ownership(
        self,
        user,
        resource: Any,
        owner_field: str = 'owner',
        permission_field: str = None
    ) -> bool:
        """
        Check if a user owns or has permission to access a resource.

        Args:
            user: The user requesting access
            resource: The resource being accessed
            owner_field: Field name containing the owner reference
            permission_field: Optional field containing permission list

        Returns:
            True if user has access, False otherwise
        """
        if not user or not user.is_authenticated:
            return False

        # Superusers have full access
        if getattr(user, 'is_superuser', False):
            return True

        # Check direct ownership
        owner = getattr(resource, owner_field, None)
        if owner:
            owner_id = getattr(owner, 'id', owner)
            if owner_id == user.id:
                return True

        # Check tenant ownership
        if hasattr(resource, 'tenant_id') and hasattr(user, 'tenant_id'):
            if resource.tenant_id == user.tenant_id:
                # Additional role-based check within tenant
                if self._check_tenant_permission(user, resource):
                    return True

        # Check explicit permissions
        if permission_field:
            permissions = getattr(resource, permission_field, [])
            if user.id in permissions or user in permissions:
                return True

        return False

    def _check_tenant_permission(self, user, resource) -> bool:
        """Check tenant-level permissions for the resource."""
        # Check if user has appropriate role for this resource type
        user_role = getattr(user, 'role', None)
        if not user_role:
            return False

        # Admin and supervisor roles have broader access
        admin_roles = {'admin', 'pdg', 'supervisor', 'manager'}
        if user_role.lower() in admin_roles:
            return True

        return False

    def require_ownership(
        self,
        owner_field: str = 'owner',
        permission_field: str = None
    ) -> Callable:
        """
        Decorator to require resource ownership for view access.

        Args:
            owner_field: Field name containing the owner reference
            permission_field: Optional field containing permission list

        Returns:
            Decorator function
        """
        def decorator(view_func: Callable) -> Callable:
            @wraps(view_func)
            def wrapper(request, *args, **kwargs):
                # Get the resource from the view
                resource = kwargs.get('object') or kwargs.get('instance')

                if resource and not self.check_ownership(
                    request.user, resource, owner_field, permission_field
                ):
                    self._log_access_violation(request, resource)
                    raise PermissionDenied('You do not have permission to access this resource.')

                return view_func(request, *args, **kwargs)
            return wrapper
        return decorator

    def _log_access_violation(self, request: HttpRequest, resource: Any):
        """Log a resource access violation."""
        event = SecurityEvent(
            event_type=SecurityEventType.RESOURCE_ACCESS_VIOLATION,
            severity='medium',
            message=f'Unauthorized resource access attempt',
            user_id=str(getattr(request.user, 'id', None)),
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', ''),
            request_path=request.path,
            request_method=request.method,
            details={
                'resource_type': type(resource).__name__,
                'resource_id': str(getattr(resource, 'id', None)),
            }
        )
        self.logger.log(event)


# =============================================================================
# A02:2021 - Cryptographic Failures
# =============================================================================

class SecureStorageValidator:
    """
    Validates secure storage practices for sensitive data.

    Ensures sensitive data is properly encrypted at rest and in transit,
    following OWASP cryptographic guidelines.
    """

    # Fields that should always be encrypted
    SENSITIVE_FIELDS = {
        'password', 'secret', 'token', 'key', 'api_key', 'private_key',
        'credit_card', 'ssn', 'social_security', 'bank_account',
        'routing_number', 'cvv', 'pin', 'secret_answer', 'security_question',
    }

    # Minimum encryption standards
    MIN_KEY_SIZE = 256
    APPROVED_ALGORITHMS = {'AES-256-GCM', 'AES-256-CBC', 'ChaCha20-Poly1305'}

    def __init__(self):
        self.logger = SecurityEventLogger()

    def validate_field_encryption(
        self,
        model_class: type,
        field_name: str
    ) -> Tuple[bool, str]:
        """
        Validate that a sensitive field is properly encrypted.

        Args:
            model_class: The model class containing the field
            field_name: The name of the field to check

        Returns:
            Tuple of (is_valid, message)
        """
        field = getattr(model_class, field_name, None)
        if not field:
            return False, f"Field '{field_name}' not found on {model_class.__name__}"

        # Check if field uses encrypted field type
        field_type = type(field).__name__
        encrypted_types = {'EncryptedCharField', 'EncryptedTextField', 'EncryptedField'}

        if field_type not in encrypted_types:
            # Check if it's a sensitive field that should be encrypted
            if any(sensitive in field_name.lower() for sensitive in self.SENSITIVE_FIELDS):
                return False, f"Sensitive field '{field_name}' should use encrypted storage"

        return True, "Field storage validated"

    def validate_password_storage(self, password_hash: str) -> Tuple[bool, str]:
        """
        Validate that a password is stored using a secure hashing algorithm.

        Args:
            password_hash: The stored password hash

        Returns:
            Tuple of (is_valid, message)
        """
        # Check for known secure password hashers
        secure_prefixes = [
            'pbkdf2_sha256$',  # Django default
            'argon2$',         # Argon2 (recommended)
            'bcrypt$',         # bcrypt
            'scrypt$',         # scrypt
        ]

        # Insecure prefixes to reject
        insecure_prefixes = [
            'md5$',            # MD5 is broken
            'sha1$',           # SHA1 is weak
            'unsalted_md5',    # Unsalted MD5
            'unsalted_sha1',   # Unsalted SHA1
        ]

        for prefix in insecure_prefixes:
            if password_hash.startswith(prefix):
                self._log_weak_encryption('password', f'Insecure hash algorithm: {prefix}')
                return False, f"Insecure password hash algorithm detected: {prefix}"

        for prefix in secure_prefixes:
            if password_hash.startswith(prefix):
                return True, "Password storage validated"

        return False, "Unknown password hashing algorithm"

    def generate_secure_key(self, length: int = 32) -> bytes:
        """
        Generate a cryptographically secure random key.

        Args:
            length: Key length in bytes (default 32 for 256-bit)

        Returns:
            Secure random bytes
        """
        return secrets.token_bytes(length)

    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate a cryptographically secure URL-safe token.

        Args:
            length: Token length in bytes

        Returns:
            URL-safe token string
        """
        return secrets.token_urlsafe(length)

    def _log_weak_encryption(self, data_type: str, details: str):
        """Log a weak encryption detection."""
        event = SecurityEvent(
            event_type=SecurityEventType.WEAK_ENCRYPTION,
            severity='high',
            message=f'Weak encryption detected for {data_type}',
            details={'data_type': data_type, 'issue': details}
        )
        self.logger.log(event)


class TLSEnforcer:
    """
    Enforces TLS/SSL requirements for secure communications.

    Ensures all connections use modern TLS versions with secure cipher suites.
    """

    # Minimum acceptable TLS version
    MIN_TLS_VERSION = 'TLSv1.2'

    # Weak cipher suites to reject
    WEAK_CIPHERS = {
        'DES', '3DES', 'RC4', 'RC2', 'MD5', 'NULL', 'EXPORT', 'anon', 'ADH', 'AECDH'
    }

    def __init__(self):
        self.logger = SecurityEventLogger()

    def check_request_security(self, request: HttpRequest) -> Tuple[bool, str]:
        """
        Check if the request uses secure transport.

        Args:
            request: The HTTP request

        Returns:
            Tuple of (is_secure, message)
        """
        # Check if request is secure
        if not request.is_secure():
            # Allow non-secure in DEBUG mode
            if getattr(settings, 'DEBUG', False):
                return True, "Non-secure request allowed in DEBUG mode"

            # Log and reject
            self._log_tls_failure(request, 'Request not using HTTPS')
            return False, "HTTPS is required"

        return True, "Request security validated"

    def validate_external_connection(self, url: str) -> Tuple[bool, str]:
        """
        Validate that an external URL uses secure transport.

        Args:
            url: The URL to validate

        Returns:
            Tuple of (is_valid, message)
        """
        parsed = urllib.parse.urlparse(url)

        # Require HTTPS for external connections
        if parsed.scheme != 'https':
            return False, f"External connection must use HTTPS: {url}"

        return True, "URL security validated"

    def get_ssl_context(self):
        """
        Get a properly configured SSL context.

        Returns:
            Configured SSL context
        """
        import ssl

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Disable weak ciphers
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')

        # Enable certificate verification
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()

        return context

    def _log_tls_failure(self, request: HttpRequest, details: str):
        """Log a TLS security failure."""
        event = SecurityEvent(
            event_type=SecurityEventType.TLS_FAILURE,
            severity='medium',
            message='TLS security requirement not met',
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', ''),
            request_path=request.path,
            details={'issue': details}
        )
        self.logger.log(event)


# =============================================================================
# A03:2021 - Injection
# =============================================================================

class SQLInjectionPreventer:
    """
    Prevents SQL injection attacks through input validation and sanitization.

    Detects and blocks common SQL injection patterns in user input.
    """

    # Common SQL injection patterns
    INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE|CAST|CONVERT)\b)",
        r"(--|\#|\/\*|\*\/)",  # SQL comments
        r"(\bOR\b\s+\d+\s*=\s*\d+)",  # OR 1=1 style
        r"(\bAND\b\s+\d+\s*=\s*\d+)",  # AND 1=1 style
        r"(;\s*(SELECT|INSERT|UPDATE|DELETE|DROP))",  # Stacked queries
        r"(\bWAITFOR\b\s+\bDELAY\b)",  # Time-based blind injection
        r"(\bBENCHMARK\b\s*\()",  # MySQL benchmark
        r"(\bSLEEP\b\s*\()",  # MySQL sleep
        r"(\'|\"\s*(\bOR\b|\bAND\b))",  # Quote followed by OR/AND
        r"(\bLOAD_FILE\b|\bINTO\s+OUTFILE\b|\bINTO\s+DUMPFILE\b)",  # File operations
        r"(\bINFORMATION_SCHEMA\b)",  # Schema access
        r"(\bsys\.|sysobjects|syscolumns)",  # System table access
    ]

    def __init__(self):
        self.logger = SecurityEventLogger()
        self._compiled_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.INJECTION_PATTERNS
        ]

    def check_input(
        self,
        value: str,
        request: HttpRequest = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Check input for SQL injection patterns.

        Args:
            value: The input value to check
            request: Optional request for logging context

        Returns:
            Tuple of (is_safe, detected_pattern)
        """
        if not isinstance(value, str):
            return True, None

        for pattern in self._compiled_patterns:
            match = pattern.search(value)
            if match:
                self._log_injection_attempt(value, match.group(), request)
                return False, match.group()

        return True, None

    def sanitize_identifier(self, identifier: str) -> str:
        """
        Sanitize a database identifier (table/column name).

        Args:
            identifier: The identifier to sanitize

        Returns:
            Sanitized identifier safe for SQL
        """
        # Only allow alphanumeric and underscore
        sanitized = re.sub(r'[^a-zA-Z0-9_]', '', identifier)

        # Ensure it doesn't start with a number
        if sanitized and sanitized[0].isdigit():
            sanitized = '_' + sanitized

        return sanitized

    def check_parameters(
        self,
        params: Dict[str, Any],
        request: HttpRequest = None
    ) -> Tuple[bool, List[str]]:
        """
        Check all parameters for SQL injection patterns.

        Args:
            params: Dictionary of parameters to check
            request: Optional request for logging context

        Returns:
            Tuple of (all_safe, list of unsafe parameter names)
        """
        unsafe_params = []

        for key, value in params.items():
            if isinstance(value, str):
                is_safe, _ = self.check_input(value, request)
                if not is_safe:
                    unsafe_params.append(key)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    if isinstance(item, str):
                        is_safe, _ = self.check_input(item, request)
                        if not is_safe:
                            unsafe_params.append(key)
                            break

        return len(unsafe_params) == 0, unsafe_params

    def _log_injection_attempt(
        self,
        input_value: str,
        matched_pattern: str,
        request: HttpRequest = None
    ):
        """Log a SQL injection attempt."""
        event = SecurityEvent(
            event_type=SecurityEventType.SQL_INJECTION_ATTEMPT,
            severity='critical',
            message='SQL injection attempt detected',
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', '') if request else None,
            user_agent=request.META.get('HTTP_USER_AGENT', '') if request else None,
            request_path=request.path if request else None,
            request_method=request.method if request else None,
            details={
                'input_preview': input_value[:200] if len(input_value) > 200 else input_value,
                'matched_pattern': matched_pattern,
            }
        )
        self.logger.log(event)


class CommandInjectionPreventer:
    """
    Prevents OS command injection attacks.

    Validates and sanitizes input before use in system commands.
    """

    # Dangerous shell characters and commands
    DANGEROUS_PATTERNS = [
        r'[;&|`$]',  # Shell metacharacters
        r'\$\(',  # Command substitution
        r'\$\{',  # Variable expansion
        r'\|{2}',  # Logical OR
        r'&{2}',  # Logical AND
        r'>{1,2}',  # Redirections
        r'<',  # Input redirection
        r'\n|\r',  # Newlines
        r'\\',  # Backslashes
        r'\.{2,}/',  # Directory traversal
    ]

    DANGEROUS_COMMANDS = {
        'rm', 'del', 'format', 'mkfs', 'dd', 'wget', 'curl', 'nc', 'netcat',
        'bash', 'sh', 'cmd', 'powershell', 'python', 'perl', 'ruby', 'php',
        'chmod', 'chown', 'sudo', 'su', 'passwd', 'useradd', 'userdel',
        'kill', 'pkill', 'shutdown', 'reboot', 'init', 'systemctl', 'service',
    }

    def __init__(self):
        self.logger = SecurityEventLogger()
        self._compiled_patterns = [
            re.compile(pattern) for pattern in self.DANGEROUS_PATTERNS
        ]

    def check_input(
        self,
        value: str,
        request: HttpRequest = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Check input for command injection patterns.

        Args:
            value: The input value to check
            request: Optional request for logging context

        Returns:
            Tuple of (is_safe, reason if unsafe)
        """
        if not isinstance(value, str):
            return True, None

        # Check for dangerous patterns
        for pattern in self._compiled_patterns:
            if pattern.search(value):
                self._log_injection_attempt(value, 'dangerous_pattern', request)
                return False, 'Contains dangerous shell characters'

        # Check for dangerous commands
        value_lower = value.lower()
        for cmd in self.DANGEROUS_COMMANDS:
            if re.search(rf'\b{cmd}\b', value_lower):
                self._log_injection_attempt(value, f'dangerous_command:{cmd}', request)
                return False, f'Contains dangerous command: {cmd}'

        return True, None

    def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize a filename to prevent path traversal and injection.

        Args:
            filename: The filename to sanitize

        Returns:
            Sanitized filename
        """
        # Remove path components
        filename = os.path.basename(filename)

        # Remove null bytes
        filename = filename.replace('\x00', '')

        # Only allow safe characters
        filename = re.sub(r'[^a-zA-Z0-9_.\-]', '_', filename)

        # Prevent hidden files
        if filename.startswith('.'):
            filename = '_' + filename[1:]

        return filename

    def safe_execute(
        self,
        args: List[str],
        allowed_commands: Set[str] = None,
        timeout: int = 30
    ) -> Tuple[bool, str]:
        """
        Safely execute a command with validation.

        Args:
            args: Command arguments (first element is the command)
            allowed_commands: Set of allowed command names
            timeout: Command timeout in seconds

        Returns:
            Tuple of (success, output or error message)
        """
        if not args:
            return False, 'No command specified'

        command = args[0]

        # Validate against allowed commands
        if allowed_commands and command not in allowed_commands:
            return False, f'Command not allowed: {command}'

        # Validate all arguments
        for arg in args:
            is_safe, reason = self.check_input(arg)
            if not is_safe:
                return False, f'Unsafe argument: {reason}'

        try:
            # Execute with timeout and no shell
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False  # Never use shell=True
            )
            return True, result.stdout
        except subprocess.TimeoutExpired:
            return False, 'Command timed out'
        except Exception as e:
            return False, str(e)

    def _log_injection_attempt(
        self,
        input_value: str,
        reason: str,
        request: HttpRequest = None
    ):
        """Log a command injection attempt."""
        event = SecurityEvent(
            event_type=SecurityEventType.COMMAND_INJECTION_ATTEMPT,
            severity='critical',
            message='Command injection attempt detected',
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', '') if request else None,
            request_path=request.path if request else None,
            details={
                'input_preview': input_value[:100],
                'reason': reason,
            }
        )
        self.logger.log(event)


class LDAPInjectionPreventer:
    """
    Prevents LDAP injection attacks.

    Sanitizes input for safe use in LDAP queries.
    """

    # Characters that need escaping in LDAP
    LDAP_ESCAPE_CHARS = {
        '\\': r'\5c',
        '*': r'\2a',
        '(': r'\28',
        ')': r'\29',
        '\x00': r'\00',
        '/': r'\2f',
    }

    # Dangerous LDAP patterns
    INJECTION_PATTERNS = [
        r'\*\)',  # Wildcard closure
        r'\)\(',  # Filter chaining
        r'\|\(',  # OR injection
        r'&\(',  # AND injection
        r'!\(',  # NOT injection
        r'[\x00-\x1f]',  # Control characters
    ]

    def __init__(self):
        self.logger = SecurityEventLogger()
        self._compiled_patterns = [
            re.compile(pattern) for pattern in self.INJECTION_PATTERNS
        ]

    def escape_filter_value(self, value: str) -> str:
        """
        Escape a value for safe use in LDAP filter.

        Args:
            value: The value to escape

        Returns:
            Escaped value safe for LDAP filters
        """
        for char, escape in self.LDAP_ESCAPE_CHARS.items():
            value = value.replace(char, escape)
        return value

    def escape_dn_value(self, value: str) -> str:
        """
        Escape a value for safe use in LDAP DN.

        Args:
            value: The value to escape

        Returns:
            Escaped value safe for LDAP DN
        """
        dn_escape_chars = {
            '\\': r'\\',
            ',': r'\,',
            '+': r'\+',
            '"': r'\"',
            '<': r'\<',
            '>': r'\>',
            ';': r'\;',
            '=': r'\=',
        }

        for char, escape in dn_escape_chars.items():
            value = value.replace(char, escape)

        # Escape leading/trailing spaces
        if value.startswith(' '):
            value = '\\ ' + value[1:]
        if value.endswith(' '):
            value = value[:-1] + '\\ '

        # Escape leading #
        if value.startswith('#'):
            value = '\\#' + value[1:]

        return value

    def check_input(
        self,
        value: str,
        request: HttpRequest = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Check input for LDAP injection patterns.

        Args:
            value: The input value to check
            request: Optional request for logging context

        Returns:
            Tuple of (is_safe, reason if unsafe)
        """
        if not isinstance(value, str):
            return True, None

        for pattern in self._compiled_patterns:
            if pattern.search(value):
                self._log_injection_attempt(value, request)
                return False, 'Contains LDAP injection pattern'

        return True, None

    def _log_injection_attempt(self, input_value: str, request: HttpRequest = None):
        """Log an LDAP injection attempt."""
        event = SecurityEvent(
            event_type=SecurityEventType.LDAP_INJECTION_ATTEMPT,
            severity='high',
            message='LDAP injection attempt detected',
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', '') if request else None,
            request_path=request.path if request else None,
            details={
                'input_preview': input_value[:100],
            }
        )
        self.logger.log(event)


# =============================================================================
# A04:2021 - Insecure Design
# =============================================================================

class SecurityRequirementsValidator:
    """
    Validates security requirements are met in application design.

    Checks for proper security controls in business logic and workflows.
    """

    def __init__(self):
        self.logger = SecurityEventLogger()

    def validate_rate_limiting(self, view_name: str) -> Tuple[bool, str]:
        """
        Validate that a view has appropriate rate limiting.

        Args:
            view_name: The name of the view to check

        Returns:
            Tuple of (has_rate_limit, message)
        """
        # Check for django-ratelimit configuration
        ratelimit_enable = getattr(settings, 'RATELIMIT_ENABLE', False)

        if not ratelimit_enable:
            return False, 'Rate limiting not enabled'

        return True, 'Rate limiting configured'

    def validate_authentication_required(
        self,
        view_func: Callable,
        endpoint: str
    ) -> Tuple[bool, str]:
        """
        Validate that sensitive endpoints require authentication.

        Args:
            view_func: The view function to check
            endpoint: The endpoint path

        Returns:
            Tuple of (is_protected, message)
        """
        # Check for authentication decorators
        auth_decorators = {
            'login_required', 'permission_required', 'user_passes_test',
            'staff_member_required', 'admin_required'
        }

        # Check if view has authentication
        if hasattr(view_func, '__wrapped__'):
            wrapper_names = []
            current = view_func
            while hasattr(current, '__wrapped__'):
                wrapper_names.append(current.__name__)
                current = current.__wrapped__

            for decorator in auth_decorators:
                if decorator in str(wrapper_names):
                    return True, f'Protected by {decorator}'

        # Sensitive endpoint patterns that should always be protected
        sensitive_patterns = [
            r'/admin/', r'/api/', r'/dashboard/', r'/settings/',
            r'/profile/', r'/account/', r'/payment/', r'/billing/',
        ]

        for pattern in sensitive_patterns:
            if re.search(pattern, endpoint):
                return False, f'Sensitive endpoint {endpoint} may lack authentication'

        return True, 'Endpoint validation passed'

    def validate_input_validation(
        self,
        view_func: Callable
    ) -> Tuple[bool, List[str]]:
        """
        Check if a view properly validates input.

        Args:
            view_func: The view function to check

        Returns:
            Tuple of (has_validation, list of recommendations)
        """
        recommendations = []

        # Check for form usage
        source = ''
        try:
            import inspect
            source = inspect.getsource(view_func)
        except:
            pass

        if not source:
            return True, []

        # Check for direct request data access without validation
        if 'request.POST' in source or 'request.GET' in source:
            if 'is_valid()' not in source and 'clean' not in source:
                recommendations.append(
                    'Consider using Django forms for input validation'
                )

        # Check for raw SQL usage
        if 'raw(' in source or 'execute(' in source:
            recommendations.append(
                'Raw SQL detected - ensure parameterized queries are used'
            )

        return len(recommendations) == 0, recommendations


# =============================================================================
# A05:2021 - Security Misconfiguration
# =============================================================================

class ConfigurationAuditor:
    """
    Audits Django security configuration settings.

    Checks for common security misconfigurations.
    """

    def __init__(self):
        self.logger = SecurityEventLogger()
        self.issues: List[Dict[str, Any]] = []

    def audit_all(self) -> List[Dict[str, Any]]:
        """
        Run all configuration audits.

        Returns:
            List of configuration issues found
        """
        self.issues = []

        self._audit_debug_mode()
        self._audit_secret_key()
        self._audit_allowed_hosts()
        self._audit_ssl_settings()
        self._audit_session_settings()
        self._audit_csrf_settings()
        self._audit_security_middleware()
        self._audit_database_settings()
        self._audit_password_validators()
        self._audit_cors_settings()

        return self.issues

    def _audit_debug_mode(self):
        """Check DEBUG mode setting."""
        if getattr(settings, 'DEBUG', False):
            self.issues.append({
                'severity': 'critical',
                'setting': 'DEBUG',
                'message': 'DEBUG mode is enabled - must be False in production',
                'recommendation': 'Set DEBUG=False in production'
            })

    def _audit_secret_key(self):
        """Check SECRET_KEY configuration."""
        secret_key = getattr(settings, 'SECRET_KEY', '')

        # Check for default/weak secret key
        weak_keys = ['django-insecure-', 'change-me', 'secret', 'dev-key']
        for weak in weak_keys:
            if weak in secret_key.lower():
                self.issues.append({
                    'severity': 'critical',
                    'setting': 'SECRET_KEY',
                    'message': 'SECRET_KEY appears to be a default or weak value',
                    'recommendation': 'Generate a strong random SECRET_KEY'
                })
                break

        if len(secret_key) < 50:
            self.issues.append({
                'severity': 'high',
                'setting': 'SECRET_KEY',
                'message': f'SECRET_KEY is too short ({len(secret_key)} chars)',
                'recommendation': 'Use a SECRET_KEY of at least 50 characters'
            })

    def _audit_allowed_hosts(self):
        """Check ALLOWED_HOSTS configuration."""
        allowed_hosts = getattr(settings, 'ALLOWED_HOSTS', [])

        if '*' in allowed_hosts:
            self.issues.append({
                'severity': 'high',
                'setting': 'ALLOWED_HOSTS',
                'message': 'ALLOWED_HOSTS contains wildcard (*)',
                'recommendation': 'Specify explicit allowed hosts'
            })

        if not allowed_hosts or allowed_hosts == ['']:
            self.issues.append({
                'severity': 'medium',
                'setting': 'ALLOWED_HOSTS',
                'message': 'ALLOWED_HOSTS is empty',
                'recommendation': 'Configure ALLOWED_HOSTS with valid hostnames'
            })

    def _audit_ssl_settings(self):
        """Check SSL/TLS settings."""
        if not getattr(settings, 'DEBUG', True):
            if not getattr(settings, 'SECURE_SSL_REDIRECT', False):
                self.issues.append({
                    'severity': 'high',
                    'setting': 'SECURE_SSL_REDIRECT',
                    'message': 'SSL redirect not enabled',
                    'recommendation': 'Set SECURE_SSL_REDIRECT=True'
                })

            if not getattr(settings, 'SECURE_HSTS_SECONDS', 0):
                self.issues.append({
                    'severity': 'medium',
                    'setting': 'SECURE_HSTS_SECONDS',
                    'message': 'HSTS not configured',
                    'recommendation': 'Set SECURE_HSTS_SECONDS to at least 31536000'
                })

    def _audit_session_settings(self):
        """Check session security settings."""
        if not getattr(settings, 'SESSION_COOKIE_SECURE', False):
            if not getattr(settings, 'DEBUG', True):
                self.issues.append({
                    'severity': 'high',
                    'setting': 'SESSION_COOKIE_SECURE',
                    'message': 'Session cookie not marked as secure',
                    'recommendation': 'Set SESSION_COOKIE_SECURE=True'
                })

        if not getattr(settings, 'SESSION_COOKIE_HTTPONLY', True):
            self.issues.append({
                'severity': 'high',
                'setting': 'SESSION_COOKIE_HTTPONLY',
                'message': 'Session cookie accessible via JavaScript',
                'recommendation': 'Set SESSION_COOKIE_HTTPONLY=True'
            })

        session_age = getattr(settings, 'SESSION_COOKIE_AGE', 1209600)
        if session_age > 86400 * 30:  # More than 30 days
            self.issues.append({
                'severity': 'low',
                'setting': 'SESSION_COOKIE_AGE',
                'message': f'Session lifetime is very long ({session_age} seconds)',
                'recommendation': 'Consider reducing session lifetime'
            })

    def _audit_csrf_settings(self):
        """Check CSRF protection settings."""
        if not getattr(settings, 'CSRF_COOKIE_SECURE', False):
            if not getattr(settings, 'DEBUG', True):
                self.issues.append({
                    'severity': 'high',
                    'setting': 'CSRF_COOKIE_SECURE',
                    'message': 'CSRF cookie not marked as secure',
                    'recommendation': 'Set CSRF_COOKIE_SECURE=True'
                })

        if not getattr(settings, 'CSRF_COOKIE_HTTPONLY', False):
            self.issues.append({
                'severity': 'medium',
                'setting': 'CSRF_COOKIE_HTTPONLY',
                'message': 'CSRF cookie accessible via JavaScript',
                'recommendation': 'Set CSRF_COOKIE_HTTPONLY=True'
            })

    def _audit_security_middleware(self):
        """Check security middleware configuration."""
        middleware = getattr(settings, 'MIDDLEWARE', [])

        required_middleware = {
            'django.middleware.security.SecurityMiddleware': 'Security middleware',
            'django.middleware.csrf.CsrfViewMiddleware': 'CSRF middleware',
            'django.middleware.clickjacking.XFrameOptionsMiddleware': 'Clickjacking protection',
        }

        for mw, name in required_middleware.items():
            if mw not in middleware:
                self.issues.append({
                    'severity': 'high',
                    'setting': 'MIDDLEWARE',
                    'message': f'{name} not found in MIDDLEWARE',
                    'recommendation': f'Add {mw} to MIDDLEWARE'
                })

    def _audit_database_settings(self):
        """Check database security settings."""
        databases = getattr(settings, 'DATABASES', {})

        for db_name, db_config in databases.items():
            # Check for default passwords
            password = db_config.get('PASSWORD', '')
            if password in ['', 'password', 'postgres', 'admin', 'root']:
                self.issues.append({
                    'severity': 'critical',
                    'setting': f'DATABASES.{db_name}.PASSWORD',
                    'message': f'Database {db_name} has weak or default password',
                    'recommendation': 'Use a strong, unique database password'
                })

            # Check for SSL
            options = db_config.get('OPTIONS', {})
            if not options.get('sslmode') and db_name != 'default':
                self.issues.append({
                    'severity': 'medium',
                    'setting': f'DATABASES.{db_name}.OPTIONS',
                    'message': f'Database {db_name} SSL not explicitly configured',
                    'recommendation': 'Configure sslmode in database OPTIONS'
                })

    def _audit_password_validators(self):
        """Check password validation settings."""
        validators = getattr(settings, 'AUTH_PASSWORD_VALIDATORS', [])

        required_validators = [
            'UserAttributeSimilarityValidator',
            'MinimumLengthValidator',
            'CommonPasswordValidator',
            'NumericPasswordValidator',
        ]

        validator_names = [v.get('NAME', '').split('.')[-1] for v in validators]

        for required in required_validators:
            if required not in validator_names:
                self.issues.append({
                    'severity': 'medium',
                    'setting': 'AUTH_PASSWORD_VALIDATORS',
                    'message': f'Missing password validator: {required}',
                    'recommendation': f'Add {required} to AUTH_PASSWORD_VALIDATORS'
                })

    def _audit_cors_settings(self):
        """Check CORS configuration."""
        cors_allow_all = getattr(settings, 'CORS_ALLOW_ALL_ORIGINS', False)
        cors_allow_credentials = getattr(settings, 'CORS_ALLOW_CREDENTIALS', False)

        if cors_allow_all:
            self.issues.append({
                'severity': 'high',
                'setting': 'CORS_ALLOW_ALL_ORIGINS',
                'message': 'CORS allows all origins',
                'recommendation': 'Specify explicit allowed origins'
            })

        if cors_allow_all and cors_allow_credentials:
            self.issues.append({
                'severity': 'critical',
                'setting': 'CORS',
                'message': 'CORS allows all origins with credentials',
                'recommendation': 'Never allow all origins with credentials'
            })


# =============================================================================
# A06:2021 - Vulnerable and Outdated Components
# =============================================================================

class DependencyChecker:
    """
    Checks for vulnerable and outdated dependencies.

    Analyzes requirements.txt for known security issues.
    """

    # Known vulnerable versions (sample data - in production, use safety DB)
    KNOWN_VULNERABILITIES = {
        'django': [
            {'version_below': '3.2.20', 'cve': 'CVE-2023-36053', 'severity': 'high'},
            {'version_below': '4.2.5', 'cve': 'CVE-2023-41164', 'severity': 'medium'},
        ],
        'pillow': [
            {'version_below': '10.0.1', 'cve': 'CVE-2023-44271', 'severity': 'high'},
        ],
        'requests': [
            {'version_below': '2.31.0', 'cve': 'CVE-2023-32681', 'severity': 'medium'},
        ],
        'cryptography': [
            {'version_below': '41.0.4', 'cve': 'CVE-2023-38325', 'severity': 'high'},
        ],
        'urllib3': [
            {'version_below': '2.0.6', 'cve': 'CVE-2023-43804', 'severity': 'high'},
        ],
    }

    # Packages that should always be updated
    SECURITY_PACKAGES = {
        'django', 'djangorestframework', 'cryptography', 'pyopenssl',
        'requests', 'urllib3', 'pillow', 'pyjwt', 'python-jose',
    }

    def __init__(self, requirements_path: str = None):
        self.requirements_path = requirements_path or os.path.join(
            settings.BASE_DIR, 'requirements.txt'
        )
        self.logger = SecurityEventLogger()

    def check_requirements(self) -> List[Dict[str, Any]]:
        """
        Check requirements.txt for vulnerable packages.

        Returns:
            List of vulnerability findings
        """
        findings = []

        try:
            with open(self.requirements_path, 'r') as f:
                requirements = f.read()
        except FileNotFoundError:
            return [{
                'severity': 'info',
                'package': 'requirements.txt',
                'message': 'Requirements file not found',
            }]

        # Parse requirements
        for line in requirements.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Parse package name and version
            package_info = self._parse_requirement(line)
            if not package_info:
                continue

            package_name, version = package_info

            # Check against known vulnerabilities
            vulns = self._check_vulnerabilities(package_name.lower(), version)
            findings.extend(vulns)

        return findings

    def _parse_requirement(self, line: str) -> Optional[Tuple[str, Optional[str]]]:
        """
        Parse a requirement line.

        Args:
            line: A line from requirements.txt

        Returns:
            Tuple of (package_name, version) or None
        """
        # Remove comments
        line = line.split('#')[0].strip()

        # Handle various formats
        match = re.match(r'^([a-zA-Z0-9_-]+)\s*([<>=!]+)\s*([0-9.]+)', line)
        if match:
            return match.group(1), match.group(3)

        match = re.match(r'^([a-zA-Z0-9_-]+)', line)
        if match:
            return match.group(1), None

        return None

    def _check_vulnerabilities(
        self,
        package: str,
        version: Optional[str]
    ) -> List[Dict[str, Any]]:
        """
        Check a package against known vulnerabilities.

        Args:
            package: Package name
            version: Package version

        Returns:
            List of vulnerabilities found
        """
        findings = []

        if package not in self.KNOWN_VULNERABILITIES:
            return findings

        if not version:
            findings.append({
                'severity': 'medium',
                'package': package,
                'message': f'Package {package} has no pinned version',
                'recommendation': 'Pin to a specific secure version',
            })
            return findings

        for vuln in self.KNOWN_VULNERABILITIES[package]:
            if self._version_below(version, vuln['version_below']):
                findings.append({
                    'severity': vuln['severity'],
                    'package': package,
                    'version': version,
                    'cve': vuln['cve'],
                    'message': f"{package}=={version} is vulnerable to {vuln['cve']}",
                    'recommendation': f"Upgrade to at least {vuln['version_below']}",
                })

                # Log the vulnerability
                self._log_vulnerability(package, version, vuln)

        return findings

    def _version_below(self, version: str, target: str) -> bool:
        """
        Check if version is below target.

        Args:
            version: Current version
            target: Target version to compare against

        Returns:
            True if version < target
        """
        try:
            from packaging.version import Version
            return Version(version) < Version(target)
        except:
            # Simple comparison fallback
            return version < target

    def _log_vulnerability(
        self,
        package: str,
        version: str,
        vuln: Dict[str, Any]
    ):
        """Log a detected vulnerability."""
        event = SecurityEvent(
            event_type=SecurityEventType.VULNERABLE_COMPONENT,
            severity=vuln['severity'],
            message=f"Vulnerable package detected: {package}=={version}",
            details={
                'package': package,
                'version': version,
                'cve': vuln['cve'],
                'vulnerable_below': vuln['version_below'],
            }
        )
        self.logger.log(event)


# =============================================================================
# A07:2021 - Identification and Authentication Failures
# =============================================================================

class LoginAttemptTracker:
    """
    Tracks login attempts for security monitoring and brute force prevention.

    Records successful and failed login attempts with contextual information.
    """

    CACHE_PREFIX = 'login_attempt:'
    ATTEMPT_WINDOW = 3600  # 1 hour window for tracking

    def __init__(self):
        self.logger = SecurityEventLogger()

    def record_attempt(
        self,
        username: str,
        ip_address: str,
        success: bool,
        user_agent: str = '',
        tenant_id: str = None
    ):
        """
        Record a login attempt.

        Args:
            username: The username attempted
            ip_address: Client IP address
            success: Whether the attempt was successful
            user_agent: Client user agent
            tenant_id: Tenant identifier if applicable
        """
        attempt = {
            'username': username,
            'ip_address': ip_address,
            'success': success,
            'user_agent': user_agent,
            'tenant_id': tenant_id,
            'timestamp': timezone.now().isoformat(),
        }

        # Store in cache for rate limiting
        cache_key = f"{self.CACHE_PREFIX}{ip_address}:{username}"
        attempts = cache.get(cache_key, [])
        attempts.append(attempt)
        cache.set(cache_key, attempts, self.ATTEMPT_WINDOW)

        # Log the event
        event_type = SecurityEventType.LOGIN_SUCCESS if success else SecurityEventType.LOGIN_FAILURE
        event = SecurityEvent(
            event_type=event_type,
            severity='info' if success else 'medium',
            message=f"Login {'successful' if success else 'failed'} for {username}",
            tenant_id=tenant_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={'username': username}
        )
        self.logger.log(event)

    def get_attempt_count(
        self,
        ip_address: str = None,
        username: str = None,
        window_minutes: int = 60
    ) -> int:
        """
        Get the number of failed attempts within a time window.

        Args:
            ip_address: Filter by IP address
            username: Filter by username
            window_minutes: Time window in minutes

        Returns:
            Number of failed attempts
        """
        cache_key = f"{self.CACHE_PREFIX}{ip_address or '*'}:{username or '*'}"
        attempts = cache.get(cache_key, [])

        # Filter by time window
        cutoff = timezone.now() - timedelta(minutes=window_minutes)
        recent_attempts = [
            a for a in attempts
            if not a['success'] and
            datetime.fromisoformat(a['timestamp'].replace('Z', '+00:00')) > cutoff
        ]

        return len(recent_attempts)

    def is_suspicious(
        self,
        ip_address: str,
        username: str = None,
        threshold: int = 5
    ) -> Tuple[bool, str]:
        """
        Check if login activity is suspicious.

        Args:
            ip_address: Client IP address
            username: Username being attempted
            threshold: Number of failures to consider suspicious

        Returns:
            Tuple of (is_suspicious, reason)
        """
        # Check IP-based attempts
        ip_attempts = self.get_attempt_count(ip_address=ip_address)
        if ip_attempts >= threshold:
            return True, f'Multiple failed attempts from IP ({ip_attempts})'

        # Check username-based attempts
        if username:
            user_attempts = self.get_attempt_count(username=username)
            if user_attempts >= threshold:
                return True, f'Multiple failed attempts for user ({user_attempts})'

        return False, ''


class AccountLockoutManager:
    """
    Manages account lockouts for brute force protection.

    Implements progressive lockouts with increasing durations.
    """

    LOCKOUT_CACHE_PREFIX = 'account_lockout:'
    LOCKOUT_COUNT_PREFIX = 'lockout_count:'

    # Progressive lockout durations (in seconds)
    LOCKOUT_DURATIONS = [
        300,     # 5 minutes
        900,     # 15 minutes
        3600,    # 1 hour
        86400,   # 24 hours
        604800,  # 7 days
    ]

    DEFAULT_THRESHOLD = 5

    def __init__(self):
        self.logger = SecurityEventLogger()
        self.threshold = getattr(settings, 'AUTH_FAIL_LIMIT', self.DEFAULT_THRESHOLD)

    def check_lockout(
        self,
        identifier: str,
        identifier_type: str = 'username'
    ) -> Tuple[bool, Optional[datetime]]:
        """
        Check if an identifier is locked out.

        Args:
            identifier: The identifier to check (username, IP, etc.)
            identifier_type: Type of identifier

        Returns:
            Tuple of (is_locked, lockout_expires)
        """
        cache_key = f"{self.LOCKOUT_CACHE_PREFIX}{identifier_type}:{identifier}"
        lockout_data = cache.get(cache_key)

        if lockout_data:
            expires = datetime.fromisoformat(lockout_data['expires'])
            if timezone.now() < expires:
                return True, expires
            # Lockout expired, clear it
            cache.delete(cache_key)

        return False, None

    def record_failure(
        self,
        identifier: str,
        identifier_type: str = 'username',
        ip_address: str = None,
        tenant_id: str = None
    ) -> Tuple[bool, int]:
        """
        Record a failed authentication attempt.

        Args:
            identifier: The identifier that failed
            identifier_type: Type of identifier
            ip_address: Client IP address
            tenant_id: Tenant identifier

        Returns:
            Tuple of (is_now_locked, failure_count)
        """
        count_key = f"{self.LOCKOUT_COUNT_PREFIX}{identifier_type}:{identifier}"
        failure_count = cache.get(count_key, 0) + 1
        cache.set(count_key, failure_count, 86400)  # Track for 24 hours

        if failure_count >= self.threshold:
            self._apply_lockout(identifier, identifier_type, failure_count, ip_address, tenant_id)
            return True, failure_count

        return False, failure_count

    def clear_failures(self, identifier: str, identifier_type: str = 'username'):
        """
        Clear failure count after successful authentication.

        Args:
            identifier: The identifier to clear
            identifier_type: Type of identifier
        """
        count_key = f"{self.LOCKOUT_COUNT_PREFIX}{identifier_type}:{identifier}"
        cache.delete(count_key)

    def _apply_lockout(
        self,
        identifier: str,
        identifier_type: str,
        failure_count: int,
        ip_address: str = None,
        tenant_id: str = None
    ):
        """Apply a lockout to an identifier."""
        # Determine lockout duration based on history
        lockout_index = min(
            (failure_count - self.threshold) // self.threshold,
            len(self.LOCKOUT_DURATIONS) - 1
        )
        duration = self.LOCKOUT_DURATIONS[lockout_index]

        expires = timezone.now() + timedelta(seconds=duration)

        cache_key = f"{self.LOCKOUT_CACHE_PREFIX}{identifier_type}:{identifier}"
        cache.set(
            cache_key,
            {'expires': expires.isoformat(), 'failure_count': failure_count},
            duration
        )

        # Log the lockout
        event = SecurityEvent(
            event_type=SecurityEventType.ACCOUNT_LOCKED,
            severity='high',
            message=f'Account locked: {identifier_type}={identifier}',
            tenant_id=tenant_id,
            ip_address=ip_address,
            details={
                'identifier': identifier,
                'identifier_type': identifier_type,
                'failure_count': failure_count,
                'duration_seconds': duration,
                'expires': expires.isoformat(),
            }
        )
        self.logger.log(event)

    def unlock(self, identifier: str, identifier_type: str = 'username'):
        """
        Manually unlock an identifier.

        Args:
            identifier: The identifier to unlock
            identifier_type: Type of identifier
        """
        cache_key = f"{self.LOCKOUT_CACHE_PREFIX}{identifier_type}:{identifier}"
        cache.delete(cache_key)

        count_key = f"{self.LOCKOUT_COUNT_PREFIX}{identifier_type}:{identifier}"
        cache.delete(count_key)


class PasswordPolicyEnforcer:
    """
    Enforces strong password policies.

    Implements NIST 800-63B compliant password requirements.
    """

    # Default policy settings
    DEFAULT_MIN_LENGTH = 12
    DEFAULT_MAX_LENGTH = 128

    # Common passwords to block (sample - use full list in production)
    COMMON_PASSWORDS = {
        'password', 'password123', '123456', '123456789', 'qwerty',
        'abc123', 'monkey', 'master', 'dragon', 'letmein', 'login',
        'admin', 'welcome', 'football', 'iloveyou', 'trustno1',
    }

    def __init__(self):
        self.min_length = getattr(settings, 'PASSWORD_MIN_LENGTH', self.DEFAULT_MIN_LENGTH)
        self.max_length = getattr(settings, 'PASSWORD_MAX_LENGTH', self.DEFAULT_MAX_LENGTH)
        self.require_special = getattr(settings, 'PASSWORD_REQUIRE_SPECIAL', True)
        self.require_numbers = getattr(settings, 'PASSWORD_REQUIRE_NUMBERS', True)
        self.require_uppercase = getattr(settings, 'PASSWORD_REQUIRE_UPPERCASE', True)
        self.require_lowercase = getattr(settings, 'PASSWORD_REQUIRE_LOWERCASE', True)

    def validate(
        self,
        password: str,
        user=None,
        context: Dict[str, str] = None
    ) -> Tuple[bool, List[str]]:
        """
        Validate a password against the policy.

        Args:
            password: The password to validate
            user: Optional user object for context
            context: Additional context (email, username, etc.)

        Returns:
            Tuple of (is_valid, list of violations)
        """
        violations = []

        # Length checks
        if len(password) < self.min_length:
            violations.append(f'Password must be at least {self.min_length} characters')

        if len(password) > self.max_length:
            violations.append(f'Password cannot exceed {self.max_length} characters')

        # Complexity checks
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            violations.append('Password must contain at least one uppercase letter')

        if self.require_lowercase and not re.search(r'[a-z]', password):
            violations.append('Password must contain at least one lowercase letter')

        if self.require_numbers and not re.search(r'\d', password):
            violations.append('Password must contain at least one number')

        if self.require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            violations.append('Password must contain at least one special character')

        # Common password check
        if password.lower() in self.COMMON_PASSWORDS:
            violations.append('This password is too common')

        # Context-based checks
        if context:
            context_violations = self._check_context(password, context)
            violations.extend(context_violations)

        if user:
            user_violations = self._check_user_context(password, user)
            violations.extend(user_violations)

        return len(violations) == 0, violations

    def _check_context(
        self,
        password: str,
        context: Dict[str, str]
    ) -> List[str]:
        """Check password against contextual information."""
        violations = []
        password_lower = password.lower()

        for key, value in context.items():
            if value and len(value) >= 3:
                if value.lower() in password_lower:
                    violations.append(f'Password cannot contain your {key}')

        return violations

    def _check_user_context(self, password: str, user) -> List[str]:
        """Check password against user information."""
        violations = []
        password_lower = password.lower()

        # Check against user attributes
        user_attrs = ['username', 'email', 'first_name', 'last_name']
        for attr in user_attrs:
            value = getattr(user, attr, '')
            if value and len(value) >= 3:
                if value.lower() in password_lower:
                    violations.append(f'Password cannot contain your {attr.replace("_", " ")}')

        return violations

    def get_strength(self, password: str) -> Dict[str, Any]:
        """
        Calculate password strength score.

        Args:
            password: The password to evaluate

        Returns:
            Dictionary with strength score and details
        """
        score = 0
        details = []

        # Length scoring
        if len(password) >= 8:
            score += 1
            details.append('Minimum length met')
        if len(password) >= 12:
            score += 1
            details.append('Good length')
        if len(password) >= 16:
            score += 1
            details.append('Excellent length')

        # Complexity scoring
        if re.search(r'[a-z]', password):
            score += 1
            details.append('Has lowercase')
        if re.search(r'[A-Z]', password):
            score += 1
            details.append('Has uppercase')
        if re.search(r'\d', password):
            score += 1
            details.append('Has numbers')
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
            details.append('Has special characters')

        # Calculate strength label
        strength = 'weak'
        if score >= 3:
            strength = 'fair'
        if score >= 5:
            strength = 'good'
        if score >= 7:
            strength = 'strong'

        return {
            'score': score,
            'max_score': 7,
            'strength': strength,
            'details': details,
        }


# =============================================================================
# A08:2021 - Software and Data Integrity Failures
# =============================================================================

class IntegrityValidator:
    """
    Validates data integrity to prevent tampering.

    Implements HMAC-based integrity checking for sensitive data.
    """

    def __init__(self, secret_key: str = None):
        self.secret_key = (secret_key or getattr(settings, 'SECRET_KEY', '')).encode()
        self.logger = SecurityEventLogger()

    def sign(self, data: Union[str, bytes, dict]) -> str:
        """
        Create an HMAC signature for data.

        Args:
            data: Data to sign

        Returns:
            Base64-encoded signature
        """
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)
        if isinstance(data, str):
            data = data.encode()

        signature = hmac.new(
            self.secret_key,
            data,
            hashlib.sha256
        ).hexdigest()

        return signature

    def verify(
        self,
        data: Union[str, bytes, dict],
        signature: str,
        request: HttpRequest = None
    ) -> bool:
        """
        Verify an HMAC signature.

        Args:
            data: Original data
            signature: Signature to verify
            request: Optional request for logging

        Returns:
            True if signature is valid
        """
        expected = self.sign(data)

        if not constant_time_compare(expected, signature):
            self._log_tampering(data, request)
            return False

        return True

    def create_signed_data(self, data: dict) -> dict:
        """
        Create a signed data payload.

        Args:
            data: Data to sign

        Returns:
            Data with signature added
        """
        signature = self.sign(data)
        return {
            **data,
            '_signature': signature,
            '_timestamp': timezone.now().isoformat(),
        }

    def verify_signed_data(
        self,
        signed_data: dict,
        max_age_seconds: int = None,
        request: HttpRequest = None
    ) -> Tuple[bool, Optional[dict]]:
        """
        Verify and extract signed data.

        Args:
            signed_data: Signed data payload
            max_age_seconds: Maximum age of signature
            request: Optional request for logging

        Returns:
            Tuple of (is_valid, original_data)
        """
        if '_signature' not in signed_data:
            return False, None

        signature = signed_data.pop('_signature')
        timestamp = signed_data.pop('_timestamp', None)

        # Check age if required
        if max_age_seconds and timestamp:
            try:
                created = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                age = (timezone.now() - created).total_seconds()
                if age > max_age_seconds:
                    return False, None
            except:
                return False, None

        # Verify signature
        if not self.verify(signed_data, signature, request):
            return False, None

        return True, signed_data

    def _log_tampering(self, data: Any, request: HttpRequest = None):
        """Log a data tampering attempt."""
        event = SecurityEvent(
            event_type=SecurityEventType.DATA_TAMPERING,
            severity='high',
            message='Data integrity violation detected',
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', '') if request else None,
            request_path=request.path if request else None,
            details={
                'data_type': type(data).__name__,
            }
        )
        self.logger.log(event)


class CSRFEnhancer:
    """
    Enhanced CSRF protection beyond Django defaults.

    Implements additional CSRF countermeasures for sensitive operations.
    """

    def __init__(self):
        self.logger = SecurityEventLogger()

    def generate_action_token(
        self,
        action: str,
        user_id: str,
        expires_minutes: int = 30
    ) -> str:
        """
        Generate a single-use action token for sensitive operations.

        Args:
            action: The action this token authorizes
            user_id: The user ID this token is for
            expires_minutes: Token validity duration

        Returns:
            Action token
        """
        payload = {
            'action': action,
            'user_id': user_id,
            'nonce': secrets.token_hex(16),
            'expires': (timezone.now() + timedelta(minutes=expires_minutes)).isoformat(),
        }

        token = self._encode_token(payload)

        # Store nonce to prevent reuse
        cache_key = f"csrf_action_token:{payload['nonce']}"
        cache.set(cache_key, True, expires_minutes * 60)

        return token

    def verify_action_token(
        self,
        token: str,
        action: str,
        user_id: str,
        request: HttpRequest = None
    ) -> Tuple[bool, str]:
        """
        Verify an action token.

        Args:
            token: The token to verify
            action: Expected action
            user_id: Expected user ID
            request: Optional request for logging

        Returns:
            Tuple of (is_valid, error_message)
        """
        payload = self._decode_token(token)
        if not payload:
            return False, 'Invalid token format'

        # Check action
        if payload.get('action') != action:
            self._log_csrf_violation('action_mismatch', request)
            return False, 'Token action mismatch'

        # Check user
        if payload.get('user_id') != user_id:
            self._log_csrf_violation('user_mismatch', request)
            return False, 'Token user mismatch'

        # Check expiry
        try:
            expires = datetime.fromisoformat(payload['expires'].replace('Z', '+00:00'))
            if timezone.now() > expires:
                return False, 'Token expired'
        except:
            return False, 'Invalid token expiry'

        # Check nonce (single use)
        nonce = payload.get('nonce')
        cache_key = f"csrf_action_token:{nonce}"
        if not cache.get(cache_key):
            self._log_csrf_violation('token_reuse', request)
            return False, 'Token already used or expired'

        # Invalidate nonce
        cache.delete(cache_key)

        return True, ''

    def _encode_token(self, payload: dict) -> str:
        """Encode a token payload."""
        import base64
        data = json.dumps(payload)
        return base64.urlsafe_b64encode(data.encode()).decode()

    def _decode_token(self, token: str) -> Optional[dict]:
        """Decode a token payload."""
        import base64
        try:
            data = base64.urlsafe_b64decode(token.encode())
            return json.loads(data)
        except:
            return None

    def _log_csrf_violation(self, reason: str, request: HttpRequest = None):
        """Log a CSRF violation."""
        event = SecurityEvent(
            event_type=SecurityEventType.CSRF_VIOLATION,
            severity='high',
            message=f'CSRF violation: {reason}',
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', '') if request else None,
            request_path=request.path if request else None,
            details={'reason': reason}
        )
        self.logger.log(event)


# =============================================================================
# A09:2021 - Security Logging and Monitoring Failures
# =============================================================================

class SecurityEventLogger:
    """
    Centralized security event logging service.

    Provides structured logging for all security events with support
    for multiple output destinations.
    """

    def __init__(self):
        self.logger = logging.getLogger('security.events')
        self.audit_logger = logging.getLogger('security.audit')

    def log(self, event: SecurityEvent):
        """
        Log a security event.

        Args:
            event: The security event to log
        """
        # Determine log level
        level_map = {
            'critical': logging.CRITICAL,
            'high': logging.ERROR,
            'medium': logging.WARNING,
            'low': logging.INFO,
            'info': logging.INFO,
        }
        level = level_map.get(event.severity, logging.INFO)

        # Create log record
        log_data = event.to_dict()

        # Log to security logger
        self.logger.log(level, event.message, extra={'security_event': log_data})

        # Log to audit logger for compliance
        self.audit_logger.info(
            json.dumps(log_data),
            extra={'event_type': event.event_type.value}
        )

        # Store in database for tenant-scoped audit
        self._store_event(event)

        # Trigger alerts for high-severity events
        if event.severity in ('critical', 'high'):
            self._trigger_alert(event)

    def _store_event(self, event: SecurityEvent):
        """Store event in database for audit trail."""
        try:
            # Import here to avoid circular imports
            from security.models import SecurityEvent as SecurityEventModel

            SecurityEventModel.objects.create(
                event_type=event.event_type.value,
                description=event.message,
                ip_address=event.ip_address,
                user_agent=event.user_agent,
                # Additional fields as needed
            )
        except Exception as e:
            # Don't fail logging if DB storage fails
            self.logger.error(f'Failed to store security event: {e}')

    def _trigger_alert(self, event: SecurityEvent):
        """Trigger alert for high-severity events."""
        try:
            AlertingService().send_alert(event)
        except Exception as e:
            self.logger.error(f'Failed to send security alert: {e}')


class AlertingService:
    """
    Security alerting service for critical events.

    Supports multiple notification channels: email, webhook, Slack, etc.
    """

    def __init__(self):
        self.logger = logging.getLogger('security.alerts')
        self.enabled = getattr(settings, 'SECURITY_ALERTS_ENABLED', True)
        self.email_recipients = getattr(settings, 'ADMIN_EMAIL_LIST', [])
        self.webhook_url = getattr(settings, 'SECURITY_ALERT_WEBHOOK', None)
        self.slack_webhook = getattr(settings, 'SLACK_SECURITY_WEBHOOK', None)

    def send_alert(self, event: SecurityEvent):
        """
        Send security alert through configured channels.

        Args:
            event: The security event to alert on
        """
        if not self.enabled:
            return

        alert_data = self._format_alert(event)

        # Send to all configured channels
        if self.email_recipients:
            self._send_email_alert(alert_data)

        if self.webhook_url:
            self._send_webhook_alert(alert_data)

        if self.slack_webhook:
            self._send_slack_alert(alert_data)

    def _format_alert(self, event: SecurityEvent) -> dict:
        """Format event for alerting."""
        return {
            'title': f'Security Alert: {event.event_type.value}',
            'severity': event.severity.upper(),
            'message': event.message,
            'timestamp': event.timestamp.isoformat(),
            'details': {
                'ip_address': event.ip_address,
                'user_id': event.user_id,
                'tenant_id': event.tenant_id,
                'request_path': event.request_path,
                **event.details,
            }
        }

    def _send_email_alert(self, alert_data: dict):
        """Send alert via email."""
        try:
            from django.core.mail import send_mail

            subject = f"[SECURITY] {alert_data['title']}"
            body = f"""
Security Alert

Severity: {alert_data['severity']}
Time: {alert_data['timestamp']}

{alert_data['message']}

Details:
{json.dumps(alert_data['details'], indent=2)}
"""
            send_mail(
                subject,
                body,
                getattr(settings, 'DEFAULT_FROM_EMAIL', 'security@zumodra.com'),
                self.email_recipients,
                fail_silently=True,
            )
        except Exception as e:
            self.logger.error(f'Failed to send email alert: {e}')

    def _send_webhook_alert(self, alert_data: dict):
        """Send alert via webhook."""
        try:
            import requests
            requests.post(
                self.webhook_url,
                json=alert_data,
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )
        except Exception as e:
            self.logger.error(f'Failed to send webhook alert: {e}')

    def _send_slack_alert(self, alert_data: dict):
        """Send alert to Slack."""
        try:
            import requests

            severity_emoji = {
                'CRITICAL': ':rotating_light:',
                'HIGH': ':warning:',
                'MEDIUM': ':large_yellow_circle:',
                'LOW': ':information_source:',
            }

            emoji = severity_emoji.get(alert_data['severity'], ':grey_question:')

            slack_message = {
                'text': f"{emoji} {alert_data['title']}",
                'attachments': [{
                    'color': '#ff0000' if alert_data['severity'] == 'CRITICAL' else '#ffcc00',
                    'fields': [
                        {'title': 'Severity', 'value': alert_data['severity'], 'short': True},
                        {'title': 'Time', 'value': alert_data['timestamp'], 'short': True},
                        {'title': 'Message', 'value': alert_data['message']},
                    ]
                }]
            }

            requests.post(
                self.slack_webhook,
                json=slack_message,
                timeout=10,
            )
        except Exception as e:
            self.logger.error(f'Failed to send Slack alert: {e}')


# =============================================================================
# A10:2021 - Server-Side Request Forgery (SSRF)
# =============================================================================

class SSRFProtector:
    """
    Protects against Server-Side Request Forgery attacks.

    Validates and restricts outbound requests to prevent SSRF.
    """

    # Private IP ranges to block
    PRIVATE_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),  # Link-local
        ipaddress.ip_network('::1/128'),  # IPv6 loopback
        ipaddress.ip_network('fc00::/7'),  # IPv6 private
        ipaddress.ip_network('fe80::/10'),  # IPv6 link-local
    ]

    # Blocked hostnames
    BLOCKED_HOSTNAMES = {
        'localhost', 'localhost.localdomain',
        'metadata.google.internal',  # GCP metadata
        '169.254.169.254',  # AWS/Azure metadata
        'metadata.internal',
    }

    # Blocked ports (cloud metadata, internal services)
    BLOCKED_PORTS = {22, 3306, 5432, 6379, 27017, 9200, 11211}

    # Allowed schemes
    ALLOWED_SCHEMES = {'http', 'https'}

    def __init__(self):
        self.logger = SecurityEventLogger()
        self.allowed_hosts = set(getattr(settings, 'SSRF_ALLOWED_HOSTS', []))
        self.allowed_domains = set(getattr(settings, 'SSRF_ALLOWED_DOMAINS', []))

    def validate_url(
        self,
        url: str,
        request: HttpRequest = None
    ) -> Tuple[bool, str]:
        """
        Validate a URL for SSRF safety.

        Args:
            url: The URL to validate
            request: Optional request for logging context

        Returns:
            Tuple of (is_safe, reason if unsafe)
        """
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            return False, 'Invalid URL format'

        # Check scheme
        if parsed.scheme.lower() not in self.ALLOWED_SCHEMES:
            self._log_ssrf_attempt(url, 'blocked_scheme', request)
            return False, f'Scheme not allowed: {parsed.scheme}'

        # Check for empty or suspicious host
        hostname = parsed.hostname
        if not hostname:
            return False, 'No hostname specified'

        # Check blocked hostnames
        if hostname.lower() in self.BLOCKED_HOSTNAMES:
            self._log_ssrf_attempt(url, 'blocked_hostname', request)
            return False, f'Hostname blocked: {hostname}'

        # Check port
        port = parsed.port
        if port and port in self.BLOCKED_PORTS:
            self._log_ssrf_attempt(url, 'blocked_port', request)
            return False, f'Port blocked: {port}'

        # Resolve hostname and check IP
        try:
            ip_check = self._check_resolved_ip(hostname, request, url)
            if not ip_check[0]:
                return ip_check
        except socket.gaierror:
            # Can't resolve - might be temporary, allow with caution
            pass

        # Check against allowlists if configured
        if self.allowed_hosts or self.allowed_domains:
            if not self._is_allowed(hostname):
                self._log_ssrf_attempt(url, 'not_allowlisted', request)
                return False, 'Host not in allowlist'

        return True, ''

    def _check_resolved_ip(
        self,
        hostname: str,
        request: HttpRequest,
        url: str
    ) -> Tuple[bool, str]:
        """Check resolved IP addresses against blocked ranges."""
        try:
            # Get all IPs for hostname
            ips = socket.getaddrinfo(hostname, None)
            for info in ips:
                ip_str = info[4][0]
                try:
                    ip = ipaddress.ip_address(ip_str)

                    # Check against private ranges
                    for network in self.PRIVATE_RANGES:
                        if ip in network:
                            self._log_ssrf_attempt(url, f'private_ip:{ip_str}', request)
                            return False, f'Private IP address not allowed: {ip_str}'

                except ValueError:
                    continue

        except socket.gaierror:
            pass  # DNS resolution failed, handled by caller

        return True, ''

    def _is_allowed(self, hostname: str) -> bool:
        """Check if hostname is in allowlist."""
        hostname_lower = hostname.lower()

        # Check exact hostname match
        if hostname_lower in self.allowed_hosts:
            return True

        # Check domain suffix match
        for domain in self.allowed_domains:
            if hostname_lower.endswith('.' + domain) or hostname_lower == domain:
                return True

        return False

    def safe_request(
        self,
        url: str,
        method: str = 'GET',
        request: HttpRequest = None,
        **kwargs
    ) -> Tuple[bool, Any]:
        """
        Make a safe HTTP request after SSRF validation.

        Args:
            url: The URL to request
            method: HTTP method
            request: Optional request for logging
            **kwargs: Additional arguments for requests

        Returns:
            Tuple of (success, response or error)
        """
        # Validate URL
        is_safe, reason = self.validate_url(url, request)
        if not is_safe:
            return False, reason

        try:
            import requests

            # Set reasonable timeout
            kwargs.setdefault('timeout', 10)

            # Disable redirects to prevent redirect-based SSRF
            kwargs.setdefault('allow_redirects', False)

            response = requests.request(method, url, **kwargs)

            # Check for redirects to blocked locations
            if response.is_redirect:
                redirect_url = response.headers.get('Location', '')
                redirect_safe, redirect_reason = self.validate_url(redirect_url, request)
                if not redirect_safe:
                    return False, f'Redirect blocked: {redirect_reason}'

            return True, response

        except requests.RequestException as e:
            return False, str(e)

    def _log_ssrf_attempt(
        self,
        url: str,
        reason: str,
        request: HttpRequest = None
    ):
        """Log an SSRF attempt."""
        event = SecurityEvent(
            event_type=SecurityEventType.SSRF_ATTEMPT,
            severity='high',
            message=f'SSRF attempt blocked: {reason}',
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', '') if request else None,
            request_path=request.path if request else None,
            details={
                'target_url': url[:500],
                'block_reason': reason,
            }
        )
        self.logger.log(event)


class URLSafetyChecker:
    """
    Validates URLs for safety before use.

    Provides comprehensive URL validation including protocol, domain,
    and content type checks.
    """

    # Dangerous URL schemes
    DANGEROUS_SCHEMES = {
        'javascript', 'data', 'vbscript', 'file', 'ftp',
    }

    # Common phishing TLDs
    SUSPICIOUS_TLDS = {
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Freenom TLDs often used for phishing
    }

    def __init__(self):
        self.logger = SecurityEventLogger()
        self.ssrf_protector = SSRFProtector()

    def check(
        self,
        url: str,
        check_ssrf: bool = True,
        request: HttpRequest = None
    ) -> Tuple[bool, List[str]]:
        """
        Perform comprehensive URL safety checks.

        Args:
            url: The URL to check
            check_ssrf: Whether to include SSRF checks
            request: Optional request for logging

        Returns:
            Tuple of (is_safe, list of issues)
        """
        issues = []

        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            return False, ['Invalid URL format']

        # Check scheme
        if parsed.scheme.lower() in self.DANGEROUS_SCHEMES:
            issues.append(f'Dangerous scheme: {parsed.scheme}')

        # Check for suspicious TLD
        hostname = parsed.hostname or ''
        for tld in self.SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                issues.append(f'Suspicious TLD: {tld}')
                break

        # Check for URL encoding abuse
        if '%00' in url or '%0a' in url.lower() or '%0d' in url.lower():
            issues.append('Suspicious URL encoding detected')

        # Check for potential redirect abuse
        if parsed.query:
            query_lower = parsed.query.lower()
            redirect_params = ['redirect', 'url', 'next', 'return', 'goto', 'target']
            for param in redirect_params:
                if param in query_lower:
                    issues.append(f'Potential open redirect parameter: {param}')

        # SSRF check
        if check_ssrf:
            ssrf_safe, ssrf_reason = self.ssrf_protector.validate_url(url, request)
            if not ssrf_safe:
                issues.append(f'SSRF risk: {ssrf_reason}')

        return len(issues) == 0, issues

    def sanitize_url(self, url: str) -> str:
        """
        Sanitize a URL for safe display/storage.

        Args:
            url: The URL to sanitize

        Returns:
            Sanitized URL
        """
        # Parse and reconstruct to normalize
        try:
            parsed = urllib.parse.urlparse(url)

            # Only allow safe schemes
            if parsed.scheme.lower() not in ('http', 'https'):
                return ''

            # Rebuild URL without fragments (potential XSS vector)
            clean = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                ''  # Remove fragment
            ))

            return clean

        except Exception:
            return ''

    def is_same_origin(self, url: str, base_url: str) -> bool:
        """
        Check if a URL is same-origin with a base URL.

        Args:
            url: The URL to check
            base_url: The base URL for comparison

        Returns:
            True if same origin
        """
        try:
            parsed = urllib.parse.urlparse(url)
            base_parsed = urllib.parse.urlparse(base_url)

            return (
                parsed.scheme == base_parsed.scheme and
                parsed.netloc == base_parsed.netloc
            )
        except:
            return False
