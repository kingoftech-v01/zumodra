"""
Core Validators - Input validation and sanitization utilities.

This module provides:
- HTML sanitization with nh3/bleach
- SQL injection prevention
- XSS prevention
- File upload validators
- Common pattern validators (email, phone, etc.)

Usage:
    from core.validators import (
        sanitize_html,
        validate_file_upload,
        validate_email,
        NoSQLInjection,
    )

    # In forms
    class CommentForm(forms.Form):
        content = forms.CharField(validators=[NoSQLInjection()])

    # Direct sanitization
    safe_html = sanitize_html(user_input, allowed_tags=['p', 'b', 'i'])
"""

import logging
import os
import re
from typing import List, Optional, Set, Tuple

from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator, RegexValidator
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security.validators')


# =============================================================================
# HTML SANITIZATION
# =============================================================================

# Default allowed HTML tags for user content
DEFAULT_ALLOWED_TAGS = {
    'p', 'br', 'b', 'i', 'u', 'strong', 'em',
    'ul', 'ol', 'li',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'blockquote', 'code', 'pre',
    'a', 'span',
}

# Default allowed attributes
DEFAULT_ALLOWED_ATTRIBUTES = {
    'a': {'href', 'title', 'target', 'rel'},
    'span': {'class'},
    '*': {'class'},
}

# URL schemes allowed in links
ALLOWED_URL_SCHEMES = {'http', 'https', 'mailto'}


def sanitize_html(
    content: str,
    allowed_tags: Optional[Set[str]] = None,
    allowed_attributes: Optional[dict] = None,
    strip: bool = True
) -> str:
    """
    Sanitize HTML content to prevent XSS attacks.

    Args:
        content: HTML content to sanitize
        allowed_tags: Set of allowed HTML tags
        allowed_attributes: Dict of tag -> allowed attributes
        strip: If True, strip disallowed tags; if False, escape them

    Returns:
        Sanitized HTML string
    """
    if not content:
        return content

    if allowed_tags is None:
        allowed_tags = DEFAULT_ALLOWED_TAGS

    if allowed_attributes is None:
        allowed_attributes = DEFAULT_ALLOWED_ATTRIBUTES

    try:
        # Try nh3 first (faster, more secure)
        import nh3
        return nh3.clean(
            content,
            tags=allowed_tags,
            attributes=allowed_attributes,
            url_schemes=ALLOWED_URL_SCHEMES,
            strip_comments=True,
        )
    except ImportError:
        pass

    try:
        # Fall back to bleach
        import bleach
        return bleach.clean(
            content,
            tags=list(allowed_tags),
            attributes=allowed_attributes,
            strip=strip,
            protocols=list(ALLOWED_URL_SCHEMES),
        )
    except ImportError:
        pass

    # Last resort: strip all HTML
    security_logger.warning(
        "No HTML sanitization library available (nh3 or bleach). "
        "Stripping all HTML tags."
    )
    return strip_all_html(content)


def strip_all_html(content: str) -> str:
    """Strip all HTML tags from content."""
    import html
    # Remove tags
    clean = re.sub(r'<[^>]+>', '', content)
    # Unescape HTML entities
    return html.unescape(clean)


def sanitize_plain_text(content: str) -> str:
    """
    Sanitize plain text by removing any HTML and escaping special characters.

    Args:
        content: Text to sanitize

    Returns:
        Safe plain text string
    """
    import html
    # Strip HTML tags
    clean = strip_all_html(content)
    # Escape any remaining special characters
    return html.escape(clean)


# =============================================================================
# SQL INJECTION PREVENTION
# =============================================================================

# Patterns that indicate potential SQL injection
SQL_INJECTION_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE)\b)",
    r"(--|\#|/\*|\*/)",  # SQL comments
    r"(\b(OR|AND)\b\s+\d+\s*=\s*\d+)",  # Tautologies like OR 1=1
    r"(\bunion\b\s+\bselect\b)",  # UNION SELECT
    r"(;.*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b)",  # Stacked queries
    r"(\b(WAITFOR|SLEEP|BENCHMARK)\b)",  # Time-based attacks
    r"(\bINTO\s+(OUTFILE|DUMPFILE)\b)",  # File operations
]


class NoSQLInjection:
    """
    Validator that checks for SQL injection patterns.

    Usage:
        from core.validators import NoSQLInjection

        class SearchForm(forms.Form):
            query = forms.CharField(validators=[NoSQLInjection()])
    """
    message = _("Input contains potentially dangerous SQL patterns.")
    code = "sql_injection"

    def __init__(self, message: Optional[str] = None):
        if message:
            self.message = message
        self.patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in SQL_INJECTION_PATTERNS
        ]

    def __call__(self, value: str) -> None:
        if not isinstance(value, str):
            return

        for pattern in self.patterns:
            if pattern.search(value):
                security_logger.warning(
                    f"SQL_INJECTION_BLOCKED: pattern matched in input"
                )
                raise ValidationError(self.message, code=self.code)

    def __eq__(self, other):
        return isinstance(other, NoSQLInjection)


def contains_sql_injection(value: str) -> bool:
    """
    Check if a string contains SQL injection patterns.

    Args:
        value: String to check

    Returns:
        True if SQL injection patterns detected
    """
    validator = NoSQLInjection()
    try:
        validator(value)
        return False
    except ValidationError:
        return True


# =============================================================================
# XSS PREVENTION
# =============================================================================

# Patterns that indicate potential XSS
XSS_PATTERNS = [
    r"<\s*script",
    r"javascript\s*:",
    r"on\w+\s*=",  # Event handlers like onclick, onerror
    r"<\s*iframe",
    r"<\s*object",
    r"<\s*embed",
    r"<\s*form",
    r"<\s*input",
    r"<\s*button",
    r"expression\s*\(",  # CSS expression
    r"url\s*\(\s*['\"]?\s*data:",  # Data URLs
]


class NoXSS:
    """
    Validator that checks for XSS patterns.

    Usage:
        from core.validators import NoXSS

        class CommentForm(forms.Form):
            content = forms.CharField(validators=[NoXSS()])
    """
    message = _("Input contains potentially dangerous content.")
    code = "xss_detected"

    def __init__(self, message: Optional[str] = None):
        if message:
            self.message = message
        self.patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in XSS_PATTERNS
        ]

    def __call__(self, value: str) -> None:
        if not isinstance(value, str):
            return

        for pattern in self.patterns:
            if pattern.search(value):
                security_logger.warning(
                    f"XSS_BLOCKED: pattern matched in input"
                )
                raise ValidationError(self.message, code=self.code)

    def __eq__(self, other):
        return isinstance(other, NoXSS)


# =============================================================================
# FILE UPLOAD VALIDATION
# =============================================================================

# Maximum file sizes by type (in bytes)
MAX_FILE_SIZES = {
    'image': 5 * 1024 * 1024,      # 5MB
    'document': 10 * 1024 * 1024,  # 10MB
    'resume': 10 * 1024 * 1024,    # 10MB
    'video': 100 * 1024 * 1024,    # 100MB
    'default': 10 * 1024 * 1024,   # 10MB
}

# Allowed MIME types by category
ALLOWED_MIME_TYPES = {
    'image': {
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    },
    'document': {
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'text/plain',
    },
    'resume': {
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'text/plain',
    },
}

# Allowed extensions by category
ALLOWED_EXTENSIONS = {
    'image': {'.jpg', '.jpeg', '.png', '.gif', '.webp'},
    'document': {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt'},
    'resume': {'.pdf', '.doc', '.docx', '.txt'},
}


def validate_file_upload(
    file,
    file_type: str = 'document',
    max_size: Optional[int] = None,
    allowed_extensions: Optional[Set[str]] = None,
    allowed_mime_types: Optional[Set[str]] = None,
    check_content: bool = True
) -> Tuple[bool, Optional[str]]:
    """
    Validate an uploaded file for security.

    Checks:
    - File size
    - File extension
    - MIME type (from header and content)
    - Content-based type detection (if available)

    Args:
        file: The uploaded file object
        file_type: Type category ('image', 'document', 'resume', etc.)
        max_size: Maximum file size in bytes (overrides default)
        allowed_extensions: Set of allowed extensions (overrides default)
        allowed_mime_types: Set of allowed MIME types (overrides default)
        check_content: Whether to check file content with magic

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not file:
        return True, None

    # Get defaults for file type
    if max_size is None:
        max_size = MAX_FILE_SIZES.get(file_type, MAX_FILE_SIZES['default'])

    if allowed_extensions is None:
        allowed_extensions = ALLOWED_EXTENSIONS.get(file_type, set())

    if allowed_mime_types is None:
        allowed_mime_types = ALLOWED_MIME_TYPES.get(file_type, set())

    # Check file size
    file_size = file.size if hasattr(file, 'size') else len(file.read())
    if hasattr(file, 'seek'):
        file.seek(0)

    if file_size > max_size:
        max_mb = max_size / (1024 * 1024)
        return False, f"File size exceeds maximum of {max_mb:.1f}MB"

    # Check extension
    filename = file.name if hasattr(file, 'name') else ''
    ext = os.path.splitext(filename.lower())[1]

    if allowed_extensions and ext not in allowed_extensions:
        return False, f"File extension '{ext}' not allowed. Allowed: {', '.join(allowed_extensions)}"

    # Check MIME type from header
    content_type = getattr(file, 'content_type', None)
    if content_type and allowed_mime_types and content_type not in allowed_mime_types:
        return False, f"File type '{content_type}' not allowed"

    # Check actual content type using magic
    if check_content:
        try:
            import magic
            file_head = file.read(2048)
            file.seek(0)

            detected_type = magic.from_buffer(file_head, mime=True)
            if allowed_mime_types and detected_type not in allowed_mime_types:
                security_logger.warning(
                    f"FILE_TYPE_MISMATCH: declared={content_type} detected={detected_type}"
                )
                return False, f"Detected file type '{detected_type}' not allowed"
        except ImportError:
            # python-magic not available
            pass
        except Exception as e:
            logger.warning(f"Content type detection failed: {e}")

    return True, None


class FileValidator:
    """
    Django form validator for file uploads.

    Usage:
        from core.validators import FileValidator

        class ResumeForm(forms.Form):
            resume = forms.FileField(validators=[FileValidator('resume')])
    """

    def __init__(
        self,
        file_type: str = 'document',
        max_size: Optional[int] = None,
        allowed_extensions: Optional[Set[str]] = None,
        allowed_mime_types: Optional[Set[str]] = None,
    ):
        self.file_type = file_type
        self.max_size = max_size
        self.allowed_extensions = allowed_extensions
        self.allowed_mime_types = allowed_mime_types

    def __call__(self, file) -> None:
        is_valid, error = validate_file_upload(
            file,
            file_type=self.file_type,
            max_size=self.max_size,
            allowed_extensions=self.allowed_extensions,
            allowed_mime_types=self.allowed_mime_types,
        )

        if not is_valid:
            raise ValidationError(error)

    def __eq__(self, other):
        return (
            isinstance(other, FileValidator) and
            self.file_type == other.file_type
        )


# =============================================================================
# COMMON PATTERN VALIDATORS
# =============================================================================

# Phone number patterns
PHONE_PATTERN = re.compile(r'^[\d\s\-\+\(\)\.]{7,20}$')

# Canadian postal code
CA_POSTAL_CODE_PATTERN = re.compile(
    r'^[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z]\s?\d[ABCEGHJ-NPRSTV-Z]\d$',
    re.IGNORECASE
)

# US ZIP code
US_ZIP_PATTERN = re.compile(r'^\d{5}(-\d{4})?$')

# Canadian SIN
CA_SIN_PATTERN = re.compile(r'^\d{3}[\s\-]?\d{3}[\s\-]?\d{3}$')


class PhoneValidator:
    """Validate phone number format."""
    message = _("Enter a valid phone number.")
    code = "invalid_phone"

    def __call__(self, value: str) -> None:
        if not PHONE_PATTERN.match(value):
            raise ValidationError(self.message, code=self.code)


class CanadianPostalCodeValidator:
    """Validate Canadian postal code format."""
    message = _("Enter a valid Canadian postal code (e.g., A1A 1A1).")
    code = "invalid_postal_code"

    def __call__(self, value: str) -> None:
        if not CA_POSTAL_CODE_PATTERN.match(value):
            raise ValidationError(self.message, code=self.code)


class USZipCodeValidator:
    """Validate US ZIP code format."""
    message = _("Enter a valid US ZIP code (e.g., 12345 or 12345-6789).")
    code = "invalid_zip"

    def __call__(self, value: str) -> None:
        if not US_ZIP_PATTERN.match(value):
            raise ValidationError(self.message, code=self.code)


class CanadianSINValidator:
    """Validate Canadian Social Insurance Number format."""
    message = _("Enter a valid SIN (9 digits).")
    code = "invalid_sin"

    def __call__(self, value: str) -> None:
        # Remove spaces and dashes
        clean = re.sub(r'[\s\-]', '', value)

        if not clean.isdigit() or len(clean) != 9:
            raise ValidationError(self.message, code=self.code)

        # Luhn algorithm validation
        if not self._luhn_check(clean):
            raise ValidationError(self.message, code=self.code)

    def _luhn_check(self, number: str) -> bool:
        """Validate using Luhn algorithm."""
        digits = [int(d) for d in number]
        odd_sum = sum(digits[0::2])
        even_sum = sum(
            sum(divmod(2 * d, 10)) for d in digits[1::2]
        )
        return (odd_sum + even_sum) % 10 == 0


# =============================================================================
# URL VALIDATORS
# =============================================================================

class SafeURLValidator:
    """
    Validate URL and ensure it's safe (no javascript:, data:, etc.).
    """
    message = _("Enter a valid and safe URL.")
    code = "unsafe_url"

    UNSAFE_SCHEMES = {'javascript', 'data', 'vbscript', 'file'}

    def __call__(self, value: str) -> None:
        from urllib.parse import urlparse

        try:
            result = urlparse(value)

            # Check for unsafe schemes
            if result.scheme.lower() in self.UNSAFE_SCHEMES:
                raise ValidationError(self.message, code=self.code)

            # Must have a scheme and netloc for absolute URLs
            if result.scheme and not result.netloc:
                raise ValidationError(self.message, code=self.code)

        except Exception:
            raise ValidationError(self.message, code=self.code)


# =============================================================================
# COMPOSITE VALIDATORS
# =============================================================================

class SecureTextValidator:
    """
    Combined validator for secure text input.

    Checks for:
    - SQL injection patterns
    - XSS patterns
    - Maximum length
    """

    def __init__(self, max_length: int = 10000):
        self.max_length = max_length
        self.sql_validator = NoSQLInjection()
        self.xss_validator = NoXSS()

    def __call__(self, value: str) -> None:
        if len(value) > self.max_length:
            raise ValidationError(
                f"Text exceeds maximum length of {self.max_length} characters."
            )

        self.sql_validator(value)
        self.xss_validator(value)


def validate_secure_text(value: str, max_length: int = 10000) -> str:
    """
    Validate and sanitize text input.

    Args:
        value: Text to validate
        max_length: Maximum allowed length

    Returns:
        Sanitized text

    Raises:
        ValidationError: If validation fails
    """
    validator = SecureTextValidator(max_length=max_length)
    validator(value)
    return sanitize_plain_text(value)
