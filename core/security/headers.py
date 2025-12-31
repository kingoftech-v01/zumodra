"""
Security Headers Configuration Module for Zumodra

Provides comprehensive security headers configuration including:
- Content Security Policy (strict, with nonces for inline scripts)
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Referrer-Policy: strict-origin-when-cross-origin
- Permissions-Policy (disable camera, microphone, geolocation by default)

All configurations are designed for production Django deployment.
"""

import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set
from functools import wraps

from django.conf import settings
from django.http import HttpRequest, HttpResponse


# =============================================================================
# Content Security Policy Configuration
# =============================================================================

@dataclass
class ContentSecurityPolicyConfig:
    """
    Content Security Policy configuration builder.

    Provides a strict CSP with support for nonces for inline scripts.
    """

    # Default directives
    default_src: List[str] = field(default_factory=lambda: ["'self'"])
    script_src: List[str] = field(default_factory=lambda: ["'self'"])
    style_src: List[str] = field(default_factory=lambda: ["'self'"])
    img_src: List[str] = field(default_factory=lambda: ["'self'", "data:", "https:"])
    font_src: List[str] = field(default_factory=lambda: ["'self'"])
    connect_src: List[str] = field(default_factory=lambda: ["'self'"])
    media_src: List[str] = field(default_factory=lambda: ["'self'"])
    object_src: List[str] = field(default_factory=lambda: ["'none'"])
    frame_src: List[str] = field(default_factory=lambda: ["'none'"])
    frame_ancestors: List[str] = field(default_factory=lambda: ["'none'"])
    base_uri: List[str] = field(default_factory=lambda: ["'self'"])
    form_action: List[str] = field(default_factory=lambda: ["'self'"])
    worker_src: List[str] = field(default_factory=lambda: ["'self'"])
    manifest_src: List[str] = field(default_factory=lambda: ["'self'"])

    # Report settings
    report_uri: Optional[str] = None
    report_to: Optional[str] = None

    # Mode
    report_only: bool = False

    # Nonce support
    use_nonces: bool = True

    def generate_nonce(self) -> str:
        """
        Generate a cryptographic nonce for inline scripts/styles.

        Returns:
            Base64-encoded nonce
        """
        return secrets.token_urlsafe(16)

    def build_policy(self, nonce: str = None) -> str:
        """
        Build the complete CSP header value.

        Args:
            nonce: Optional nonce for inline scripts/styles

        Returns:
            CSP header string
        """
        directives = []

        # Build each directive
        directive_map = {
            'default-src': self.default_src,
            'script-src': self._build_script_src(nonce),
            'style-src': self._build_style_src(nonce),
            'img-src': self.img_src,
            'font-src': self.font_src,
            'connect-src': self.connect_src,
            'media-src': self.media_src,
            'object-src': self.object_src,
            'frame-src': self.frame_src,
            'frame-ancestors': self.frame_ancestors,
            'base-uri': self.base_uri,
            'form-action': self.form_action,
            'worker-src': self.worker_src,
            'manifest-src': self.manifest_src,
        }

        for directive, sources in directive_map.items():
            if sources:
                directives.append(f"{directive} {' '.join(sources)}")

        # Add reporting
        if self.report_uri:
            directives.append(f"report-uri {self.report_uri}")
        if self.report_to:
            directives.append(f"report-to {self.report_to}")

        return '; '.join(directives)

    def _build_script_src(self, nonce: str = None) -> List[str]:
        """Build script-src with optional nonce."""
        sources = self.script_src.copy()
        if nonce and self.use_nonces:
            sources.append(f"'nonce-{nonce}'")
            # Add strict-dynamic for modern CSP
            sources.append("'strict-dynamic'")
        return sources

    def _build_style_src(self, nonce: str = None) -> List[str]:
        """Build style-src with optional nonce."""
        sources = self.style_src.copy()
        if nonce and self.use_nonces:
            sources.append(f"'nonce-{nonce}'")
        return sources

    def get_header_name(self) -> str:
        """Get the appropriate CSP header name."""
        if self.report_only:
            return 'Content-Security-Policy-Report-Only'
        return 'Content-Security-Policy'

    @classmethod
    def strict(cls) -> 'ContentSecurityPolicyConfig':
        """
        Create a strict CSP configuration.

        Returns:
            Strict CSP configuration
        """
        return cls(
            default_src=["'self'"],
            script_src=["'self'"],
            style_src=["'self'"],
            img_src=["'self'", "data:"],
            font_src=["'self'"],
            connect_src=["'self'"],
            media_src=["'self'"],
            object_src=["'none'"],
            frame_src=["'none'"],
            frame_ancestors=["'none'"],
            base_uri=["'self'"],
            form_action=["'self'"],
            use_nonces=True,
        )

    @classmethod
    def moderate(cls) -> 'ContentSecurityPolicyConfig':
        """
        Create a moderate CSP configuration for common use cases.

        Returns:
            Moderate CSP configuration
        """
        return cls(
            default_src=["'self'"],
            script_src=["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            style_src=["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            img_src=["'self'", "data:", "https:"],
            font_src=["'self'", "https://fonts.gstatic.com"],
            connect_src=["'self'", "wss:", "https:"],
            media_src=["'self'"],
            object_src=["'none'"],
            frame_src=["'self'"],
            frame_ancestors=["'self'"],
            base_uri=["'self'"],
            form_action=["'self'"],
            use_nonces=False,
        )

    @classmethod
    def from_settings(cls) -> 'ContentSecurityPolicyConfig':
        """
        Create CSP configuration from Django settings.

        Returns:
            CSP configuration based on settings
        """
        return cls(
            default_src=list(getattr(settings, 'CSP_DEFAULT_SRC', ["'self'"])),
            script_src=list(getattr(settings, 'CSP_SCRIPT_SRC', ["'self'"])),
            style_src=list(getattr(settings, 'CSP_STYLE_SRC', ["'self'"])),
            img_src=list(getattr(settings, 'CSP_IMG_SRC', ["'self'", "data:"])),
            font_src=list(getattr(settings, 'CSP_FONT_SRC', ["'self'"])),
            connect_src=list(getattr(settings, 'CSP_CONNECT_SRC', ["'self'"])),
            media_src=list(getattr(settings, 'CSP_MEDIA_SRC', ["'self'"])),
            object_src=list(getattr(settings, 'CSP_OBJECT_SRC', ["'none'"])),
            frame_src=list(getattr(settings, 'CSP_FRAME_SRC', ["'none'"])),
            frame_ancestors=list(getattr(settings, 'CSP_FRAME_ANCESTORS', ["'none'"])),
            base_uri=list(getattr(settings, 'CSP_BASE_URI', ["'self'"])),
            form_action=list(getattr(settings, 'CSP_FORM_ACTION', ["'self'"])),
            report_uri=getattr(settings, 'CSP_REPORT_URI', None),
            report_only=getattr(settings, 'CSP_REPORT_ONLY', False),
            use_nonces=getattr(settings, 'CSP_USE_NONCES', True),
        )


# =============================================================================
# Security Headers Configuration
# =============================================================================

@dataclass
class SecurityHeadersConfig:
    """
    Complete security headers configuration.

    Includes all recommended security headers for production deployment.
    """

    # HSTS settings
    hsts_enabled: bool = True
    hsts_max_age: int = 31536000  # 1 year
    hsts_include_subdomains: bool = True
    hsts_preload: bool = True

    # Content-Type options
    content_type_nosniff: bool = True

    # Frame options
    x_frame_options: str = 'DENY'

    # XSS Protection (legacy, but still useful)
    xss_protection: bool = True
    xss_protection_mode: str = 'block'

    # Referrer Policy
    referrer_policy: str = 'strict-origin-when-cross-origin'

    # Permissions Policy
    permissions_policy: Dict[str, List[str]] = field(default_factory=lambda: {
        'camera': [],
        'microphone': [],
        'geolocation': [],
        'payment': ["'self'"],
        'usb': [],
        'magnetometer': [],
        'gyroscope': [],
        'accelerometer': [],
        'autoplay': ["'self'"],
        'encrypted-media': ["'self'"],
        'fullscreen': ["'self'"],
    })

    # Cross-Origin policies
    cross_origin_embedder_policy: str = 'require-corp'
    cross_origin_opener_policy: str = 'same-origin'
    cross_origin_resource_policy: str = 'same-origin'

    # CSP
    csp_config: ContentSecurityPolicyConfig = field(
        default_factory=ContentSecurityPolicyConfig.from_settings
    )

    def build_headers(self, nonce: str = None) -> Dict[str, str]:
        """
        Build all security headers.

        Args:
            nonce: Optional nonce for CSP

        Returns:
            Dictionary of header name -> value
        """
        headers = {}

        # HSTS
        if self.hsts_enabled:
            hsts_value = f'max-age={self.hsts_max_age}'
            if self.hsts_include_subdomains:
                hsts_value += '; includeSubDomains'
            if self.hsts_preload:
                hsts_value += '; preload'
            headers['Strict-Transport-Security'] = hsts_value

        # Content-Type Options
        if self.content_type_nosniff:
            headers['X-Content-Type-Options'] = 'nosniff'

        # Frame Options
        if self.x_frame_options:
            headers['X-Frame-Options'] = self.x_frame_options

        # XSS Protection
        if self.xss_protection:
            headers['X-XSS-Protection'] = f'1; mode={self.xss_protection_mode}'

        # Referrer Policy
        if self.referrer_policy:
            headers['Referrer-Policy'] = self.referrer_policy

        # Permissions Policy
        if self.permissions_policy:
            headers['Permissions-Policy'] = self._build_permissions_policy()

        # Cross-Origin policies
        if self.cross_origin_embedder_policy:
            headers['Cross-Origin-Embedder-Policy'] = self.cross_origin_embedder_policy
        if self.cross_origin_opener_policy:
            headers['Cross-Origin-Opener-Policy'] = self.cross_origin_opener_policy
        if self.cross_origin_resource_policy:
            headers['Cross-Origin-Resource-Policy'] = self.cross_origin_resource_policy

        # CSP
        if self.csp_config:
            csp_header = self.csp_config.get_header_name()
            csp_value = self.csp_config.build_policy(nonce)
            headers[csp_header] = csp_value

        return headers

    def _build_permissions_policy(self) -> str:
        """Build Permissions-Policy header value."""
        policies = []
        for feature, sources in self.permissions_policy.items():
            if not sources:
                policies.append(f"{feature}=()")
            else:
                sources_str = ' '.join(sources)
                policies.append(f"{feature}=({sources_str})")
        return ', '.join(policies)

    @classmethod
    def production(cls) -> 'SecurityHeadersConfig':
        """
        Create production-ready security headers configuration.

        Returns:
            Production security headers configuration
        """
        return cls(
            hsts_enabled=True,
            hsts_max_age=31536000,
            hsts_include_subdomains=True,
            hsts_preload=True,
            content_type_nosniff=True,
            x_frame_options='DENY',
            xss_protection=True,
            referrer_policy='strict-origin-when-cross-origin',
            permissions_policy={
                'camera': [],
                'microphone': [],
                'geolocation': [],
                'payment': ["'self'"],
                'usb': [],
                'magnetometer': [],
                'gyroscope': [],
                'accelerometer': [],
            },
            cross_origin_embedder_policy='require-corp',
            cross_origin_opener_policy='same-origin',
            cross_origin_resource_policy='same-origin',
            csp_config=ContentSecurityPolicyConfig.strict(),
        )

    @classmethod
    def development(cls) -> 'SecurityHeadersConfig':
        """
        Create development-friendly security headers configuration.

        Returns:
            Development security headers configuration
        """
        return cls(
            hsts_enabled=False,  # Don't enable HSTS in dev
            content_type_nosniff=True,
            x_frame_options='SAMEORIGIN',  # Allow frames for dev tools
            xss_protection=True,
            referrer_policy='no-referrer-when-downgrade',
            permissions_policy={},  # No restrictions in dev
            cross_origin_embedder_policy='',  # Disabled in dev
            cross_origin_opener_policy='',
            cross_origin_resource_policy='',
            csp_config=ContentSecurityPolicyConfig.moderate(),
        )


# =============================================================================
# Security Headers Middleware
# =============================================================================

class SecurityHeadersMiddleware:
    """
    Middleware to apply security headers to all responses.

    Integrates CSP nonces and all security headers.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.config = self._get_config()

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Process request and add security headers to response."""
        # Generate nonce for this request
        nonce = secrets.token_urlsafe(16)
        request.csp_nonce = nonce

        # Get response
        response = self.get_response(request)

        # Add security headers
        headers = self.config.build_headers(nonce)
        for header_name, header_value in headers.items():
            if header_value:  # Only set non-empty headers
                response[header_name] = header_value

        return response

    def _get_config(self) -> SecurityHeadersConfig:
        """Get configuration based on environment."""
        if getattr(settings, 'DEBUG', False):
            return SecurityHeadersConfig.development()
        return SecurityHeadersConfig.production()


# =============================================================================
# Helper Functions
# =============================================================================

def get_security_settings() -> Dict[str, Any]:
    """
    Get Django settings for security headers.

    Returns settings that should be added to Django settings.py

    Returns:
        Dictionary of security settings
    """
    config = SecurityHeadersConfig.production()

    return {
        # Session Security
        'SESSION_COOKIE_SECURE': True,
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'SESSION_COOKIE_AGE': 1209600,  # 2 weeks

        # CSRF Security
        'CSRF_COOKIE_SECURE': True,
        'CSRF_COOKIE_HTTPONLY': True,
        'CSRF_COOKIE_SAMESITE': 'Strict',
        'CSRF_USE_SESSIONS': False,

        # Security Middleware Settings
        'SECURE_BROWSER_XSS_FILTER': True,
        'SECURE_CONTENT_TYPE_NOSNIFF': True,
        'X_FRAME_OPTIONS': 'DENY',

        # HSTS
        'SECURE_HSTS_SECONDS': 31536000,
        'SECURE_HSTS_INCLUDE_SUBDOMAINS': True,
        'SECURE_HSTS_PRELOAD': True,

        # SSL/TLS
        'SECURE_SSL_REDIRECT': True,
        'SECURE_PROXY_SSL_HEADER': ('HTTP_X_FORWARDED_PROTO', 'https'),

        # Referrer Policy
        'SECURE_REFERRER_POLICY': 'strict-origin-when-cross-origin',

        # CSP Settings (for django-csp)
        'CSP_DEFAULT_SRC': ("'self'",),
        'CSP_SCRIPT_SRC': ("'self'",),
        'CSP_STYLE_SRC': ("'self'",),
        'CSP_IMG_SRC': ("'self'", "data:", "https:"),
        'CSP_FONT_SRC': ("'self'",),
        'CSP_CONNECT_SRC': ("'self'", "wss:", "https:"),
        'CSP_FRAME_ANCESTORS': ("'none'",),
        'CSP_BASE_URI': ("'self'",),
        'CSP_FORM_ACTION': ("'self'",),
        'CSP_INCLUDE_NONCE_IN': ['script-src', 'style-src'],
    }


def get_csp_nonce_tag(request: HttpRequest) -> str:
    """
    Get the CSP nonce attribute for templates.

    Usage in templates:
        <script {{ csp_nonce }}>...</script>

    Args:
        request: The HTTP request

    Returns:
        Nonce attribute string
    """
    nonce = getattr(request, 'csp_nonce', '')
    if nonce:
        return f'nonce="{nonce}"'
    return ''


def csp_exempt(view_func: Callable) -> Callable:
    """
    Decorator to exempt a view from CSP.

    Use sparingly - only for views that absolutely need it.

    Args:
        view_func: The view function

    Returns:
        Wrapped view function
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        response = view_func(request, *args, **kwargs)
        # Remove CSP headers
        if 'Content-Security-Policy' in response:
            del response['Content-Security-Policy']
        if 'Content-Security-Policy-Report-Only' in response:
            del response['Content-Security-Policy-Report-Only']
        return response
    return wrapper


def add_nonce_to_response(
    response: HttpResponse,
    nonce: str,
    header_name: str = 'Content-Security-Policy'
) -> HttpResponse:
    """
    Add a nonce to an existing CSP header.

    Args:
        response: The HTTP response
        nonce: The nonce to add
        header_name: CSP header name

    Returns:
        Modified response
    """
    if header_name in response:
        csp = response[header_name]
        # Add nonce to script-src
        if 'script-src' in csp:
            csp = csp.replace(
                "script-src ",
                f"script-src 'nonce-{nonce}' "
            )
        # Add nonce to style-src
        if 'style-src' in csp:
            csp = csp.replace(
                "style-src ",
                f"style-src 'nonce-{nonce}' "
            )
        response[header_name] = csp
    return response


# =============================================================================
# Django Settings Template
# =============================================================================

SECURITY_SETTINGS_TEMPLATE = """
# =============================================================================
# SECURITY HEADERS CONFIGURATION
# =============================================================================
# Add these settings to your Django settings.py for production deployment

# -----------------------------------------------------------------------------
# Session Security
# -----------------------------------------------------------------------------
SESSION_COOKIE_SECURE = True  # Only send cookies over HTTPS
SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access
SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
SESSION_COOKIE_AGE = 1209600  # 2 weeks in seconds

# -----------------------------------------------------------------------------
# CSRF Security
# -----------------------------------------------------------------------------
CSRF_COOKIE_SECURE = True  # Only send CSRF cookie over HTTPS
CSRF_COOKIE_HTTPONLY = True  # Recommended: prevent JS access
CSRF_COOKIE_SAMESITE = 'Strict'  # Strict CSRF protection
CSRF_USE_SESSIONS = False  # Use cookie-based CSRF
CSRF_TRUSTED_ORIGINS = [
    'https://yourdomain.com',
    'https://www.yourdomain.com',
]

# -----------------------------------------------------------------------------
# Security Middleware
# -----------------------------------------------------------------------------
SECURE_BROWSER_XSS_FILTER = True  # Enable XSS filter
SECURE_CONTENT_TYPE_NOSNIFF = True  # Prevent MIME sniffing
X_FRAME_OPTIONS = 'DENY'  # Prevent clickjacking

# -----------------------------------------------------------------------------
# HSTS (HTTP Strict Transport Security)
# -----------------------------------------------------------------------------
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True  # Apply to all subdomains
SECURE_HSTS_PRELOAD = True  # Allow browser preloading

# -----------------------------------------------------------------------------
# SSL/TLS
# -----------------------------------------------------------------------------
SECURE_SSL_REDIRECT = True  # Redirect HTTP to HTTPS
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')  # For reverse proxy

# -----------------------------------------------------------------------------
# Referrer Policy
# -----------------------------------------------------------------------------
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# -----------------------------------------------------------------------------
# Content Security Policy (django-csp)
# -----------------------------------------------------------------------------
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)  # Add CDNs as needed
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'",)  # Inline styles if needed
CSP_IMG_SRC = ("'self'", "data:", "https:",)
CSP_FONT_SRC = ("'self'", "https://fonts.gstatic.com",)
CSP_CONNECT_SRC = ("'self'", "wss:", "https:",)
CSP_FRAME_ANCESTORS = ("'none'",)
CSP_BASE_URI = ("'self'",)
CSP_FORM_ACTION = ("'self'",)
CSP_OBJECT_SRC = ("'none'",)
CSP_INCLUDE_NONCE_IN = ['script-src', 'style-src']  # Enable nonces

# CSP Reporting (optional)
# CSP_REPORT_URI = '/csp-report/'
# CSP_REPORT_ONLY = True  # Start in report-only mode

# -----------------------------------------------------------------------------
# Permissions Policy
# -----------------------------------------------------------------------------
# Configured via SecurityHeadersMiddleware or manually:
# Permissions-Policy: camera=(), microphone=(), geolocation=()

# -----------------------------------------------------------------------------
# Add SecurityHeadersMiddleware to MIDDLEWARE
# -----------------------------------------------------------------------------
# MIDDLEWARE = [
#     ...
#     'core.security.headers.SecurityHeadersMiddleware',
#     ...
# ]
"""


def print_security_settings():
    """Print security settings template for copy-paste to settings.py."""
    print(SECURITY_SETTINGS_TEMPLATE)
