"""
Honeypot Protection for Zumodra

Bot detection and spam prevention for the multi-tenant ATS/HR SaaS platform:
- HoneypotField: Hidden form field that bots fill out
- HoneypotMixin: View mixin for honeypot validation
- HoneypotMiddleware: Global bot detection middleware
- TimingHoneypot: Detects rapid form submissions

All components log suspicious activity for security monitoring.
"""

import hashlib
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from django import forms
from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, HttpResponseForbidden
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from django.views import View

logger = logging.getLogger('security.honeypot')


# =============================================================================
# HONEYPOT CONFIGURATION
# =============================================================================

# Default field names for honeypot (look legitimate to bots)
HONEYPOT_FIELD_NAMES = [
    'email_confirm',
    'website_url',
    'phone_number',
    'address_2',
    'company_name',
    'fax_number',
    'middle_name',
]

# Minimum time (seconds) for form submission (prevents rapid bot submissions)
MIN_FORM_TIME = getattr(settings, 'HONEYPOT_MIN_FORM_TIME', 3)

# Maximum time (seconds) for form submission (prevents replay attacks)
MAX_FORM_TIME = getattr(settings, 'HONEYPOT_MAX_FORM_TIME', 3600)

# Cache timeout for tracking
TRACKING_TIMEOUT = getattr(settings, 'HONEYPOT_TRACKING_TIMEOUT', 86400)


# =============================================================================
# HONEYPOT FORM FIELD
# =============================================================================

class HoneypotWidget(forms.TextInput):
    """
    Hidden widget for honeypot field.
    Uses CSS to hide rather than type="hidden" to fool simple bots.
    """

    def __init__(self, attrs=None):
        default_attrs = {
            'autocomplete': 'off',
            'tabindex': '-1',
            'style': 'position: absolute !important; left: -9999px !important; opacity: 0 !important; pointer-events: none !important;',
            'aria-hidden': 'true',
        }
        if attrs:
            default_attrs.update(attrs)
        super().__init__(default_attrs)


class HoneypotField(forms.CharField):
    """
    Honeypot form field that bots will fill out.

    Features:
    - Hidden via CSS (invisible to users)
    - Uses legitimate-looking field names
    - Validates that field is empty
    - Logs bot detection attempts

    Usage:
        class ContactForm(forms.Form):
            name = forms.CharField()
            email = forms.EmailField()
            # Honeypot field
            website_url = HoneypotField()
    """

    widget = HoneypotWidget

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('required', False)
        kwargs.setdefault('label', '')
        kwargs.setdefault('help_text', '')
        super().__init__(*args, **kwargs)

    def clean(self, value):
        """Validate that the honeypot field is empty."""
        if value:
            logger.warning(
                "Honeypot field filled",
                extra={'value': value[:100] if value else None}
            )
            raise forms.ValidationError(
                "Form submission failed validation.",
                code='honeypot_triggered'
            )
        return value


class TimestampField(forms.CharField):
    """
    Hidden field containing encrypted timestamp for timing validation.

    Detects:
    - Rapid form submissions (bots)
    - Very old form submissions (replay attacks)

    Usage:
        class ContactForm(forms.Form):
            name = forms.CharField()
            # Timestamp field
            form_timestamp = TimestampField()
    """

    widget = forms.HiddenInput

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('required', False)
        super().__init__(*args, **kwargs)

    @staticmethod
    def generate_timestamp() -> str:
        """Generate encrypted timestamp for form."""
        timestamp = str(int(time.time()))
        secret = getattr(settings, 'SECRET_KEY', 'default-secret')
        signature = hashlib.sha256(f"{timestamp}{secret}".encode()).hexdigest()[:16]
        return f"{timestamp}:{signature}"

    def clean(self, value):
        """Validate the timestamp."""
        if not value:
            # If no timestamp, don't block but log
            logger.debug("No timestamp field in form submission")
            return value

        try:
            parts = value.split(':')
            if len(parts) != 2:
                raise ValueError("Invalid format")

            timestamp_str, signature = parts
            timestamp = int(timestamp_str)

            # Verify signature
            secret = getattr(settings, 'SECRET_KEY', 'default-secret')
            expected_signature = hashlib.sha256(f"{timestamp_str}{secret}".encode()).hexdigest()[:16]

            if signature != expected_signature:
                logger.warning("Invalid timestamp signature")
                raise forms.ValidationError(
                    "Form submission failed validation.",
                    code='invalid_timestamp_signature'
                )

            # Check timing
            now = int(time.time())
            elapsed = now - timestamp

            if elapsed < MIN_FORM_TIME:
                logger.warning(
                    f"Form submitted too quickly: {elapsed}s",
                    extra={'elapsed': elapsed, 'min_time': MIN_FORM_TIME}
                )
                raise forms.ValidationError(
                    "Please wait before submitting the form.",
                    code='submission_too_fast'
                )

            if elapsed > MAX_FORM_TIME:
                logger.warning(
                    f"Form submission too old: {elapsed}s",
                    extra={'elapsed': elapsed, 'max_time': MAX_FORM_TIME}
                )
                raise forms.ValidationError(
                    "Form has expired. Please refresh and try again.",
                    code='submission_expired'
                )

        except (ValueError, TypeError) as e:
            logger.warning(f"Timestamp validation error: {e}")
            # Don't block on timestamp errors, just log
            pass

        return value


# =============================================================================
# HONEYPOT FORM MIXIN
# =============================================================================

class HoneypotFormMixin:
    """
    Form mixin that adds honeypot protection.

    Features:
    - Adds honeypot field automatically
    - Adds timestamp validation
    - Logs suspicious submissions

    Usage:
        class ContactForm(HoneypotFormMixin, forms.Form):
            name = forms.CharField()
            email = forms.EmailField()
    """

    honeypot_field_name = 'website_url'
    timestamp_field_name = 'form_time'
    use_timestamp = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Add honeypot field
        self.fields[self.honeypot_field_name] = HoneypotField()

        # Add timestamp field if enabled
        if self.use_timestamp:
            self.fields[self.timestamp_field_name] = TimestampField()

            # Set initial timestamp value
            if not self.is_bound:
                self.initial[self.timestamp_field_name] = TimestampField.generate_timestamp()


# =============================================================================
# HONEYPOT VIEW MIXIN
# =============================================================================

class HoneypotMixin:
    """
    View mixin that validates honeypot fields in POST requests.

    Features:
    - Checks for honeypot field in POST data
    - Validates form timing
    - Tracks suspicious IPs
    - Returns 403 for bot submissions

    Usage:
        class ContactView(HoneypotMixin, FormView):
            form_class = ContactForm
    """

    honeypot_field_name = 'website_url'
    timestamp_field_name = 'form_time'
    honeypot_error_response = None

    def dispatch(self, request, *args, **kwargs):
        """Check honeypot before processing request."""
        if request.method == 'POST':
            is_valid, error = self._validate_honeypot(request)
            if not is_valid:
                return self._honeypot_failure_response(request, error)

        return super().dispatch(request, *args, **kwargs)

    def _validate_honeypot(self, request: HttpRequest) -> Tuple[bool, Optional[str]]:
        """Validate honeypot fields in request."""
        # Check honeypot field
        honeypot_value = request.POST.get(self.honeypot_field_name)
        if honeypot_value:
            self._log_bot_attempt(request, 'honeypot_filled')
            return (False, "Honeypot field filled")

        # Check timestamp
        timestamp_value = request.POST.get(self.timestamp_field_name)
        if timestamp_value:
            try:
                timestamp_field = TimestampField()
                timestamp_field.clean(timestamp_value)
            except forms.ValidationError as e:
                self._log_bot_attempt(request, f'timestamp_failed: {e.code}')
                return (False, str(e.message))

        return (True, None)

    def _honeypot_failure_response(self, request: HttpRequest, error: str) -> HttpResponse:
        """Return response for honeypot failure."""
        if self.honeypot_error_response:
            return self.honeypot_error_response

        # Return generic 403 (don't reveal honeypot detection)
        return HttpResponseForbidden("Request blocked.")

    def _log_bot_attempt(self, request: HttpRequest, reason: str):
        """Log bot detection attempt."""
        ip = self._get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:200]

        logger.warning(
            f"Bot attempt detected: {reason}",
            extra={
                'ip': ip,
                'user_agent': user_agent,
                'path': request.path,
                'method': request.method,
            }
        )

        # Track suspicious IP
        self._track_suspicious_ip(ip)

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '127.0.0.1')

    def _track_suspicious_ip(self, ip: str):
        """Track suspicious IP for rate limiting."""
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
        cache_key = f'honeypot:suspicious:{ip_hash}'

        count = cache.get(cache_key, 0)
        cache.set(cache_key, count + 1, timeout=TRACKING_TIMEOUT)

        # Flag as suspicious after multiple attempts
        if count >= 3:
            flag_key = f'honeypot:blocked:{ip_hash}'
            cache.set(flag_key, True, timeout=TRACKING_TIMEOUT)
            logger.warning(f"IP flagged as bot: {ip}")


# =============================================================================
# HONEYPOT MIDDLEWARE
# =============================================================================

class HoneypotMiddleware(MiddlewareMixin):
    """
    Middleware that detects bot activity across all POST requests.

    Features:
    - Checks for known bot patterns
    - Validates request headers
    - Blocks flagged IPs
    - Tracks suspicious activity

    Configure in settings.py:
        MIDDLEWARE = [
            ...
            'core.security.honeypot.HoneypotMiddleware',
            ...
        ]

        HONEYPOT_PROTECTED_PATHS = [
            '/contact/',
            '/register/',
            '/api/auth/',
        ]
    """

    # Common bot user agent patterns
    BOT_PATTERNS = [
        'bot', 'crawler', 'spider', 'scraper',
        'curl', 'wget', 'python-requests',
        'libwww', 'httpclient', 'httpunit',
        'phantomjs', 'headless',
    ]

    # Paths to protect (if None, protect all POST requests)
    protected_paths = None

    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.protected_paths = getattr(
            settings, 'HONEYPOT_PROTECTED_PATHS', None
        )

    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Check for bot activity before processing request."""
        # Only check POST requests
        if request.method != 'POST':
            return None

        # Check if path should be protected
        if not self._should_protect(request.path):
            return None

        # Check if IP is blocked
        if self._is_ip_blocked(request):
            logger.warning(
                "Blocked bot IP attempted access",
                extra={'ip': self._get_client_ip(request), 'path': request.path}
            )
            return HttpResponseForbidden("Access denied.")

        # Check for bot patterns
        if self._is_likely_bot(request):
            self._track_bot_attempt(request, 'pattern_match')
            # Don't block immediately, just track
            pass

        return None

    def _should_protect(self, path: str) -> bool:
        """Check if path should be protected."""
        if self.protected_paths is None:
            return True

        for protected in self.protected_paths:
            if path.startswith(protected):
                return True

        return False

    def _is_ip_blocked(self, request: HttpRequest) -> bool:
        """Check if IP is in blocked list."""
        ip = self._get_client_ip(request)
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
        flag_key = f'honeypot:blocked:{ip_hash}'
        return cache.get(flag_key, False)

    def _is_likely_bot(self, request: HttpRequest) -> bool:
        """Detect likely bot based on request characteristics."""
        user_agent = request.META.get('HTTP_USER_AGENT', '').lower()

        # Check user agent patterns
        for pattern in self.BOT_PATTERNS:
            if pattern in user_agent:
                return True

        # Check for missing headers that browsers typically send
        if not request.META.get('HTTP_ACCEPT_LANGUAGE'):
            return True

        if not request.META.get('HTTP_ACCEPT'):
            return True

        # Check for suspicious header combinations
        if 'application/json' in request.META.get('HTTP_ACCEPT', '') and not user_agent:
            return True

        return False

    def _track_bot_attempt(self, request: HttpRequest, reason: str):
        """Track bot detection for analytics."""
        ip = self._get_client_ip(request)
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]

        # Increment attempt counter
        cache_key = f'honeypot:attempts:{ip_hash}'
        count = cache.get(cache_key, 0)
        cache.set(cache_key, count + 1, timeout=TRACKING_TIMEOUT)

        # Log attempt
        logger.info(
            f"Potential bot detected: {reason}",
            extra={
                'ip': ip,
                'user_agent': request.META.get('HTTP_USER_AGENT', '')[:200],
                'path': request.path,
                'attempt_count': count + 1,
            }
        )

        # Block after multiple attempts
        if count >= 5:
            flag_key = f'honeypot:blocked:{ip_hash}'
            cache.set(flag_key, True, timeout=TRACKING_TIMEOUT)
            logger.warning(f"IP auto-blocked: {ip}")

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '127.0.0.1')


# =============================================================================
# JAVASCRIPT CHALLENGE
# =============================================================================

class JavaScriptChallengeField(forms.CharField):
    """
    Hidden field that requires JavaScript to fill.
    Bots without JS execution will fail validation.

    The field value is set by JavaScript on page load.
    """

    widget = forms.HiddenInput

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('required', False)
        super().__init__(*args, **kwargs)

    @staticmethod
    def get_challenge_script(field_name: str, challenge_value: str) -> str:
        """
        Generate JavaScript to set the challenge field.

        Include this script in your template:
            {{ form.get_challenge_script }}
        """
        return f"""
        <script>
            document.addEventListener('DOMContentLoaded', function() {{
                var field = document.querySelector('[name="{field_name}"]');
                if (field) {{
                    field.value = "{challenge_value}";
                }}
            }});
        </script>
        """

    @staticmethod
    def generate_challenge() -> str:
        """Generate challenge value that JS must set."""
        timestamp = str(int(time.time()))
        secret = getattr(settings, 'SECRET_KEY', 'default-secret')[:10]
        return hashlib.sha256(f"js:{timestamp}:{secret}".encode()).hexdigest()[:16]

    def clean(self, value):
        """Validate that JS challenge was completed."""
        expected = self.generate_challenge()

        # Allow some time drift
        for offset in range(0, MAX_FORM_TIME, 60):
            timestamp = str(int(time.time()) - offset)
            secret = getattr(settings, 'SECRET_KEY', 'default-secret')[:10]
            possible = hashlib.sha256(f"js:{timestamp}:{secret}".encode()).hexdigest()[:16]
            if value == possible:
                return value

        if not value:
            logger.warning("JS challenge field empty (possible bot)")
            raise forms.ValidationError(
                "Please enable JavaScript to submit this form.",
                code='js_required'
            )

        logger.warning("JS challenge validation failed")
        raise forms.ValidationError(
            "Form validation failed. Please try again.",
            code='js_challenge_failed'
        )


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def is_ip_suspicious(ip: str) -> bool:
    """
    Check if an IP is flagged as suspicious.

    Args:
        ip: IP address to check

    Returns:
        True if IP is suspicious
    """
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
    cache_key = f'honeypot:suspicious:{ip_hash}'
    count = cache.get(cache_key, 0)
    return count >= 3


def is_ip_blocked(ip: str) -> bool:
    """
    Check if an IP is blocked.

    Args:
        ip: IP address to check

    Returns:
        True if IP is blocked
    """
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
    flag_key = f'honeypot:blocked:{ip_hash}'
    return cache.get(flag_key, False)


def block_ip(ip: str, duration: int = None):
    """
    Block an IP address.

    Args:
        ip: IP address to block
        duration: Block duration in seconds (default: TRACKING_TIMEOUT)
    """
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
    flag_key = f'honeypot:blocked:{ip_hash}'
    cache.set(flag_key, True, timeout=duration or TRACKING_TIMEOUT)
    logger.info(f"IP manually blocked: {ip}")


def unblock_ip(ip: str):
    """
    Unblock an IP address.

    Args:
        ip: IP address to unblock
    """
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
    flag_key = f'honeypot:blocked:{ip_hash}'
    cache.delete(flag_key)

    # Also clear suspicious counter
    cache_key = f'honeypot:suspicious:{ip_hash}'
    cache.delete(cache_key)

    logger.info(f"IP unblocked: {ip}")


def get_bot_stats() -> Dict[str, Any]:
    """
    Get statistics about bot detection.

    Returns:
        Dict with bot detection statistics
    """
    # This is a simple implementation
    # In production, use proper analytics/monitoring

    today = timezone.now().date().isoformat()
    stats_key = f'honeypot:stats:{today}'
    stats = cache.get(stats_key, {
        'attempts': 0,
        'blocked': 0,
        'honeypot_triggered': 0,
        'timing_violations': 0,
    })

    return stats


def record_bot_stat(stat_type: str):
    """
    Record a bot detection statistic.

    Args:
        stat_type: Type of stat (attempts, blocked, honeypot_triggered, timing_violations)
    """
    today = timezone.now().date().isoformat()
    stats_key = f'honeypot:stats:{today}'
    stats = cache.get(stats_key, {
        'attempts': 0,
        'blocked': 0,
        'honeypot_triggered': 0,
        'timing_violations': 0,
    })

    if stat_type in stats:
        stats[stat_type] += 1
        cache.set(stats_key, stats, timeout=86400 * 7)  # Keep for 7 days
