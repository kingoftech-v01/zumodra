"""
Security Middleware for Authentication Protection.

This middleware provides rate limiting and blocking for failed authentication attempts.
It uses IP-based blocking only (not MAC or User-Agent) as those are trivially spoofed.

SECURITY NOTES:
- MAC addresses are NOT accessible via HTTP in web contexts and MUST NOT be trusted
- User-Agent headers are easily spoofed and MUST NOT be used for security decisions
- Only IP-based blocking is reliable (with proper X-Forwarded-For handling)
"""
import time
import logging
from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.core.mail import send_mail
import requests

logger = logging.getLogger('auth_security')


def get_client_ip(request):
    """
    Get client IP address with proper X-Forwarded-For handling.

    SECURITY: Only trust X-Forwarded-For if behind a trusted proxy.
    Configure SECURITY_TRUSTED_PROXY_COUNT in settings.
    """
    trusted_proxy_count = getattr(settings, 'SECURITY_TRUSTED_PROXY_COUNT', 0)

    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for and trusted_proxy_count > 0:
        # X-Forwarded-For is a comma-separated list, rightmost is closest to server
        # We trust only the entries added by our trusted proxies
        ips = [ip.strip() for ip in x_forwarded_for.split(',')]
        if len(ips) >= trusted_proxy_count:
            # Get the IP added by the first trusted proxy
            return ips[-trusted_proxy_count]
        return ips[0]

    # Fall back to REMOTE_ADDR (direct connection)
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def notify_admin(subject, message):
    """Send security alert notifications via email and webhook."""
    # Email notification
    if hasattr(settings, "ADMIN_EMAIL_LIST") and settings.ADMIN_EMAIL_LIST:
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                settings.ADMIN_EMAIL_LIST,
                fail_silently=True
            )
        except Exception as e:
            logger.error(f"Email notification failed: {e}")

    # Webhook notification
    if hasattr(settings, "SECURITY_ALERT_WEBHOOK") and settings.SECURITY_ALERT_WEBHOOK:
        try:
            requests.post(
                settings.SECURITY_ALERT_WEBHOOK,
                json={"subject": subject, "message": message},
                timeout=5
            )
        except Exception as e:
            logger.error(f"Webhook notification failed: {e}")


def integrate_firewall_block(ip):
    """
    Hook for firewall integration.
    Override this in production to integrate with your firewall API.
    """
    logger.warning(f"Firewall block requested for IP: {ip}")
    # Example: requests.get(f"https://firewall.local/api/block?ip={ip}")


class AuthSecurityMiddleware:
    """
    Middleware to block IPs after too many failed authentication attempts.

    Features:
    - Blocks for configurable duration on repeated failures (default: 48 hours)
    - Logs and tracks attempts by IP only (secure, not spoofable)
    - Can be extended for alerting via email/webhook

    SECURITY:
    - Only uses IP for blocking (MAC/User-Agent are NOT used - they are spoofable)
    - Properly handles X-Forwarded-For with trusted proxy count
    - Uses server-side session/JWT for actual authentication, not headers
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.fail_limit = getattr(settings, 'AUTH_FAIL_LIMIT', 5)
        self.block_duration = getattr(settings, 'AUTH_BLOCK_DURATION', 48 * 3600)  # 48 hours
        self.attack_window = getattr(settings, 'ATTACK_WINDOW', 300)  # 5 minutes

    def __call__(self, request):
        ip = get_client_ip(request)

        # Only apply to authentication endpoints
        login_url = getattr(settings, 'LOGIN_URL', '/accounts/login/')
        if request.path == login_url and request.method == "POST":
            if self.is_ip_blocked(ip):
                logger.warning(f"Blocked login attempt from IP: {ip}")
                return HttpResponseForbidden(
                    "Too many failed attempts from your IP address. "
                    "Please try again after 48 hours or contact support."
                )

        response = self.get_response(request)

        # Track failed/successful logins
        if request.path == login_url and request.method == "POST":
            if response.status_code != 200:
                self.on_login_fail(ip, request)
            else:
                self.on_login_success(ip)

        return response

    def get_cache_key(self, prefix, identifier):
        """Generate cache key with prefix."""
        return f"auth_security:{prefix}:{identifier}"

    def is_ip_blocked(self, ip):
        """Check if IP is currently blocked."""
        return cache.get(self.get_cache_key("blocked_ip", ip), False)

    def on_login_fail(self, ip, request):
        """Handle failed login attempt."""
        fail_key = self.get_cache_key("fail_count", ip)
        fails = cache.get(fail_key, 0) + 1
        cache.set(fail_key, fails, self.block_duration)

        username = request.POST.get('username', 'unknown')
        logger.info(f"Failed login: IP={ip} count={fails} user={username}")

        # Block if limit exceeded
        if fails >= self.fail_limit:
            blocked_key = self.get_cache_key("blocked_ip", ip)
            if not cache.get(blocked_key):
                cache.set(blocked_key, True, self.block_duration)
                logger.critical(f"BLOCKED IP: {ip} after {fails} failed attempts at {time.ctime()}")

                # Send admin notification
                subject = f"SECURITY ALERT: IP Blocked - {ip}"
                msg = (
                    f"IP Address {ip} has been blocked for 48 hours "
                    f"after {fails} failed login attempts.\n\n"
                    f"Last attempted username: {username}\n"
                    f"Time: {time.ctime()}"
                )
                notify_admin(subject, msg)

                # Optional firewall integration
                integrate_firewall_block(ip)

    def on_login_success(self, ip):
        """Clear failure count on successful login."""
        cache.delete(self.get_cache_key("fail_count", ip))


class RateLimitMiddleware:
    """
    General rate limiting middleware for API endpoints.

    Uses IP-based rate limiting with proper X-Forwarded-For handling.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.rate_limit = getattr(settings, 'API_RATE_LIMIT', 100)  # requests per minute
        self.rate_window = getattr(settings, 'API_RATE_WINDOW', 60)  # 1 minute

    def __call__(self, request):
        # Only apply to API endpoints
        if not request.path.startswith('/api/'):
            return self.get_response(request)

        ip = get_client_ip(request)
        cache_key = f"rate_limit:{ip}"

        requests_made = cache.get(cache_key, 0)

        if requests_made >= self.rate_limit:
            logger.warning(f"Rate limit exceeded for IP: {ip}")
            return HttpResponseForbidden(
                "Rate limit exceeded. Please slow down your requests."
            )

        cache.set(cache_key, requests_made + 1, self.rate_window)

        return self.get_response(request)


# Admin dashboard for security monitoring (staff only)
from django.contrib.admin.views.decorators import staff_member_required
from django.shortcuts import render


@staff_member_required
def security_dashboard(request):
    """
    Security dashboard for staff to view blocked IPs.

    NOTE: In production, use a proper database model for persistent storage
    instead of cache keys which may be ephemeral.
    """
    # This is a simplified example - in production use a proper model
    context = {
        'blocked_count': 'Use database model for production',
        'recent_blocks': [],
    }
    return render(request, "security/dashboard.html", context)
