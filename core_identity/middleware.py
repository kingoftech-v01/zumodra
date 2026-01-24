"""
Core Identity Middleware

Provides:
1. Unified MFA Enforcement - 30-day grace period using allauth.mfa
2. Authentication Security - Brute force protection with IP/MAC/User-Agent tracking

Author: Zumodra Team
Date: 2026-01-17
"""

import time
import logging
from datetime import timedelta
from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.core.mail import send_mail
from django.shortcuts import redirect
from django.contrib import messages
from django.urls import reverse
from django.utils import timezone
import requests  # For webhooks
from django.contrib.admin.views.decorators import staff_member_required
from django.urls import path
from django.shortcuts import render
from core.security.audit import AuditLogger, AuditAction, AuditSeverity


logger = logging.getLogger('auth_security')


# ===================================================================
# UNIFIED MFA ENFORCEMENT MIDDLEWARE
# ===================================================================


class UnifiedMFAEnforcementMiddleware:
    """
    Single MFA enforcement middleware using ONLY allauth.mfa.

    Enforces 30-day grace period for MFA setup. Shows reminder when 7 days remaining.
    Replaces both the old MFAEnforcementMiddleware (accounts) and Require2FAMiddleware
    (custom_account_u).

    Features:
    - 30-day grace period from account creation
    - 7-day reminder before grace period expires
    - Session-based reminder (shows once per session)
    - Exempts: MFA setup pages, logout, static/media, API, health checks, superusers
    """

    EXEMPT_PATHS = [
        '/accounts/mfa/',          # MFA setup/management pages
        '/accounts/logout/',       # Logout page
        '/accounts/password/',     # Password reset pages
        '/static/',                # Static files
        '/media/',                 # Media files
        '/api/',                   # API endpoints (use JWT, not sessions)
        '/health/',                # Health check endpoints
        '/admin/',                 # Admin interface (separate protection)
        '/.well-known/',           # ACME/WebFinger/etc.
    ]

    GRACE_PERIOD_DAYS = 30     # Grace period duration
    REMINDER_DAYS = 7          # Show reminder when X days remaining

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip if not authenticated
        if not request.user.is_authenticated:
            return self.get_response(request)

        # Skip exempt paths
        if any(request.path.startswith(path) for path in self.EXEMPT_PATHS):
            return self.get_response(request)

        # Skip for superusers (emergency access)
        if request.user.is_superuser:
            return self.get_response(request)

        # Check if user has MFA enabled via allauth
        if self._user_has_mfa(request.user):
            return self.get_response(request)

        # Check if grace period has expired
        grace_expired = self._grace_period_expired(request.user)

        if grace_expired:
            messages.warning(
                request,
                'Multi-factor authentication is required for security. '
                'Please set it up now to continue using the platform.'
            )
            # Redirect to MFA setup
            try:
                return redirect(reverse('mfa_activate_totp'))
            except Exception:
                # Fallback if URL not found
                return redirect('/accounts/mfa/')

        # Grace period active - show reminder if close to deadline
        days_remaining = self._days_until_grace_expires(request.user)
        if days_remaining is not None and days_remaining <= self.REMINDER_DAYS:
            # Only show reminder once per session to avoid annoyance
            session_key = f'mfa_reminder_shown_{request.user.id}'
            if not request.session.get(session_key):
                plural = "s" if days_remaining != 1 else ""
                messages.info(
                    request,
                    f'Please set up multi-factor authentication. '
                    f'It will be required in {days_remaining} day{plural}.'
                )
                request.session[session_key] = True

        return self.get_response(request)

    def _user_has_mfa(self, user):
        """
        Check if user has MFA enabled via allauth.mfa.

        Checks for active MFA authenticators (TOTP or WebAuthn).
        """
        try:
            # Try using allauth.mfa's built-in helper
            from allauth.mfa.utils import is_mfa_enabled
            return is_mfa_enabled(user)
        except ImportError:
            # Fallback: check authenticators directly
            try:
                if hasattr(user, 'mfa_authenticators'):
                    return user.mfa_authenticators.filter(is_active=True).exists()
            except Exception:
                pass

        return False

    def _grace_period_expired(self, user):
        """
        Check if 30-day grace period has expired.

        Returns:
            bool: True if user has exceeded grace period, False otherwise
        """
        # Check if user has mfa_grace_period_end field (new CustomUser model)
        if hasattr(user, 'mfa_grace_period_end') and user.mfa_grace_period_end:
            return timezone.now() > user.mfa_grace_period_end

        # Fallback to date_joined calculation
        if not user.date_joined:
            return False

        grace_end = user.date_joined + timedelta(days=self.GRACE_PERIOD_DAYS)
        return timezone.now() > grace_end

    def _days_until_grace_expires(self, user):
        """
        Calculate days remaining in grace period.

        Returns:
            int|None: Number of days until MFA required (minimum 0), or None if unknown
        """
        # Check if user has mfa_grace_period_end field
        if hasattr(user, 'mfa_grace_period_end') and user.mfa_grace_period_end:
            delta = user.mfa_grace_period_end - timezone.now()
            return max(0, delta.days)

        # Fallback to date_joined calculation
        if not user.date_joined:
            return None

        grace_end = user.date_joined + timedelta(days=self.GRACE_PERIOD_DAYS)
        delta = grace_end - timezone.now()
        return max(0, delta.days)


# ===================================================================
# AUTHENTICATION SECURITY MIDDLEWARE
# ===================================================================

def get_mac_address(request):
    return request.META.get('HTTP_X_MAC_ADDRESS')

def get_user_agent(request):
    return request.META.get('HTTP_USER_AGENT')

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def notify_admin(subject, message):
    # Email notification
    if hasattr(settings, "ADMIN_EMAIL_LIST"):
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, settings.ADMIN_EMAIL_LIST)
    # Webhook notification
    if hasattr(settings, "SECURITY_ALERT_WEBHOOK"):
        try:
            requests.post(settings.SECURITY_ALERT_WEBHOOK, json={"subject": subject, "message": message})
        except Exception as e:
            logger.error(f"Webhook notification failed: {e}")

def integrate_firewall_block(ip):
    # Place actual integration here (API, script, etc.)
    logger.warning(f"FW BLOCK: {ip}")
    # Example: requests.get(f"https://firewall.local/api/block?ip={ip}")

class AuthSecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.fail_limit = getattr(settings, 'AUTH_FAIL_LIMIT', 5)
        self.block_duration = getattr(settings, 'AUTH_BLOCK_DURATION', 48*3600)
        self.attack_window = getattr(settings, 'ATTACK_WINDOW', 300)  # 5 minutes for rapid attacks

    def __call__(self, request):
        ip = get_client_ip(request)
        mac = get_mac_address(request)
        ua = get_user_agent(request)

        if request.path == settings.LOGIN_URL and request.method == "POST":
            if self.is_locked(ip, mac, ua):
                logger.warning(f"Blocked login attempt: IP={ip} MAC={mac} UA={ua}")
                return HttpResponseForbidden("Too many failed attempts from your address. Wait 48 hours.")

        response = self.get_response(request)

        if request.path == settings.LOGIN_URL and request.method == "POST":
            if response.status_code != 200:
                self.on_fail(ip, mac, ua, request)
            else:
                self.clear_failures(ip, mac, ua, request)
        return response

    def get_cache_key(self, prefix, identifier):
        return f"{prefix}_{identifier}"

    def is_locked(self, ip, mac, ua):
        return any([
            cache.get(self.get_cache_key("blocked_ip", ip)),
            mac and cache.get(self.get_cache_key("blocked_mac", mac)),
            ua and cache.get(self.get_cache_key("blocked_ua", ua))
        ])

    def on_fail(self, ip, mac, ua, request):
        username_attempted = request.POST.get('username', '') or request.POST.get('login', '')

        # Log failed login attempt in audit system
        AuditLogger.log_authentication(
            action=AuditAction.LOGIN_FAILED,
            user=None,
            request=request,
            success=False,
            extra_data={
                'username_attempted': username_attempted,
                'ip_address': ip,
                'mac_address': mac,
                'user_agent': ua,
            }
        )

        for ident, val in {'ip': ip, 'mac': mac, 'ua': ua}.items():
            if val:
                k = self.get_cache_key(f'fail_{ident}', val)
                fails = cache.get(k, 0) + 1
                cache.set(k, fails, self.block_duration)
                logger.info(f"Failed login: {ident.upper()}={val} count={fails} User={username_attempted}")

                # Persistent/rapid attack detection and alert
                if fails >= self.fail_limit:
                    blocked_key = self.get_cache_key(f"blocked_{ident}", val)
                    already_blocked = cache.get(blocked_key)
                    if not already_blocked:
                        cache.set(blocked_key, True, self.block_duration)
                        logger.critical(f"BLOCKED: {ident.upper()}={val} - Triggered at {time.ctime()}")

                        # Log security event in audit system
                        AuditLogger.log_security_event(
                            event_type='brute_force_block',
                            description=f"{ident.upper()} {val} blocked for 48h after {fails} failed login attempts",
                            user=None,
                            request=request,
                            severity=AuditSeverity.CRITICAL,
                            extra_data={
                                'identifier_type': ident,
                                'identifier_value': val,
                                'failed_attempts': fails,
                                'block_duration_hours': 48,
                            }
                        )

                        subject = f"ALERT: {ident.upper()} BLOCKED"
                        msg = f"{ident.upper()} {val} blocked for 48h after {fails} failed attempts."
                        notify_admin(subject, msg)
                        if ident == "ip":
                            integrate_firewall_block(val)

    def clear_failures(self, ip, mac, ua, request):
        # Log successful login in audit system
        if request.user.is_authenticated:
            AuditLogger.log_authentication(
                action=AuditAction.LOGIN,
                user=request.user,
                request=request,
                success=True,
                extra_data={
                    'ip_address': ip,
                    'mac_address': mac,
                    'user_agent': ua,
                }
            )

        for ident, val in {'ip': ip, 'mac': mac, 'ua': ua}.items():
            if val:
                cache.delete(self.get_cache_key(f'fail_{ident}', val))
        username = request.POST.get("username") or request.POST.get("login")
        if username:
            cache.delete(self.get_cache_key('fail_user', username))


# --- Admin Dashboard Endpoint Example ---

@staff_member_required
def security_dashboard(request):
    # Review currently blocked and failed IP/MAC/UA (shows sampled keys, assume small data for demo!)
    blocked = []
    for prefix in ['blocked_ip', 'blocked_mac', 'blocked_ua']:
        # In production, use a dedicated model for persistent/large datasets
        example_keys = cache._cache.keys(f"{prefix}_*")
        for k in example_keys:
            if cache.get(k):
                blocked.append(k.replace(f"{prefix}_", '').upper())
    context = {'blocked': blocked}
    return render(request, "security_dashboard.html", context)

# Add this to your urls.py for staff admin visibility
urlpatterns = [
    path("admin/security-dashboard/", security_dashboard, name="security_dashboard"),
]

# Ensure LOGGING and email/webhook settings are set in settings.py, for example:
# LOGGING = {
#     'version': 1,
#     'handlers': {'console': {'class': 'logging.StreamHandler'}},
#     'loggers': {'auth_security': {'handlers': ['console'], 'level': 'INFO'}}
# }
# ADMIN_EMAIL_LIST = ["admin@example.com"]
# DEFAULT_FROM_EMAIL = "noreply@example.com"
# SECURITY_ALERT_WEBHOOK = "https://webhook.site/abcde123"


# ===================================================================
# WAITLIST ENFORCEMENT MIDDLEWARE
# ===================================================================


class WaitlistEnforcementMiddleware:
    """
    Enforce waitlist access restrictions before platform launch.

    Features:
    - Redirects waitlisted users to countdown page
    - Allows access after platform launch date
    - Exempts admin, static files, and essential paths
    - Automatically updates user status when platform launches

    Configuration:
    - Set launch date in PlatformLaunch model via admin
    - Enable/disable waitlist system dynamically
    - Manual launch override available
    """

    EXEMPT_PATHS = [
        '/accounts/waitlist/countdown/',  # Countdown page itself
        '/accounts/logout/',              # Allow logout
        '/accounts/password/',            # Password reset
        '/static/',                       # Static files
        '/media/',                        # Media files
        '/api/v1/waitlist/status/',       # API to check waitlist status
        '/.well-known/',                  # ACME, WebFinger, etc.
        '/health/',                       # Health check endpoints
        '/admin/',                        # Admin interface (admins always access)
    ]

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip if not authenticated
        if not request.user.is_authenticated:
            return self.get_response(request)

        # Skip exempt paths
        if any(request.path.startswith(path) for path in self.EXEMPT_PATHS):
            return self.get_response(request)

        # Skip for superusers (admin always has access)
        if request.user.is_superuser:
            return self.get_response(request)

        # Get platform launch configuration
        from core_identity.models import PlatformLaunch
        try:
            launch_config = PlatformLaunch.get_config()
        except Exception as e:
            logger.error(f"Failed to get PlatformLaunch config: {e}")
            # If config fails, allow access (fail open for safety)
            return self.get_response(request)

        # Check if waitlist is disabled or platform has launched
        if not launch_config.waitlist_enabled or launch_config.is_platform_launched:
            # Platform is accessible - auto-update user status if needed
            if request.user.is_waitlisted:
                try:
                    request.user.is_waitlisted = False
                    request.user.save(update_fields=['is_waitlisted'])
                    logger.info(f"User {request.user.email} auto-granted access (platform launched)")
                except Exception as e:
                    logger.error(f"Failed to update user waitlist status: {e}")

            return self.get_response(request)

        # Check if user is waitlisted
        if request.user.is_waitlisted:
            # Redirect to countdown page
            messages.info(
                request,
                'Welcome! The platform will launch soon. You\'ll be automatically granted access on launch day.'
            )
            return redirect(reverse('core_identity:waitlist_countdown'))

        # User is not waitlisted - allow access
        return self.get_response(request)
