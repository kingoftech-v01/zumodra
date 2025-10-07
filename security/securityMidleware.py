import time
import logging
from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.core.mail import send_mail
import requests  # For webhooks
from django.contrib.admin.views.decorators import staff_member_required
from django.urls import path
from django.shortcuts import render

logger = logging.getLogger('auth_security')

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
        for ident, val in {'ip': ip, 'mac': mac, 'ua': ua}.items():
            if val:
                k = self.get_cache_key(f'fail_{ident}', val)
                fails = cache.get(k, 0) + 1
                cache.set(k, fails, self.block_duration)
                logger.info(f"Failed login: {ident.upper()}={val} count={fails} User={request.POST.get('username', '')}")
                
                # Persistent/rapid attack detection and alert
                if fails >= self.fail_limit:
                    blocked_key = self.get_cache_key(f"blocked_{ident}", val)
                    already_blocked = cache.get(blocked_key)
                    if not already_blocked:
                        cache.set(blocked_key, True, self.block_duration)
                        logger.critical(f"BLOCKED: {ident.upper()}={val} - Triggered at {time.ctime()}")
                        subject = f"ALERT: {ident.upper()} BLOCKED"
                        msg = f"{ident.upper()} {val} blocked for 48h after {fails} failed attempts."
                        notify_admin(subject, msg)
                        if ident == "ip":
                            integrate_firewall_block(val)

    def clear_failures(self, ip, mac, ua, request):
        for ident, val in {'ip': ip, 'mac': mac, 'ua': ua}.items():
            if val:
                cache.delete(self.get_cache_key(f'fail_{ident}', val))
        username = request.POST.get("username")
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



import time
from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseForbidden

# Optional: Helper to extract MAC address (this is only realistic for intranet/local setups, in web context this is ineffective)
def get_mac_address(request):
    # Realistically, MAC address is not accessible via HTTP requests.
    # Placeholder for scenarios like trusted internal networks.
    return request.META.get('HTTP_X_MAC_ADDRESS')

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

class AuthSecurityMiddleware:
    """
    Middleware to block IPs and optionally MAC addresses after too many failed authentication attempts.
    Features:
    - Blocks for 48 hours on repeated failure (configurable)
    - Logs and tracks attempts by IP, (optionally) by MAC and username
    - Can be extended for further auditing and alerting
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.fail_limit = getattr(settings, 'AUTH_FAIL_LIMIT', 5)
        self.block_duration = getattr(settings, 'AUTH_BLOCK_DURATION', 48*3600)  # 48 hours

    def __call__(self, request):
        ip = get_client_ip(request)
        mac = get_mac_address(request)  # Real effect only possible with special setups

        # Only block authentication endpoints (e.g. login)
        if request.path == settings.LOGIN_URL and request.method == "POST":
            # Check for locked IP or MAC address
            if self.is_locked(ip, mac):
                return HttpResponseForbidden("Too many failed attempts from your IP or MAC. Try again after 48 hours.")

        response = self.get_response(request)

        # Check for failed authentication (status not 200)
        if request.path == settings.LOGIN_URL and request.method == "POST":
            if response.status_code != 200:
                self.on_fail(ip, mac, request)
            else:
                self.clear_failures(ip, mac, request)
        return response

    def get_cache_key(self, prefix, identifier):
        return f"{prefix}_{identifier}"

    def is_locked(self, ip, mac):
        ip_locked = cache.get(self.get_cache_key("blocked_ip", ip))
        if ip_locked:
            return True
        if mac:
            mac_locked = cache.get(self.get_cache_key("blocked_mac", mac))
            if mac_locked:
                return True
        return False

    def on_fail(self, ip, mac, request):
        # Increment IP failure count
        key_ip = self.get_cache_key('fail_ip', ip)
        fails_ip = cache.get(key_ip, 0) + 1
        cache.set(key_ip, fails_ip, self.block_duration)

        # Optional: Increment MAC failure count
        if mac:
            key_mac = self.get_cache_key('fail_mac', mac)
            fails_mac = cache.get(key_mac, 0) + 1
            cache.set(key_mac, fails_mac, self.block_duration)

        # Optional: Per-username limits (prefers POST['username'])
        username = request.POST.get("username")
        if username:
            key_user = self.get_cache_key('fail_user', username)
            fails_user = cache.get(key_user, 0) + 1
            cache.set(key_user, fails_user, self.block_duration)

        # Block if threshold exceeded
        if fails_ip >= self.fail_limit:
            cache.set(self.get_cache_key("blocked_ip", ip), True, timeout=self.block_duration)
        if mac and fails_mac >= self.fail_limit:
            cache.set(self.get_cache_key("blocked_mac", mac), True, timeout=self.block_duration)
        if username and fails_user >= self.fail_limit:
            cache.set(self.get_cache_key("blocked_user", username), True, timeout=self.block_duration)

    def clear_failures(self, ip, mac, request):
        # On a successful login, clear failure history
        cache.delete(self.get_cache_key('fail_ip', ip))
        if mac:
            cache.delete(self.get_cache_key('fail_mac', mac))
        username = request.POST.get("username")
        if username:
            cache.delete(self.get_cache_key('fail_user', username))

# In settings.py, add:
# MIDDLEWARE.append('yourapp.security_middleware.AuthSecurityMiddleware')
# LOGIN_URL = "/login"  # Or your actual login URL
# AUTH_FAIL_LIMIT = 5
# AUTH_BLOCK_DURATION = 48*3600  # 48 hours

# Make sure Django cache is properly configured for production!
