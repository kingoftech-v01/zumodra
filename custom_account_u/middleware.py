from django.shortcuts import redirect
from django.urls import reverse
from allauth.mfa.utils import is_mfa_enabled
from django.utils.deprecation import MiddlewareMixin

import time
import logging
from zumodra import settings
from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.core.mail import send_mail
import requests  # For webhooks
from django.contrib.admin.views.decorators import staff_member_required
from django.urls import path
from django.shortcuts import render



class Require2FAMiddleware(MiddlewareMixin):
    allowed_urls = [
        'account_logout',
        'account_login',
        'account_signup',
        'account_reauthenticate',
        'mfa_activate_totp',
        'mfa_reauthenticate',
        'mfa_generate_recovery_codes',
        'mfa_recovery_code_used',
        'account_reset_password',
        'account_reset_password_done',
        'account_reset_password_from_key',
        'account_reset_password_from_key_done',
        'account_email',
        'account_email_verification_sent',
        'account_confirm_email',
    ]

    def process_view(self, request, view_func, view_args, view_kwargs):
        if request.user.is_authenticated and not is_mfa_enabled(request.user):
            if request.resolver_match and request.resolver_match.url_name not in self.allowed_urls:
                return redirect(reverse('mfa_activate_totp'))
        return None

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
