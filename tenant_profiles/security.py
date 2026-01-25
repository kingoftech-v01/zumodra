"""
Accounts Security - Comprehensive Security Utilities for Multi-Tenant SaaS

This module implements:

PASSWORD SECURITY:
- PasswordPolicy: Configurable password policy enforcement
- PasswordStrengthValidator: Django-compatible password validator
- PasswordHistory: Prevent password reuse

BRUTE FORCE PROTECTION:
- BruteForceProtection: Login attempt tracking and lockout
- IPBlacklist: Automatic IP blocking

SUSPICIOUS ACTIVITY DETECTION:
- SuspiciousActivityDetector: Detect anomalous behavior
- RiskScorer: Calculate risk scores for actions

SECURITY EVENT LOGGING:
- SecurityEventLogger: Comprehensive security audit logging
- SecurityEventType: Event type definitions

SECURITY UTILITIES:
- SecureTokenGenerator: Cryptographically secure token generation
- InputSanitizer: Input sanitization utilities
- SecurityHeaders: Security header utilities
"""

import re
import hashlib
import secrets
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

User = get_user_model()


# =============================================================================
# PASSWORD POLICY
# =============================================================================

@dataclass
class PasswordPolicyConfig:
    """Configuration for password policy."""
    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_special: bool = True
    special_characters: str = "!@#$%^&*()_+-=[]{}|;:',.<>?/`~"
    min_unique_chars: int = 8
    disallow_common_passwords: bool = True
    disallow_user_attributes: bool = True
    password_history_count: int = 5
    max_consecutive_chars: int = 3
    max_sequential_chars: int = 3


class PasswordPolicy:
    """
    Comprehensive password policy enforcement.

    Usage:
        policy = PasswordPolicy()
        is_valid, errors = policy.validate('MyPassword123!', user=user)
    """

    # Common passwords list (abbreviated - in production, use a comprehensive list)
    COMMON_PASSWORDS = {
        'password', 'password1', 'password123', '123456', '12345678',
        'qwerty', 'abc123', 'monkey', 'master', 'dragon', 'letmein',
        'login', 'admin', 'welcome', 'passw0rd', 'iloveyou',
    }

    def __init__(self, config: Optional[PasswordPolicyConfig] = None):
        self.config = config or PasswordPolicyConfig()

    def validate(self, password: str, user=None) -> Tuple[bool, List[str]]:
        """
        Validate password against policy.

        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors = []

        # Length checks
        if len(password) < self.config.min_length:
            errors.append(f'Password must be at least {self.config.min_length} characters long.')

        if len(password) > self.config.max_length:
            errors.append(f'Password must not exceed {self.config.max_length} characters.')

        # Character type checks
        if self.config.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append('Password must contain at least one uppercase letter.')

        if self.config.require_lowercase and not re.search(r'[a-z]', password):
            errors.append('Password must contain at least one lowercase letter.')

        if self.config.require_digit and not re.search(r'\d', password):
            errors.append('Password must contain at least one digit.')

        if self.config.require_special:
            special_pattern = f'[{re.escape(self.config.special_characters)}]'
            if not re.search(special_pattern, password):
                errors.append('Password must contain at least one special character.')

        # Unique characters check
        if len(set(password)) < self.config.min_unique_chars:
            errors.append(f'Password must contain at least {self.config.min_unique_chars} unique characters.')

        # Common password check
        if self.config.disallow_common_passwords:
            if password.lower() in self.COMMON_PASSWORDS:
                errors.append('This password is too common.')

        # User attribute check
        if self.config.disallow_user_attributes and user:
            user_attrs = self._get_user_attributes(user)
            password_lower = password.lower()
            for attr in user_attrs:
                if attr and len(attr) >= 3 and attr.lower() in password_lower:
                    errors.append('Password cannot contain your personal information.')
                    break

        # Consecutive character check
        if self.config.max_consecutive_chars:
            if self._has_consecutive_chars(password, self.config.max_consecutive_chars):
                errors.append(f'Password cannot have more than {self.config.max_consecutive_chars} consecutive identical characters.')

        # Sequential character check
        if self.config.max_sequential_chars:
            if self._has_sequential_chars(password, self.config.max_sequential_chars):
                errors.append(f'Password cannot have more than {self.config.max_sequential_chars} sequential characters (e.g., abc, 123).')

        return (len(errors) == 0, errors)

    def _get_user_attributes(self, user) -> List[str]:
        """Extract user attributes to check against password."""
        attrs = []
        if hasattr(user, 'email'):
            email_parts = user.email.split('@')
            attrs.append(email_parts[0])
            if len(email_parts) > 1:
                domain_parts = email_parts[1].split('.')
                attrs.extend(domain_parts)
        if hasattr(user, 'first_name'):
            attrs.append(user.first_name)
        if hasattr(user, 'last_name'):
            attrs.append(user.last_name)
        if hasattr(user, 'username'):
            attrs.append(user.username)
        return [a for a in attrs if a]

    def _has_consecutive_chars(self, password: str, max_consecutive: int) -> bool:
        """Check for consecutive identical characters."""
        count = 1
        for i in range(1, len(password)):
            if password[i] == password[i - 1]:
                count += 1
                if count > max_consecutive:
                    return True
            else:
                count = 1
        return False

    def _has_sequential_chars(self, password: str, max_sequential: int) -> bool:
        """Check for sequential characters (abc, 123, etc.)."""
        password_lower = password.lower()

        for i in range(len(password_lower) - max_sequential):
            seq = password_lower[i:i + max_sequential + 1]

            # Check ascending sequence
            is_ascending = all(
                ord(seq[j + 1]) == ord(seq[j]) + 1
                for j in range(len(seq) - 1)
            )
            # Check descending sequence
            is_descending = all(
                ord(seq[j + 1]) == ord(seq[j]) - 1
                for j in range(len(seq) - 1)
            )

            if is_ascending or is_descending:
                return True

        return False

    def get_strength_score(self, password: str) -> int:
        """
        Calculate password strength score (0-100).
        """
        score = 0

        # Length scoring
        score += min(25, len(password) * 2)

        # Character diversity
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'\d', password):
            score += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            score += 15

        # Unique characters
        unique_ratio = len(set(password)) / len(password) if password else 0
        score += int(unique_ratio * 20)

        # Penalties
        if password.lower() in self.COMMON_PASSWORDS:
            score -= 30

        return max(0, min(100, score))


class PasswordStrengthValidator:
    """
    Django-compatible password validator.

    Add to AUTH_PASSWORD_VALIDATORS in settings.py:
        {
            'NAME': 'tenant_profiles.security.PasswordStrengthValidator',
            'OPTIONS': {
                'min_length': 12,
            }
        }
    """

    def __init__(self, min_length=12, **kwargs):
        config = PasswordPolicyConfig(min_length=min_length, **kwargs)
        self.policy = PasswordPolicy(config)

    def validate(self, password, user=None):
        is_valid, errors = self.policy.validate(password, user)
        if not is_valid:
            raise ValidationError(errors)

    def get_help_text(self):
        return _(
            f'Your password must be at least {self.policy.config.min_length} characters '
            'and contain uppercase, lowercase, digits, and special characters.'
        )


class PasswordHistory:
    """
    Track password history to prevent reuse.
    Uses Django's password hashing for secure storage with backward compatibility.
    """

    CACHE_PREFIX = 'password_history:'
    MAX_HISTORY = 10
    # Marker to identify new secure hashes vs legacy SHA256
    SECURE_HASH_PREFIX = 'django:'

    @classmethod
    def add_password(cls, user_id: int, password: str):
        """
        Add password to history using Django's secure hashing.

        Args:
            user_id: The user's ID
            password: The raw password (will be hashed securely)
        """
        from django.contrib.auth.hashers import make_password

        cache_key = f"{cls.CACHE_PREFIX}{user_id}"
        history = cache.get(cache_key) or []

        # Use Django's secure password hashing
        secure_hash = f"{cls.SECURE_HASH_PREFIX}{make_password(password)}"

        history.insert(0, {
            'hash': secure_hash,
            'created_at': timezone.now().isoformat(),
            'hash_version': 2  # Version 2 = Django make_password
        })

        # Keep only last N passwords
        history = history[:cls.MAX_HISTORY]

        # Store for 2 years
        cache.set(cache_key, history, timeout=2 * 365 * 24 * 60 * 60)

    @classmethod
    def check_password(cls, user_id: int, password: str, count: int = 5) -> bool:
        """
        Check if password was recently used.
        Supports both legacy SHA256 hashes and new Django password hashes.

        Args:
            user_id: The user's ID
            password: The raw password to check
            count: Number of recent passwords to check against

        Returns:
            True if password is in recent history (not allowed)
        """
        from django.contrib.auth.hashers import check_password as django_check_password

        cache_key = f"{cls.CACHE_PREFIX}{user_id}"
        history = cache.get(cache_key) or []

        # Also compute legacy hash for backward compatibility
        legacy_hash = cls._hash_password_legacy(password)

        for entry in history[:count]:
            stored_hash = entry.get('hash', '')
            hash_version = entry.get('hash_version', 1)

            if hash_version >= 2 or stored_hash.startswith(cls.SECURE_HASH_PREFIX):
                # New secure hash - use Django's check_password
                django_hash = stored_hash.replace(cls.SECURE_HASH_PREFIX, '', 1)
                if django_check_password(password, django_hash):
                    return True
            else:
                # Legacy SHA256 hash - maintain backward compatibility
                if stored_hash == legacy_hash:
                    return True

        return False

    @classmethod
    def _hash_password_legacy(cls, password: str) -> str:
        """
        Legacy SHA256 hash for backward compatibility only.
        DO NOT use for new password storage.
        """
        return hashlib.sha256(password.encode()).hexdigest()

    @classmethod
    def migrate_legacy_hashes(cls, user_id: int, password: str):
        """
        Migrate legacy SHA256 hash to secure Django hash if found.
        Call this during successful password validation to upgrade storage.

        Args:
            user_id: The user's ID
            password: The validated password
        """
        from django.contrib.auth.hashers import make_password

        cache_key = f"{cls.CACHE_PREFIX}{user_id}"
        history = cache.get(cache_key) or []
        legacy_hash = cls._hash_password_legacy(password)
        modified = False

        for entry in history:
            if entry.get('hash') == legacy_hash and entry.get('hash_version', 1) == 1:
                # Upgrade legacy hash to secure hash
                entry['hash'] = f"{cls.SECURE_HASH_PREFIX}{make_password(password)}"
                entry['hash_version'] = 2
                entry['migrated_at'] = timezone.now().isoformat()
                modified = True
                break

        if modified:
            cache.set(cache_key, history, timeout=2 * 365 * 24 * 60 * 60)


# =============================================================================
# BRUTE FORCE PROTECTION
# =============================================================================

class CaptchaConfig:
    """
    CAPTCHA configuration for brute force protection.
    Configure via Django settings.
    """

    # Number of failed attempts before requiring CAPTCHA
    CAPTCHA_THRESHOLD = 3

    # Supported CAPTCHA providers
    PROVIDER_RECAPTCHA_V2 = 'recaptcha_v2'
    PROVIDER_RECAPTCHA_V3 = 'recaptcha_v3'
    PROVIDER_HCAPTCHA = 'hcaptcha'
    PROVIDER_TURNSTILE = 'turnstile'  # Cloudflare Turnstile

    @classmethod
    def is_enabled(cls) -> bool:
        """Check if CAPTCHA is enabled."""
        return getattr(settings, 'SECURITY_CAPTCHA_ENABLED', False)

    @classmethod
    def get_provider(cls) -> str:
        """Get configured CAPTCHA provider."""
        return getattr(settings, 'SECURITY_CAPTCHA_PROVIDER', cls.PROVIDER_RECAPTCHA_V2)

    @classmethod
    def get_site_key(cls) -> str:
        """Get CAPTCHA site key."""
        return getattr(settings, 'SECURITY_CAPTCHA_SITE_KEY', '')

    @classmethod
    def get_secret_key(cls) -> str:
        """Get CAPTCHA secret key."""
        return getattr(settings, 'SECURITY_CAPTCHA_SECRET_KEY', '')

    @classmethod
    def get_threshold(cls) -> int:
        """Get number of attempts before CAPTCHA is required."""
        return getattr(settings, 'SECURITY_CAPTCHA_THRESHOLD', cls.CAPTCHA_THRESHOLD)

    @classmethod
    def verify_captcha(cls, token: str, ip_address: str = None) -> Tuple[bool, str]:
        """
        Verify CAPTCHA token with provider.

        Args:
            token: The CAPTCHA response token from client
            ip_address: Client IP for additional validation

        Returns:
            Tuple of (is_valid, error_message)
        """
        import logging
        import requests
        logger = logging.getLogger('security')

        if not cls.is_enabled():
            return (True, '')

        if not token:
            return (False, 'CAPTCHA token required')

        provider = cls.get_provider()
        secret_key = cls.get_secret_key()

        try:
            if provider in [cls.PROVIDER_RECAPTCHA_V2, cls.PROVIDER_RECAPTCHA_V3]:
                verify_url = 'https://www.google.com/recaptcha/api/siteverify'
                data = {
                    'secret': secret_key,
                    'response': token,
                }
                if ip_address:
                    data['remoteip'] = ip_address

            elif provider == cls.PROVIDER_HCAPTCHA:
                verify_url = 'https://hcaptcha.com/siteverify'
                data = {
                    'secret': secret_key,
                    'response': token,
                }
                if ip_address:
                    data['remoteip'] = ip_address

            elif provider == cls.PROVIDER_TURNSTILE:
                verify_url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
                data = {
                    'secret': secret_key,
                    'response': token,
                }
                if ip_address:
                    data['remoteip'] = ip_address

            else:
                logger.error(f"Unknown CAPTCHA provider: {provider}")
                return (False, 'CAPTCHA configuration error')

            response = requests.post(verify_url, data=data, timeout=10)
            result = response.json()

            if result.get('success'):
                logger.info("CAPTCHA verification successful")
                return (True, '')
            else:
                error_codes = result.get('error-codes', [])
                logger.warning(f"CAPTCHA verification failed: {error_codes}")
                return (False, 'CAPTCHA verification failed')

        except requests.RequestException as e:
            logger.error(f"CAPTCHA verification request failed: {e}")
            # Fail open to prevent blocking legitimate users during outages
            # Consider failing closed in high-security environments
            return (True, '')
        except Exception as e:
            logger.error(f"CAPTCHA verification error: {e}")
            return (False, 'CAPTCHA verification error')


class BruteForceProtection:
    """
    Protection against brute force attacks.

    Features:
    - Track failed login attempts per user and IP
    - Progressive lockout durations
    - Automatic IP blocking for severe abuse
    - CAPTCHA integration after threshold attempts
    - Account lockout notifications
    """

    CACHE_PREFIX = 'brute_force:'
    MAX_ATTEMPTS = 5
    LOCKOUT_DURATION = 15 * 60  # 15 minutes
    PROGRESSIVE_LOCKOUT = [60, 300, 900, 3600, 86400]  # 1min, 5min, 15min, 1hr, 1day
    IP_BLOCK_THRESHOLD = 20  # Block IP after this many failed attempts

    @classmethod
    def record_failed_attempt(
        cls,
        identifier: str,
        ip_address: str = None,
        user_email: str = None
    ) -> Dict[str, Any]:
        """
        Record a failed login attempt.

        Args:
            identifier: User ID, email, or username
            ip_address: Client IP address
            user_email: User's email for lockout notifications

        Returns:
            Dict with lockout status, remaining attempts, and CAPTCHA requirements
        """
        import logging
        logger = logging.getLogger('security')

        # Track by identifier
        user_key = f"{cls.CACHE_PREFIX}user:{identifier}"
        user_data = cache.get(user_key) or {'attempts': 0, 'first_attempt': None}

        user_data['attempts'] += 1
        if not user_data['first_attempt']:
            user_data['first_attempt'] = timezone.now().isoformat()
        user_data['last_attempt'] = timezone.now().isoformat()

        cache.set(user_key, user_data, timeout=cls.LOCKOUT_DURATION)

        # Track by IP
        if ip_address:
            ip_key = f"{cls.CACHE_PREFIX}ip:{ip_address}"
            ip_data = cache.get(ip_key) or {'attempts': 0}
            ip_data['attempts'] += 1
            cache.set(ip_key, ip_data, timeout=cls.LOCKOUT_DURATION)

            # Check for IP block threshold
            if ip_data['attempts'] >= cls.IP_BLOCK_THRESHOLD:
                IPBlacklist.block_ip(ip_address, reason='Brute force attack detected')

        # Calculate lockout
        is_locked = user_data['attempts'] >= cls.MAX_ATTEMPTS
        lockout_index = min(user_data['attempts'] - cls.MAX_ATTEMPTS, len(cls.PROGRESSIVE_LOCKOUT) - 1)
        lockout_duration = cls.PROGRESSIVE_LOCKOUT[max(0, lockout_index)] if is_locked else 0

        # Check if CAPTCHA is required
        captcha_threshold = CaptchaConfig.get_threshold()
        requires_captcha = (
            CaptchaConfig.is_enabled() and
            user_data['attempts'] >= captcha_threshold and
            not is_locked
        )

        if is_locked:
            lock_key = f"{cls.CACHE_PREFIX}locked:{identifier}"
            cache.set(lock_key, True, timeout=lockout_duration)

            # Send lockout notification
            cls._send_lockout_notification(
                identifier=identifier,
                user_email=user_email,
                ip_address=ip_address,
                attempts=user_data['attempts'],
                lockout_duration=lockout_duration
            )

            # Log security event
            logger.warning(
                f"Account locked due to brute force attempts",
                extra={
                    'identifier': identifier,
                    'ip_address': ip_address,
                    'attempts': user_data['attempts'],
                    'lockout_duration': lockout_duration
                }
            )

        return {
            'is_locked': is_locked,
            'attempts': user_data['attempts'],
            'remaining_attempts': max(0, cls.MAX_ATTEMPTS - user_data['attempts']),
            'lockout_duration': lockout_duration,
            'lockout_until': (timezone.now() + timedelta(seconds=lockout_duration)).isoformat() if is_locked else None,
            'requires_captcha': requires_captcha,
            'captcha_site_key': CaptchaConfig.get_site_key() if requires_captcha else None,
            'captcha_provider': CaptchaConfig.get_provider() if requires_captcha else None
        }

    @classmethod
    def _send_lockout_notification(
        cls,
        identifier: str,
        user_email: str = None,
        ip_address: str = None,
        attempts: int = 0,
        lockout_duration: int = 0
    ):
        """
        Send notification when account is locked out.

        Args:
            identifier: User identifier
            user_email: Email to send notification to
            ip_address: IP that triggered lockout
            attempts: Number of failed attempts
            lockout_duration: Lockout duration in seconds
        """
        import logging
        logger = logging.getLogger('security')

        # Check if notifications are enabled
        if not getattr(settings, 'SECURITY_LOCKOUT_NOTIFICATION_ENABLED', True):
            return

        if not user_email:
            # Try to find email from identifier
            try:
                user = User.objects.filter(email=identifier).first()
                if user:
                    user_email = user.email
            except Exception:
                pass

        if not user_email:
            logger.debug(f"No email for lockout notification: {identifier}")
            return

        try:
            from django.core.mail import send_mail
            from django.template.loader import render_to_string

            lockout_minutes = lockout_duration // 60

            # Try to render email template, fall back to plain text
            try:
                html_message = render_to_string('accounts/email/lockout_notification.html', {
                    'attempts': attempts,
                    'ip_address': ip_address,
                    'lockout_minutes': lockout_minutes,
                    'timestamp': timezone.now(),
                })
                plain_message = None
            except Exception:
                html_message = None
                plain_message = (
                    f"Security Alert: Your account has been temporarily locked.\n\n"
                    f"There were {attempts} failed login attempts from IP address {ip_address}.\n"
                    f"Your account will be unlocked in {lockout_minutes} minutes.\n\n"
                    f"If this was not you, please secure your account by changing your password.\n"
                )

            send_mail(
                subject='Security Alert: Account Temporarily Locked',
                message=plain_message or '',
                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com'),
                recipient_list=[user_email],
                html_message=html_message,
                fail_silently=True,
            )

            logger.info(f"Lockout notification sent to {user_email}")

        except Exception as e:
            logger.error(f"Failed to send lockout notification: {e}")

    @classmethod
    def validate_captcha_if_required(
        cls,
        identifier: str,
        captcha_token: str = None,
        ip_address: str = None
    ) -> Tuple[bool, str]:
        """
        Check if CAPTCHA is required and validate it.

        Args:
            identifier: User identifier
            captcha_token: CAPTCHA response token from client
            ip_address: Client IP

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not CaptchaConfig.is_enabled():
            return (True, '')

        user_key = f"{cls.CACHE_PREFIX}user:{identifier}"
        user_data = cache.get(user_key)

        if not user_data:
            return (True, '')

        attempts = user_data.get('attempts', 0)
        captcha_threshold = CaptchaConfig.get_threshold()

        if attempts >= captcha_threshold:
            if not captcha_token:
                return (False, 'CAPTCHA verification required')
            return CaptchaConfig.verify_captcha(captcha_token, ip_address)

        return (True, '')

    @classmethod
    def is_locked(cls, identifier: str) -> Tuple[bool, Optional[int]]:
        """
        Check if identifier is locked out.

        Returns:
            Tuple of (is_locked, seconds_remaining)
        """
        lock_key = f"{cls.CACHE_PREFIX}locked:{identifier}"
        is_locked = cache.get(lock_key) is True

        if is_locked:
            # Get TTL
            user_key = f"{cls.CACHE_PREFIX}user:{identifier}"
            ttl = cache.ttl(user_key) if hasattr(cache, 'ttl') else cls.LOCKOUT_DURATION
            return (True, ttl)

        return (False, None)

    @classmethod
    def clear_attempts(cls, identifier: str):
        """
        Clear failed attempts after successful login.
        """
        cache.delete(f"{cls.CACHE_PREFIX}user:{identifier}")
        cache.delete(f"{cls.CACHE_PREFIX}locked:{identifier}")

    @classmethod
    def get_attempt_count(cls, identifier: str) -> int:
        """
        Get current attempt count for identifier.
        """
        user_key = f"{cls.CACHE_PREFIX}user:{identifier}"
        data = cache.get(user_key)
        return data['attempts'] if data else 0


class IPBlacklist:
    """
    IP address blacklist management.
    """

    CACHE_PREFIX = 'ip_blacklist:'
    DEFAULT_BLOCK_DURATION = 24 * 60 * 60  # 24 hours

    @classmethod
    def block_ip(cls, ip_address: str, reason: str = '', duration: int = None):
        """
        Block an IP address.
        """
        cache_key = f"{cls.CACHE_PREFIX}{ip_address}"
        block_duration = duration or cls.DEFAULT_BLOCK_DURATION

        cache.set(
            cache_key,
            {
                'blocked_at': timezone.now().isoformat(),
                'reason': reason,
                'duration': block_duration
            },
            timeout=block_duration
        )

        # Log the block
        SecurityEventLogger.log_event(
            event_type='ip_blocked',
            ip_address=ip_address,
            details={'reason': reason, 'duration': block_duration}
        )

    @classmethod
    def is_blocked(cls, ip_address: str) -> Tuple[bool, Optional[str]]:
        """
        Check if IP is blocked.

        Returns:
            Tuple of (is_blocked, reason)
        """
        cache_key = f"{cls.CACHE_PREFIX}{ip_address}"
        data = cache.get(cache_key)

        if data:
            return (True, data.get('reason', ''))

        return (False, None)

    @classmethod
    def unblock_ip(cls, ip_address: str):
        """
        Remove IP from blacklist.
        """
        cache_key = f"{cls.CACHE_PREFIX}{ip_address}"
        cache.delete(cache_key)

    @classmethod
    def get_blocked_ips(cls) -> List[Dict]:
        """
        Get list of currently blocked IPs.
        Note: This requires cache backend that supports key scanning.
        """
        # This is a simplified implementation
        # In production, you might want to store blocked IPs in database
        return []


# =============================================================================
# TRUSTED PROXY CONFIGURATION
# =============================================================================

class TrustedProxyConfig:
    """
    Configuration for trusted proxy validation.
    Prevents X-Forwarded-For header spoofing attacks.
    """

    # Number of trusted proxies between client and server
    # Set via settings.SECURITY_TRUSTED_PROXY_COUNT or default to 1
    DEFAULT_TRUSTED_PROXY_COUNT = 1

    # List of trusted proxy IP ranges (e.g., internal load balancers)
    # Set via settings.SECURITY_TRUSTED_PROXY_IPS
    DEFAULT_TRUSTED_PROXY_IPS = []

    @classmethod
    def get_trusted_proxy_count(cls) -> int:
        """Get configured number of trusted proxies."""
        return getattr(settings, 'SECURITY_TRUSTED_PROXY_COUNT', cls.DEFAULT_TRUSTED_PROXY_COUNT)

    @classmethod
    def get_trusted_proxy_ips(cls) -> List[str]:
        """Get list of trusted proxy IP addresses/ranges."""
        return getattr(settings, 'SECURITY_TRUSTED_PROXY_IPS', cls.DEFAULT_TRUSTED_PROXY_IPS)

    @classmethod
    def is_trusted_proxy(cls, ip_address: str) -> bool:
        """
        Check if an IP address is a trusted proxy.

        Args:
            ip_address: IP address to check

        Returns:
            True if the IP is in the trusted proxy list
        """
        trusted_ips = cls.get_trusted_proxy_ips()
        if not trusted_ips:
            return False

        try:
            check_ip = ipaddress.ip_address(ip_address)
            for trusted in trusted_ips:
                if '/' in trusted:
                    # CIDR notation
                    if check_ip in ipaddress.ip_network(trusted, strict=False):
                        return True
                else:
                    # Single IP
                    if check_ip == ipaddress.ip_address(trusted):
                        return True
        except ValueError:
            pass

        return False


def get_client_ip_secure(request, trusted_proxy_count: int = None) -> str:
    """
    Securely extract client IP from request with proxy validation.

    This function properly handles X-Forwarded-For headers when behind
    a known number of trusted proxies, preventing IP spoofing attacks.

    Args:
        request: The HTTP request object
        trusted_proxy_count: Number of trusted proxies (defaults to config)

    Returns:
        The client's IP address

    Security Notes:
        - X-Forwarded-For can be spoofed by clients
        - Only trust IPs from known proxy positions
        - Use REMOTE_ADDR as fallback (always reliable but may be proxy IP)
    """
    import logging
    logger = logging.getLogger('security')

    if trusted_proxy_count is None:
        trusted_proxy_count = TrustedProxyConfig.get_trusted_proxy_count()

    remote_addr = request.META.get('REMOTE_ADDR', '')
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', '')

    if not x_forwarded_for:
        # No proxy headers, use direct connection IP
        return remote_addr

    # Parse X-Forwarded-For header
    # Format: "client, proxy1, proxy2, ..." (rightmost is closest to server)
    forwarded_ips = [ip.strip() for ip in x_forwarded_for.split(',')]

    # Validate header structure
    if len(forwarded_ips) < trusted_proxy_count:
        # Header has fewer IPs than expected proxies - possible manipulation
        logger.warning(
            f"X-Forwarded-For header has fewer IPs than trusted proxy count",
            extra={
                'x_forwarded_for': x_forwarded_for,
                'trusted_proxy_count': trusted_proxy_count,
                'remote_addr': remote_addr
            }
        )
        # Fall back to REMOTE_ADDR for safety
        return remote_addr

    # Validate that rightmost IPs match trusted proxies (if configured)
    trusted_proxy_ips = TrustedProxyConfig.get_trusted_proxy_ips()
    if trusted_proxy_ips:
        # Check the rightmost IPs are from trusted proxies
        for i in range(1, min(trusted_proxy_count + 1, len(forwarded_ips))):
            proxy_ip = forwarded_ips[-i]
            if not TrustedProxyConfig.is_trusted_proxy(proxy_ip):
                logger.warning(
                    f"X-Forwarded-For contains untrusted proxy IP",
                    extra={
                        'untrusted_ip': proxy_ip,
                        'position': i,
                        'x_forwarded_for': x_forwarded_for
                    }
                )
                # Don't trust the header chain
                return remote_addr

    # Extract client IP: skip the rightmost N IPs (proxies)
    # Client IP is at position -(trusted_proxy_count + 1) from the end
    client_ip_index = -(trusted_proxy_count + 1)

    try:
        # If index goes beyond list, use leftmost (original client)
        if abs(client_ip_index) > len(forwarded_ips):
            client_ip = forwarded_ips[0]
        else:
            client_ip = forwarded_ips[client_ip_index]

        # Validate IP format
        ipaddress.ip_address(client_ip)
        return client_ip

    except (IndexError, ValueError) as e:
        logger.warning(
            f"Invalid IP in X-Forwarded-For header",
            extra={
                'error': str(e),
                'x_forwarded_for': x_forwarded_for
            }
        )
        return remote_addr


# =============================================================================
# SUSPICIOUS ACTIVITY DETECTION
# =============================================================================

class SuspiciousActivityType(Enum):
    """Types of suspicious activity."""
    MULTIPLE_FAILED_LOGINS = 'multiple_failed_logins'
    UNUSUAL_LOCATION = 'unusual_location'
    UNUSUAL_TIME = 'unusual_time'
    RAPID_REQUESTS = 'rapid_requests'
    SENSITIVE_DATA_ACCESS = 'sensitive_data_access'
    PRIVILEGE_ESCALATION = 'privilege_escalation'
    UNUSUAL_DEVICE = 'unusual_device'
    IMPOSSIBLE_TRAVEL = 'impossible_travel'


class SuspiciousActivityDetector:
    """
    Detect and flag suspicious user activity.
    """

    CACHE_PREFIX = 'suspicious_activity:'

    @classmethod
    def check_login(cls, user, request) -> Dict[str, Any]:
        """
        Check for suspicious login activity.

        Returns:
            Dict with risk assessment
        """
        risks = []
        risk_score = 0

        ip_address = cls._get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        # Check for unusual location
        if cls._is_unusual_location(user, ip_address):
            risks.append(SuspiciousActivityType.UNUSUAL_LOCATION)
            risk_score += 30

        # Check for unusual time
        if cls._is_unusual_time(user):
            risks.append(SuspiciousActivityType.UNUSUAL_TIME)
            risk_score += 10

        # Check for unusual device
        if cls._is_unusual_device(user, user_agent):
            risks.append(SuspiciousActivityType.UNUSUAL_DEVICE)
            risk_score += 20

        # Check for impossible travel
        if cls._is_impossible_travel(user, ip_address):
            risks.append(SuspiciousActivityType.IMPOSSIBLE_TRAVEL)
            risk_score += 50

        # Log if suspicious
        if risks:
            SecurityEventLogger.log_event(
                event_type='suspicious_login',
                user=user,
                ip_address=ip_address,
                details={
                    'risks': [r.value for r in risks],
                    'risk_score': risk_score,
                    'user_agent': user_agent[:200]
                }
            )

        return {
            'is_suspicious': len(risks) > 0,
            'risks': risks,
            'risk_score': risk_score,
            'requires_2fa': risk_score >= 30,
            'requires_verification': risk_score >= 50
        }

    @classmethod
    def _is_unusual_location(cls, user, ip_address: str) -> bool:
        """Check if login is from unusual location."""
        # Get user's known locations
        cache_key = f"{cls.CACHE_PREFIX}locations:{user.id}"
        known_locations = cache.get(cache_key) or set()

        try:
            # Use first two octets for rough location grouping
            ip_prefix = '.'.join(ip_address.split('.')[:2])
            is_unusual = ip_prefix not in known_locations

            # Add to known locations
            known_locations.add(ip_prefix)
            cache.set(cache_key, known_locations, timeout=90 * 24 * 60 * 60)  # 90 days

            # First login is not suspicious
            if len(known_locations) == 1:
                return False

            return is_unusual
        except Exception:
            return False

    @classmethod
    def _is_unusual_time(cls, user) -> bool:
        """Check if login is at unusual time for user."""
        current_hour = timezone.now().hour

        # Get user's typical login hours
        cache_key = f"{cls.CACHE_PREFIX}hours:{user.id}"
        login_hours = cache.get(cache_key) or {}

        # Track login hour
        login_hours[current_hour] = login_hours.get(current_hour, 0) + 1
        cache.set(cache_key, login_hours, timeout=90 * 24 * 60 * 60)

        # Need enough data
        total_logins = sum(login_hours.values())
        if total_logins < 10:
            return False

        # Check if current hour is rare
        hour_frequency = login_hours.get(current_hour, 0) / total_logins
        return hour_frequency < 0.05  # Less than 5% of logins

    @classmethod
    def _is_unusual_device(cls, user, user_agent: str) -> bool:
        """Check if login is from unusual device."""
        device_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:16]

        cache_key = f"{cls.CACHE_PREFIX}devices:{user.id}"
        known_devices = cache.get(cache_key) or set()

        is_unusual = device_hash not in known_devices

        # Add to known devices
        known_devices.add(device_hash)
        cache.set(cache_key, known_devices, timeout=90 * 24 * 60 * 60)

        # First device is not suspicious
        if len(known_devices) == 1:
            return False

        return is_unusual

    @classmethod
    def _is_impossible_travel(cls, user, ip_address: str) -> bool:
        """Check for impossible travel (login from distant location too quickly)."""
        cache_key = f"{cls.CACHE_PREFIX}last_login:{user.id}"
        last_login = cache.get(cache_key)

        # Store current login
        cache.set(cache_key, {
            'ip': ip_address,
            'time': timezone.now().isoformat()
        }, timeout=24 * 60 * 60)

        if not last_login:
            return False

        try:
            last_time = datetime.fromisoformat(last_login['time'])
            time_diff = (timezone.now() - last_time).total_seconds() / 60  # minutes

            # If less than 60 minutes, check IP distance
            if time_diff < 60:
                last_ip_prefix = '.'.join(last_login['ip'].split('.')[:2])
                current_ip_prefix = '.'.join(ip_address.split('.')[:2])

                # Different IP prefix in short time = suspicious
                if last_ip_prefix != current_ip_prefix:
                    return True

        except Exception:
            pass

        return False

    @classmethod
    def _get_client_ip(cls, request) -> str:
        """
        Extract client IP from request using secure proxy validation.
        Uses get_client_ip_secure() for proper X-Forwarded-For handling.
        """
        return get_client_ip_secure(request)


class RiskScorer:
    """
    Calculate risk scores for various actions.
    """

    @classmethod
    def calculate_action_risk(
        cls,
        action: str,
        user,
        request,
        context: Dict = None
    ) -> Dict[str, Any]:
        """
        Calculate risk score for an action.

        Returns:
            Dict with risk score and recommendations
        """
        risk_score = 0
        risk_factors = []
        context = context or {}

        # Base risk by action type
        action_risks = {
            'password_change': 20,
            'email_change': 30,
            'delete_account': 50,
            'export_data': 25,
            'admin_action': 30,
            'financial_transaction': 40,
            'permission_change': 35,
        }
        risk_score += action_risks.get(action, 10)

        # Session age factor
        if hasattr(request, 'auth') and hasattr(request.auth, 'payload'):
            iat = request.auth.payload.get('iat')
            if iat:
                session_age = (datetime.utcnow() - datetime.fromtimestamp(iat)).total_seconds() / 60
                if session_age > 30:
                    risk_score += 10
                    risk_factors.append('old_session')

        # IP reputation (simplified)
        ip_address = cls._get_client_ip(request)
        if BruteForceProtection.get_attempt_count(ip_address) > 0:
            risk_score += 20
            risk_factors.append('suspicious_ip')

        # User history factor
        if user and user.is_authenticated:
            account_age = (timezone.now() - user.date_joined).days if hasattr(user, 'date_joined') else 365
            if account_age < 7:
                risk_score += 15
                risk_factors.append('new_account')

        # Determine recommendations
        recommendations = []
        if risk_score >= 50:
            recommendations.append('require_2fa')
            recommendations.append('require_password')
        elif risk_score >= 30:
            recommendations.append('require_2fa')

        return {
            'risk_score': min(100, risk_score),
            'risk_level': cls._get_risk_level(risk_score),
            'risk_factors': risk_factors,
            'recommendations': recommendations,
            'allow_action': risk_score < 80
        }

    @classmethod
    def _get_risk_level(cls, score: int) -> str:
        """Convert score to risk level."""
        if score < 20:
            return 'low'
        elif score < 40:
            return 'medium'
        elif score < 60:
            return 'high'
        else:
            return 'critical'

    @classmethod
    def _get_client_ip(cls, request) -> str:
        """
        Extract client IP from request using secure proxy validation.
        Uses get_client_ip_secure() for proper X-Forwarded-For handling.
        """
        return get_client_ip_secure(request)


# =============================================================================
# SECURITY EVENT LOGGING
# =============================================================================

class SecurityEventType(Enum):
    """Security event types for logging."""
    LOGIN_SUCCESS = 'login_success'
    LOGIN_FAILURE = 'login_failure'
    LOGOUT = 'logout'
    PASSWORD_CHANGE = 'password_change'
    PASSWORD_RESET_REQUEST = 'password_reset_request'
    PASSWORD_RESET_COMPLETE = 'password_reset_complete'
    MFA_ENABLED = 'mfa_enabled'
    MFA_DISABLED = 'mfa_disabled'
    MFA_CHALLENGE_SUCCESS = 'mfa_challenge_success'
    MFA_CHALLENGE_FAILURE = 'mfa_challenge_failure'
    ACCOUNT_LOCKED = 'account_locked'
    ACCOUNT_UNLOCKED = 'account_unlocked'
    SESSION_CREATED = 'session_created'
    SESSION_TERMINATED = 'session_terminated'
    PERMISSION_CHANGE = 'permission_change'
    ROLE_CHANGE = 'role_change'
    SUSPICIOUS_ACTIVITY = 'suspicious_activity'
    IP_BLOCKED = 'ip_blocked'
    DATA_EXPORT = 'data_export'
    SENSITIVE_ACCESS = 'sensitive_access'


class SecurityEventLogger:
    """
    Comprehensive security event logging.
    """

    CACHE_PREFIX = 'security_events:'

    @classmethod
    def log_event(
        cls,
        event_type: str,
        user=None,
        tenant=None,
        ip_address: str = None,
        user_agent: str = None,
        details: Dict = None,
        severity: str = 'info'
    ):
        """
        Log a security event.

        Args:
            event_type: Type of security event
            user: User involved (optional)
            tenant: Tenant context (optional)
            ip_address: Client IP address
            user_agent: User agent string
            details: Additional event details
            severity: Event severity (info, warning, error, critical)
        """
        import logging
        logger = logging.getLogger('security')

        event = {
            'event_type': event_type,
            'timestamp': timezone.now().isoformat(),
            'user_id': user.id if user else None,
            'user_email': user.email if user else None,
            'tenant_id': tenant.id if tenant else None,
            'ip_address': ip_address,
            'user_agent': user_agent[:500] if user_agent else None,
            'details': details or {},
            'severity': severity
        }

        # Log to Python logger
        log_message = f"Security Event: {event_type}"
        if user:
            log_message += f" | User: {user.email}"
        if ip_address:
            log_message += f" | IP: {ip_address}"

        log_level = {
            'info': logging.INFO,
            'warning': logging.WARNING,
            'error': logging.ERROR,
            'critical': logging.CRITICAL
        }.get(severity, logging.INFO)

        logger.log(log_level, log_message, extra=event)

        # Store in cache for recent events (last 24 hours per user)
        if user:
            cls._store_user_event(user.id, event)

        # Store for tenant audit
        if tenant:
            cls._store_tenant_event(tenant.id, event)

        # For critical events, trigger alerts
        if severity == 'critical':
            cls._trigger_alert(event)

    @classmethod
    def _store_user_event(cls, user_id: int, event: Dict):
        """Store event in user's recent events."""
        cache_key = f"{cls.CACHE_PREFIX}user:{user_id}"
        events = cache.get(cache_key) or []
        events.insert(0, event)
        events = events[:100]  # Keep last 100
        cache.set(cache_key, events, timeout=24 * 60 * 60)

    @classmethod
    def _store_tenant_event(cls, tenant_id: int, event: Dict):
        """Store event in tenant's audit log."""
        cache_key = f"{cls.CACHE_PREFIX}tenant:{tenant_id}"
        events = cache.get(cache_key) or []
        events.insert(0, event)
        events = events[:1000]  # Keep last 1000
        cache.set(cache_key, events, timeout=7 * 24 * 60 * 60)  # 7 days

    @classmethod
    def _trigger_alert(cls, event: Dict):
        """Trigger alert for critical security events."""
        # In production, this would send emails/SMS/Slack notifications
        import logging
        logger = logging.getLogger('security.alerts')
        logger.critical(f"SECURITY ALERT: {event}")

    @classmethod
    def get_user_events(cls, user_id: int, event_type: str = None) -> List[Dict]:
        """Get recent security events for user."""
        cache_key = f"{cls.CACHE_PREFIX}user:{user_id}"
        events = cache.get(cache_key) or []

        if event_type:
            events = [e for e in events if e.get('event_type') == event_type]

        return events

    @classmethod
    def get_tenant_events(cls, tenant_id: int, event_type: str = None) -> List[Dict]:
        """Get recent security events for tenant."""
        cache_key = f"{cls.CACHE_PREFIX}tenant:{tenant_id}"
        events = cache.get(cache_key) or []

        if event_type:
            events = [e for e in events if e.get('event_type') == event_type]

        return events


# =============================================================================
# SECURITY UTILITIES
# =============================================================================

class SecureTokenGenerator:
    """
    Generate cryptographically secure tokens.
    """

    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Generate URL-safe token."""
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_hex_token(length: int = 32) -> str:
        """Generate hex token."""
        return secrets.token_hex(length)

    @staticmethod
    def generate_numeric_otp(length: int = 6) -> str:
        """Generate numeric OTP."""
        return ''.join(secrets.choice('0123456789') for _ in range(length))

    @staticmethod
    def generate_alphanumeric(length: int = 8) -> str:
        """Generate alphanumeric code."""
        alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'  # Excluding confusing chars
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def hash_token(token: str) -> str:
        """Hash token for storage."""
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def verify_token(token: str, hashed: str) -> bool:
        """Verify token against hash."""
        return secrets.compare_digest(
            hashlib.sha256(token.encode()).hexdigest(),
            hashed
        )


class InputSanitizer:
    """
    Input sanitization utilities.
    """

    @staticmethod
    def sanitize_html(content: str) -> str:
        """Remove potentially dangerous HTML."""
        import html
        # Basic HTML escape
        sanitized = html.escape(content)
        return sanitized

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename for safe storage."""
        # Remove path separators and null bytes
        sanitized = filename.replace('/', '').replace('\\', '').replace('\x00', '')
        # Remove other dangerous characters
        sanitized = re.sub(r'[<>:"|?*]', '', sanitized)
        # Limit length
        if len(sanitized) > 255:
            name, ext = sanitized.rsplit('.', 1) if '.' in sanitized else (sanitized, '')
            sanitized = name[:250] + ('.' + ext if ext else '')
        return sanitized

    @staticmethod
    def sanitize_email(email: str) -> str:
        """Normalize and sanitize email."""
        return email.lower().strip()

    @staticmethod
    def is_valid_ip(ip_string: str) -> bool:
        """Check if string is valid IP address."""
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False


class SecurityHeaders:
    """
    Security header utilities for responses.
    """

    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """Get recommended security headers."""
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
        }

    @staticmethod
    def add_security_headers(response):
        """Add security headers to response."""
        for header, value in SecurityHeaders.get_security_headers().items():
            response[header] = value
        return response
