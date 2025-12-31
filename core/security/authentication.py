"""
Authentication Security Module for Zumodra

Provides comprehensive authentication security features including:
- MFA Service (TOTP, backup codes, SMS fallback)
- Session Security Manager (concurrent session limits, session binding)
- Password Validator (NIST 800-63B compliant)
- Brute Force Protection (progressive delays, CAPTCHA triggers)
- JWT Security Enhancer (short expiry, refresh token rotation, token binding)

All components are tenant-aware and integrate with the security logging system.
"""

import base64
import hashlib
import hmac
import io
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse
from django.utils import timezone
from django.utils.crypto import constant_time_compare, get_random_string

from .owasp import SecurityEvent, SecurityEventLogger, SecurityEventType

logger = logging.getLogger('security.authentication')
User = get_user_model()


# =============================================================================
# MFA Service
# =============================================================================

class MFAMethod(Enum):
    """Supported MFA methods."""
    TOTP = 'totp'
    BACKUP_CODE = 'backup_code'
    SMS = 'sms'
    EMAIL = 'email'


@dataclass
class MFAConfig:
    """MFA configuration for a user."""
    user_id: str
    enabled: bool = False
    primary_method: MFAMethod = MFAMethod.TOTP
    totp_secret: Optional[str] = None
    backup_codes: List[str] = field(default_factory=list)
    phone_number: Optional[str] = None
    email: Optional[str] = None
    verified_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None


class MFAService:
    """
    Multi-Factor Authentication service supporting TOTP, backup codes, and SMS.

    Implements secure MFA with proper secret handling and verification.
    """

    # TOTP settings
    TOTP_INTERVAL = 30  # seconds
    TOTP_DIGITS = 6
    TOTP_ALGORITHM = 'SHA1'
    TOTP_WINDOW = 1  # Allow 1 step before/after for clock drift

    # Backup code settings
    BACKUP_CODE_COUNT = 10
    BACKUP_CODE_LENGTH = 8

    # SMS settings
    SMS_CODE_LENGTH = 6
    SMS_CODE_EXPIRY = 300  # 5 minutes

    # Rate limiting
    MAX_VERIFICATION_ATTEMPTS = 5
    ATTEMPT_WINDOW = 300  # 5 minutes

    def __init__(self):
        self.logger = SecurityEventLogger()
        self.cache_prefix = 'mfa:'

    def generate_totp_secret(self) -> str:
        """
        Generate a new TOTP secret.

        Returns:
            Base32-encoded secret
        """
        # Generate 160-bit secret (20 bytes)
        secret_bytes = secrets.token_bytes(20)
        return base64.b32encode(secret_bytes).decode('ascii')

    def get_totp_provisioning_uri(
        self,
        secret: str,
        email: str,
        issuer: str = None
    ) -> str:
        """
        Generate TOTP provisioning URI for QR code.

        Args:
            secret: The TOTP secret
            email: User's email
            issuer: Service name (default: from settings)

        Returns:
            otpauth:// URI for QR code generation
        """
        issuer = issuer or getattr(settings, 'SITE_NAME', 'Zumodra')
        # URL encode the parameters
        from urllib.parse import quote

        return (
            f"otpauth://totp/{quote(issuer)}:{quote(email)}"
            f"?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm={self.TOTP_ALGORITHM}&digits={self.TOTP_DIGITS}"
            f"&period={self.TOTP_INTERVAL}"
        )

    def generate_qr_code(self, provisioning_uri: str) -> bytes:
        """
        Generate QR code image for TOTP setup.

        Args:
            provisioning_uri: The otpauth:// URI

        Returns:
            PNG image bytes
        """
        try:
            import qrcode
            from qrcode.constants import ERROR_CORRECT_L

            qr = qrcode.QRCode(
                version=1,
                error_correction=ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(provisioning_uri)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")

            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            return buffer.getvalue()

        except ImportError:
            logger.warning('qrcode library not installed')
            return b''

    def verify_totp(
        self,
        secret: str,
        code: str,
        user_id: str = None,
        request: HttpRequest = None
    ) -> Tuple[bool, str]:
        """
        Verify a TOTP code.

        Args:
            secret: The user's TOTP secret
            code: The code to verify
            user_id: User ID for rate limiting
            request: Optional request for logging

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Rate limiting check
        if user_id and not self._check_rate_limit(user_id, 'totp'):
            return False, 'Too many verification attempts'

        # Clean the code
        code = re.sub(r'\s', '', code)

        if not code.isdigit() or len(code) != self.TOTP_DIGITS:
            return False, 'Invalid code format'

        # Calculate current TOTP
        try:
            current_time = int(time.time())

            # Check current and adjacent time windows
            for offset in range(-self.TOTP_WINDOW, self.TOTP_WINDOW + 1):
                time_counter = (current_time // self.TOTP_INTERVAL) + offset
                expected_code = self._generate_totp(secret, time_counter)

                if constant_time_compare(code, expected_code):
                    # Prevent replay attacks
                    if self._check_totp_replay(user_id, time_counter):
                        return False, 'Code already used'

                    self._mark_totp_used(user_id, time_counter)
                    self._clear_rate_limit(user_id, 'totp')

                    self._log_mfa_success(user_id, MFAMethod.TOTP, request)
                    return True, ''

            self._increment_rate_limit(user_id, 'totp')
            self._log_mfa_failure(user_id, MFAMethod.TOTP, request)
            return False, 'Invalid code'

        except Exception as e:
            logger.error(f'TOTP verification error: {e}')
            return False, 'Verification failed'

    def _generate_totp(self, secret: str, time_counter: int) -> str:
        """Generate TOTP code for a given time counter."""
        # Decode secret
        try:
            secret_bytes = base64.b32decode(secret.upper() + '=' * (8 - len(secret) % 8))
        except Exception:
            secret_bytes = base64.b32decode(secret.upper())

        # Time counter as 8-byte big-endian
        time_bytes = time_counter.to_bytes(8, byteorder='big')

        # HMAC-SHA1
        hmac_result = hmac.new(secret_bytes, time_bytes, hashlib.sha1).digest()

        # Dynamic truncation
        offset = hmac_result[-1] & 0x0F
        code_int = (
            ((hmac_result[offset] & 0x7F) << 24) |
            ((hmac_result[offset + 1] & 0xFF) << 16) |
            ((hmac_result[offset + 2] & 0xFF) << 8) |
            (hmac_result[offset + 3] & 0xFF)
        )

        # Get 6-digit code
        code = str(code_int % (10 ** self.TOTP_DIGITS))
        return code.zfill(self.TOTP_DIGITS)

    def generate_backup_codes(self) -> List[str]:
        """
        Generate a set of backup codes.

        Returns:
            List of backup codes
        """
        codes = []
        for _ in range(self.BACKUP_CODE_COUNT):
            # Generate code in format XXXX-XXXX
            code = get_random_string(self.BACKUP_CODE_LENGTH, 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789')
            formatted = f"{code[:4]}-{code[4:]}"
            codes.append(formatted)
        return codes

    def hash_backup_code(self, code: str) -> str:
        """
        Hash a backup code for storage.

        Args:
            code: The backup code

        Returns:
            Hashed code
        """
        # Normalize code
        code = code.upper().replace('-', '').replace(' ', '')
        return hashlib.sha256(code.encode()).hexdigest()

    def verify_backup_code(
        self,
        code: str,
        stored_hashes: List[str],
        user_id: str = None,
        request: HttpRequest = None
    ) -> Tuple[bool, Optional[int]]:
        """
        Verify a backup code and return its index for removal.

        Args:
            code: The code to verify
            stored_hashes: List of hashed backup codes
            user_id: User ID for logging
            request: Optional request for logging

        Returns:
            Tuple of (is_valid, index of used code or None)
        """
        code_hash = self.hash_backup_code(code)

        for i, stored_hash in enumerate(stored_hashes):
            if constant_time_compare(code_hash, stored_hash):
                self._log_mfa_success(user_id, MFAMethod.BACKUP_CODE, request)
                return True, i

        self._log_mfa_failure(user_id, MFAMethod.BACKUP_CODE, request)
        return False, None

    def send_sms_code(
        self,
        phone_number: str,
        user_id: str,
        tenant_id: str = None
    ) -> Tuple[bool, str]:
        """
        Generate and send SMS verification code.

        Args:
            phone_number: Phone number to send to
            user_id: User ID for tracking
            tenant_id: Tenant ID for context

        Returns:
            Tuple of (success, message)
        """
        # Rate limit SMS sending
        sms_key = f"{self.cache_prefix}sms_sent:{user_id}"
        if cache.get(sms_key):
            return False, 'Please wait before requesting another code'

        # Generate code
        code = ''.join(secrets.choice('0123456789') for _ in range(self.SMS_CODE_LENGTH))

        # Store code with expiry
        code_key = f"{self.cache_prefix}sms_code:{user_id}"
        cache.set(code_key, self._hash_sms_code(code), self.SMS_CODE_EXPIRY)

        # Rate limit flag
        cache.set(sms_key, True, 60)  # 1 minute between SMS

        # Send SMS
        try:
            self._send_sms(phone_number, f'Your verification code is: {code}')
            return True, 'Verification code sent'
        except Exception as e:
            logger.error(f'Failed to send SMS: {e}')
            cache.delete(code_key)
            return False, 'Failed to send verification code'

    def verify_sms_code(
        self,
        code: str,
        user_id: str,
        request: HttpRequest = None
    ) -> Tuple[bool, str]:
        """
        Verify an SMS code.

        Args:
            code: The code to verify
            user_id: User ID
            request: Optional request for logging

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Rate limiting
        if not self._check_rate_limit(user_id, 'sms'):
            return False, 'Too many verification attempts'

        code_key = f"{self.cache_prefix}sms_code:{user_id}"
        stored_hash = cache.get(code_key)

        if not stored_hash:
            return False, 'Code expired or not found'

        code = re.sub(r'\s', '', code)
        if constant_time_compare(self._hash_sms_code(code), stored_hash):
            cache.delete(code_key)
            self._clear_rate_limit(user_id, 'sms')
            self._log_mfa_success(user_id, MFAMethod.SMS, request)
            return True, ''

        self._increment_rate_limit(user_id, 'sms')
        self._log_mfa_failure(user_id, MFAMethod.SMS, request)
        return False, 'Invalid code'

    def _hash_sms_code(self, code: str) -> str:
        """Hash an SMS code."""
        return hashlib.sha256(code.encode()).hexdigest()

    def _send_sms(self, phone_number: str, message: str):
        """Send SMS via configured provider."""
        # Twilio integration
        account_sid = getattr(settings, 'TWILIO_ACCOUNT_SID', '')
        auth_token = getattr(settings, 'TWILIO_AUTH_TOKEN', '')
        from_number = getattr(settings, 'TWILIO_PHONE_NUMBER', '')

        if not all([account_sid, auth_token, from_number]):
            raise ValueError('Twilio not configured')

        try:
            from twilio.rest import Client
            client = Client(account_sid, auth_token)
            client.messages.create(
                body=message,
                from_=from_number,
                to=phone_number
            )
        except ImportError:
            raise ValueError('Twilio library not installed')

    def _check_rate_limit(self, user_id: str, method: str) -> bool:
        """Check if user is within rate limit."""
        key = f"{self.cache_prefix}attempts:{method}:{user_id}"
        attempts = cache.get(key, 0)
        return attempts < self.MAX_VERIFICATION_ATTEMPTS

    def _increment_rate_limit(self, user_id: str, method: str):
        """Increment rate limit counter."""
        key = f"{self.cache_prefix}attempts:{method}:{user_id}"
        attempts = cache.get(key, 0) + 1
        cache.set(key, attempts, self.ATTEMPT_WINDOW)

    def _clear_rate_limit(self, user_id: str, method: str):
        """Clear rate limit counter."""
        key = f"{self.cache_prefix}attempts:{method}:{user_id}"
        cache.delete(key)

    def _check_totp_replay(self, user_id: str, time_counter: int) -> bool:
        """Check if TOTP code was already used (replay attack)."""
        key = f"{self.cache_prefix}totp_used:{user_id}:{time_counter}"
        return cache.get(key) is not None

    def _mark_totp_used(self, user_id: str, time_counter: int):
        """Mark TOTP time counter as used."""
        key = f"{self.cache_prefix}totp_used:{user_id}:{time_counter}"
        cache.set(key, True, self.TOTP_INTERVAL * 3)  # Keep for 3 intervals

    def _log_mfa_success(
        self,
        user_id: str,
        method: MFAMethod,
        request: HttpRequest = None
    ):
        """Log successful MFA verification."""
        event = SecurityEvent(
            event_type=SecurityEventType.LOGIN_SUCCESS,
            severity='info',
            message=f'MFA verification successful via {method.value}',
            user_id=user_id,
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', '') if request else None,
            details={'mfa_method': method.value}
        )
        self.logger.log(event)

    def _log_mfa_failure(
        self,
        user_id: str,
        method: MFAMethod,
        request: HttpRequest = None
    ):
        """Log failed MFA verification."""
        event = SecurityEvent(
            event_type=SecurityEventType.LOGIN_FAILURE,
            severity='medium',
            message=f'MFA verification failed via {method.value}',
            user_id=user_id,
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', '') if request else None,
            details={'mfa_method': method.value}
        )
        self.logger.log(event)


# =============================================================================
# Session Security Manager
# =============================================================================

class SessionSecurityManager:
    """
    Manages session security including concurrent session limits and session binding.

    Provides protection against session hijacking and unauthorized concurrent access.
    """

    CACHE_PREFIX = 'session_security:'
    DEFAULT_MAX_CONCURRENT_SESSIONS = 3
    SESSION_BIND_IP = True
    SESSION_BIND_USER_AGENT = True

    def __init__(self):
        self.logger = SecurityEventLogger()
        self.max_sessions = getattr(
            settings, 'MAX_CONCURRENT_SESSIONS',
            self.DEFAULT_MAX_CONCURRENT_SESSIONS
        )
        self.bind_ip = getattr(settings, 'SESSION_BIND_IP', self.SESSION_BIND_IP)
        self.bind_user_agent = getattr(
            settings, 'SESSION_BIND_USER_AGENT',
            self.SESSION_BIND_USER_AGENT
        )

    def create_session(
        self,
        user,
        session_key: str,
        request: HttpRequest
    ) -> Tuple[bool, str]:
        """
        Create and register a new session.

        Args:
            user: The authenticated user
            session_key: Django session key
            request: The HTTP request

        Returns:
            Tuple of (success, message)
        """
        user_id = str(user.id)
        tenant_id = self._get_tenant_id(request)

        # Get existing sessions
        sessions = self._get_user_sessions(user_id)

        # Check concurrent limit
        if len(sessions) >= self.max_sessions:
            # Remove oldest session
            oldest = min(sessions, key=lambda s: s.get('created_at', ''))
            self._remove_session(user_id, oldest['session_key'])
            sessions = [s for s in sessions if s['session_key'] != oldest['session_key']]

        # Create session binding data
        session_data = {
            'session_key': session_key,
            'ip_address': self._get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', '')[:500],
            'created_at': timezone.now().isoformat(),
            'last_activity': timezone.now().isoformat(),
            'tenant_id': tenant_id,
        }

        # Calculate binding hash
        session_data['binding_hash'] = self._calculate_binding_hash(session_data)

        # Store session
        sessions.append(session_data)
        self._store_user_sessions(user_id, sessions)

        return True, 'Session created'

    def validate_session(
        self,
        user,
        session_key: str,
        request: HttpRequest
    ) -> Tuple[bool, str]:
        """
        Validate a session against binding rules.

        Args:
            user: The authenticated user
            session_key: Django session key
            request: The HTTP request

        Returns:
            Tuple of (is_valid, error_message)
        """
        user_id = str(user.id)
        sessions = self._get_user_sessions(user_id)

        # Find session
        session = next(
            (s for s in sessions if s['session_key'] == session_key),
            None
        )

        if not session:
            return False, 'Session not found'

        # Validate IP binding
        if self.bind_ip:
            current_ip = self._get_client_ip(request)
            stored_ip = session.get('ip_address')

            if stored_ip and current_ip != stored_ip:
                self._log_session_hijack_attempt(user_id, session_key, 'ip_mismatch', request)
                return False, 'IP address mismatch'

        # Validate User-Agent binding
        if self.bind_user_agent:
            current_ua = request.META.get('HTTP_USER_AGENT', '')
            stored_ua = session.get('user_agent', '')

            # Allow minor UA changes (browser updates) but detect major changes
            if stored_ua and not self._user_agent_compatible(stored_ua, current_ua):
                self._log_session_hijack_attempt(user_id, session_key, 'ua_mismatch', request)
                return False, 'User agent mismatch'

        # Update last activity
        session['last_activity'] = timezone.now().isoformat()
        self._store_user_sessions(user_id, sessions)

        return True, ''

    def end_session(self, user, session_key: str):
        """
        End a specific session.

        Args:
            user: The user
            session_key: Session to end
        """
        user_id = str(user.id)
        self._remove_session(user_id, session_key)

    def end_all_sessions(self, user, except_current: str = None):
        """
        End all sessions for a user.

        Args:
            user: The user
            except_current: Session key to keep
        """
        user_id = str(user.id)

        if except_current:
            sessions = self._get_user_sessions(user_id)
            sessions = [s for s in sessions if s['session_key'] == except_current]
            self._store_user_sessions(user_id, sessions)
        else:
            self._clear_user_sessions(user_id)

    def get_active_sessions(self, user) -> List[Dict[str, Any]]:
        """
        Get all active sessions for a user.

        Args:
            user: The user

        Returns:
            List of session data
        """
        user_id = str(user.id)
        sessions = self._get_user_sessions(user_id)

        # Clean sensitive data for display
        return [
            {
                'session_key': s['session_key'][:8] + '...',
                'ip_address': s.get('ip_address'),
                'user_agent': self._parse_user_agent(s.get('user_agent', '')),
                'created_at': s.get('created_at'),
                'last_activity': s.get('last_activity'),
                'is_current': False,  # Set by caller
            }
            for s in sessions
        ]

    def _get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all sessions for a user from cache."""
        key = f"{self.CACHE_PREFIX}sessions:{user_id}"
        return cache.get(key, [])

    def _store_user_sessions(self, user_id: str, sessions: List[Dict[str, Any]]):
        """Store user sessions in cache."""
        key = f"{self.CACHE_PREFIX}sessions:{user_id}"
        cache.set(key, sessions, settings.SESSION_COOKIE_AGE)

    def _remove_session(self, user_id: str, session_key: str):
        """Remove a specific session."""
        sessions = self._get_user_sessions(user_id)
        sessions = [s for s in sessions if s['session_key'] != session_key]
        self._store_user_sessions(user_id, sessions)

    def _clear_user_sessions(self, user_id: str):
        """Clear all sessions for a user."""
        key = f"{self.CACHE_PREFIX}sessions:{user_id}"
        cache.delete(key)

    def _calculate_binding_hash(self, session_data: Dict[str, Any]) -> str:
        """Calculate session binding hash."""
        binding_str = ''
        if self.bind_ip:
            binding_str += session_data.get('ip_address', '')
        if self.bind_user_agent:
            binding_str += session_data.get('user_agent', '')

        return hashlib.sha256(binding_str.encode()).hexdigest()[:16]

    def _user_agent_compatible(self, stored: str, current: str) -> bool:
        """Check if user agents are compatible (allow minor changes)."""
        # Extract browser family and major version
        stored_parts = stored.split()
        current_parts = current.split()

        # If either is empty, they're incompatible
        if not stored_parts or not current_parts:
            return False

        # Compare first few tokens (browser identification)
        stored_prefix = ' '.join(stored_parts[:3])
        current_prefix = ' '.join(current_parts[:3])

        # Allow some variation
        return stored_prefix == current_prefix

    def _parse_user_agent(self, ua: str) -> Dict[str, str]:
        """Parse user agent into readable format."""
        try:
            from user_agents import parse
            parsed = parse(ua)
            return {
                'browser': f"{parsed.browser.family} {parsed.browser.version_string}",
                'os': f"{parsed.os.family} {parsed.os.version_string}",
                'device': parsed.device.family,
            }
        except ImportError:
            return {'raw': ua[:50]}

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')

    def _get_tenant_id(self, request: HttpRequest) -> Optional[str]:
        """Get tenant ID from request."""
        if hasattr(request, 'tenant'):
            return str(getattr(request.tenant, 'id', None))
        return None

    def _log_session_hijack_attempt(
        self,
        user_id: str,
        session_key: str,
        reason: str,
        request: HttpRequest
    ):
        """Log a potential session hijacking attempt."""
        event = SecurityEvent(
            event_type=SecurityEventType.SESSION_HIJACK_ATTEMPT,
            severity='high',
            message=f'Potential session hijack detected: {reason}',
            user_id=user_id,
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={
                'session_key_prefix': session_key[:8],
                'reason': reason,
            }
        )
        self.logger.log(event)


# =============================================================================
# Password Validator (NIST 800-63B Compliant)
# =============================================================================

class PasswordValidator:
    """
    NIST 800-63B compliant password validator.

    Implements modern password policy guidelines:
    - Minimum length of 8 characters (12+ recommended)
    - No arbitrary complexity requirements
    - Check against common passwords
    - Check against breached password databases
    - Context-aware (email, username similarity)
    """

    MIN_LENGTH = 8
    RECOMMENDED_LENGTH = 12
    MAX_LENGTH = 128

    # Top common passwords (abbreviated list - use full list in production)
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
        'bailey', 'shadow', '123123', '654321', 'superman',
        'qazwsx', 'michael', 'football', 'password1', 'password123',
    }

    def __init__(self):
        self.logger = SecurityEventLogger()
        self.check_breaches = getattr(settings, 'PASSWORD_CHECK_BREACHES', True)

    def validate(
        self,
        password: str,
        user=None,
        context: Dict[str, str] = None
    ) -> Tuple[bool, List[str]]:
        """
        Validate password against NIST 800-63B guidelines.

        Args:
            password: Password to validate
            user: Optional user for context
            context: Additional context (email, username)

        Returns:
            Tuple of (is_valid, list of issues)
        """
        issues = []

        # Length check
        if len(password) < self.MIN_LENGTH:
            issues.append(f'Password must be at least {self.MIN_LENGTH} characters')

        if len(password) > self.MAX_LENGTH:
            issues.append(f'Password cannot exceed {self.MAX_LENGTH} characters')

        # Common password check
        if password.lower() in self.COMMON_PASSWORDS:
            issues.append('This is a commonly used password')

        # Sequential/repeated characters
        if self._has_sequential_chars(password):
            issues.append('Password contains too many sequential characters')

        if self._has_repeated_chars(password):
            issues.append('Password contains too many repeated characters')

        # Context checks
        if user:
            context_issues = self._check_user_context(password, user)
            issues.extend(context_issues)

        if context:
            context_issues = self._check_context(password, context)
            issues.extend(context_issues)

        # Breach check (async in production)
        if self.check_breaches and len(issues) == 0:
            is_breached = self._check_breach_database(password)
            if is_breached:
                issues.append('This password has appeared in a data breach')

        return len(issues) == 0, issues

    def get_strength_score(self, password: str) -> Dict[str, Any]:
        """
        Calculate password strength score.

        Args:
            password: Password to evaluate

        Returns:
            Strength assessment
        """
        score = 0
        feedback = []

        # Length scoring (major factor per NIST)
        length = len(password)
        if length >= 8:
            score += 1
            feedback.append('Meets minimum length')
        if length >= 12:
            score += 2
            feedback.append('Good length')
        if length >= 16:
            score += 2
            feedback.append('Excellent length')

        # Character variety (not required but helpful)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

        variety_count = sum([has_lower, has_upper, has_digit, has_special])
        if variety_count >= 2:
            score += 1
            feedback.append('Uses multiple character types')
        if variety_count >= 3:
            score += 1
            feedback.append('Good character variety')

        # Entropy estimation (simplified)
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32

        import math
        if charset_size > 0:
            entropy = length * math.log2(charset_size)
            if entropy >= 60:
                score += 1
                feedback.append('High entropy')

        # Determine strength label
        if score <= 2:
            strength = 'weak'
        elif score <= 4:
            strength = 'fair'
        elif score <= 6:
            strength = 'good'
        else:
            strength = 'strong'

        return {
            'score': score,
            'max_score': 8,
            'strength': strength,
            'feedback': feedback,
        }

    def _has_sequential_chars(self, password: str, max_seq: int = 4) -> bool:
        """Check for sequential characters (abc, 123, etc.)."""
        sequences = [
            'abcdefghijklmnopqrstuvwxyz',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            '0123456789',
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm',
        ]

        password_lower = password.lower()

        for seq in sequences:
            for i in range(len(seq) - max_seq + 1):
                if seq[i:i + max_seq] in password_lower:
                    return True
                # Also check reverse
                if seq[i:i + max_seq][::-1] in password_lower:
                    return True

        return False

    def _has_repeated_chars(self, password: str, max_repeat: int = 3) -> bool:
        """Check for repeated characters (aaa, 111, etc.)."""
        for i in range(len(password) - max_repeat + 1):
            if len(set(password[i:i + max_repeat])) == 1:
                return True
        return False

    def _check_user_context(self, password: str, user) -> List[str]:
        """Check password against user information."""
        issues = []
        password_lower = password.lower()

        # Fields to check
        fields = {
            'username': getattr(user, 'username', ''),
            'email': getattr(user, 'email', '').split('@')[0],
            'first_name': getattr(user, 'first_name', ''),
            'last_name': getattr(user, 'last_name', ''),
        }

        for field_name, value in fields.items():
            if value and len(value) >= 3:
                if value.lower() in password_lower:
                    issues.append(
                        f'Password should not contain your {field_name.replace("_", " ")}'
                    )

        return issues

    def _check_context(self, password: str, context: Dict[str, str]) -> List[str]:
        """Check password against contextual information."""
        issues = []
        password_lower = password.lower()

        for key, value in context.items():
            if value and len(value) >= 3:
                if value.lower() in password_lower:
                    issues.append(f'Password should not contain your {key}')

        return issues

    def _check_breach_database(self, password: str) -> bool:
        """
        Check if password appears in breach database using k-anonymity.

        Uses Have I Been Pwned API with k-anonymity model.
        """
        try:
            import requests

            # SHA-1 hash of password
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            # Query HIBP API
            response = requests.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                timeout=5,
                headers={'Add-Padding': 'true'}
            )

            if response.status_code == 200:
                # Check if our suffix is in the response
                for line in response.text.splitlines():
                    if ':' in line:
                        hash_suffix, count = line.split(':')
                        if hash_suffix == suffix:
                            return int(count) > 0

            return False

        except Exception as e:
            logger.warning(f'Breach database check failed: {e}')
            return False


# =============================================================================
# Brute Force Protection
# =============================================================================

class BruteForceProtection:
    """
    Brute force attack protection with progressive delays and CAPTCHA triggers.

    Implements intelligent rate limiting that increases delays with each failure.
    """

    CACHE_PREFIX = 'brute_force:'

    # Progressive delay configuration (in seconds)
    DELAY_SCHEDULE = [
        (3, 0),      # 0-3 attempts: no delay
        (5, 5),      # 4-5 attempts: 5 second delay
        (8, 30),     # 6-8 attempts: 30 second delay
        (10, 60),    # 9-10 attempts: 1 minute delay
        (15, 300),   # 11-15 attempts: 5 minute delay
        (20, 900),   # 16-20 attempts: 15 minute delay
        (float('inf'), 3600),  # 21+ attempts: 1 hour delay
    ]

    # CAPTCHA trigger threshold
    CAPTCHA_THRESHOLD = 3

    # Lockout threshold
    LOCKOUT_THRESHOLD = 10

    def __init__(self):
        self.logger = SecurityEventLogger()
        self.attempt_window = getattr(settings, 'BRUTE_FORCE_WINDOW', 3600)

    def check_allowed(
        self,
        identifier: str,
        identifier_type: str = 'ip',
        request: HttpRequest = None
    ) -> Tuple[bool, Optional[int], bool]:
        """
        Check if an authentication attempt is allowed.

        Args:
            identifier: The identifier (IP, username, etc.)
            identifier_type: Type of identifier
            request: Optional request for logging

        Returns:
            Tuple of (is_allowed, delay_seconds, requires_captcha)
        """
        key = f"{self.CACHE_PREFIX}attempts:{identifier_type}:{identifier}"
        attempts = cache.get(key, 0)

        # Check if locked out
        if attempts >= self.LOCKOUT_THRESHOLD:
            lockout_key = f"{self.CACHE_PREFIX}lockout:{identifier_type}:{identifier}"
            if cache.get(lockout_key):
                return False, None, True

        # Calculate required delay
        delay = self._get_delay(attempts)

        # Check if delay has passed
        if delay > 0:
            last_attempt_key = f"{self.CACHE_PREFIX}last:{identifier_type}:{identifier}"
            last_attempt = cache.get(last_attempt_key)

            if last_attempt:
                elapsed = (timezone.now() - last_attempt).total_seconds()
                if elapsed < delay:
                    remaining = int(delay - elapsed)
                    return False, remaining, attempts >= self.CAPTCHA_THRESHOLD

        # Check CAPTCHA requirement
        requires_captcha = attempts >= self.CAPTCHA_THRESHOLD

        return True, delay, requires_captcha

    def record_failure(
        self,
        identifier: str,
        identifier_type: str = 'ip',
        request: HttpRequest = None
    ) -> Dict[str, Any]:
        """
        Record a failed authentication attempt.

        Args:
            identifier: The identifier
            identifier_type: Type of identifier
            request: Optional request for logging

        Returns:
            Status information
        """
        key = f"{self.CACHE_PREFIX}attempts:{identifier_type}:{identifier}"
        attempts = cache.get(key, 0) + 1
        cache.set(key, attempts, self.attempt_window)

        # Record timestamp
        last_key = f"{self.CACHE_PREFIX}last:{identifier_type}:{identifier}"
        cache.set(last_key, timezone.now(), self.attempt_window)

        # Check for lockout
        if attempts >= self.LOCKOUT_THRESHOLD:
            self._apply_lockout(identifier, identifier_type, request)

        return {
            'attempts': attempts,
            'delay': self._get_delay(attempts),
            'requires_captcha': attempts >= self.CAPTCHA_THRESHOLD,
            'locked_out': attempts >= self.LOCKOUT_THRESHOLD,
        }

    def record_success(self, identifier: str, identifier_type: str = 'ip'):
        """
        Record a successful authentication (clears failures).

        Args:
            identifier: The identifier
            identifier_type: Type of identifier
        """
        key = f"{self.CACHE_PREFIX}attempts:{identifier_type}:{identifier}"
        cache.delete(key)

        last_key = f"{self.CACHE_PREFIX}last:{identifier_type}:{identifier}"
        cache.delete(last_key)

    def _get_delay(self, attempts: int) -> int:
        """Get the delay for the current attempt count."""
        for threshold, delay in self.DELAY_SCHEDULE:
            if attempts <= threshold:
                return delay
        return self.DELAY_SCHEDULE[-1][1]

    def _apply_lockout(
        self,
        identifier: str,
        identifier_type: str,
        request: HttpRequest = None
    ):
        """Apply a lockout for repeated failures."""
        lockout_key = f"{self.CACHE_PREFIX}lockout:{identifier_type}:{identifier}"
        lockout_duration = 3600  # 1 hour default

        cache.set(lockout_key, True, lockout_duration)

        event = SecurityEvent(
            event_type=SecurityEventType.ACCOUNT_LOCKED,
            severity='high',
            message=f'Brute force lockout: {identifier_type}={identifier}',
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', '') if request else None,
            details={
                'identifier': identifier,
                'identifier_type': identifier_type,
                'lockout_duration': lockout_duration,
            }
        )
        self.logger.log(event)

    def verify_captcha(
        self,
        response: str,
        remote_ip: str = None
    ) -> bool:
        """
        Verify CAPTCHA response.

        Args:
            response: CAPTCHA response token
            remote_ip: Client IP address

        Returns:
            True if CAPTCHA is valid
        """
        secret_key = getattr(settings, 'RECAPTCHA_SECRET_KEY', '')

        if not secret_key:
            logger.warning('CAPTCHA secret key not configured')
            return True  # Allow if not configured

        try:
            import requests

            verify_url = 'https://www.google.com/recaptcha/api/siteverify'
            payload = {
                'secret': secret_key,
                'response': response,
            }
            if remote_ip:
                payload['remoteip'] = remote_ip

            result = requests.post(verify_url, data=payload, timeout=10)
            return result.json().get('success', False)

        except Exception as e:
            logger.error(f'CAPTCHA verification failed: {e}')
            return False


# =============================================================================
# JWT Security Enhancer
# =============================================================================

class JWTSecurityEnhancer:
    """
    Enhanced JWT security with short expiry, refresh token rotation, and token binding.

    Implements secure JWT practices beyond simplejwt defaults.
    """

    CACHE_PREFIX = 'jwt_security:'

    # Token settings
    ACCESS_TOKEN_LIFETIME = timedelta(minutes=15)  # Short-lived
    REFRESH_TOKEN_LIFETIME = timedelta(days=7)

    def __init__(self):
        self.logger = SecurityEventLogger()

    def create_token_pair(
        self,
        user,
        request: HttpRequest = None,
        device_id: str = None
    ) -> Dict[str, str]:
        """
        Create a bound access/refresh token pair.

        Args:
            user: The authenticated user
            request: HTTP request for binding
            device_id: Optional device identifier

        Returns:
            Dictionary with access_token and refresh_token
        """
        from rest_framework_simplejwt.tokens import RefreshToken

        # Create refresh token
        refresh = RefreshToken.for_user(user)

        # Add custom claims
        refresh['tenant_id'] = self._get_tenant_id(user)

        # Token binding
        if request:
            binding = self._create_token_binding(request, device_id)
            refresh['binding_hash'] = binding

        # Set custom lifetime
        refresh.set_exp(lifetime=self.REFRESH_TOKEN_LIFETIME)
        refresh.access_token.set_exp(lifetime=self.ACCESS_TOKEN_LIFETIME)

        # Track token for rotation
        jti = str(refresh['jti'])
        self._track_token(user.id, jti)

        return {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }

    def rotate_refresh_token(
        self,
        refresh_token: str,
        request: HttpRequest = None
    ) -> Tuple[Optional[Dict[str, str]], str]:
        """
        Rotate a refresh token (issue new pair, invalidate old).

        Args:
            refresh_token: Current refresh token
            request: HTTP request for validation

        Returns:
            Tuple of (new_tokens or None, error_message)
        """
        from rest_framework_simplejwt.tokens import RefreshToken
        from rest_framework_simplejwt.exceptions import TokenError

        try:
            refresh = RefreshToken(refresh_token)

            # Verify binding
            if request:
                stored_binding = refresh.get('binding_hash')
                if stored_binding:
                    current_binding = self._create_token_binding(request)
                    if not constant_time_compare(stored_binding, current_binding):
                        self._log_token_binding_failure(refresh, request)
                        return None, 'Token binding mismatch'

            # Check if token was already rotated (replay attack)
            jti = str(refresh['jti'])
            user_id = refresh['user_id']

            if self._is_token_used(user_id, jti):
                self._log_token_replay_attempt(user_id, jti, request)
                # Invalidate all tokens for user (security measure)
                self._invalidate_all_tokens(user_id)
                return None, 'Token replay detected'

            # Mark old token as used
            self._mark_token_used(user_id, jti)

            # Blacklist old token
            try:
                refresh.blacklist()
            except AttributeError:
                pass  # Blacklist not configured

            # Create new token pair
            user = User.objects.get(id=user_id)
            new_tokens = self.create_token_pair(user, request)

            return new_tokens, ''

        except TokenError as e:
            return None, str(e)

    def validate_access_token(
        self,
        access_token: str,
        request: HttpRequest = None
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Validate an access token with binding check.

        Args:
            access_token: The access token
            request: HTTP request for binding check

        Returns:
            Tuple of (is_valid, error_message, claims)
        """
        from rest_framework_simplejwt.tokens import AccessToken
        from rest_framework_simplejwt.exceptions import TokenError

        try:
            token = AccessToken(access_token)

            # Verify binding
            if request:
                stored_binding = token.get('binding_hash')
                if stored_binding:
                    current_binding = self._create_token_binding(request)
                    if not constant_time_compare(stored_binding, current_binding):
                        return False, 'Token binding mismatch', None

            return True, '', dict(token)

        except TokenError as e:
            return False, str(e), None

    def revoke_token(self, token: str, token_type: str = 'refresh'):
        """
        Revoke a specific token.

        Args:
            token: The token to revoke
            token_type: Type of token (refresh or access)
        """
        from rest_framework_simplejwt.tokens import RefreshToken
        from rest_framework_simplejwt.exceptions import TokenError

        try:
            if token_type == 'refresh':
                refresh = RefreshToken(token)
                refresh.blacklist()

                # Also mark as used
                user_id = refresh['user_id']
                jti = str(refresh['jti'])
                self._mark_token_used(user_id, jti)

        except (TokenError, AttributeError):
            pass

    def revoke_all_tokens(self, user):
        """
        Revoke all tokens for a user.

        Args:
            user: The user
        """
        self._invalidate_all_tokens(user.id)

    def _create_token_binding(
        self,
        request: HttpRequest,
        device_id: str = None
    ) -> str:
        """Create token binding hash from request context."""
        binding_parts = []

        # IP address (first part of X-Forwarded-For or REMOTE_ADDR)
        ip = request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
        if not ip:
            ip = request.META.get('REMOTE_ADDR', '')
        binding_parts.append(ip)

        # User agent family (not full UA to allow minor updates)
        ua = request.META.get('HTTP_USER_AGENT', '')
        ua_family = ua.split('/')[0] if '/' in ua else ua[:20]
        binding_parts.append(ua_family)

        # Device ID if provided
        if device_id:
            binding_parts.append(device_id)

        binding_str = '|'.join(binding_parts)
        return hashlib.sha256(binding_str.encode()).hexdigest()[:16]

    def _track_token(self, user_id: int, jti: str):
        """Track a token for replay detection."""
        key = f"{self.CACHE_PREFIX}tokens:{user_id}"
        tokens = cache.get(key, set())
        tokens.add(jti)
        cache.set(key, tokens, int(self.REFRESH_TOKEN_LIFETIME.total_seconds()))

    def _is_token_used(self, user_id: int, jti: str) -> bool:
        """Check if a token was already used (rotated)."""
        key = f"{self.CACHE_PREFIX}used:{user_id}:{jti}"
        return cache.get(key) is not None

    def _mark_token_used(self, user_id: int, jti: str):
        """Mark a token as used."""
        key = f"{self.CACHE_PREFIX}used:{user_id}:{jti}"
        cache.set(key, True, int(self.REFRESH_TOKEN_LIFETIME.total_seconds()))

    def _invalidate_all_tokens(self, user_id: int):
        """Invalidate all tokens for a user."""
        key = f"{self.CACHE_PREFIX}tokens:{user_id}"
        tokens = cache.get(key, set())

        # Mark all as used
        for jti in tokens:
            self._mark_token_used(user_id, jti)

        cache.delete(key)

    def _get_tenant_id(self, user) -> Optional[str]:
        """Get tenant ID for user."""
        if hasattr(user, 'tenant_id'):
            return str(user.tenant_id)
        if hasattr(user, 'tenant'):
            return str(user.tenant.id)
        return None

    def _log_token_binding_failure(
        self,
        token,
        request: HttpRequest
    ):
        """Log token binding failure."""
        event = SecurityEvent(
            event_type=SecurityEventType.SESSION_HIJACK_ATTEMPT,
            severity='high',
            message='JWT token binding mismatch detected',
            user_id=str(token.get('user_id')),
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'jti': str(token.get('jti'))}
        )
        self.logger.log(event)

    def _log_token_replay_attempt(
        self,
        user_id: int,
        jti: str,
        request: HttpRequest = None
    ):
        """Log token replay attempt."""
        event = SecurityEvent(
            event_type=SecurityEventType.SESSION_HIJACK_ATTEMPT,
            severity='critical',
            message='JWT token replay attack detected',
            user_id=str(user_id),
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', '') if request else None,
            details={'jti': jti}
        )
        self.logger.log(event)
