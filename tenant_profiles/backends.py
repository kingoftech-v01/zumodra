"""
Accounts Authentication Backends - Custom Authentication for Multi-Tenant SaaS

This module implements:
- Custom model authentication backend with tenant support
- Multi-factor authentication (MFA) backend
- Tenant-scoped authentication
- Social authentication integration
- API key authentication
"""

import hashlib
import secrets
from typing import Optional, Any
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.cache import cache
from django.utils import timezone
from django.db.models import Q

User = get_user_model()


# =============================================================================
# TENANT-AWARE MODEL BACKEND
# =============================================================================

class TenantModelBackend(ModelBackend):
    """
    Custom authentication backend with tenant awareness.

    Features:
    - Email or username authentication
    - Tenant-scoped login validation
    - Account status checks
    - Login attempt tracking
    """

    def authenticate(
        self,
        request,
        username: Optional[str] = None,
        password: Optional[str] = None,
        tenant=None,
        **kwargs
    ):
        """
        Authenticate user with optional tenant context.

        Args:
            request: The HTTP request
            username: Email or username
            password: User password
            tenant: Optional tenant for scoped authentication

        Returns:
            User instance if authentication successful, None otherwise
        """
        if username is None:
            username = kwargs.get(User.USERNAME_FIELD)

        if username is None or password is None:
            return None

        # Try to find user by email or username
        try:
            user = self._get_user_by_identifier(username)
        except User.DoesNotExist:
            # Run password hasher to prevent timing attacks
            User().set_password(password)
            return None

        # Check password
        if not user.check_password(password):
            self._record_failed_attempt(user, request)
            return None

        # Check if account is active
        if not self.user_can_authenticate(user):
            return None

        # Check tenant membership if tenant context provided
        if tenant and not self._validate_tenant_membership(user, tenant):
            return None

        # Check for account lockout
        if self._is_account_locked(user):
            return None

        # Clear failed attempts on successful login
        self._clear_failed_attempts(user)

        return user

    def _get_user_by_identifier(self, identifier: str) -> User:
        """
        Get user by email or username.
        """
        # Determine if identifier is email
        if '@' in identifier:
            return User.objects.get(email__iexact=identifier)
        else:
            return User.objects.get(**{User.USERNAME_FIELD: identifier})

    def _validate_tenant_membership(self, user, tenant) -> bool:
        """
        Validate that user is an active member of the tenant.
        """
        from .models import TenantUser

        return TenantUser.objects.filter(
            user=user,
            tenant=tenant,
            is_active=True
        ).exists()

    def _record_failed_attempt(self, user, request):
        """
        Record failed login attempt for security monitoring.
        """
        cache_key = f"login_attempts:{user.id}"
        attempts = cache.get(cache_key) or []

        attempt = {
            'timestamp': timezone.now().isoformat(),
            'ip_address': self._get_client_ip(request) if request else None,
            'user_agent': request.META.get('HTTP_USER_AGENT', '')[:200] if request else None
        }
        attempts.append(attempt)

        # Keep last 10 attempts
        attempts = attempts[-10:]
        cache.set(cache_key, attempts, timeout=24 * 60 * 60)

    def _clear_failed_attempts(self, user):
        """
        Clear failed login attempts after successful authentication.
        """
        cache_key = f"login_attempts:{user.id}"
        cache.delete(cache_key)

    def _is_account_locked(self, user) -> bool:
        """
        Check if account is locked due to too many failed attempts.
        """
        cache_key = f"account_locked:{user.id}"
        return cache.get(cache_key) is True

    def _get_client_ip(self, request) -> str:
        """
        Extract client IP from request.
        """
        if not request:
            return ''
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


# =============================================================================
# MULTI-FACTOR AUTHENTICATION BACKEND
# =============================================================================

class MFABackend(ModelBackend):
    """
    Multi-Factor Authentication backend.

    Supports:
    - TOTP (Time-based One-Time Password)
    - Email OTP
    - SMS OTP
    - Backup codes
    """

    MFA_CODE_LENGTH = 6
    MFA_CODE_EXPIRY = 300  # 5 minutes
    MAX_MFA_ATTEMPTS = 5

    def authenticate(
        self,
        request,
        user=None,
        mfa_code: Optional[str] = None,
        mfa_method: str = 'totp',
        **kwargs
    ):
        """
        Authenticate MFA code for user.

        Args:
            request: The HTTP request
            user: Pre-authenticated user requiring MFA
            mfa_code: The MFA code to verify
            mfa_method: MFA method ('totp', 'email', 'sms', 'backup')

        Returns:
            User if MFA verification successful, None otherwise
        """
        if user is None or mfa_code is None:
            return None

        # Check MFA attempt limit
        if self._is_mfa_locked(user):
            return None

        # Verify MFA based on method
        if mfa_method == 'totp':
            verified = self._verify_totp(user, mfa_code)
        elif mfa_method == 'email':
            verified = self._verify_email_otp(user, mfa_code)
        elif mfa_method == 'sms':
            verified = self._verify_sms_otp(user, mfa_code)
        elif mfa_method == 'backup':
            verified = self._verify_backup_code(user, mfa_code)
        else:
            verified = False

        if not verified:
            self._record_mfa_attempt(user)
            return None

        # Clear MFA attempts on success
        self._clear_mfa_attempts(user)

        return user

    def _verify_totp(self, user, code: str) -> bool:
        """
        Verify TOTP code using django-otp.
        """
        try:
            from django_otp import match_token
            device = match_token(user, code)
            return device is not None
        except ImportError:
            return False

    def _verify_email_otp(self, user, code: str) -> bool:
        """
        Verify email OTP code.
        """
        cache_key = f"email_otp:{user.id}"
        stored = cache.get(cache_key)

        if stored and stored.get('code') == code:
            cache.delete(cache_key)
            return True
        return False

    def _verify_sms_otp(self, user, code: str) -> bool:
        """
        Verify SMS OTP code.
        """
        cache_key = f"sms_otp:{user.id}"
        stored = cache.get(cache_key)

        if stored and stored.get('code') == code:
            cache.delete(cache_key)
            return True
        return False

    def _verify_backup_code(self, user, code: str) -> bool:
        """
        Verify and consume backup code.
        """
        from .models import SecurityQuestion  # Backup codes could be stored similarly

        # Check django_otp static device
        try:
            from django_otp.plugins.otp_static.models import StaticDevice
            device = StaticDevice.objects.filter(user=user, confirmed=True).first()
            if device and device.verify_token(code):
                return True
        except ImportError:
            pass

        return False

    def _record_mfa_attempt(self, user):
        """
        Record failed MFA attempt.
        """
        cache_key = f"mfa_attempts:{user.id}"
        attempts = cache.get(cache_key) or 0
        attempts += 1
        cache.set(cache_key, attempts, timeout=15 * 60)  # 15 minute window

        if attempts >= self.MAX_MFA_ATTEMPTS:
            lock_key = f"mfa_locked:{user.id}"
            cache.set(lock_key, True, timeout=30 * 60)  # Lock for 30 minutes

    def _clear_mfa_attempts(self, user):
        """
        Clear MFA attempts after successful verification.
        """
        cache.delete(f"mfa_attempts:{user.id}")
        cache.delete(f"mfa_locked:{user.id}")

    def _is_mfa_locked(self, user) -> bool:
        """
        Check if MFA is locked for user.
        """
        return cache.get(f"mfa_locked:{user.id}") is True

    @classmethod
    def generate_email_otp(cls, user) -> str:
        """
        Generate and store email OTP.
        """
        code = ''.join(secrets.choice('0123456789') for _ in range(cls.MFA_CODE_LENGTH))
        cache_key = f"email_otp:{user.id}"
        cache.set(
            cache_key,
            {'code': code, 'created_at': timezone.now().isoformat()},
            timeout=cls.MFA_CODE_EXPIRY
        )
        return code

    @classmethod
    def generate_sms_otp(cls, user) -> str:
        """
        Generate and store SMS OTP.
        """
        code = ''.join(secrets.choice('0123456789') for _ in range(cls.MFA_CODE_LENGTH))
        cache_key = f"sms_otp:{user.id}"
        cache.set(
            cache_key,
            {'code': code, 'created_at': timezone.now().isoformat()},
            timeout=cls.MFA_CODE_EXPIRY
        )
        return code


# =============================================================================
# API KEY AUTHENTICATION BACKEND
# =============================================================================

class APIKeyBackend:
    """
    API Key authentication backend for service-to-service communication.

    Supports:
    - Tenant-scoped API keys
    - Key rotation
    - Usage tracking
    - Rate limiting per key
    """

    API_KEY_HEADER = 'X-API-Key'
    API_SECRET_HEADER = 'X-API-Secret'

    def authenticate(self, request, api_key: Optional[str] = None, api_secret: Optional[str] = None, **kwargs):
        """
        Authenticate using API key and secret.
        """
        if api_key is None:
            api_key = request.META.get(f'HTTP_{self.API_KEY_HEADER.replace("-", "_").upper()}')
        if api_secret is None:
            api_secret = request.META.get(f'HTTP_{self.API_SECRET_HEADER.replace("-", "_").upper()}')

        if not api_key or not api_secret:
            return None

        # Look up API key
        key_data = self._get_api_key(api_key)
        if not key_data:
            return None

        # Verify secret
        if not self._verify_secret(api_secret, key_data.get('secret_hash')):
            return None

        # Check if key is active
        if not key_data.get('is_active'):
            return None

        # Check expiration
        if key_data.get('expires_at'):
            expires = timezone.datetime.fromisoformat(key_data['expires_at'])
            if timezone.now() > expires:
                return None

        # Get associated user
        user_id = key_data.get('user_id')
        if not user_id:
            return None

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None

        # Track API key usage
        self._track_usage(api_key, request)

        # Attach key metadata to request
        request.api_key_data = key_data

        return user

    def _get_api_key(self, api_key: str) -> Optional[dict]:
        """
        Retrieve API key data from cache or database.
        """
        cache_key = f"api_key:{api_key}"
        key_data = cache.get(cache_key)

        if key_data is None:
            # Try to load from database
            try:
                from .models import APIKey
                key_obj = APIKey.objects.get(key=api_key)
                key_data = {
                    'id': key_obj.id,
                    'key': key_obj.key,
                    'secret_hash': key_obj.secret_hash,
                    'user_id': key_obj.user_id,
                    'tenant_id': key_obj.tenant_id,
                    'is_active': key_obj.is_active,
                    'expires_at': key_obj.expires_at.isoformat() if key_obj.expires_at else None,
                    'permissions': list(key_obj.permissions)
                }
                cache.set(cache_key, key_data, timeout=60 * 60)  # 1 hour cache
            except Exception:
                return None

        return key_data

    def _verify_secret(self, secret: str, secret_hash: str) -> bool:
        """
        Verify API secret against stored hash.
        """
        computed_hash = hashlib.sha256(secret.encode()).hexdigest()
        return secrets.compare_digest(computed_hash, secret_hash)

    def _track_usage(self, api_key: str, request):
        """
        Track API key usage for analytics and rate limiting.
        """
        cache_key = f"api_key_usage:{api_key}:{timezone.now().strftime('%Y%m%d%H')}"
        usage = cache.get(cache_key) or 0
        cache.set(cache_key, usage + 1, timeout=2 * 60 * 60)

    def get_user(self, user_id):
        """
        Get user by ID.
        """
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


# =============================================================================
# TENANT-SCOPED AUTHENTICATION BACKEND
# =============================================================================

class TenantScopedBackend(TenantModelBackend):
    """
    Authentication backend that strictly requires tenant context.

    Used for tenant-specific login flows where users must
    authenticate within a specific tenant context.
    """

    def authenticate(
        self,
        request,
        username: Optional[str] = None,
        password: Optional[str] = None,
        tenant=None,
        **kwargs
    ):
        """
        Authenticate user with mandatory tenant context.
        """
        # Tenant is required for this backend
        if tenant is None:
            tenant = getattr(request, 'tenant', None) if request else None

        if tenant is None:
            return None

        # Use parent authentication
        user = super().authenticate(
            request,
            username=username,
            password=password,
            tenant=tenant,
            **kwargs
        )

        if user is None:
            return None

        # Additional tenant-specific checks
        from .models import TenantUser

        try:
            tenant_user = TenantUser.objects.get(
                user=user,
                tenant=tenant,
                is_active=True
            )
        except TenantUser.DoesNotExist:
            return None

        # Check tenant settings
        if hasattr(tenant, 'settings'):
            tenant_settings = tenant.settings

            # Check IP whitelist
            if tenant_settings.ip_whitelist:
                client_ip = self._get_client_ip(request)
                if client_ip not in tenant_settings.ip_whitelist:
                    return None

            # Check allowed email domains
            if tenant_settings.allowed_email_domains:
                email_domain = user.email.split('@')[1] if '@' in user.email else ''
                if email_domain not in tenant_settings.allowed_email_domains:
                    return None

        return user


# =============================================================================
# REMEMBER ME AUTHENTICATION BACKEND
# =============================================================================

class RememberMeBackend(ModelBackend):
    """
    Authentication backend for 'Remember Me' functionality.

    Uses secure tokens for persistent login without requiring
    password on subsequent visits.
    """

    COOKIE_NAME = 'remember_token'
    TOKEN_EXPIRY_DAYS = 30

    def authenticate(self, request, remember_token: Optional[str] = None, **kwargs):
        """
        Authenticate using remember me token.
        """
        if remember_token is None:
            return None

        # Parse token (format: user_id:selector:validator)
        try:
            user_id, selector, validator = remember_token.split(':')
            user_id = int(user_id)
        except (ValueError, AttributeError):
            return None

        # Look up token by selector
        cache_key = f"remember_me:{user_id}:{selector}"
        stored_data = cache.get(cache_key)

        if stored_data is None:
            return None

        # Verify validator
        validator_hash = hashlib.sha256(validator.encode()).hexdigest()
        if not secrets.compare_digest(validator_hash, stored_data.get('validator_hash', '')):
            # Token compromised - clear all remember me tokens for user
            self._clear_all_tokens(user_id)
            return None

        # Check expiration
        expires = stored_data.get('expires_at')
        if expires and timezone.now().isoformat() > expires:
            cache.delete(cache_key)
            return None

        # Get user
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None

        if not self.user_can_authenticate(user):
            return None

        # Rotate token for security
        self._rotate_token(user, selector)

        return user

    @classmethod
    def generate_token(cls, user) -> str:
        """
        Generate a new remember me token.
        """
        selector = secrets.token_urlsafe(16)
        validator = secrets.token_urlsafe(32)
        validator_hash = hashlib.sha256(validator.encode()).hexdigest()

        cache_key = f"remember_me:{user.id}:{selector}"
        expires_at = (timezone.now() + timedelta(days=cls.TOKEN_EXPIRY_DAYS)).isoformat()

        cache.set(
            cache_key,
            {
                'validator_hash': validator_hash,
                'expires_at': expires_at,
                'created_at': timezone.now().isoformat()
            },
            timeout=cls.TOKEN_EXPIRY_DAYS * 24 * 60 * 60
        )

        # Track selector for this user
        cls._add_user_selector(user.id, selector)

        return f"{user.id}:{selector}:{validator}"

    @classmethod
    def revoke_token(cls, user_id: int, selector: str):
        """
        Revoke a specific remember me token.
        """
        cache_key = f"remember_me:{user_id}:{selector}"
        cache.delete(cache_key)
        cls._remove_user_selector(user_id, selector)

    def _rotate_token(self, user, old_selector: str):
        """
        Rotate token after use for security.
        """
        # Remove old token
        self.revoke_token(user.id, old_selector)

        # Generate new token
        return self.generate_token(user)

    def _clear_all_tokens(self, user_id: int):
        """
        Clear all remember me tokens for a user (security measure).
        """
        selectors = cache.get(f"remember_me_selectors:{user_id}") or []
        for selector in selectors:
            cache.delete(f"remember_me:{user_id}:{selector}")
        cache.delete(f"remember_me_selectors:{user_id}")

    @classmethod
    def _add_user_selector(cls, user_id: int, selector: str):
        """
        Track selector for user.
        """
        key = f"remember_me_selectors:{user_id}"
        selectors = cache.get(key) or []
        selectors.append(selector)
        cache.set(key, selectors, timeout=cls.TOKEN_EXPIRY_DAYS * 24 * 60 * 60)

    @classmethod
    def _remove_user_selector(cls, user_id: int, selector: str):
        """
        Remove selector from user tracking.
        """
        key = f"remember_me_selectors:{user_id}"
        selectors = cache.get(key) or []
        if selector in selectors:
            selectors.remove(selector)
            cache.set(key, selectors, timeout=cls.TOKEN_EXPIRY_DAYS * 24 * 60 * 60)


# =============================================================================
# IMPERSONATION BACKEND
# =============================================================================

class ImpersonationBackend(ModelBackend):
    """
    Backend for admin impersonation of users.

    Allows admins to temporarily assume another user's identity
    for debugging and support purposes.
    """

    IMPERSONATION_KEY = 'impersonation'

    def authenticate(
        self,
        request,
        impersonator=None,
        target_user_id: Optional[int] = None,
        **kwargs
    ):
        """
        Authenticate for impersonation.

        Args:
            request: The HTTP request
            impersonator: The admin user performing impersonation
            target_user_id: ID of user to impersonate

        Returns:
            Target user if impersonation is authorized, None otherwise
        """
        if impersonator is None or target_user_id is None:
            return None

        # Verify impersonator has permission
        if not self._can_impersonate(impersonator):
            return None

        # Get target user
        try:
            target_user = User.objects.get(id=target_user_id)
        except User.DoesNotExist:
            return None

        # Cannot impersonate superusers unless you are one
        if target_user.is_superuser and not impersonator.is_superuser:
            return None

        # Log impersonation
        self._log_impersonation(impersonator, target_user, request)

        return target_user

    def _can_impersonate(self, user) -> bool:
        """
        Check if user has impersonation permission.
        """
        if user.is_superuser:
            return True

        # Check for specific permission
        return user.has_perm('tenant_profiles.can_impersonate')

    def _log_impersonation(self, impersonator, target_user, request):
        """
        Log impersonation event for audit.
        """
        from .models import DataAccessLog

        DataAccessLog.objects.create(
            accessor=impersonator,
            data_subject=target_user,
            data_category='impersonation',
            data_fields=['full_access'],
            access_reason=f"Admin impersonation by {impersonator.email}",
            ip_address=self._get_client_ip(request) if request else None,
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500] if request else '',
            endpoint=request.path if request else ''
        )

    def _get_client_ip(self, request) -> str:
        """
        Extract client IP from request.
        """
        if not request:
            return ''
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')
