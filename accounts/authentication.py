"""
Accounts Authentication - Custom JWT Authentication for Multi-Tenant SaaS

This module implements:
- Tenant-aware JWT token generation and validation
- Custom token claims with tenant/role context
- Token refresh with tenant validation
- Session management with security features
- Token blacklisting and revocation
"""

import uuid
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple

from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.cache import cache
from django.db import models

from rest_framework import authentication, exceptions
from rest_framework.request import Request
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken, Token
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

User = get_user_model()


# =============================================================================
# CUSTOM JWT TOKEN CLASSES
# =============================================================================

class TenantAccessToken(AccessToken):
    """
    Custom access token with tenant-aware claims.
    Includes tenant_id, role, and permission context.
    """

    token_type = 'access'
    lifetime = timedelta(hours=1)

    @classmethod
    def for_user_and_tenant(cls, user, tenant=None, tenant_user=None):
        """
        Generate access token with tenant context.

        Args:
            user: The authenticated user
            tenant: The tenant context (optional)
            tenant_user: The TenantUser membership (optional)

        Returns:
            TenantAccessToken with custom claims
        """
        token = cls()

        # Standard claims
        token['user_id'] = user.id
        token['email'] = user.email
        token['token_id'] = str(uuid.uuid4())
        token['iat'] = datetime.utcnow().timestamp()

        # User claims
        token['is_superuser'] = user.is_superuser
        token['is_staff'] = user.is_staff
        token['is_active'] = user.is_active

        # KYC status
        if hasattr(user, 'kyc_verifications'):
            from .models import KYCVerification
            verified_kyc = user.kyc_verifications.filter(
                status=KYCVerification.VerificationStatus.VERIFIED,
                expires_at__gt=timezone.now()
            ).first()
            token['kyc_verified'] = verified_kyc is not None
            token['kyc_level'] = verified_kyc.level if verified_kyc else None
        else:
            token['kyc_verified'] = False
            token['kyc_level'] = None

        # 2FA status
        token['has_2fa'] = cls._check_2fa_status(user)

        # Tenant context
        if tenant:
            token['tenant_id'] = tenant.id
            token['tenant_uuid'] = str(tenant.uuid)
            token['tenant_name'] = tenant.name
            token['tenant_status'] = tenant.status

            # Plan features
            if tenant.plan:
                token['plan_type'] = tenant.plan.plan_type
                token['plan_features'] = cls._get_plan_features(tenant.plan)

        if tenant_user:
            token['role'] = tenant_user.role
            token['permissions'] = list(tenant_user.get_all_permissions())
            token['is_admin'] = tenant_user.is_admin
            token['can_hire'] = tenant_user.can_hire
            token['department_id'] = tenant_user.department_id

        return token

    @staticmethod
    def _check_2fa_status(user) -> bool:
        """Check if user has 2FA enabled."""
        try:
            from django_otp import devices_for_user
            return any(devices_for_user(user, confirmed=True))
        except ImportError:
            return False

    @staticmethod
    def _get_plan_features(plan) -> Dict[str, bool]:
        """Extract enabled features from plan."""
        features = {}
        for field in plan._meta.get_fields():
            if field.name.startswith('feature_'):
                features[field.name] = getattr(plan, field.name, False)
        return features


class TenantRefreshToken(RefreshToken):
    """
    Custom refresh token with tenant context.
    Supports tenant-scoped token refresh and rotation.
    """

    token_type = 'refresh'
    lifetime = timedelta(days=7)
    access_token_class = TenantAccessToken

    @classmethod
    def for_user_and_tenant(cls, user, tenant=None, tenant_user=None):
        """
        Generate refresh token with tenant context.
        """
        token = cls()

        token['user_id'] = user.id
        token['token_id'] = str(uuid.uuid4())
        token['iat'] = datetime.utcnow().timestamp()

        if tenant:
            token['tenant_id'] = tenant.id
            token['tenant_uuid'] = str(tenant.uuid)

        if tenant_user:
            token['role'] = tenant_user.role

        # Store token metadata for revocation
        cls._store_token_metadata(token, user, tenant)

        return token

    @staticmethod
    def _store_token_metadata(token, user, tenant):
        """Store token metadata in cache for tracking and revocation."""
        token_id = token.get('token_id')
        if token_id:
            cache_key = f"jwt_token:{user.id}:{token_id}"
            metadata = {
                'user_id': user.id,
                'tenant_id': tenant.id if tenant else None,
                'created_at': timezone.now().isoformat(),
                'is_valid': True
            }
            # Store for token lifetime + 1 day buffer
            cache.set(cache_key, metadata, timeout=8 * 24 * 60 * 60)

    def access_token_with_tenant(self, tenant=None, tenant_user=None):
        """
        Generate access token maintaining tenant context from refresh token.
        """
        access = self.access_token_class()

        # Copy claims from refresh token
        access['user_id'] = self['user_id']
        access['token_id'] = str(uuid.uuid4())
        access['iat'] = datetime.utcnow().timestamp()

        # Add tenant context
        if tenant:
            access['tenant_id'] = tenant.id
            access['tenant_uuid'] = str(tenant.uuid)
            access['tenant_name'] = tenant.name
        elif 'tenant_id' in self.payload:
            access['tenant_id'] = self['tenant_id']
            access['tenant_uuid'] = self.get('tenant_uuid')

        if tenant_user:
            access['role'] = tenant_user.role
            access['permissions'] = list(tenant_user.get_all_permissions())
        elif 'role' in self.payload:
            access['role'] = self['role']

        return access


# =============================================================================
# TENANT-AWARE JWT AUTHENTICATION
# =============================================================================

class TenantJWTAuthentication(JWTAuthentication):
    """
    Custom JWT authentication with tenant context validation.

    Validates:
    - Token signature and expiration
    - Tenant membership and status
    - User active status
    - Token blacklist status
    """

    def authenticate(self, request: Request) -> Optional[Tuple[User, Dict]]:
        """
        Authenticate request with tenant-aware JWT validation.

        Returns:
            Tuple of (user, validated_token) or None
        """
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        user = self.get_user(validated_token)

        # Validate tenant context
        self._validate_tenant_context(request, user, validated_token)

        # Check token blacklist
        self._check_token_blacklist(validated_token)

        # Update last activity
        self._update_last_activity(user, validated_token)

        return (user, validated_token)

    def _validate_tenant_context(self, request, user, token):
        """
        Validate that user has access to the requested tenant.
        """
        from .models import TenantUser

        # Get tenant from request or token
        request_tenant = getattr(request, 'tenant', None)
        token_tenant_id = token.get('tenant_id')

        if request_tenant and token_tenant_id:
            # Validate token tenant matches request tenant
            if request_tenant.id != token_tenant_id:
                raise exceptions.AuthenticationFailed(
                    'Token tenant does not match request tenant.'
                )

            # Validate user is active member of tenant
            try:
                tenant_user = TenantUser.objects.get(
                    user=user,
                    tenant=request_tenant,
                    is_active=True
                )
                # Attach tenant_user to request for permission checks
                request.tenant_user = tenant_user
            except TenantUser.DoesNotExist:
                raise exceptions.AuthenticationFailed(
                    'User is not a member of this organization.'
                )

            # Validate tenant status
            if not request_tenant.is_active and request_tenant.status != 'trial':
                raise exceptions.AuthenticationFailed(
                    'Organization access is suspended.'
                )

    def _check_token_blacklist(self, token):
        """
        Check if token has been revoked/blacklisted.
        """
        token_id = token.get('token_id')
        if token_id:
            cache_key = f"jwt_blacklist:{token_id}"
            if cache.get(cache_key):
                raise exceptions.AuthenticationFailed(
                    'Token has been revoked.'
                )

    def _update_last_activity(self, user, token):
        """
        Update user's last activity timestamp.
        """
        from .models import TenantUser

        tenant_id = token.get('tenant_id')
        if tenant_id:
            TenantUser.objects.filter(
                user=user,
                tenant_id=tenant_id
            ).update(last_active_at=timezone.now())


# =============================================================================
# SESSION MANAGEMENT
# =============================================================================

class SessionStorage:
    """
    Database-backed session storage with cache layer.
    Ensures sessions survive cache restarts while maintaining performance.
    """

    @classmethod
    def save_session(cls, user_id: int, session_id: str, session_data: Dict[str, Any]) -> bool:
        """
        Save session to both database and cache.

        Args:
            user_id: The user's ID
            session_id: Unique session identifier
            session_data: Session metadata dictionary

        Returns:
            True if saved successfully
        """
        import logging
        import json
        logger = logging.getLogger('security')

        cache_key = f"user_session:{user_id}:{session_id}"

        try:
            # Save to database first (primary storage)
            from django.db import connection

            with connection.cursor() as cursor:
                # Create table if not exists
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_sessions (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        session_id VARCHAR(255) NOT NULL UNIQUE,
                        session_data TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP NOT NULL,
                        is_active BOOLEAN DEFAULT TRUE,
                        CONSTRAINT unique_user_session UNIQUE (user_id, session_id)
                    )
                ''')

                # Create index for faster lookups
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id
                    ON user_sessions (user_id, is_active)
                ''')

                expires_at = timezone.now() + timedelta(days=7)
                cursor.execute(
                    '''
                    INSERT INTO user_sessions (user_id, session_id, session_data, expires_at, is_active)
                    VALUES (%s, %s, %s, %s, TRUE)
                    ON CONFLICT (session_id) DO UPDATE SET
                        session_data = EXCLUDED.session_data,
                        last_activity = CURRENT_TIMESTAMP,
                        is_active = TRUE
                    ''',
                    [user_id, session_id, json.dumps(session_data), expires_at]
                )

            # Then cache for performance (7 days)
            cache.set(cache_key, session_data, timeout=7 * 24 * 60 * 60)

            logger.debug(f"Session saved: user={user_id}, session={session_id[:8]}...")
            return True

        except Exception as e:
            logger.error(
                f"Failed to save session to database",
                extra={'user_id': user_id, 'session_id': session_id, 'error': str(e)}
            )
            # Still try to save to cache as fallback
            try:
                cache.set(cache_key, session_data, timeout=7 * 24 * 60 * 60)
                return True
            except Exception:
                return False

    @classmethod
    def get_session(cls, user_id: int, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve session, checking cache first then database.
        """
        import json
        cache_key = f"user_session:{user_id}:{session_id}"

        # Try cache first
        session_data = cache.get(cache_key)
        if session_data:
            return session_data

        # Fallback to database
        try:
            from django.db import connection

            with connection.cursor() as cursor:
                cursor.execute(
                    '''
                    SELECT session_data FROM user_sessions
                    WHERE user_id = %s AND session_id = %s AND is_active = TRUE
                    AND expires_at > CURRENT_TIMESTAMP
                    ''',
                    [user_id, session_id]
                )
                row = cursor.fetchone()

                if row:
                    session_data = json.loads(row[0])
                    # Repopulate cache
                    cache.set(cache_key, session_data, timeout=7 * 24 * 60 * 60)
                    return session_data

        except Exception:
            pass

        return None

    @classmethod
    def delete_session(cls, user_id: int, session_id: str):
        """
        Mark session as inactive in database and remove from cache.
        """
        import logging
        logger = logging.getLogger('security')

        cache_key = f"user_session:{user_id}:{session_id}"

        try:
            from django.db import connection

            with connection.cursor() as cursor:
                cursor.execute(
                    '''
                    UPDATE user_sessions
                    SET is_active = FALSE, last_activity = CURRENT_TIMESTAMP
                    WHERE user_id = %s AND session_id = %s
                    ''',
                    [user_id, session_id]
                )

            cache.delete(cache_key)
            logger.info(f"Session revoked: user={user_id}, session={session_id[:8]}...")

        except Exception as e:
            logger.error(f"Failed to delete session: {e}")
            # Still try to delete from cache
            cache.delete(cache_key)

    @classmethod
    def get_user_sessions(cls, user_id: int) -> list:
        """
        Get all active sessions for a user from database.
        """
        import json
        sessions = []

        try:
            from django.db import connection

            with connection.cursor() as cursor:
                cursor.execute(
                    '''
                    SELECT session_id, session_data FROM user_sessions
                    WHERE user_id = %s AND is_active = TRUE
                    AND expires_at > CURRENT_TIMESTAMP
                    ORDER BY created_at ASC
                    ''',
                    [user_id]
                )

                for row in cursor.fetchall():
                    session_data = json.loads(row[1])
                    session_data['session_id'] = row[0]
                    sessions.append(session_data)

        except Exception:
            # Fallback to cache-based session list
            list_key = f"user_sessions:{user_id}"
            session_ids = cache.get(list_key) or []
            for sid in session_ids:
                data = cache.get(f"user_session:{user_id}:{sid}")
                if data and data.get('is_active'):
                    sessions.append(data)

        return sessions

    @classmethod
    def cleanup_expired_sessions(cls):
        """
        Clean up expired sessions from database. Run periodically via Celery.
        """
        import logging
        logger = logging.getLogger('security')

        try:
            from django.db import connection

            with connection.cursor() as cursor:
                cursor.execute(
                    '''
                    DELETE FROM user_sessions
                    WHERE expires_at < CURRENT_TIMESTAMP
                    OR (is_active = FALSE AND last_activity < CURRENT_TIMESTAMP - INTERVAL '24 hours')
                    '''
                )
                deleted = cursor.rowcount
                logger.info(f"Cleaned up {deleted} expired sessions")

        except Exception as e:
            logger.error(f"Session cleanup failed: {e}")


class SessionManager:
    """
    Manages user sessions with security features:
    - Active session tracking with database persistence
    - Concurrent session limits
    - Session revocation
    - Device fingerprinting
    - Cache layer for performance with DB fallback
    """

    MAX_SESSIONS_PER_USER = 5
    SESSION_PREFIX = 'user_session:'

    @classmethod
    def create_session(
        cls,
        user,
        request,
        tenant=None,
        device_info: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Create a new session with full tracking.
        Sessions are persisted to database with cache layer.

        Returns:
            Dict containing session_id, tokens, and metadata
        """
        session_id = str(uuid.uuid4())

        # Generate device fingerprint
        fingerprint = cls._generate_fingerprint(request, device_info)

        # Check and enforce session limits
        cls._enforce_session_limit(user)

        # Get tenant user if in tenant context
        tenant_user = None
        if tenant:
            from .models import TenantUser
            tenant_user = TenantUser.objects.filter(
                user=user,
                tenant=tenant,
                is_active=True
            ).first()

        # Generate tokens
        refresh = TenantRefreshToken.for_user_and_tenant(user, tenant, tenant_user)
        access = refresh.access_token_with_tenant(tenant, tenant_user)

        # Store session metadata
        session_data = {
            'session_id': session_id,
            'user_id': user.id,
            'tenant_id': tenant.id if tenant else None,
            'fingerprint': fingerprint,
            'ip_address': cls._get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', '')[:500],
            'device_info': device_info or {},
            'created_at': timezone.now().isoformat(),
            'last_activity': timezone.now().isoformat(),
            'is_active': True
        }

        # Save to database with cache layer
        SessionStorage.save_session(user.id, session_id, session_data)

        # Also maintain backward-compatible cache key for existing code
        cache_key = f"{cls.SESSION_PREFIX}{user.id}:{session_id}"
        cache.set(cache_key, session_data, timeout=7 * 24 * 60 * 60)  # 7 days

        # Add to user's session list
        cls._add_to_user_sessions(user.id, session_id)

        return {
            'session_id': session_id,
            'access_token': str(access),
            'refresh_token': str(refresh),
            'expires_in': int(access.lifetime.total_seconds()),
            'token_type': 'Bearer'
        }

    @classmethod
    def refresh_session(
        cls,
        refresh_token: str,
        request,
        tenant=None
    ) -> Dict[str, Any]:
        """
        Refresh tokens with session validation.
        """
        try:
            refresh = TenantRefreshToken(refresh_token)
        except TokenError as e:
            raise InvalidToken(str(e))

        user_id = refresh.get('user_id')
        user = User.objects.get(id=user_id)

        # Validate tenant context
        token_tenant_id = refresh.get('tenant_id')
        if tenant and token_tenant_id and tenant.id != token_tenant_id:
            raise InvalidToken('Token tenant mismatch')

        # Get tenant user
        tenant_user = None
        if tenant:
            from .models import TenantUser
            tenant_user = TenantUser.objects.filter(
                user=user,
                tenant=tenant,
                is_active=True
            ).first()

        # Generate new access token
        access = refresh.access_token_with_tenant(tenant, tenant_user)

        # Optionally rotate refresh token
        if getattr(settings, 'SIMPLE_JWT', {}).get('ROTATE_REFRESH_TOKENS', True):
            refresh.set_exp()
            refresh.set_iat()

            # Blacklist old token
            if getattr(settings, 'SIMPLE_JWT', {}).get('BLACKLIST_AFTER_ROTATION', True):
                cls.blacklist_token(refresh_token)

        return {
            'access_token': str(access),
            'refresh_token': str(refresh),
            'expires_in': int(access.lifetime.total_seconds()),
            'token_type': 'Bearer'
        }

    @classmethod
    def revoke_session(cls, user_id: int, session_id: str):
        """
        Revoke a specific session.
        Uses database-backed storage with cache layer.
        """
        # Use SessionStorage for database-backed revocation
        SessionStorage.delete_session(user_id, session_id)

        # Also update cache for backward compatibility
        cache_key = f"{cls.SESSION_PREFIX}{user_id}:{session_id}"
        session_data = cache.get(cache_key)

        if session_data:
            session_data['is_active'] = False
            session_data['revoked_at'] = timezone.now().isoformat()
            cache.set(cache_key, session_data, timeout=24 * 60 * 60)  # Keep for audit

        cls._remove_from_user_sessions(user_id, session_id)

    @classmethod
    def revoke_all_sessions(cls, user_id: int, except_session: Optional[str] = None):
        """
        Revoke all sessions for a user (logout everywhere).
        """
        sessions = cls._get_user_sessions(user_id)

        for session_id in sessions:
            if session_id != except_session:
                cls.revoke_session(user_id, session_id)

    @classmethod
    def get_active_sessions(cls, user_id: int) -> list:
        """
        Get all active sessions for a user.
        Uses database-backed storage with cache fallback.
        """
        # Try database-backed storage first
        active_sessions = SessionStorage.get_user_sessions(user_id)

        if active_sessions:
            return active_sessions

        # Fallback to cache-only method for backward compatibility
        sessions = cls._get_user_sessions(user_id)
        active_sessions = []

        for session_id in sessions:
            cache_key = f"{cls.SESSION_PREFIX}{user_id}:{session_id}"
            session_data = cache.get(cache_key)

            if session_data and session_data.get('is_active'):
                active_sessions.append(session_data)

        return active_sessions

    @classmethod
    def blacklist_token(cls, token: str, max_retries: int = 3) -> bool:
        """
        Add token to blacklist with proper logging and retry mechanism.

        Args:
            token: The token to blacklist
            max_retries: Maximum retry attempts for transient failures

        Returns:
            True if successfully blacklisted, False otherwise
        """
        import logging
        import time
        logger = logging.getLogger('security')

        try:
            if isinstance(token, str):
                decoded = TenantRefreshToken(token)
            else:
                decoded = token

            token_id = decoded.get('token_id')
            if token_id:
                cache_key = f"jwt_blacklist:{token_id}"

                # Retry mechanism for transient cache failures
                for attempt in range(max_retries):
                    try:
                        cache.set(cache_key, True, timeout=8 * 24 * 60 * 60)
                        logger.info(
                            f"Token blacklisted successfully",
                            extra={
                                'token_id': token_id,
                                'cache_key': cache_key,
                                'attempt': attempt + 1
                            }
                        )
                        return True
                    except Exception as cache_error:
                        logger.warning(
                            f"Token blacklist cache operation failed (attempt {attempt + 1}/{max_retries})",
                            extra={
                                'token_id': token_id,
                                'error': str(cache_error),
                                'attempt': attempt + 1
                            }
                        )
                        if attempt < max_retries - 1:
                            time.sleep(0.1 * (attempt + 1))  # Exponential backoff
                        else:
                            # Final attempt failed - log critical and try database fallback
                            logger.critical(
                                f"Token blacklist failed after {max_retries} attempts - SECURITY RISK",
                                extra={
                                    'token_id': token_id,
                                    'error': str(cache_error)
                                }
                            )
                            # Attempt database fallback
                            try:
                                cls._blacklist_token_db_fallback(token_id)
                                return True
                            except Exception as db_error:
                                logger.critical(
                                    f"Token blacklist database fallback also failed",
                                    extra={
                                        'token_id': token_id,
                                        'error': str(db_error)
                                    }
                                )
                return False
            else:
                logger.warning("Token blacklist attempted but token has no token_id")
                return False

        except TokenError as e:
            logger.warning(
                f"Token blacklist failed - invalid token",
                extra={'error': str(e)}
            )
            return False
        except Exception as e:
            logger.error(
                f"Unexpected error during token blacklist",
                extra={'error': str(e), 'error_type': type(e).__name__}
            )
            return False

    @classmethod
    def _blacklist_token_db_fallback(cls, token_id: str):
        """
        Database fallback for token blacklisting when cache is unavailable.
        Uses Django's database to store blacklisted tokens.
        """
        from django.db import connection
        from django.utils import timezone

        # Create table if not exists (idempotent)
        with connection.cursor() as cursor:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS jwt_token_blacklist (
                    token_id VARCHAR(255) PRIMARY KEY,
                    blacklisted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP
                )
            ''')

            # Insert blacklisted token
            expires_at = timezone.now() + timedelta(days=8)
            cursor.execute(
                '''
                INSERT INTO jwt_token_blacklist (token_id, blacklisted_at, expires_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (token_id) DO NOTHING
                ''',
                [token_id, timezone.now(), expires_at]
            )

    @classmethod
    def _generate_fingerprint(cls, request, device_info: Optional[Dict] = None) -> str:
        """
        Generate device fingerprint for session binding.
        """
        components = [
            cls._get_client_ip(request),
            request.META.get('HTTP_USER_AGENT', ''),
            request.META.get('HTTP_ACCEPT_LANGUAGE', ''),
        ]

        if device_info:
            components.extend([
                str(device_info.get('screen_resolution', '')),
                str(device_info.get('timezone', '')),
            ])

        fingerprint_string = '|'.join(components)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:32]

    @classmethod
    def _get_client_ip(cls, request) -> str:
        """
        Extract client IP from request using secure proxy validation.
        Delegates to get_client_ip_secure() for proper X-Forwarded-For handling.
        """
        from .security import get_client_ip_secure
        return get_client_ip_secure(request)

    @classmethod
    def _enforce_session_limit(cls, user):
        """
        Enforce maximum session limit per user.
        """
        sessions = cls._get_user_sessions(user.id)

        if len(sessions) >= cls.MAX_SESSIONS_PER_USER:
            # Revoke oldest session
            oldest_session = sessions[0]
            cls.revoke_session(user.id, oldest_session)

    @classmethod
    def _add_to_user_sessions(cls, user_id: int, session_id: str):
        """
        Add session to user's session list.
        """
        list_key = f"user_sessions:{user_id}"
        sessions = cache.get(list_key) or []
        sessions.append(session_id)
        cache.set(list_key, sessions, timeout=7 * 24 * 60 * 60)

    @classmethod
    def _remove_from_user_sessions(cls, user_id: int, session_id: str):
        """
        Remove session from user's session list.
        """
        list_key = f"user_sessions:{user_id}"
        sessions = cache.get(list_key) or []
        if session_id in sessions:
            sessions.remove(session_id)
            cache.set(list_key, sessions, timeout=7 * 24 * 60 * 60)

    @classmethod
    def _get_user_sessions(cls, user_id: int) -> list:
        """
        Get list of session IDs for user.
        """
        list_key = f"user_sessions:{user_id}"
        return cache.get(list_key) or []


# =============================================================================
# TOKEN UTILITIES
# =============================================================================

def generate_tokens_for_user(user, tenant=None, request=None) -> Dict[str, Any]:
    """
    Convenience function to generate tokens for a user.

    Args:
        user: The authenticated user
        tenant: Optional tenant context
        request: Optional request for session tracking

    Returns:
        Dict containing tokens and metadata
    """
    if request:
        return SessionManager.create_session(user, request, tenant)

    tenant_user = None
    if tenant:
        from .models import TenantUser
        tenant_user = TenantUser.objects.filter(
            user=user,
            tenant=tenant,
            is_active=True
        ).first()

    refresh = TenantRefreshToken.for_user_and_tenant(user, tenant, tenant_user)
    access = refresh.access_token_with_tenant(tenant, tenant_user)

    return {
        'access_token': str(access),
        'refresh_token': str(refresh),
        'expires_in': int(access.lifetime.total_seconds()),
        'token_type': 'Bearer'
    }


def refresh_access_token(refresh_token: str, tenant=None) -> Dict[str, Any]:
    """
    Refresh access token from refresh token.
    """
    try:
        refresh = TenantRefreshToken(refresh_token)
    except TokenError as e:
        raise InvalidToken(str(e))

    user_id = refresh.get('user_id')
    user = User.objects.get(id=user_id)

    tenant_user = None
    if tenant:
        from .models import TenantUser
        tenant_user = TenantUser.objects.filter(
            user=user,
            tenant=tenant,
            is_active=True
        ).first()

    access = refresh.access_token_with_tenant(tenant, tenant_user)

    return {
        'access_token': str(access),
        'expires_in': int(access.lifetime.total_seconds()),
        'token_type': 'Bearer'
    }


def revoke_token(token: str):
    """
    Revoke/blacklist a token.
    """
    SessionManager.blacklist_token(token)


def validate_token_tenant(token: str, tenant) -> bool:
    """
    Validate that token is valid for the specified tenant.
    """
    try:
        decoded = TenantAccessToken(token)
        token_tenant_id = decoded.get('tenant_id')
        return token_tenant_id == tenant.id
    except TokenError:
        return False
