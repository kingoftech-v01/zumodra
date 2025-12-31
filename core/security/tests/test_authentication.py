"""
Authentication Security Tests for Zumodra ATS/HR Platform

This module tests authentication security including:
- Password policy enforcement (min length, complexity, common passwords)
- Account lockout after failed attempts
- MFA enrollment and verification
- Session security (concurrent sessions, session fixation)
- JWT token security (expiry, refresh rotation)
- Brute force protection

Each test documents the attack vector being tested.
"""

import time
import jwt
import hashlib
from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.core.cache import cache
from django.test import TestCase, RequestFactory, override_settings
from django.utils import timezone

User = get_user_model()


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def password_validator():
    """Create PasswordValidator instance."""
    from core.security.authentication import PasswordValidator
    return PasswordValidator()


@pytest.fixture
def mfa_service():
    """Create MFAService instance."""
    from core.security.authentication import MFAService
    return MFAService()


@pytest.fixture
def session_manager():
    """Create SessionSecurityManager instance."""
    from core.security.authentication import SessionSecurityManager
    return SessionSecurityManager()


@pytest.fixture
def jwt_service():
    """Create JWTSecurityEnhancer instance."""
    from core.security.authentication import JWTSecurityEnhancer
    return JWTSecurityEnhancer()


@pytest.fixture
def brute_force_protection():
    """Create BruteForceProtection instance."""
    from core.security.authentication import BruteForceProtection
    return BruteForceProtection()


@pytest.fixture
def clear_cache():
    """Clear cache before and after tests."""
    cache.clear()
    yield
    cache.clear()


# =============================================================================
# PASSWORD POLICY TESTS
# =============================================================================

class TestPasswordPolicy:
    """
    Tests for password policy enforcement.

    Attack Vectors:
    - Weak passwords enable brute force attacks
    - Common passwords are in rainbow tables
    - Passwords similar to personal data are guessable
    - Short passwords have limited keyspace
    """

    def test_rejects_password_too_short(self, password_validator):
        """
        Test: Passwords under minimum length are rejected.
        Attack Vector: Short passwords are easily brute-forced.
        Minimum should be 12+ characters per NIST guidelines.
        """
        with pytest.raises(ValueError) as excinfo:
            password_validator.validate('Short1!')

        assert 'length' in str(excinfo.value).lower() or 'short' in str(excinfo.value).lower()

    def test_rejects_password_without_uppercase(self, password_validator):
        """
        Test: Passwords must contain uppercase letters.
        Attack Vector: Reduced character set is easier to crack.
        """
        with pytest.raises(ValueError) as excinfo:
            password_validator.validate('alllowercase123!')

        assert 'uppercase' in str(excinfo.value).lower()

    def test_rejects_password_without_lowercase(self, password_validator):
        """
        Test: Passwords must contain lowercase letters.
        Attack Vector: Reduced character set is easier to crack.
        """
        with pytest.raises(ValueError) as excinfo:
            password_validator.validate('ALLUPPERCASE123!')

        assert 'lowercase' in str(excinfo.value).lower()

    def test_rejects_password_without_number(self, password_validator):
        """
        Test: Passwords must contain at least one number.
        Attack Vector: Reduced character set is easier to crack.
        """
        with pytest.raises(ValueError) as excinfo:
            password_validator.validate('NoNumbersHere!')

        assert 'number' in str(excinfo.value).lower() or 'digit' in str(excinfo.value).lower()

    def test_rejects_password_without_special_char(self, password_validator):
        """
        Test: Passwords must contain special characters.
        Attack Vector: Reduced character set is easier to crack.
        """
        with pytest.raises(ValueError) as excinfo:
            password_validator.validate('NoSpecialChars123')

        assert 'special' in str(excinfo.value).lower()

    def test_rejects_common_passwords(self, password_validator):
        """
        Test: Common passwords from breach lists are rejected.
        Attack Vector: Top 10000 passwords cover large % of users.
        """
        common_passwords = [
            'Password123!',
            'Qwerty123!@#',
            'Welcome1!@#',
            'Admin123!@#',
            'Password1!',
        ]

        for password in common_passwords:
            with pytest.raises(ValueError) as excinfo:
                password_validator.validate(password)

            assert 'common' in str(excinfo.value).lower() or 'weak' in str(excinfo.value).lower()

    def test_rejects_password_similar_to_username(self, password_validator, user_factory, db):
        """
        Test: Passwords similar to username are rejected.
        Attack Vector: User-specific password guessing.
        """
        user = user_factory(username='johnsmith')

        with pytest.raises(ValueError) as excinfo:
            password_validator.validate('JohnSmith123!', user=user)

        assert 'username' in str(excinfo.value).lower() or 'similar' in str(excinfo.value).lower()

    def test_rejects_password_similar_to_email(self, password_validator, user_factory, db):
        """
        Test: Passwords similar to email are rejected.
        Attack Vector: User-specific password guessing.
        """
        user = user_factory(email='john.doe@company.com')

        with pytest.raises(ValueError) as excinfo:
            password_validator.validate('JohnDoe123!@#', user=user)

    def test_accepts_strong_password(self, password_validator):
        """
        Positive Test: Strong passwords are accepted.
        """
        strong_passwords = [
            'Tr0ub4dor&3$ecure',
            'C0mpl3x!P@ssw0rd#2024',
            'Xk9#mN2$pL7@vQ4w',
        ]

        for password in strong_passwords:
            # Should not raise
            password_validator.validate(password)

    def test_password_entropy_check(self, password_validator):
        """
        Test: Passwords with low entropy are rejected.
        Attack Vector: Repetitive patterns are easily guessed.
        """
        low_entropy_passwords = [
            'Aaaaaaa111!!!!',
            'Abcd1234!!!!',
            'Qqqqqqqq1!1!',
        ]

        for password in low_entropy_passwords:
            with pytest.raises(ValueError) as excinfo:
                password_validator.validate(password)

    def test_password_history_check(self, password_validator, user_factory, db):
        """
        Test: Previous passwords cannot be reused.
        Attack Vector: Cycling through same passwords.
        """
        user = user_factory()

        # Simulate password history
        with patch.object(password_validator, 'get_password_history') as mock:
            mock.return_value = [
                hashlib.sha256(b'OldPassword123!').hexdigest(),
            ]

            with pytest.raises(ValueError) as excinfo:
                password_validator.validate('OldPassword123!', user=user)

            assert 'previous' in str(excinfo.value).lower() or 'history' in str(excinfo.value).lower()


# =============================================================================
# ACCOUNT LOCKOUT TESTS
# =============================================================================

class TestAccountLockout:
    """
    Tests for account lockout after failed attempts.

    Attack Vectors:
    - Brute force password attacks
    - Credential stuffing
    - User enumeration via timing attacks
    """

    @pytest.fixture
    def lockout_service(self):
        """Create AccountLockoutManager instance."""
        from core.security.authentication import AccountLockoutManager
        return AccountLockoutManager()

    def test_lockout_after_max_failed_attempts(
        self, lockout_service, user_factory, db, clear_cache
    ):
        """
        Test: Account locks after maximum failed attempts.
        Attack Vector: Brute force password guessing.
        """
        user = user_factory()

        # Simulate failed attempts (default max is usually 5)
        for i in range(5):
            lockout_service.record_failed_attempt(user.email)

        is_locked = lockout_service.is_locked(user.email)
        assert is_locked, "Account should be locked after 5 failed attempts"

    def test_lockout_duration(
        self, lockout_service, user_factory, db, clear_cache
    ):
        """
        Test: Lockout expires after specified duration.
        """
        user = user_factory()

        # Lock the account
        for i in range(5):
            lockout_service.record_failed_attempt(user.email)

        # Verify locked
        assert lockout_service.is_locked(user.email)

        # Simulate time passing (lockout duration is typically 15-30 min)
        with patch('core.security.authentication.timezone.now') as mock_now:
            mock_now.return_value = timezone.now() + timedelta(minutes=31)
            assert not lockout_service.is_locked(user.email)

    def test_successful_login_resets_counter(
        self, lockout_service, user_factory, db, clear_cache
    ):
        """
        Test: Successful login resets the failure counter.
        """
        user = user_factory()

        # Record some failed attempts (but not enough to lock)
        for i in range(3):
            lockout_service.record_failed_attempt(user.email)

        # Record successful login
        lockout_service.record_successful_login(user.email)

        # More failed attempts shouldn't immediately lock
        for i in range(3):
            lockout_service.record_failed_attempt(user.email)

        # Shouldn't be locked yet (counter was reset)
        assert not lockout_service.is_locked(user.email)

    def test_lockout_per_account_not_global(
        self, lockout_service, user_factory, db, clear_cache
    ):
        """
        Test: Lockout is per-account, not global.
        Attack Vector: DoS by locking all accounts.
        """
        user1 = user_factory(email='user1@test.com')
        user2 = user_factory(email='user2@test.com')

        # Lock user1
        for i in range(5):
            lockout_service.record_failed_attempt(user1.email)

        # User2 should not be affected
        assert not lockout_service.is_locked(user2.email)

    def test_lockout_includes_ip_tracking(
        self, lockout_service, user_factory, db, clear_cache
    ):
        """
        Test: Failed attempts are tracked by IP as well.
        Attack Vector: Distributed brute force from single IP.
        """
        ip_address = '192.168.1.100'

        # Multiple failed attempts from same IP for different users
        for i in range(10):
            lockout_service.record_failed_attempt(
                f'user{i}@test.com',
                ip_address=ip_address
            )

        # IP should be temporarily blocked
        assert lockout_service.is_ip_blocked(ip_address)

    def test_timing_attack_mitigation(
        self, lockout_service, user_factory, db, clear_cache
    ):
        """
        Test: Response time is consistent to prevent user enumeration.
        Attack Vector: Timing differences reveal valid usernames.
        """
        existing_user = user_factory(email='exists@test.com')

        # Time response for existing user
        import time
        start = time.time()
        lockout_service.check_and_record_attempt('exists@test.com', success=False)
        existing_time = time.time() - start

        # Time response for non-existing user
        start = time.time()
        lockout_service.check_and_record_attempt('notexists@test.com', success=False)
        nonexisting_time = time.time() - start

        # Times should be similar (within 50ms)
        assert abs(existing_time - nonexisting_time) < 0.05


# =============================================================================
# MFA TESTS
# =============================================================================

class TestMFA:
    """
    Tests for Multi-Factor Authentication.

    Attack Vectors:
    - MFA bypass attempts
    - TOTP code brute forcing
    - Backup code abuse
    - MFA fatigue attacks
    """

    def test_mfa_secret_generation(self, mfa_service, user_factory, db):
        """
        Test: MFA secrets are properly generated.
        """
        user = user_factory()

        secret = mfa_service.generate_secret(user)

        # Secret should be 32 characters (base32 encoded 160 bits)
        assert len(secret) >= 16
        # Should be valid base32
        import base64
        try:
            base64.b32decode(secret)
        except Exception:
            pytest.fail("MFA secret is not valid base32")

    def test_mfa_totp_verification(self, mfa_service, user_factory, db):
        """
        Positive Test: Valid TOTP codes are accepted.
        """
        user = user_factory()
        secret = mfa_service.generate_secret(user)

        # Generate valid TOTP
        import pyotp
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        assert mfa_service.verify_totp(user, valid_code)

    def test_mfa_rejects_invalid_code(self, mfa_service, user_factory, db):
        """
        Test: Invalid TOTP codes are rejected.
        """
        user = user_factory()
        mfa_service.generate_secret(user)

        assert not mfa_service.verify_totp(user, '000000')
        assert not mfa_service.verify_totp(user, '123456')

    def test_mfa_code_cannot_be_reused(self, mfa_service, user_factory, db, clear_cache):
        """
        Test: TOTP codes cannot be reused.
        Attack Vector: Replay attacks.
        """
        user = user_factory()
        secret = mfa_service.generate_secret(user)

        import pyotp
        totp = pyotp.TOTP(secret)
        code = totp.now()

        # First use should succeed
        assert mfa_service.verify_totp(user, code)

        # Second use should fail
        assert not mfa_service.verify_totp(user, code)

    def test_mfa_rate_limiting(self, mfa_service, user_factory, db, clear_cache):
        """
        Test: MFA verification is rate limited.
        Attack Vector: TOTP code brute forcing (10^6 combinations).
        """
        user = user_factory()
        mfa_service.generate_secret(user)

        # Attempt multiple wrong codes
        for i in range(5):
            mfa_service.verify_totp(user, f'{i:06d}')

        # Should be rate limited
        with pytest.raises(Exception) as excinfo:
            mfa_service.verify_totp(user, '999999')

        assert 'rate' in str(excinfo.value).lower() or 'limit' in str(excinfo.value).lower()

    def test_backup_codes_generated(self, mfa_service, user_factory, db):
        """
        Test: Backup codes are generated during MFA enrollment.
        """
        user = user_factory()

        backup_codes = mfa_service.generate_backup_codes(user)

        # Should generate 10 codes
        assert len(backup_codes) == 10
        # Each code should be unique
        assert len(set(backup_codes)) == 10
        # Codes should be 8+ characters
        assert all(len(code) >= 8 for code in backup_codes)

    def test_backup_code_single_use(self, mfa_service, user_factory, db):
        """
        Test: Backup codes can only be used once.
        """
        user = user_factory()
        backup_codes = mfa_service.generate_backup_codes(user)

        first_code = backup_codes[0]

        # First use should succeed
        assert mfa_service.verify_backup_code(user, first_code)

        # Second use should fail
        assert not mfa_service.verify_backup_code(user, first_code)

    def test_mfa_cannot_be_disabled_without_verification(
        self, mfa_service, user_factory, db
    ):
        """
        Test: MFA cannot be disabled without current MFA verification.
        Attack Vector: Account takeover disabling MFA.
        """
        user = user_factory()
        secret = mfa_service.generate_secret(user)
        mfa_service.enable_mfa(user)

        with pytest.raises(Exception):
            mfa_service.disable_mfa(user, verification_code=None)


# =============================================================================
# SESSION SECURITY TESTS
# =============================================================================

class TestSessionSecurity:
    """
    Tests for session security.

    Attack Vectors:
    - Session fixation
    - Session hijacking
    - Concurrent session abuse
    - Session timeout bypass
    """

    def test_session_regenerated_on_login(self, session_manager, user_factory, db):
        """
        Test: Session ID is regenerated after login.
        Attack Vector: Session fixation - attacker sets session before victim logs in.
        """
        user = user_factory()
        request = MagicMock()
        request.session = MagicMock()
        old_session_key = 'old_session_key_12345'
        request.session.session_key = old_session_key

        session_manager.handle_login(request, user)

        request.session.cycle_key.assert_called()

    def test_session_data_cleared_on_logout(self, session_manager, user_factory, db):
        """
        Test: Session data is cleared on logout.
        Attack Vector: Session data persistence after logout.
        """
        user = user_factory()
        request = MagicMock()
        request.session = {'user_id': user.id, 'tenant_id': 1, 'sensitive': 'data'}
        request.user = user

        session_manager.handle_logout(request)

        request.session.flush.assert_called()

    def test_concurrent_session_limit(self, session_manager, user_factory, db):
        """
        Test: Users cannot have more than allowed concurrent sessions.
        Attack Vector: Session sharing, unauthorized access.
        """
        user = user_factory()

        # Create max sessions
        max_sessions = 3
        for i in range(max_sessions):
            session_manager.create_session(user, f'device_{i}')

        # Trying to create another should fail or invalidate oldest
        with pytest.raises(Exception) as excinfo:
            session_manager.create_session(user, 'device_new')
            # Or verify oldest was invalidated

    def test_session_binding_to_user_agent(self, session_manager, user_factory, db):
        """
        Test: Sessions are bound to user agent.
        Attack Vector: Session hijacking with different browser.
        """
        user = user_factory()
        request = MagicMock()
        request.META = {'HTTP_USER_AGENT': 'Mozilla/5.0 Chrome'}

        session = session_manager.create_session(user, request=request)

        # Validate with same user agent
        assert session_manager.validate_session(session, user_agent='Mozilla/5.0 Chrome')

        # Should fail with different user agent
        assert not session_manager.validate_session(session, user_agent='curl/7.0')

    def test_session_binding_to_ip(self, session_manager, user_factory, db):
        """
        Test: Sessions can be bound to IP address.
        Attack Vector: Session hijacking from different location.
        """
        user = user_factory()
        request = MagicMock()
        request.META = {'REMOTE_ADDR': '192.168.1.100'}

        session = session_manager.create_session(user, request=request, bind_ip=True)

        # Validate with same IP
        assert session_manager.validate_session(session, ip_address='192.168.1.100')

        # Should fail with different IP
        assert not session_manager.validate_session(session, ip_address='10.0.0.1')

    def test_session_timeout(self, session_manager, user_factory, db):
        """
        Test: Sessions expire after timeout.
        """
        user = user_factory()

        session = session_manager.create_session(user, timeout_minutes=30)

        # Session should be valid now
        assert session_manager.is_session_valid(session)

        # Simulate time passing
        with patch('core.security.authentication.timezone.now') as mock_now:
            mock_now.return_value = timezone.now() + timedelta(minutes=31)
            assert not session_manager.is_session_valid(session)

    def test_session_activity_extends_timeout(self, session_manager, user_factory, db):
        """
        Test: Session activity extends timeout (sliding expiration).
        """
        user = user_factory()
        session = session_manager.create_session(user, timeout_minutes=30)

        # Simulate activity after 20 minutes
        with patch('core.security.authentication.timezone.now') as mock_now:
            mock_now.return_value = timezone.now() + timedelta(minutes=20)
            session_manager.record_activity(session)

        # Session should still be valid after 40 minutes from start
        # (20 minutes after last activity)
        with patch('core.security.authentication.timezone.now') as mock_now:
            mock_now.return_value = timezone.now() + timedelta(minutes=40)
            assert session_manager.is_session_valid(session)

    def test_secure_cookie_flags(self, session_manager):
        """
        Test: Session cookies have secure flags set.
        """
        cookie_settings = session_manager.get_cookie_settings()

        assert cookie_settings['secure'] is True
        assert cookie_settings['httponly'] is True
        assert cookie_settings['samesite'] in ['Strict', 'Lax']


# =============================================================================
# JWT SECURITY TESTS
# =============================================================================

class TestJWTSecurity:
    """
    Tests for JWT token security.

    Attack Vectors:
    - Token replay
    - Token tampering
    - Algorithm confusion
    - Expired token usage
    """

    def test_jwt_contains_required_claims(self, jwt_service, user_factory, db):
        """
        Test: JWT contains all required security claims.
        """
        user = user_factory()

        token = jwt_service.generate_access_token(user)
        decoded = jwt.decode(token, options={'verify_signature': False})

        # Required claims
        assert 'sub' in decoded  # Subject (user ID)
        assert 'iat' in decoded  # Issued at
        assert 'exp' in decoded  # Expiration
        assert 'jti' in decoded  # JWT ID (for revocation)
        assert 'iss' in decoded  # Issuer

    def test_jwt_expires(self, jwt_service, user_factory, db):
        """
        Test: JWT tokens expire after specified time.
        """
        user = user_factory()

        token = jwt_service.generate_access_token(user, expires_in_minutes=5)

        # Token should be valid now
        assert jwt_service.validate_token(token)

        # Simulate time passing
        with patch('core.security.authentication.timezone.now') as mock_now:
            mock_now.return_value = timezone.now() + timedelta(minutes=6)
            assert not jwt_service.validate_token(token)

    def test_jwt_algorithm_not_none(self, jwt_service, user_factory, db):
        """
        Test: JWT 'none' algorithm is rejected.
        Attack Vector: Algorithm confusion - signing with 'none'.
        """
        user = user_factory()
        valid_token = jwt_service.generate_access_token(user)

        # Decode without verification to get payload
        payload = jwt.decode(valid_token, options={'verify_signature': False})

        # Create unsigned token with 'none' algorithm
        unsigned_token = jwt.encode(payload, '', algorithm='none')

        # Should be rejected
        assert not jwt_service.validate_token(unsigned_token)

    def test_jwt_signature_validation(self, jwt_service, user_factory, db):
        """
        Test: JWT with invalid signature is rejected.
        Attack Vector: Token tampering.
        """
        user = user_factory()
        token = jwt_service.generate_access_token(user)

        # Tamper with token (change last character)
        tampered_token = token[:-1] + ('a' if token[-1] != 'a' else 'b')

        assert not jwt_service.validate_token(tampered_token)

    def test_refresh_token_rotation(self, jwt_service, user_factory, db):
        """
        Test: Refresh tokens are rotated on use.
        Attack Vector: Token replay - using stolen refresh token.
        """
        user = user_factory()

        refresh_token = jwt_service.generate_refresh_token(user)

        # Use refresh token to get new access token
        new_access, new_refresh = jwt_service.refresh_access_token(refresh_token)

        # Old refresh token should be invalidated
        with pytest.raises(Exception):
            jwt_service.refresh_access_token(refresh_token)

    def test_refresh_token_family_revocation(self, jwt_service, user_factory, db):
        """
        Test: Refresh token reuse revokes entire token family.
        Attack Vector: Parallel use of stolen refresh token.
        """
        user = user_factory()

        refresh_token = jwt_service.generate_refresh_token(user)

        # Legitimate user refreshes
        new_access, new_refresh = jwt_service.refresh_access_token(refresh_token)

        # Attacker tries to use old refresh token
        # This should revoke ALL tokens in the family
        try:
            jwt_service.refresh_access_token(refresh_token)
        except Exception:
            pass

        # Even the new refresh token should now be invalid
        with pytest.raises(Exception):
            jwt_service.refresh_access_token(new_refresh)

    def test_jwt_blacklisting(self, jwt_service, user_factory, db, clear_cache):
        """
        Test: Revoked JWTs are rejected.
        """
        user = user_factory()
        token = jwt_service.generate_access_token(user)

        # Token valid before revocation
        assert jwt_service.validate_token(token)

        # Revoke token
        jwt_service.revoke_token(token)

        # Token should be rejected
        assert not jwt_service.validate_token(token)


# =============================================================================
# BRUTE FORCE PROTECTION TESTS
# =============================================================================

class TestBruteForceProtection:
    """
    Tests for brute force protection.

    Attack Vectors:
    - Password brute forcing
    - Credential stuffing
    - Username enumeration
    """

    def test_blocks_after_failed_attempts(
        self, brute_force_protection, user_factory, db, clear_cache
    ):
        """
        Test: IP is blocked after multiple failed login attempts.
        """
        ip = '192.168.1.200'

        for i in range(10):
            brute_force_protection.record_failed_attempt(ip=ip)

        assert brute_force_protection.is_blocked(ip=ip)

    def test_exponential_backoff(
        self, brute_force_protection, user_factory, db, clear_cache
    ):
        """
        Test: Block duration increases with repeated violations.
        """
        ip = '192.168.1.201'

        # First block
        for i in range(5):
            brute_force_protection.record_failed_attempt(ip=ip)

        first_block_duration = brute_force_protection.get_block_duration(ip=ip)

        # Wait and trigger second block
        brute_force_protection.reset(ip=ip)
        for i in range(5):
            brute_force_protection.record_failed_attempt(ip=ip)

        second_block_duration = brute_force_protection.get_block_duration(ip=ip)

        assert second_block_duration > first_block_duration

    def test_captcha_triggered(self, brute_force_protection, clear_cache):
        """
        Test: CAPTCHA is triggered after suspicious activity.
        """
        ip = '192.168.1.202'

        for i in range(3):
            brute_force_protection.record_failed_attempt(ip=ip)

        assert brute_force_protection.requires_captcha(ip=ip)

    def test_distributed_attack_detection(
        self, brute_force_protection, clear_cache
    ):
        """
        Test: Distributed attacks against single account are detected.
        Attack Vector: Same account attacked from multiple IPs.
        """
        target_email = 'victim@test.com'

        # Attacks from multiple IPs
        for i in range(20):
            brute_force_protection.record_failed_attempt(
                ip=f'10.0.0.{i}',
                identifier=target_email
            )

        # Account should be protected
        assert brute_force_protection.is_identifier_blocked(target_email)

    def test_successful_login_clears_attempts(
        self, brute_force_protection, clear_cache
    ):
        """
        Test: Successful login clears failed attempt counter.
        """
        ip = '192.168.1.203'

        for i in range(3):
            brute_force_protection.record_failed_attempt(ip=ip)

        brute_force_protection.record_success(ip=ip)

        # Should no longer require captcha
        assert not brute_force_protection.requires_captcha(ip=ip)

    def test_geographic_anomaly_detection(
        self, brute_force_protection, user_factory, db, clear_cache
    ):
        """
        Test: Login from unusual location is flagged.
        Attack Vector: Account access from unexpected location.
        """
        user = user_factory()

        # Normal login location
        brute_force_protection.record_success(
            ip='192.168.1.1',
            identifier=user.email,
            location={'country': 'CA', 'city': 'Toronto'}
        )

        # Attempt from different country
        result = brute_force_protection.check_location_anomaly(
            identifier=user.email,
            location={'country': 'RU', 'city': 'Moscow'}
        )

        assert result['is_anomalous']
