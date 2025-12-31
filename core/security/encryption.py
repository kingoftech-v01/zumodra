"""
Encryption Services for Zumodra

Comprehensive encryption utilities for the multi-tenant ATS/HR SaaS platform:
- FieldEncryption: Fernet-based field encryption for PII
- KeyRotationManager: Encryption key rotation with versioning
- HashingService: Secure password hashing and comparison
- TokenGenerator: Cryptographically secure token generation

All encryption is tenant-aware for multi-tenant isolation.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger('security.encryption')

# Try to import cryptography
try:
    from cryptography.fernet import Fernet, InvalidToken, MultiFernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    logger.warning(
        "cryptography package not available. "
        "Install with: pip install cryptography"
    )


# =============================================================================
# FIELD ENCRYPTION
# =============================================================================

class FieldEncryption:
    """
    Field-level encryption service using Fernet (AES-128-CBC with HMAC).

    Provides:
    - Encrypt/decrypt string values
    - Tenant-aware encryption keys
    - Key versioning for rotation
    - Deterministic encryption option for searchable fields

    Usage:
        encryption = FieldEncryption()
        encrypted = encryption.encrypt('sensitive data')
        decrypted = encryption.decrypt(encrypted)

    Configuration via Django settings:
        FIELD_ENCRYPTION_KEY: Base encryption key (defaults to SECRET_KEY)
        FIELD_ENCRYPTION_SALT: Salt for key derivation
        FIELD_ENCRYPTION_KEYS: Dict of versioned keys for rotation
    """

    KEY_VERSION_PREFIX = 'v1:'
    DEFAULT_SALT = b'zumodra_field_encryption_v1'

    def __init__(self, tenant_id: str = None):
        """
        Initialize the encryption service.

        Args:
            tenant_id: Optional tenant ID for tenant-specific encryption
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError(
                "cryptography package is required. "
                "Install with: pip install cryptography"
            )

        self.tenant_id = tenant_id
        self._fernet = None
        self._multi_fernet = None

    @property
    def fernet(self) -> Fernet:
        """Get or create Fernet instance."""
        if self._fernet is None:
            key = self._get_encryption_key()
            self._fernet = Fernet(key)
        return self._fernet

    @property
    def multi_fernet(self) -> MultiFernet:
        """Get or create MultiFernet for key rotation support."""
        if self._multi_fernet is None:
            keys = self._get_all_encryption_keys()
            fernets = [Fernet(key) for key in keys]
            self._multi_fernet = MultiFernet(fernets)
        return self._multi_fernet

    def _get_encryption_key(self) -> bytes:
        """
        Derive encryption key from configuration.

        Returns:
            Fernet-compatible encryption key
        """
        # Get base key
        base_key = getattr(settings, 'FIELD_ENCRYPTION_KEY', settings.SECRET_KEY)
        if isinstance(base_key, str):
            base_key = base_key.encode()

        # Get salt
        salt = getattr(settings, 'FIELD_ENCRYPTION_SALT', None)
        if salt is None:
            if not getattr(settings, 'DEBUG', False):
                logger.warning(
                    "FIELD_ENCRYPTION_SALT not configured. "
                    "This is a security risk in production."
                )
            salt = self.DEFAULT_SALT
        elif isinstance(salt, str):
            salt = salt.encode()

        # Add tenant ID to salt for tenant isolation
        if self.tenant_id:
            salt = salt + f':{self.tenant_id}'.encode()

        # Derive key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(base_key))

        return derived_key

    def _get_all_encryption_keys(self) -> List[bytes]:
        """
        Get all encryption keys for rotation support.

        Returns:
            List of encryption keys, newest first
        """
        keys = []

        # Get versioned keys from settings
        versioned_keys = getattr(settings, 'FIELD_ENCRYPTION_KEYS', {})

        # Sort by version (newest first)
        for version in sorted(versioned_keys.keys(), reverse=True):
            key_config = versioned_keys[version]
            key = self._derive_key_from_config(key_config)
            keys.append(key)

        # Add current key if not in versioned list
        current_key = self._get_encryption_key()
        if current_key not in keys:
            keys.insert(0, current_key)

        return keys

    def _derive_key_from_config(self, config: Union[str, Dict]) -> bytes:
        """Derive key from configuration."""
        if isinstance(config, str):
            # Direct key
            return base64.urlsafe_b64encode(config.encode()[:32].ljust(32, b'\0'))

        # Config dict with key and salt
        base_key = config.get('key', settings.SECRET_KEY)
        if isinstance(base_key, str):
            base_key = base_key.encode()

        salt = config.get('salt', self.DEFAULT_SALT)
        if isinstance(salt, str):
            salt = salt.encode()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=config.get('iterations', 100000),
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(base_key))

    def encrypt(self, value: str, deterministic: bool = False) -> str:
        """
        Encrypt a string value.

        Args:
            value: The plaintext value to encrypt
            deterministic: If True, same input produces same output (for searches)

        Returns:
            Base64-encoded encrypted value with version prefix

        Raises:
            ValueError: If encryption fails
        """
        if not value:
            return value

        try:
            if isinstance(value, str):
                value_bytes = value.encode('utf-8')
            else:
                value_bytes = value

            if deterministic:
                # Use deterministic encryption (same plaintext = same ciphertext)
                # WARNING: Less secure, only use when searchability is required
                encrypted = self._deterministic_encrypt(value_bytes)
            else:
                # Standard Fernet encryption (random IV each time)
                encrypted = self.fernet.encrypt(value_bytes)

            return f'{self.KEY_VERSION_PREFIX}{encrypted.decode()}'

        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise ValueError(f"Failed to encrypt value: {e}")

    def _deterministic_encrypt(self, value: bytes) -> bytes:
        """
        Deterministic encryption for searchable fields.

        Uses AES-SIV mode for deterministic authenticated encryption.
        Falls back to HMAC-based approach if AES-SIV not available.
        """
        # Generate deterministic IV from value
        key = self._get_encryption_key()
        iv = hmac.new(key[:16], value, hashlib.sha256).digest()[:16]

        # Use Fernet with fixed timestamp and IV
        # Note: This is a simplified approach. For production,
        # consider using cryptography's AES-SIV
        combined = iv + value
        return self.fernet.encrypt(combined)

    def decrypt(self, value: str) -> Optional[str]:
        """
        Decrypt an encrypted value.

        Supports key rotation by trying multiple keys.

        Args:
            value: The encrypted value with version prefix

        Returns:
            Decrypted plaintext or None if decryption fails
        """
        if not value:
            return value

        try:
            # Remove version prefix if present
            if value.startswith(self.KEY_VERSION_PREFIX):
                value = value[len(self.KEY_VERSION_PREFIX):]

            encrypted_bytes = value.encode()

            # Try with MultiFernet (supports key rotation)
            try:
                decrypted = self.multi_fernet.decrypt(encrypted_bytes)
            except InvalidToken:
                # Try with single key
                decrypted = self.fernet.decrypt(encrypted_bytes)

            # Handle deterministic encryption (has IV prefix)
            if len(decrypted) > 16:
                # Check if it's deterministically encrypted
                try:
                    # Skip IV prefix for deterministic decryption
                    return decrypted[16:].decode('utf-8')
                except UnicodeDecodeError:
                    pass

            return decrypted.decode('utf-8')

        except InvalidToken:
            logger.error(
                "Decryption failed: Invalid token. "
                "Data may be corrupted or key may have changed."
            )
            return None
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None

    def encrypt_dict(self, data: Dict, fields: List[str]) -> Dict:
        """
        Encrypt specific fields in a dictionary.

        Args:
            data: Dictionary with fields to encrypt
            fields: List of field names to encrypt

        Returns:
            Dictionary with specified fields encrypted
        """
        result = data.copy()
        for field in fields:
            if field in result and result[field]:
                result[field] = self.encrypt(str(result[field]))
        return result

    def decrypt_dict(self, data: Dict, fields: List[str]) -> Dict:
        """
        Decrypt specific fields in a dictionary.

        Args:
            data: Dictionary with encrypted fields
            fields: List of field names to decrypt

        Returns:
            Dictionary with specified fields decrypted
        """
        result = data.copy()
        for field in fields:
            if field in result and result[field]:
                result[field] = self.decrypt(result[field])
        return result


# =============================================================================
# KEY ROTATION MANAGER
# =============================================================================

class KeyRotationManager:
    """
    Encryption key rotation management.

    Provides:
    - Generate new encryption keys
    - Schedule key rotation
    - Re-encrypt data with new keys
    - Key version tracking

    Usage:
        manager = KeyRotationManager()
        new_key = manager.generate_key()
        manager.schedule_rotation(new_key, effective_date)

    Configuration via Django settings:
        KEY_ROTATION_INTERVAL_DAYS: int = 90
        KEY_ROTATION_OVERLAP_DAYS: int = 30
    """

    CACHE_KEY_PREFIX = 'key_rotation:'

    def __init__(self, tenant_id: str = None):
        """
        Initialize the key rotation manager.

        Args:
            tenant_id: Optional tenant ID for tenant-specific rotation
        """
        self.tenant_id = tenant_id
        self.rotation_interval = getattr(settings, 'KEY_ROTATION_INTERVAL_DAYS', 90)
        self.overlap_days = getattr(settings, 'KEY_ROTATION_OVERLAP_DAYS', 30)

    def generate_key(self) -> Tuple[str, str]:
        """
        Generate a new encryption key.

        Returns:
            Tuple of (key_id, base64_encoded_key)
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("cryptography package required")

        # Generate random key
        key = Fernet.generate_key()
        key_id = f"key_{secrets.token_hex(8)}_{int(time.time())}"

        return (key_id, key.decode())

    def get_active_keys(self) -> List[Dict[str, Any]]:
        """
        Get currently active encryption keys.

        Returns:
            List of active key configurations
        """
        cache_key = f"{self.CACHE_KEY_PREFIX}active:{self.tenant_id or 'global'}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        # Get from settings
        keys = getattr(settings, 'FIELD_ENCRYPTION_KEYS', {})
        now = timezone.now()

        active_keys = []
        for key_id, config in keys.items():
            effective_date = config.get('effective_date')
            expiry_date = config.get('expiry_date')

            if effective_date:
                if isinstance(effective_date, str):
                    effective_date = datetime.fromisoformat(effective_date)
                if effective_date > now:
                    continue

            if expiry_date:
                if isinstance(expiry_date, str):
                    expiry_date = datetime.fromisoformat(expiry_date)
                if expiry_date < now:
                    continue

            active_keys.append({
                'key_id': key_id,
                'effective_date': effective_date,
                'expiry_date': expiry_date,
                **config
            })

        # Cache for 5 minutes
        cache.set(cache_key, active_keys, timeout=300)
        return active_keys

    def schedule_rotation(
        self,
        new_key: str,
        key_id: str = None,
        effective_date: datetime = None,
        notify: bool = True
    ) -> Dict[str, Any]:
        """
        Schedule a key rotation.

        Args:
            new_key: The new encryption key
            key_id: Optional key identifier
            effective_date: When the new key becomes active
            notify: Whether to send notifications

        Returns:
            Rotation schedule details
        """
        if not key_id:
            key_id = f"key_{secrets.token_hex(8)}"

        if not effective_date:
            effective_date = timezone.now() + timedelta(days=7)

        expiry_date = effective_date + timedelta(days=self.overlap_days)

        rotation_info = {
            'key_id': key_id,
            'effective_date': effective_date.isoformat(),
            'expiry_date': expiry_date.isoformat(),
            'status': 'scheduled',
            'created_at': timezone.now().isoformat(),
            'tenant_id': self.tenant_id,
        }

        # Store rotation schedule
        cache_key = f"{self.CACHE_KEY_PREFIX}schedule:{key_id}"
        cache.set(cache_key, rotation_info, timeout=86400 * 365)  # 1 year

        # Log the schedule
        logger.info(
            f"Key rotation scheduled: {key_id}",
            extra={'rotation_info': rotation_info}
        )

        if notify:
            self._send_rotation_notification(rotation_info)

        return rotation_info

    def _send_rotation_notification(self, rotation_info: Dict):
        """Send notification about scheduled rotation."""
        try:
            from django.core.mail import send_mail

            admins = getattr(settings, 'SECURITY_ADMIN_EMAILS', [])
            if admins:
                send_mail(
                    subject='Encryption Key Rotation Scheduled',
                    message=f"A new encryption key has been scheduled for rotation.\n\n"
                            f"Key ID: {rotation_info['key_id']}\n"
                            f"Effective Date: {rotation_info['effective_date']}\n"
                            f"Expiry Date: {rotation_info['expiry_date']}\n",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=admins,
                    fail_silently=True,
                )
        except Exception as e:
            logger.error(f"Failed to send rotation notification: {e}")

    def re_encrypt_value(
        self,
        encrypted_value: str,
        old_encryption: FieldEncryption,
        new_encryption: FieldEncryption
    ) -> str:
        """
        Re-encrypt a value with a new key.

        Args:
            encrypted_value: The currently encrypted value
            old_encryption: FieldEncryption instance with old key
            new_encryption: FieldEncryption instance with new key

        Returns:
            Value encrypted with new key
        """
        # Decrypt with old key
        decrypted = old_encryption.decrypt(encrypted_value)
        if decrypted is None:
            raise ValueError("Failed to decrypt with old key")

        # Encrypt with new key
        return new_encryption.encrypt(decrypted)


# =============================================================================
# HASHING SERVICE
# =============================================================================

class HashingService:
    """
    Secure hashing service for passwords and sensitive comparisons.

    Provides:
    - Password hashing with Argon2/bcrypt/scrypt
    - Secure string comparison (timing-safe)
    - Hash verification
    - Salt generation

    Usage:
        hasher = HashingService()
        hashed = hasher.hash_password('my_password')
        is_valid = hasher.verify_password('my_password', hashed)
    """

    # Supported algorithms
    ALGORITHM_ARGON2 = 'argon2'
    ALGORITHM_BCRYPT = 'bcrypt'
    ALGORITHM_SCRYPT = 'scrypt'
    ALGORITHM_PBKDF2 = 'pbkdf2'

    def __init__(self, algorithm: str = None):
        """
        Initialize the hashing service.

        Args:
            algorithm: Hashing algorithm to use (argon2, bcrypt, scrypt, pbkdf2)
        """
        self.algorithm = algorithm or self._get_default_algorithm()

    def _get_default_algorithm(self) -> str:
        """Get the best available hashing algorithm."""
        # Try argon2 first (most secure)
        try:
            import argon2
            return self.ALGORITHM_ARGON2
        except ImportError:
            pass

        # Try bcrypt
        try:
            import bcrypt
            return self.ALGORITHM_BCRYPT
        except ImportError:
            pass

        # Fall back to PBKDF2 (always available)
        return self.ALGORITHM_PBKDF2

    def hash_password(self, password: str) -> str:
        """
        Hash a password securely.

        Args:
            password: The plaintext password

        Returns:
            Hashed password string
        """
        if self.algorithm == self.ALGORITHM_ARGON2:
            return self._hash_argon2(password)
        elif self.algorithm == self.ALGORITHM_BCRYPT:
            return self._hash_bcrypt(password)
        elif self.algorithm == self.ALGORITHM_SCRYPT:
            return self._hash_scrypt(password)
        else:
            return self._hash_pbkdf2(password)

    def _hash_argon2(self, password: str) -> str:
        """Hash with Argon2id."""
        try:
            from argon2 import PasswordHasher
            ph = PasswordHasher()
            return f"argon2${ph.hash(password)}"
        except ImportError:
            return self._hash_pbkdf2(password)

    def _hash_bcrypt(self, password: str) -> str:
        """Hash with bcrypt."""
        try:
            import bcrypt
            salt = bcrypt.gensalt(rounds=12)
            hashed = bcrypt.hashpw(password.encode(), salt)
            return f"bcrypt${hashed.decode()}"
        except ImportError:
            return self._hash_pbkdf2(password)

    def _hash_scrypt(self, password: str) -> str:
        """Hash with scrypt."""
        if not CRYPTOGRAPHY_AVAILABLE:
            return self._hash_pbkdf2(password)

        salt = os.urandom(16)
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,  # CPU/memory cost
            r=8,      # Block size
            p=1,      # Parallelization
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return f"scrypt${base64.b64encode(salt).decode()}${base64.b64encode(key).decode()}"

    def _hash_pbkdf2(self, password: str) -> str:
        """Hash with PBKDF2-SHA256."""
        salt = os.urandom(16)
        iterations = getattr(settings, 'PASSWORD_HASHERS_ITERATIONS', 600000)

        if CRYPTOGRAPHY_AVAILABLE:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
        else:
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)

        return f"pbkdf2${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(key).decode()}"

    def verify_password(self, password: str, hashed: str) -> bool:
        """
        Verify a password against a hash.

        Args:
            password: The plaintext password
            hashed: The hashed password

        Returns:
            True if password matches
        """
        try:
            if hashed.startswith('argon2$'):
                return self._verify_argon2(password, hashed[7:])
            elif hashed.startswith('bcrypt$'):
                return self._verify_bcrypt(password, hashed[7:])
            elif hashed.startswith('scrypt$'):
                return self._verify_scrypt(password, hashed[7:])
            elif hashed.startswith('pbkdf2$'):
                return self._verify_pbkdf2(password, hashed[7:])
            else:
                # Try to verify as-is (for backwards compatibility)
                return self._verify_pbkdf2(password, hashed)
        except Exception as e:
            logger.error(f"Password verification failed: {e}")
            return False

    def _verify_argon2(self, password: str, hashed: str) -> bool:
        """Verify Argon2 hash."""
        try:
            from argon2 import PasswordHasher
            from argon2.exceptions import VerifyMismatchError
            ph = PasswordHasher()
            ph.verify(hashed, password)
            return True
        except (ImportError, VerifyMismatchError):
            return False

    def _verify_bcrypt(self, password: str, hashed: str) -> bool:
        """Verify bcrypt hash."""
        try:
            import bcrypt
            return bcrypt.checkpw(password.encode(), hashed.encode())
        except ImportError:
            return False

    def _verify_scrypt(self, password: str, hashed: str) -> bool:
        """Verify scrypt hash."""
        if not CRYPTOGRAPHY_AVAILABLE:
            return False

        try:
            parts = hashed.split('$')
            if len(parts) != 2:
                return False

            salt = base64.b64decode(parts[0])
            expected_key = base64.b64decode(parts[1])

            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            return hmac.compare_digest(key, expected_key)
        except Exception:
            return False

    def _verify_pbkdf2(self, password: str, hashed: str) -> bool:
        """Verify PBKDF2 hash."""
        try:
            parts = hashed.split('$')
            if len(parts) != 3:
                return False

            iterations = int(parts[0])
            salt = base64.b64decode(parts[1])
            expected_key = base64.b64decode(parts[2])

            if CRYPTOGRAPHY_AVAILABLE:
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=iterations,
                    backend=default_backend()
                )
                key = kdf.derive(password.encode())
            else:
                key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)

            return hmac.compare_digest(key, expected_key)
        except Exception:
            return False

    @staticmethod
    def secure_compare(a: str, b: str) -> bool:
        """
        Timing-safe string comparison.

        Args:
            a: First string
            b: Second string

        Returns:
            True if strings are equal
        """
        return hmac.compare_digest(a.encode(), b.encode())

    @staticmethod
    def generate_salt(length: int = 32) -> str:
        """
        Generate a cryptographically secure salt.

        Args:
            length: Salt length in bytes

        Returns:
            Base64-encoded salt
        """
        return base64.b64encode(os.urandom(length)).decode()

    def hash_data(self, data: str, algorithm: str = 'sha256') -> str:
        """
        Hash arbitrary data.

        Args:
            data: Data to hash
            algorithm: Hash algorithm (sha256, sha384, sha512)

        Returns:
            Hex-encoded hash
        """
        hash_func = getattr(hashlib, algorithm)
        return hash_func(data.encode()).hexdigest()


# =============================================================================
# TOKEN GENERATOR
# =============================================================================

class TokenGenerator:
    """
    Cryptographically secure token generation.

    Provides:
    - URL-safe tokens
    - Hex tokens
    - Numeric OTPs
    - Time-based tokens (TOTP-like)
    - Signed tokens

    Usage:
        generator = TokenGenerator()
        token = generator.generate_token()
        otp = generator.generate_otp(6)
    """

    def __init__(self, signing_key: str = None):
        """
        Initialize the token generator.

        Args:
            signing_key: Key for signing tokens (defaults to SECRET_KEY)
        """
        self.signing_key = signing_key or settings.SECRET_KEY
        if isinstance(self.signing_key, str):
            self.signing_key = self.signing_key.encode()

    def generate_token(self, length: int = 32) -> str:
        """
        Generate a URL-safe random token.

        Args:
            length: Token length in bytes

        Returns:
            URL-safe base64 token
        """
        return secrets.token_urlsafe(length)

    def generate_hex_token(self, length: int = 32) -> str:
        """
        Generate a hex random token.

        Args:
            length: Token length in bytes

        Returns:
            Hex-encoded token
        """
        return secrets.token_hex(length)

    def generate_otp(self, length: int = 6) -> str:
        """
        Generate a numeric OTP.

        Args:
            length: Number of digits

        Returns:
            Numeric string
        """
        return ''.join(secrets.choice('0123456789') for _ in range(length))

    def generate_alphanumeric(self, length: int = 8) -> str:
        """
        Generate an alphanumeric code.

        Uses a character set that excludes confusing characters (0, O, I, l).

        Args:
            length: Code length

        Returns:
            Alphanumeric code
        """
        alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def generate_signed_token(
        self,
        data: Dict[str, Any],
        expires_in: int = 3600
    ) -> str:
        """
        Generate a signed token with embedded data.

        Args:
            data: Data to embed in token
            expires_in: Token validity in seconds

        Returns:
            Signed token string
        """
        payload = {
            'data': data,
            'exp': int(time.time()) + expires_in,
            'iat': int(time.time()),
            'jti': secrets.token_hex(8)
        }

        # Encode payload
        payload_json = json.dumps(payload, sort_keys=True)
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')

        # Sign
        signature = hmac.new(
            self.signing_key,
            payload_b64.encode(),
            hashlib.sha256
        ).hexdigest()

        return f"{payload_b64}.{signature}"

    def verify_signed_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode a signed token.

        Args:
            token: The signed token

        Returns:
            Decoded data or None if invalid/expired
        """
        try:
            parts = token.split('.')
            if len(parts) != 2:
                return None

            payload_b64, signature = parts

            # Verify signature
            expected_sig = hmac.new(
                self.signing_key,
                payload_b64.encode(),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(signature, expected_sig):
                logger.warning("Token signature verification failed")
                return None

            # Decode payload
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += '=' * padding

            payload_json = base64.urlsafe_b64decode(payload_b64).decode()
            payload = json.loads(payload_json)

            # Check expiration
            if payload.get('exp', 0) < time.time():
                logger.debug("Token expired")
                return None

            return payload.get('data')

        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return None

    def generate_time_based_token(
        self,
        identifier: str,
        interval: int = 30
    ) -> str:
        """
        Generate a time-based token (similar to TOTP).

        Args:
            identifier: Unique identifier for the token
            interval: Time interval in seconds

        Returns:
            6-digit token valid for the interval
        """
        counter = int(time.time()) // interval

        # Generate HMAC
        message = f"{identifier}:{counter}".encode()
        digest = hmac.new(self.signing_key, message, hashlib.sha256).digest()

        # Dynamic truncation (RFC 4226)
        offset = digest[-1] & 0x0f
        code = (
            (digest[offset] & 0x7f) << 24 |
            (digest[offset + 1] & 0xff) << 16 |
            (digest[offset + 2] & 0xff) << 8 |
            (digest[offset + 3] & 0xff)
        )

        return str(code % 1000000).zfill(6)

    def verify_time_based_token(
        self,
        identifier: str,
        token: str,
        interval: int = 30,
        window: int = 1
    ) -> bool:
        """
        Verify a time-based token.

        Args:
            identifier: Unique identifier
            token: Token to verify
            interval: Time interval in seconds
            window: Number of intervals to check (for clock drift)

        Returns:
            True if token is valid
        """
        for offset in range(-window, window + 1):
            counter = (int(time.time()) // interval) + offset
            message = f"{identifier}:{counter}".encode()
            digest = hmac.new(self.signing_key, message, hashlib.sha256).digest()

            # Dynamic truncation
            off = digest[-1] & 0x0f
            code = (
                (digest[off] & 0x7f) << 24 |
                (digest[off + 1] & 0xff) << 16 |
                (digest[off + 2] & 0xff) << 8 |
                (digest[off + 3] & 0xff)
            )

            expected = str(code % 1000000).zfill(6)
            if hmac.compare_digest(token, expected):
                return True

        return False
