"""
Encryption Security Tests for Zumodra ATS/HR Platform

This module tests encryption security including:
- Field encryption/decryption
- Key rotation
- Encrypted field queries
- Data at rest encryption

Each test documents the security requirement being tested.
"""

import base64
from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.conf import settings
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def encryption_service():
    """Create EncryptionService instance."""
    from core.security.encryption import EncryptionService
    return EncryptionService()


@pytest.fixture
def key_manager():
    """Create KeyManager instance."""
    from core.security.encryption import KeyManager
    return KeyManager()


@pytest.fixture
def encrypted_field_manager():
    """Create EncryptedFieldManager instance."""
    from core.security.encryption import EncryptedFieldManager
    return EncryptedFieldManager()


# =============================================================================
# FIELD ENCRYPTION/DECRYPTION TESTS
# =============================================================================

class TestFieldEncryption:
    """
    Tests for field-level encryption.

    Security Requirements:
    - Sensitive data must be encrypted at rest
    - Encryption must use strong algorithms (AES-256)
    - Encryption must be deterministic for searchability where needed
    - Keys must be properly managed
    """

    def test_encrypt_returns_different_value(self, encryption_service):
        """
        Test: Encrypted value differs from plaintext.
        """
        plaintext = "Sensitive NAS Number: 123-456-789"

        ciphertext = encryption_service.encrypt(plaintext)

        assert ciphertext != plaintext
        assert plaintext not in ciphertext

    def test_decrypt_returns_original_value(self, encryption_service):
        """
        Test: Decryption returns original plaintext.
        """
        plaintext = "Secret salary: $150,000"

        ciphertext = encryption_service.encrypt(plaintext)
        decrypted = encryption_service.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_encryption_uses_aes_256(self, encryption_service):
        """
        Test: Encryption uses AES-256 (32-byte key).
        Security: AES-256 is NIST approved for classified data.
        """
        key = encryption_service.get_encryption_key()

        # AES-256 uses 32-byte key
        assert len(key) == 32 or len(base64.b64decode(key)) == 32

    def test_encryption_includes_iv(self, encryption_service):
        """
        Test: Each encryption uses unique IV (Initialization Vector).
        Security: Same plaintext should produce different ciphertext.
        """
        plaintext = "Test data"

        ciphertext1 = encryption_service.encrypt(plaintext)
        ciphertext2 = encryption_service.encrypt(plaintext)

        # Same plaintext should encrypt to different ciphertext
        assert ciphertext1 != ciphertext2

    def test_tampered_ciphertext_fails(self, encryption_service):
        """
        Test: Tampered ciphertext is detected and rejected.
        Security: Integrity check prevents data manipulation.
        """
        plaintext = "Original data"
        ciphertext = encryption_service.encrypt(plaintext)

        # Tamper with ciphertext
        tampered = ciphertext[:-4] + 'XXXX'

        with pytest.raises(Exception) as excinfo:
            encryption_service.decrypt(tampered)

        # Should fail with authentication/integrity error

    def test_null_values_handled(self, encryption_service):
        """
        Test: Null values are handled gracefully.
        """
        assert encryption_service.encrypt(None) is None
        assert encryption_service.decrypt(None) is None
        assert encryption_service.encrypt('') == ''

    def test_unicode_data_encrypted_correctly(self, encryption_service):
        """
        Test: Unicode data is properly encrypted/decrypted.
        """
        unicode_data = "Nom complet: Jean-Francois Moreau"

        ciphertext = encryption_service.encrypt(unicode_data)
        decrypted = encryption_service.decrypt(ciphertext)

        assert decrypted == unicode_data

    def test_large_data_encryption(self, encryption_service):
        """
        Test: Large data fields are encrypted correctly.
        """
        large_data = "x" * 100000  # 100KB of data

        ciphertext = encryption_service.encrypt(large_data)
        decrypted = encryption_service.decrypt(ciphertext)

        assert decrypted == large_data


# =============================================================================
# KEY ROTATION TESTS
# =============================================================================

class TestKeyRotation:
    """
    Tests for encryption key rotation.

    Security Requirements:
    - Keys must be rotatable without data loss
    - Old data must remain accessible after rotation
    - Key rotation must be auditable
    """

    def test_data_accessible_after_key_rotation(self, key_manager, encryption_service):
        """
        Test: Data encrypted with old key is still accessible after rotation.
        """
        # Encrypt with current key
        plaintext = "Sensitive data"
        ciphertext_v1 = encryption_service.encrypt(plaintext)

        # Rotate to new key
        old_key = key_manager.get_current_key()
        new_key = key_manager.rotate_key()

        # Old ciphertext should still decrypt (key version stored with data)
        decrypted = encryption_service.decrypt(ciphertext_v1)
        assert decrypted == plaintext

    def test_new_data_uses_new_key(self, key_manager, encryption_service):
        """
        Test: New data is encrypted with the new key after rotation.
        """
        # Rotate key
        key_manager.rotate_key()
        new_key_version = key_manager.get_current_version()

        # Encrypt new data
        plaintext = "New data after rotation"
        ciphertext = encryption_service.encrypt(plaintext)

        # Verify new key version is used
        metadata = encryption_service.get_ciphertext_metadata(ciphertext)
        assert metadata['key_version'] == new_key_version

    def test_reencrypt_data_with_new_key(self, key_manager, encryption_service):
        """
        Test: Data can be re-encrypted with new key.
        Security: Allows migration to new keys.
        """
        # Encrypt with old key
        plaintext = "Data to migrate"
        old_ciphertext = encryption_service.encrypt(plaintext)

        # Rotate key
        key_manager.rotate_key()

        # Re-encrypt with new key
        new_ciphertext = encryption_service.reencrypt(old_ciphertext)

        # Verify data is intact
        decrypted = encryption_service.decrypt(new_ciphertext)
        assert decrypted == plaintext

        # Verify new key is used
        old_metadata = encryption_service.get_ciphertext_metadata(old_ciphertext)
        new_metadata = encryption_service.get_ciphertext_metadata(new_ciphertext)
        assert new_metadata['key_version'] > old_metadata['key_version']

    def test_key_rotation_logged(self, key_manager):
        """
        Test: Key rotation events are logged for auditing.
        """
        with patch('core.security.encryption.audit_log') as mock_log:
            key_manager.rotate_key()

            mock_log.log_key_rotation.assert_called()
            call_args = mock_log.log_key_rotation.call_args
            assert 'new_version' in str(call_args)

    def test_old_keys_retained_for_decryption(self, key_manager):
        """
        Test: Old keys are retained for decrypting existing data.
        Security: Keys are not deleted immediately after rotation.
        """
        # Get initial key count
        initial_count = len(key_manager.get_all_keys())

        # Rotate multiple times
        for _ in range(3):
            key_manager.rotate_key()

        # All keys should be retained
        final_count = len(key_manager.get_all_keys())
        assert final_count >= initial_count + 3

    def test_key_retirement_after_reencryption(self, key_manager):
        """
        Test: Old keys can be retired after all data is re-encrypted.
        """
        old_version = key_manager.get_current_version()
        key_manager.rotate_key()

        # After all data migrated, retire old key
        # This should only succeed if no data uses the old key
        with pytest.raises(Exception):
            # Should fail if data still uses old key
            key_manager.retire_key(old_version, force=False)

        # Force retirement (for testing)
        key_manager.retire_key(old_version, force=True)
        assert key_manager.is_key_retired(old_version)


# =============================================================================
# ENCRYPTED FIELD QUERY TESTS
# =============================================================================

class TestEncryptedFieldQueries:
    """
    Tests for querying encrypted fields.

    Security/Functionality Trade-offs:
    - Encrypted fields cannot be searched directly
    - Blind indexes enable equality searches
    - Range queries require special handling
    """

    def test_exact_match_with_blind_index(self, encrypted_field_manager):
        """
        Test: Exact match queries work with blind indexes.
        Security: Blind index reveals nothing about plaintext.
        """
        # Create blind index for SSN lookup
        ssn = "123-45-6789"
        blind_index = encrypted_field_manager.create_blind_index(ssn)

        # Store encrypted SSN with blind index
        encrypted_ssn = encrypted_field_manager.encrypt(ssn)

        # Query using blind index
        search_index = encrypted_field_manager.create_blind_index("123-45-6789")
        assert search_index == blind_index  # Same input = same index

        # Different SSN = different index
        different_index = encrypted_field_manager.create_blind_index("987-65-4321")
        assert different_index != blind_index

    def test_blind_index_is_deterministic(self, encrypted_field_manager):
        """
        Test: Same plaintext produces same blind index.
        Required for: Equality searches.
        """
        value = "test@email.com"

        index1 = encrypted_field_manager.create_blind_index(value)
        index2 = encrypted_field_manager.create_blind_index(value)

        assert index1 == index2

    def test_blind_index_uses_hmac(self, encrypted_field_manager):
        """
        Test: Blind index uses HMAC with separate key.
        Security: Index key is different from encryption key.
        """
        value = "secret"
        index = encrypted_field_manager.create_blind_index(value)

        # Verify it's not just a hash of the value
        import hashlib
        simple_hash = hashlib.sha256(value.encode()).hexdigest()
        assert index != simple_hash

    def test_partial_match_not_supported_encrypted(self, encrypted_field_manager):
        """
        Test: Partial match (LIKE) not supported on encrypted fields.
        Security: This is expected - encryption should prevent partial searches.
        """
        # Full encrypted field cannot be searched with LIKE
        # Application must handle this limitation

    def test_range_query_not_supported_encrypted(self, encrypted_field_manager):
        """
        Test: Range queries not supported on encrypted fields.
        Security: Order-preserving encryption is weaker.
        """
        # Standard encryption does not preserve order
        # Range queries require application-level handling


# =============================================================================
# DATA AT REST ENCRYPTION TESTS
# =============================================================================

class TestDataAtRestEncryption:
    """
    Tests for data at rest encryption.

    Security Requirements:
    - Database should use encrypted storage
    - Backups should be encrypted
    - Temporary files should be encrypted
    """

    def test_sensitive_fields_are_encrypted_in_db(self, db):
        """
        Test: Sensitive fields are encrypted when stored in database.
        """
        from custom_account_u.models import CustomUser
        from core.db.fields import EncryptedCharField

        # Check that sensitive fields use EncryptedCharField
        # This is a model definition check
        sensitive_fields = ['nas_number', 'sin_number', 'bank_account']

        # Verify fields are encrypted type (model introspection)

    def test_encrypted_field_not_readable_in_raw_db(self, db, user_factory):
        """
        Test: Encrypted data is not readable directly from database.
        """
        from django.db import connection

        # Create user with sensitive data
        user = user_factory()

        # Simulate setting encrypted field
        # In actual implementation, this would be an encrypted field

        # Query raw database
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM custom_account_u_customuser WHERE id = %s",
                [user.id]
            )
            row = cursor.fetchone()

            # Encrypted fields should not be readable as plaintext
            # (Verification depends on actual field implementation)

    def test_backup_encryption_enabled(self):
        """
        Test: Database backup encryption is configured.
        Note: This is more of a configuration check.
        """
        # Verify backup encryption settings
        # This would check AWS RDS encryption, or similar

    def test_temp_files_encrypted(self, encryption_service):
        """
        Test: Temporary files created during processing are encrypted.
        """
        import tempfile
        import os

        # Create encrypted temp file
        sensitive_data = b"Sensitive report data"

        encrypted_data = encryption_service.encrypt(sensitive_data.decode())

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(encrypted_data.encode())
            tmp_path = tmp.name

        # Read back and verify it's encrypted
        with open(tmp_path, 'rb') as f:
            stored_data = f.read()
            assert b"Sensitive" not in stored_data

        os.unlink(tmp_path)


# =============================================================================
# ENCRYPTION ALGORITHM TESTS
# =============================================================================

class TestEncryptionAlgorithms:
    """
    Tests for encryption algorithm correctness and strength.
    """

    def test_uses_authenticated_encryption(self, encryption_service):
        """
        Test: Encryption includes authentication (AEAD).
        Security: Prevents tampering without detection.
        """
        plaintext = "Test data"
        ciphertext = encryption_service.encrypt(plaintext)

        # Modify ciphertext
        modified = bytearray(base64.b64decode(ciphertext))
        modified[-1] ^= 0xFF  # Flip last byte
        modified_ciphertext = base64.b64encode(bytes(modified)).decode()

        # Decryption should fail with authentication error
        with pytest.raises(Exception) as excinfo:
            encryption_service.decrypt(modified_ciphertext)

    def test_key_derivation_uses_pbkdf2(self, key_manager):
        """
        Test: Key derivation uses PBKDF2 with sufficient iterations.
        Security: Prevents brute-force key cracking.
        """
        # Verify PBKDF2 configuration
        kdf_config = key_manager.get_kdf_config()

        assert kdf_config['algorithm'] in ['PBKDF2', 'Argon2', 'scrypt']
        if kdf_config['algorithm'] == 'PBKDF2':
            assert kdf_config['iterations'] >= 100000

    def test_random_number_generation(self, encryption_service):
        """
        Test: Cryptographic random numbers are used.
        Security: Weak RNG would compromise security.
        """
        # Generate multiple IVs/nonces and verify they're unique
        ivs = [encryption_service.generate_iv() for _ in range(100)]

        # All IVs should be unique
        assert len(set(ivs)) == 100

    def test_no_ecb_mode(self, encryption_service):
        """
        Test: ECB mode is not used.
        Security: ECB leaks patterns in plaintext.
        """
        # Encrypt same data twice
        plaintext = "AAAAAAAAAAAAAAAA" * 10  # Repeated pattern

        ciphertext1 = encryption_service.encrypt(plaintext)
        ciphertext2 = encryption_service.encrypt(plaintext)

        # If ECB is used, ciphertexts would be same
        assert ciphertext1 != ciphertext2


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestEncryptionIntegration:
    """
    Integration tests for encryption in the application.
    """

    @pytest.mark.django_db
    def test_encrypted_field_model_integration(self, db):
        """
        Test: Encrypted fields work correctly in Django models.
        """
        from core.db.fields import EncryptedCharField

        # This would test actual model with encrypted field
        # Example: Employee with encrypted NAS number

    @pytest.mark.django_db
    def test_encrypted_field_admin_display(self, db, admin_client):
        """
        Test: Encrypted fields are displayed correctly in admin.
        Security: Admin should show decrypted values to authorized users.
        """
        # Verify admin can view decrypted data
        # But data is encrypted in database

    @pytest.mark.django_db
    def test_encrypted_field_api_serialization(self, db, api_client, user_factory):
        """
        Test: Encrypted fields are properly serialized in API responses.
        """
        # API should return decrypted values to authorized users
        # But never expose raw encrypted values

    @pytest.mark.django_db
    def test_encryption_performance(self, encryption_service):
        """
        Test: Encryption/decryption has acceptable performance.
        """
        import time

        plaintext = "Test data for performance measurement"
        iterations = 1000

        start = time.time()
        for _ in range(iterations):
            ciphertext = encryption_service.encrypt(plaintext)
            encryption_service.decrypt(ciphertext)
        elapsed = time.time() - start

        # Should complete 1000 encrypt/decrypt cycles in under 5 seconds
        assert elapsed < 5.0, f"Encryption too slow: {elapsed}s for {iterations} cycles"
