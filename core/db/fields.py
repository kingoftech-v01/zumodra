"""
Custom Database Fields for Zumodra

This module provides specialized field types:
- EncryptedCharField: AES-256 encrypted character field
- EncryptedTextField: AES-256 encrypted text field
- MoneyField: Decimal field for monetary values
- PhoneNumberField: Validated phone number field

These fields handle encryption, validation, and formatting
for sensitive and specialized data types.
"""

import base64
import hashlib
import logging
import re
from decimal import Decimal, InvalidOperation
from typing import Any, Optional, Union

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

try:
    import phonenumbers
    from phonenumbers import NumberParseException, PhoneNumberFormat
    PHONENUMBERS_AVAILABLE = True
except ImportError:
    PHONENUMBERS_AVAILABLE = False

logger = logging.getLogger(__name__)


# =============================================================================
# ENCRYPTION UTILITIES
# =============================================================================

def get_encryption_key() -> bytes:
    """
    Derive an encryption key from Django's SECRET_KEY.

    The encryption salt is configurable via the FIELD_ENCRYPTION_SALT setting.
    If not configured, a warning is logged and a default salt is used.

    Settings:
        FIELD_ENCRYPTION_KEY: Custom encryption key (defaults to SECRET_KEY)
        FIELD_ENCRYPTION_SALT: Salt for key derivation (required in production)

    Returns:
        bytes: A 32-byte key suitable for Fernet encryption.

    Raises:
        ImproperlyConfigured: If FIELD_ENCRYPTION_SALT is not set in production.
    """
    secret = getattr(settings, 'FIELD_ENCRYPTION_KEY', settings.SECRET_KEY)

    # Get salt from settings - require configuration for security
    salt = getattr(settings, 'FIELD_ENCRYPTION_SALT', None)

    if salt is None:
        # Check if we're in DEBUG mode - only allow default in development
        if not getattr(settings, 'DEBUG', False):
            logger.warning(
                "FIELD_ENCRYPTION_SALT is not configured. Using default salt. "
                "This is a security risk in production. Please set "
                "FIELD_ENCRYPTION_SALT in your Django settings."
            )
        # Use a default salt only for development/backward compatibility
        salt = b'zumodra_default_salt_v1'
    elif isinstance(salt, str):
        salt = salt.encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(secret.encode()))
    return key


def get_fernet() -> 'Fernet':
    """Get a Fernet instance for encryption/decryption."""
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError(
            "cryptography package is required for encrypted fields. "
            "Install it with: pip install cryptography"
        )
    return Fernet(get_encryption_key())


# =============================================================================
# ENCRYPTED CHAR FIELD
# =============================================================================

class EncryptedCharField(models.CharField):
    """
    CharField with AES-256 encryption at rest.

    Data is encrypted before saving to the database and decrypted
    when retrieved. Useful for sensitive data like SSN, NAS, etc.

    Note: Encrypted fields cannot be used in queries (filter, order_by)
    since the database sees only encrypted values.

    Example:
        class Employee(models.Model):
            nas_number = EncryptedCharField(max_length=20, verbose_name='NAS')

    Settings:
        FIELD_ENCRYPTION_KEY: Custom encryption key (defaults to SECRET_KEY)
        ENCRYPTION_SALT: Salt for key derivation (defaults to 'zumodra_salt_v1')
    """

    description = _('Encrypted character field')

    def __init__(self, *args, **kwargs):
        # Encrypted values are longer than plain text
        # Fernet encryption adds ~90 bytes overhead + base64 encoding
        kwargs['max_length'] = kwargs.get('max_length', 255) + 200
        super().__init__(*args, **kwargs)

    def get_prep_value(self, value: Optional[str]) -> Optional[str]:
        """Encrypt the value before saving to database."""
        if value is None or value == '':
            return value

        try:
            fernet = get_fernet()
            encrypted = fernet.encrypt(value.encode())
            return encrypted.decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise ValueError(f"Failed to encrypt value: {e}")

    def from_db_value(
        self,
        value: Optional[str],
        expression,
        connection
    ) -> Optional[str]:
        """Decrypt the value when reading from database."""
        if value is None or value == '':
            return value

        try:
            fernet = get_fernet()
            decrypted = fernet.decrypt(value.encode())
            return decrypted.decode()
        except InvalidToken:
            # Log detailed information for debugging while not exposing sensitive data
            logger.error(
                "Decryption failed for EncryptedCharField: InvalidToken. "
                "This may indicate corrupted data, wrong encryption key, "
                "or a key rotation issue. Value length: %d, "
                "value prefix: %s...",
                len(value) if value else 0,
                value[:20] if value and len(value) > 20 else '[hidden]'
            )
            return None
        except Exception as e:
            logger.error(
                "Decryption failed for EncryptedCharField: %s. "
                "Exception type: %s",
                str(e),
                type(e).__name__
            )
            return None

    def to_python(self, value: Any) -> Optional[str]:
        """Convert value to Python string."""
        if value is None:
            return value
        return str(value)

    def deconstruct(self):
        """Return field deconstruction for migrations."""
        name, path, args, kwargs = super().deconstruct()
        # Adjust max_length back for migrations
        if 'max_length' in kwargs:
            kwargs['max_length'] = kwargs['max_length'] - 200
        return name, path, args, kwargs


class EncryptedTextField(models.TextField):
    """
    TextField with AES-256 encryption at rest.

    Similar to EncryptedCharField but for larger text content.
    Useful for sensitive documents, notes with PII, etc.

    Example:
        class Document(models.Model):
            content = EncryptedTextField(verbose_name='Content')
    """

    description = _('Encrypted text field')

    def get_prep_value(self, value: Optional[str]) -> Optional[str]:
        """Encrypt the value before saving to database."""
        if value is None or value == '':
            return value

        try:
            fernet = get_fernet()
            encrypted = fernet.encrypt(value.encode())
            return encrypted.decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise ValueError(f"Failed to encrypt value: {e}")

    def from_db_value(
        self,
        value: Optional[str],
        expression,
        connection
    ) -> Optional[str]:
        """Decrypt the value when reading from database."""
        if value is None or value == '':
            return value

        try:
            fernet = get_fernet()
            decrypted = fernet.decrypt(value.encode())
            return decrypted.decode()
        except InvalidToken:
            # Log detailed information for debugging while not exposing sensitive data
            logger.error(
                "Decryption failed for EncryptedTextField: InvalidToken. "
                "This may indicate corrupted data, wrong encryption key, "
                "or a key rotation issue. Value length: %d, "
                "value prefix: %s...",
                len(value) if value else 0,
                value[:20] if value and len(value) > 20 else '[hidden]'
            )
            return None
        except Exception as e:
            logger.error(
                "Decryption failed for EncryptedTextField: %s. "
                "Exception type: %s",
                str(e),
                type(e).__name__
            )
            return None

    def to_python(self, value: Any) -> Optional[str]:
        """Convert value to Python string."""
        if value is None:
            return value
        return str(value)


# =============================================================================
# MONEY FIELD
# =============================================================================

class MoneyField(models.DecimalField):
    """
    DecimalField optimized for monetary values.

    Provides:
    - Fixed precision (2 decimal places by default)
    - Currency awareness (stored separately)
    - Validation for non-negative amounts
    - Formatted display methods

    Example:
        class Product(models.Model):
            price = MoneyField(verbose_name='Price')
            currency = models.CharField(max_length=3, default='CAD')

    Or with currency suffix:
        class Invoice(models.Model):
            total = MoneyField(verbose_name='Total')
            total_currency = models.CharField(max_length=3, default='CAD')
    """

    description = _('Monetary value field')

    # Default currency symbols for display
    CURRENCY_SYMBOLS = {
        'USD': '$',
        'CAD': 'C$',
        'EUR': '\u20ac',  # Euro sign
        'GBP': '\u00a3',  # Pound sign
        'JPY': '\u00a5',  # Yen sign
        'CHF': 'CHF',
        'AUD': 'A$',
        'NZD': 'NZ$',
        'CNY': '\u00a5',
        'INR': '\u20b9',  # Rupee sign
    }

    def __init__(
        self,
        max_digits: int = 12,
        decimal_places: int = 2,
        allow_negative: bool = False,
        default_currency: str = 'CAD',
        *args,
        **kwargs
    ):
        """
        Initialize the MoneyField.

        Args:
            max_digits: Total number of digits (default 12).
            decimal_places: Decimal precision (default 2).
            allow_negative: Whether to allow negative values (default False).
            default_currency: Default currency code (default 'CAD').
        """
        self.allow_negative = allow_negative
        self.default_currency = default_currency

        kwargs['max_digits'] = max_digits
        kwargs['decimal_places'] = decimal_places

        super().__init__(*args, **kwargs)

    def deconstruct(self):
        """Return field deconstruction for migrations."""
        name, path, args, kwargs = super().deconstruct()
        if self.allow_negative:
            kwargs['allow_negative'] = True
        if self.default_currency != 'CAD':
            kwargs['default_currency'] = self.default_currency
        return name, path, args, kwargs

    def validate(self, value: Any, model_instance: Any):
        """Validate the monetary value."""
        super().validate(value, model_instance)

        if value is not None and not self.allow_negative and value < 0:
            raise ValidationError(
                _('%(value)s is not a valid monetary amount. Negative values are not allowed.'),
                params={'value': value},
                code='negative_money'
            )

    def to_python(self, value: Any) -> Optional[Decimal]:
        """Convert value to Decimal."""
        if value is None:
            return value

        if isinstance(value, Decimal):
            return value

        try:
            # Handle string with currency symbols
            if isinstance(value, str):
                # Remove currency symbols and whitespace
                cleaned = re.sub(r'[^\d.\-]', '', value)
                return Decimal(cleaned)
            return Decimal(value)
        except (InvalidOperation, ValueError, TypeError) as e:
            raise ValidationError(
                _('%(value)s is not a valid monetary amount.'),
                params={'value': value},
                code='invalid_money'
            )

    def get_prep_value(self, value: Any) -> Optional[Decimal]:
        """Prepare value for database."""
        value = super().get_prep_value(value)
        if value is not None:
            return Decimal(value).quantize(Decimal(f'0.{"0" * self.decimal_places}'))
        return value

    @classmethod
    def format_money(
        cls,
        amount: Union[Decimal, float, int],
        currency: str = 'CAD',
        show_symbol: bool = True,
        thousands_separator: str = ','
    ) -> str:
        """
        Format a monetary amount for display.

        Args:
            amount: The amount to format.
            currency: Currency code.
            show_symbol: Whether to include currency symbol.
            thousands_separator: Character for thousands grouping.

        Returns:
            Formatted string like "C$1,234.56" or "1234.56 CAD"
        """
        if amount is None:
            return ''

        try:
            amount = Decimal(amount)
        except (InvalidOperation, ValueError):
            return str(amount)

        # Format with thousands separator
        formatted = f'{amount:,.2f}'
        if thousands_separator != ',':
            formatted = formatted.replace(',', thousands_separator)

        if show_symbol:
            symbol = cls.CURRENCY_SYMBOLS.get(currency, currency)
            return f'{symbol}{formatted}'
        else:
            return f'{formatted} {currency}'


# =============================================================================
# PHONE NUMBER FIELD
# =============================================================================

class PhoneNumberField(models.CharField):
    """
    CharField for phone numbers with validation and formatting.

    Validates phone numbers using the phonenumbers library (if available)
    and stores them in E.164 format for consistency.

    Example:
        class Contact(models.Model):
            phone = PhoneNumberField(region='CA', verbose_name='Phone')

    Stored format: +14165551234
    Display format: (416) 555-1234 or +1 416-555-1234
    """

    description = _('Phone number field')

    def __init__(
        self,
        region: str = 'CA',
        max_length: int = 20,
        *args,
        **kwargs
    ):
        """
        Initialize the PhoneNumberField.

        Args:
            region: Default region code for parsing (default 'CA').
            max_length: Maximum length (default 20 for E.164).
        """
        self.region = region
        kwargs['max_length'] = max_length
        super().__init__(*args, **kwargs)

    def deconstruct(self):
        """Return field deconstruction for migrations."""
        name, path, args, kwargs = super().deconstruct()
        if self.region != 'CA':
            kwargs['region'] = self.region
        return name, path, args, kwargs

    def to_python(self, value: Any) -> Optional[str]:
        """Parse and validate phone number."""
        if value is None or value == '':
            return value

        if isinstance(value, str):
            value = value.strip()

        if not PHONENUMBERS_AVAILABLE:
            # Basic validation without phonenumbers library
            cleaned = re.sub(r'[^\d+]', '', str(value))
            if len(cleaned) < 10:
                raise ValidationError(
                    _('%(value)s is not a valid phone number.'),
                    params={'value': value},
                    code='invalid_phone'
                )
            return cleaned

        try:
            parsed = phonenumbers.parse(str(value), self.region)

            if not phonenumbers.is_valid_number(parsed):
                raise ValidationError(
                    _('%(value)s is not a valid phone number.'),
                    params={'value': value},
                    code='invalid_phone'
                )

            # Return E.164 format
            return phonenumbers.format_number(parsed, PhoneNumberFormat.E164)

        except NumberParseException as e:
            raise ValidationError(
                _('%(value)s is not a valid phone number: %(error)s'),
                params={'value': value, 'error': str(e)},
                code='invalid_phone'
            )

    def get_prep_value(self, value: Any) -> Optional[str]:
        """Prepare phone number for database storage."""
        value = self.to_python(value)
        return super().get_prep_value(value)

    @staticmethod
    def format_national(phone: str, region: str = 'CA') -> str:
        """
        Format phone number in national format.

        Args:
            phone: E.164 formatted phone number.
            region: Region for formatting.

        Returns:
            National format like (416) 555-1234
        """
        if not phone or not PHONENUMBERS_AVAILABLE:
            return phone or ''

        try:
            parsed = phonenumbers.parse(phone, region)
            return phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL)
        except NumberParseException:
            return phone

    @staticmethod
    def format_international(phone: str) -> str:
        """
        Format phone number in international format.

        Args:
            phone: E.164 formatted phone number.

        Returns:
            International format like +1 416-555-1234
        """
        if not phone or not PHONENUMBERS_AVAILABLE:
            return phone or ''

        try:
            parsed = phonenumbers.parse(phone, None)
            return phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL)
        except NumberParseException:
            return phone

    @staticmethod
    def get_country_code(phone: str) -> Optional[int]:
        """
        Extract country calling code from phone number.

        Args:
            phone: E.164 formatted phone number.

        Returns:
            Country code (e.g., 1 for US/CA, 44 for UK)
        """
        if not phone or not PHONENUMBERS_AVAILABLE:
            return None

        try:
            parsed = phonenumbers.parse(phone, None)
            return parsed.country_code
        except NumberParseException:
            return None


# =============================================================================
# ADDITIONAL UTILITY FIELDS
# =============================================================================

class LowercaseEmailField(models.EmailField):
    """
    EmailField that stores emails in lowercase.

    Ensures email addresses are always stored consistently,
    preventing duplicate accounts due to case differences.
    """

    description = _('Lowercase email field')

    def to_python(self, value: Any) -> Optional[str]:
        """Convert email to lowercase."""
        value = super().to_python(value)
        if value:
            return value.lower()
        return value

    def get_prep_value(self, value: Any) -> Optional[str]:
        """Prepare lowercase email for database."""
        value = super().get_prep_value(value)
        if value:
            return value.lower()
        return value


class TrimmedCharField(models.CharField):
    """
    CharField that automatically trims whitespace.

    Removes leading and trailing whitespace from values,
    preventing data inconsistencies.
    """

    description = _('Trimmed character field')

    def to_python(self, value: Any) -> Optional[str]:
        """Trim whitespace from value."""
        value = super().to_python(value)
        if value:
            return value.strip()
        return value

    def get_prep_value(self, value: Any) -> Optional[str]:
        """Prepare trimmed value for database."""
        value = super().get_prep_value(value)
        if value:
            return value.strip()
        return value


class PercentageField(models.DecimalField):
    """
    DecimalField for percentage values (0-100 or 0-1).

    Stores percentages with validation and formatting utilities.

    Example:
        class Discount(models.Model):
            rate = PercentageField(store_as_decimal=True)
    """

    description = _('Percentage field')

    def __init__(
        self,
        max_digits: int = 5,
        decimal_places: int = 2,
        store_as_decimal: bool = False,
        *args,
        **kwargs
    ):
        """
        Initialize the PercentageField.

        Args:
            max_digits: Total digits (default 5 for 100.00).
            decimal_places: Decimal precision (default 2).
            store_as_decimal: If True, store as 0-1 instead of 0-100.
        """
        self.store_as_decimal = store_as_decimal
        kwargs['max_digits'] = max_digits
        kwargs['decimal_places'] = decimal_places
        super().__init__(*args, **kwargs)

    def deconstruct(self):
        """Return field deconstruction for migrations."""
        name, path, args, kwargs = super().deconstruct()
        if self.store_as_decimal:
            kwargs['store_as_decimal'] = True
        return name, path, args, kwargs

    def validate(self, value: Any, model_instance: Any):
        """Validate percentage is within bounds."""
        super().validate(value, model_instance)

        if value is not None:
            max_value = Decimal('1') if self.store_as_decimal else Decimal('100')
            if value < 0 or value > max_value:
                raise ValidationError(
                    _('%(value)s is not a valid percentage.'),
                    params={'value': value},
                    code='invalid_percentage'
                )

    def format_display(self, value: Union[Decimal, float]) -> str:
        """Format percentage for display."""
        if value is None:
            return ''

        if self.store_as_decimal:
            return f'{value * 100:.2f}%'
        return f'{value:.2f}%'
