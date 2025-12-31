"""
Custom Password Validators for Zumodra

Enterprise-grade password validation for the multi-tenant ATS/HR SaaS platform.
Implements NIST and OWASP password guidelines:
- Mixed case requirement
- Number requirement
- Special character requirement
- Username exclusion
- Password history prevention
- Breach database checking (optional)

Add to AUTH_PASSWORD_VALIDATORS in settings.py:
    {
        'NAME': 'core.security.password_validators.MixedCaseValidator',
    },
"""

import re
import hashlib
import logging
from typing import Optional

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger('security.password_validators')


class MixedCaseValidator:
    """
    Validates that the password contains both uppercase and lowercase letters.

    NIST guidelines recommend allowing all characters but this adds
    an extra layer of complexity for enterprise environments.
    """

    def __init__(self, min_uppercase: int = 1, min_lowercase: int = 1):
        """
        Args:
            min_uppercase: Minimum number of uppercase letters required
            min_lowercase: Minimum number of lowercase letters required
        """
        self.min_uppercase = min_uppercase
        self.min_lowercase = min_lowercase

    def validate(self, password: str, user=None) -> None:
        """Validate password meets mixed case requirements."""
        uppercase_count = sum(1 for c in password if c.isupper())
        lowercase_count = sum(1 for c in password if c.islower())

        if uppercase_count < self.min_uppercase:
            raise ValidationError(
                _("Password must contain at least %(min)d uppercase letter(s)."),
                code='password_no_uppercase',
                params={'min': self.min_uppercase},
            )

        if lowercase_count < self.min_lowercase:
            raise ValidationError(
                _("Password must contain at least %(min)d lowercase letter(s)."),
                code='password_no_lowercase',
                params={'min': self.min_lowercase},
            )

    def get_help_text(self) -> str:
        return _(
            "Your password must contain at least %(upper)d uppercase and "
            "%(lower)d lowercase letter(s)."
        ) % {'upper': self.min_uppercase, 'lower': self.min_lowercase}


class NumberValidator:
    """
    Validates that the password contains at least one number.
    """

    def __init__(self, min_digits: int = 1):
        """
        Args:
            min_digits: Minimum number of digits required
        """
        self.min_digits = min_digits

    def validate(self, password: str, user=None) -> None:
        """Validate password contains required number of digits."""
        digit_count = sum(1 for c in password if c.isdigit())

        if digit_count < self.min_digits:
            raise ValidationError(
                _("Password must contain at least %(min)d number(s)."),
                code='password_no_number',
                params={'min': self.min_digits},
            )

    def get_help_text(self) -> str:
        return _("Your password must contain at least %(min)d number(s).") % {
            'min': self.min_digits
        }


class SpecialCharacterValidator:
    """
    Validates that the password contains at least one special character.
    """

    # Common special characters allowed in passwords
    SPECIAL_CHARACTERS = "!@#$%^&*()_+-=[]{}|;:',.<>?/`~\"\\"

    def __init__(self, min_special: int = 1, special_chars: str = None):
        """
        Args:
            min_special: Minimum number of special characters required
            special_chars: String of allowed special characters
        """
        self.min_special = min_special
        self.special_chars = special_chars or self.SPECIAL_CHARACTERS

    def validate(self, password: str, user=None) -> None:
        """Validate password contains required special characters."""
        special_count = sum(1 for c in password if c in self.special_chars)

        if special_count < self.min_special:
            raise ValidationError(
                _("Password must contain at least %(min)d special character(s) "
                  "(e.g., !@#$%%^&*)."),
                code='password_no_special',
                params={'min': self.min_special},
            )

    def get_help_text(self) -> str:
        return _(
            "Your password must contain at least %(min)d special character(s) "
            "(e.g., !@#$%%^&*)."
        ) % {'min': self.min_special}


class NoUsernameValidator:
    """
    Validates that the password does not contain the username.

    Prevents users from using their username as part of the password,
    which would make it easier to guess.
    """

    def __init__(self, case_sensitive: bool = False, min_length: int = 3):
        """
        Args:
            case_sensitive: Whether comparison should be case-sensitive
            min_length: Minimum username length to check (avoids false positives)
        """
        self.case_sensitive = case_sensitive
        self.min_length = min_length

    def validate(self, password: str, user=None) -> None:
        """Validate password doesn't contain username."""
        if user is None:
            return

        username = getattr(user, 'username', None) or getattr(user, 'email', '')

        if not username or len(username) < self.min_length:
            return

        password_check = password if self.case_sensitive else password.lower()
        username_check = username if self.case_sensitive else username.lower()

        if username_check in password_check:
            raise ValidationError(
                _("Password cannot contain your username."),
                code='password_contains_username',
            )

        # Also check email local part
        if '@' in username:
            local_part = username.split('@')[0]
            local_check = local_part if self.case_sensitive else local_part.lower()
            if len(local_check) >= self.min_length and local_check in password_check:
                raise ValidationError(
                    _("Password cannot contain part of your email address."),
                    code='password_contains_email',
                )

    def get_help_text(self) -> str:
        return _("Your password cannot contain your username or email.")


class NoRepeatingCharactersValidator:
    """
    Validates that the password doesn't have too many repeating characters.

    Passwords like 'aaaaaaa123' or 'password111111' are weak.
    """

    def __init__(self, max_repeats: int = 3):
        """
        Args:
            max_repeats: Maximum consecutive identical characters allowed
        """
        self.max_repeats = max_repeats

    def validate(self, password: str, user=None) -> None:
        """Validate password doesn't have excessive repeating characters."""
        if len(password) < self.max_repeats:
            return

        count = 1
        prev = ''

        for char in password:
            if char == prev:
                count += 1
                if count > self.max_repeats:
                    raise ValidationError(
                        _("Password cannot have more than %(max)d identical "
                          "characters in a row."),
                        code='password_too_many_repeats',
                        params={'max': self.max_repeats},
                    )
            else:
                count = 1
            prev = char

    def get_help_text(self) -> str:
        return _(
            "Your password cannot have more than %(max)d identical "
            "characters in a row."
        ) % {'max': self.max_repeats}


class NoSequentialCharactersValidator:
    """
    Validates that the password doesn't have sequential characters.

    Passwords like '123456' or 'abcdef' are weak.
    """

    SEQUENCES = [
        'abcdefghijklmnopqrstuvwxyz',
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        '0123456789',
        'qwertyuiop',
        'asdfghjkl',
        'zxcvbnm',
        'QWERTYUIOP',
        'ASDFGHJKL',
        'ZXCVBNM',
    ]

    def __init__(self, max_sequential: int = 4):
        """
        Args:
            max_sequential: Maximum consecutive sequential characters allowed
        """
        self.max_sequential = max_sequential

    def validate(self, password: str, user=None) -> None:
        """Validate password doesn't have sequential characters."""
        for sequence in self.SEQUENCES:
            for i in range(len(sequence) - self.max_sequential + 1):
                substring = sequence[i:i + self.max_sequential]
                if substring in password:
                    raise ValidationError(
                        _("Password cannot contain sequential characters "
                          "like '%(seq)s'."),
                        code='password_sequential',
                        params={'seq': substring[:3] + '...'},
                    )
                # Also check reverse
                if substring[::-1] in password:
                    raise ValidationError(
                        _("Password cannot contain sequential characters."),
                        code='password_sequential_reverse',
                    )

    def get_help_text(self) -> str:
        return _(
            "Your password cannot contain sequential characters "
            "(e.g., 'abc', '123', 'qwerty')."
        )


class PasswordHistoryValidator:
    """
    Validates that the password wasn't used recently.

    Requires integration with password history model.
    """

    def __init__(self, history_count: int = 12):
        """
        Args:
            history_count: Number of previous passwords to check
        """
        self.history_count = history_count

    def validate(self, password: str, user=None) -> None:
        """Validate password wasn't used recently."""
        if user is None or not user.pk:
            return

        try:
            from core.models import PasswordHistory

            # Get recent password hashes
            recent_passwords = PasswordHistory.objects.filter(
                user=user
            ).order_by('-created_at')[:self.history_count]

            # Check against each
            from django.contrib.auth.hashers import check_password
            for history in recent_passwords:
                if check_password(password, history.password_hash):
                    raise ValidationError(
                        _("You cannot reuse any of your last %(count)d passwords."),
                        code='password_recently_used',
                        params={'count': self.history_count},
                    )
        except ImportError:
            # PasswordHistory model doesn't exist
            logger.debug("PasswordHistory model not available, skipping check")
            pass
        except Exception as e:
            logger.warning(f"Password history check failed: {e}")
            pass

    def get_help_text(self) -> str:
        return _(
            "You cannot reuse any of your last %(count)d passwords."
        ) % {'count': self.history_count}


class BreachedPasswordValidator:
    """
    Validates password against known breached password databases.

    Uses the Have I Been Pwned API with k-anonymity to check if the
    password has been exposed in a data breach.

    Note: This makes an external API call, so consider caching.
    """

    def __init__(self, threshold: int = 5):
        """
        Args:
            threshold: Minimum breach count to reject password
        """
        self.threshold = threshold
        self.api_url = 'https://api.pwnedpasswords.com/range/'

    def validate(self, password: str, user=None) -> None:
        """Check password against HIBP database."""
        try:
            import requests

            # Hash the password with SHA-1
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

            # Use k-anonymity: send only first 5 characters
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            # Query the API
            response = requests.get(
                f'{self.api_url}{prefix}',
                timeout=5,
                headers={'User-Agent': 'Zumodra-PasswordValidator'}
            )

            if response.status_code == 200:
                # Check if our suffix is in the response
                for line in response.text.splitlines():
                    parts = line.split(':')
                    if len(parts) == 2:
                        hash_suffix, count = parts
                        if hash_suffix == suffix:
                            breach_count = int(count)
                            if breach_count >= self.threshold:
                                logger.warning(
                                    f"Breached password detected: {breach_count} occurrences"
                                )
                                raise ValidationError(
                                    _("This password has been found in %(count)d data breaches. "
                                      "Please choose a different password."),
                                    code='password_breached',
                                    params={'count': breach_count},
                                )
        except requests.RequestException as e:
            # Don't block on API errors, just log
            logger.warning(f"HIBP API request failed: {e}")
        except ValidationError:
            raise
        except Exception as e:
            logger.warning(f"Breached password check failed: {e}")

    def get_help_text(self) -> str:
        return _(
            "Your password will be checked against known data breaches."
        )


class EntropyValidator:
    """
    Validates that the password has sufficient entropy (randomness).

    Uses character frequency analysis to estimate password strength.
    """

    def __init__(self, min_entropy: float = 40.0):
        """
        Args:
            min_entropy: Minimum entropy bits required
        """
        self.min_entropy = min_entropy

    def validate(self, password: str, user=None) -> None:
        """Validate password has sufficient entropy."""
        import math

        if not password:
            raise ValidationError(
                _("Password is required."),
                code='password_required',
            )

        # Calculate character set size
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in SpecialCharacterValidator.SPECIAL_CHARACTERS for c in password):
            charset_size += len(SpecialCharacterValidator.SPECIAL_CHARACTERS)

        if charset_size == 0:
            charset_size = 26  # Minimum fallback

        # Calculate entropy: log2(charset^length)
        entropy = len(password) * math.log2(charset_size)

        if entropy < self.min_entropy:
            raise ValidationError(
                _("Password is not complex enough. Try adding more varied characters."),
                code='password_low_entropy',
            )

    def get_help_text(self) -> str:
        return _(
            "Your password must be sufficiently complex and random."
        )


class MaxLengthValidator:
    """
    Validates that the password doesn't exceed maximum length.

    NIST recommends supporting at least 64 characters, but some systems
    have limits due to hashing algorithms.
    """

    def __init__(self, max_length: int = 128):
        """
        Args:
            max_length: Maximum password length
        """
        self.max_length = max_length

    def validate(self, password: str, user=None) -> None:
        """Validate password length."""
        if len(password) > self.max_length:
            raise ValidationError(
                _("Password cannot be longer than %(max)d characters."),
                code='password_too_long',
                params={'max': self.max_length},
            )

    def get_help_text(self) -> str:
        return _(
            "Your password cannot be longer than %(max)d characters."
        ) % {'max': self.max_length}


class DictionaryWordValidator:
    """
    Validates that the password isn't a common dictionary word.

    This is a lighter-weight alternative to Django's CommonPasswordValidator
    that checks against basic dictionary words.
    """

    COMMON_WORDS = {
        'password', 'letmein', 'welcome', 'monkey', 'dragon',
        'master', 'login', 'princess', 'qwerty', 'sunshine',
        'admin', 'administrator', 'root', 'user', 'guest',
        'changeme', 'temp', 'test', 'demo', 'default',
    }

    def __init__(self, extra_words: list = None):
        """
        Args:
            extra_words: Additional words to check against
        """
        self.words = self.COMMON_WORDS.copy()
        if extra_words:
            self.words.update(word.lower() for word in extra_words)

    def validate(self, password: str, user=None) -> None:
        """Validate password isn't a dictionary word."""
        password_lower = password.lower()

        # Check exact match
        if password_lower in self.words:
            raise ValidationError(
                _("This password is too common. Please choose a more unique password."),
                code='password_too_common',
            )

        # Check with common suffixes/prefixes removed
        for suffix in ('1', '12', '123', '1234', '!', '!!', '@', '#'):
            if password_lower.rstrip(suffix) in self.words:
                raise ValidationError(
                    _("This password is too predictable. Please choose a more unique password."),
                    code='password_predictable',
                )

    def get_help_text(self) -> str:
        return _(
            "Your password cannot be a common word or phrase."
        )
