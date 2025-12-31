"""
Zumodra Core Security Module

OWASP Top 10 2021 compliant security implementations for the
multi-tenant ATS/HR SaaS platform.

This module provides comprehensive security protections including:
- A01: Broken Access Control protection
- A02: Cryptographic Failures prevention
- A03: Injection prevention (SQL, Command, LDAP)
- A04: Insecure Design validation
- A05: Security Misconfiguration auditing
- A06: Vulnerable Components checking
- A07: Authentication Failures protection
- A08: Software/Data Integrity validation
- A09: Security Logging and Monitoring
- A10: SSRF protection
"""

from .owasp import (
    # A01: Broken Access Control
    TenantAccessControlValidator,
    ResourceOwnershipChecker,

    # A02: Cryptographic Failures
    SecureStorageValidator,
    TLSEnforcer,

    # A03: Injection Prevention
    SQLInjectionPreventer,
    CommandInjectionPreventer,
    LDAPInjectionPreventer,

    # A04: Insecure Design
    SecurityRequirementsValidator,

    # A05: Security Misconfiguration
    ConfigurationAuditor,

    # A06: Vulnerable Components
    DependencyChecker,

    # A07: Auth Failures
    LoginAttemptTracker,
    AccountLockoutManager,
    PasswordPolicyEnforcer,

    # A08: Software/Data Integrity
    IntegrityValidator,
    CSRFEnhancer,

    # A09: Logging Failures
    SecurityEventLogger,
    AlertingService,

    # A10: SSRF
    SSRFProtector,
    URLSafetyChecker,
)

from .authentication import (
    MFAService,
    SessionSecurityManager,
    PasswordValidator,
    BruteForceProtection,
    JWTSecurityEnhancer,
)

from .authorization import (
    PermissionChecker,
    ResourceAccessValidator,
    TenantBoundaryEnforcer,
    CrossTenantAccessPreventer,
    PrivilegeEscalationDetector,
)

from .csrf import (
    EnhancedCSRFProtection,
    DoubleSubmitCookieValidator,
    OriginValidator,
    SameSiteCookieEnforcer,
)

from .headers import (
    SecurityHeadersConfig,
    ContentSecurityPolicyConfig,
    get_security_settings,
)

from .validators import (
    InputSanitizer,
    FileUploadValidator,
    URLValidator,
    EmailValidator,
    PhoneValidator,
    UsernameValidator,
    SanitizationUtilities,
    VirusScanValidator,
    SecureFileValidator,
)

from .honeypot import (
    HoneypotField,
    HoneypotFormMixin,
    HoneypotMixin,
    HoneypotMiddleware,
    TimestampField,
    JavaScriptChallengeField,
    is_ip_suspicious,
    is_ip_blocked,
    block_ip,
    unblock_ip,
)

from .rate_limiting import (
    TokenBucketRateLimiter,
    SlidingWindowRateLimiter,
    FixedWindowRateLimiter,
    CompositeRateLimiter,
    RateLimitConfig,
    RateLimitResult,
    rate_limit,
    IPRateThrottle,
    UserRateThrottle,
    BurstRateThrottle,
    SensitiveEndpointThrottle,
    TenantAwareDRFThrottle,
    BruteForceProtection,
    brute_force_protection,
    brute_force_protect,
    LoginAttemptTracker,
    login_tracker,
)

from .password_validators import (
    MixedCaseValidator,
    NumberValidator,
    SpecialCharacterValidator,
    NoUsernameValidator,
    NoRepeatingCharactersValidator,
    NoSequentialCharactersValidator,
    PasswordHistoryValidator,
    BreachedPasswordValidator,
    EntropyValidator,
    MaxLengthValidator,
    DictionaryWordValidator,
)

__all__ = [
    # OWASP
    'TenantAccessControlValidator',
    'ResourceOwnershipChecker',
    'SecureStorageValidator',
    'TLSEnforcer',
    'SQLInjectionPreventer',
    'CommandInjectionPreventer',
    'LDAPInjectionPreventer',
    'SecurityRequirementsValidator',
    'ConfigurationAuditor',
    'DependencyChecker',
    'LoginAttemptTracker',
    'AccountLockoutManager',
    'PasswordPolicyEnforcer',
    'IntegrityValidator',
    'CSRFEnhancer',
    'SecurityEventLogger',
    'AlertingService',
    'SSRFProtector',
    'URLSafetyChecker',

    # Authentication
    'MFAService',
    'SessionSecurityManager',
    'PasswordValidator',
    'BruteForceProtection',
    'JWTSecurityEnhancer',

    # Authorization
    'PermissionChecker',
    'ResourceAccessValidator',
    'TenantBoundaryEnforcer',
    'CrossTenantAccessPreventer',
    'PrivilegeEscalationDetector',

    # CSRF
    'EnhancedCSRFProtection',
    'DoubleSubmitCookieValidator',
    'OriginValidator',
    'SameSiteCookieEnforcer',

    # Headers
    'SecurityHeadersConfig',
    'ContentSecurityPolicyConfig',
    'get_security_settings',

    # Validators
    'InputSanitizer',
    'FileUploadValidator',
    'URLValidator',
    'EmailValidator',
    'PhoneValidator',
    'UsernameValidator',
    'SanitizationUtilities',
    'VirusScanValidator',
    'SecureFileValidator',

    # Honeypot
    'HoneypotField',
    'HoneypotFormMixin',
    'HoneypotMixin',
    'HoneypotMiddleware',
    'TimestampField',
    'JavaScriptChallengeField',
    'is_ip_suspicious',
    'is_ip_blocked',
    'block_ip',
    'unblock_ip',

    # Rate Limiting
    'TokenBucketRateLimiter',
    'SlidingWindowRateLimiter',
    'FixedWindowRateLimiter',
    'CompositeRateLimiter',
    'RateLimitConfig',
    'RateLimitResult',
    'rate_limit',
    'IPRateThrottle',
    'UserRateThrottle',
    'BurstRateThrottle',
    'SensitiveEndpointThrottle',
    'TenantAwareDRFThrottle',
    'brute_force_protection',
    'brute_force_protect',
    'login_tracker',

    # Password Validators
    'MixedCaseValidator',
    'NumberValidator',
    'SpecialCharacterValidator',
    'NoUsernameValidator',
    'NoRepeatingCharactersValidator',
    'NoSequentialCharactersValidator',
    'PasswordHistoryValidator',
    'BreachedPasswordValidator',
    'EntropyValidator',
    'MaxLengthValidator',
    'DictionaryWordValidator',
]
