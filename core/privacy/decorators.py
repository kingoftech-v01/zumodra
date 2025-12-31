"""
GDPR/Privacy Compliance Decorators for Zumodra ATS/HR Platform

This module provides decorators for privacy compliance:
- @requires_consent: Check consent before processing
- @log_data_access: Audit trail for PII access
- @anonymize_in_logs: Prevent PII in log files

These decorators help enforce GDPR compliance at the view and function level.
"""

import functools
import hashlib
import logging
import re
from typing import Callable, List, Optional, Union

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import connection
from django.http import HttpRequest, HttpResponseForbidden, JsonResponse
from django.utils import timezone

logger = logging.getLogger(__name__)


def get_current_tenant():
    """Get the current tenant from the database connection."""
    return getattr(connection, 'tenant', None)


def get_client_ip(request: HttpRequest) -> str:
    """Extract client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


class requires_consent:
    """
    Decorator to check if user has given consent for a specific purpose.

    Usage:
        @requires_consent('marketing_email')
        def send_marketing_email(request):
            ...

        @requires_consent('analytics', redirect_url='/privacy/consent/')
        def track_user_behavior(request):
            ...

        @requires_consent(['recruitment', 'background_check'])
        def process_candidate(request):
            ...
    """

    def __init__(
        self,
        purpose: Union[str, List[str]],
        redirect_url: Optional[str] = None,
        api_response: bool = False,
        allow_anonymous: bool = False,
    ):
        """
        Initialize the consent decorator.

        Args:
            purpose: Consent type(s) required (from ConsentRecord.ConsentType).
            redirect_url: URL to redirect to if consent not given.
            api_response: Return JSON response instead of redirect.
            allow_anonymous: Allow anonymous users (skip consent check).
        """
        self.purposes = [purpose] if isinstance(purpose, str) else purpose
        self.redirect_url = redirect_url
        self.api_response = api_response
        self.allow_anonymous = allow_anonymous

    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(request, *args, **kwargs):
            # Check if user is authenticated
            if not request.user.is_authenticated:
                if self.allow_anonymous:
                    return func(request, *args, **kwargs)
                return self._handle_no_consent(request, "Authentication required")

            # Get current tenant
            tenant = get_current_tenant()
            if not tenant:
                return self._handle_no_consent(request, "Tenant context required")

            # Check consent for each purpose
            from core.privacy.services import ConsentService
            consent_service = ConsentService(tenant)

            missing_consents = []
            for purpose in self.purposes:
                has_consent = consent_service.check_consent(
                    user=request.user,
                    consent_type=purpose,
                )
                if not has_consent:
                    missing_consents.append(purpose)

            if missing_consents:
                logger.warning(
                    f"Consent check failed for user {request.user.id}: "
                    f"missing consents: {missing_consents}"
                )
                return self._handle_no_consent(
                    request,
                    f"Consent required for: {', '.join(missing_consents)}"
                )

            # All consents verified, proceed
            return func(request, *args, **kwargs)

        return wrapper

    def _handle_no_consent(self, request: HttpRequest, message: str):
        """Handle the case when consent is not given."""
        if self.api_response:
            return JsonResponse({
                'error': 'consent_required',
                'message': message,
                'consent_url': self.redirect_url or '/privacy/consent/',
            }, status=403)

        if self.redirect_url:
            from django.shortcuts import redirect
            return redirect(self.redirect_url)

        return HttpResponseForbidden(
            f"Consent required. Please update your privacy preferences."
        )


class log_data_access:
    """
    Decorator to log PII data access for audit trail.

    Usage:
        @log_data_access(data_category='personal')
        def view_candidate_profile(request, candidate_id):
            ...

        @log_data_access(
            data_category='sensitive',
            fields=['salary', 'ssn'],
            reason_param='access_reason'
        )
        def view_employee_payroll(request, employee_id):
            ...
    """

    def __init__(
        self,
        data_category: str,
        fields: Optional[List[str]] = None,
        reason_param: Optional[str] = None,
        log_to_db: bool = True,
        log_to_file: bool = True,
    ):
        """
        Initialize the data access logger.

        Args:
            data_category: Category of data being accessed.
            fields: Specific fields being accessed.
            reason_param: Request parameter containing access reason.
            log_to_db: Whether to log to database.
            log_to_file: Whether to log to file.
        """
        self.data_category = data_category
        self.fields = fields or []
        self.reason_param = reason_param
        self.log_to_db = log_to_db
        self.log_to_file = log_to_file

    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(request, *args, **kwargs):
            # Extract data subject ID from kwargs
            data_subject_id = kwargs.get('pk') or kwargs.get('id') or kwargs.get('user_id')

            # Get access reason if specified
            access_reason = ''
            if self.reason_param:
                access_reason = (
                    request.GET.get(self.reason_param) or
                    request.POST.get(self.reason_param) or
                    getattr(request, 'data', {}).get(self.reason_param, '')
                )

            # Log the access attempt
            access_log_entry = {
                'timestamp': timezone.now().isoformat(),
                'accessor': str(request.user.id) if request.user.is_authenticated else 'anonymous',
                'accessor_email': request.user.email if request.user.is_authenticated else None,
                'data_category': self.data_category,
                'fields': self.fields,
                'data_subject_id': str(data_subject_id) if data_subject_id else None,
                'endpoint': request.path,
                'method': request.method,
                'ip_address': get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', '')[:500],
                'access_reason': access_reason,
            }

            # Log to file
            if self.log_to_file:
                logger.info(
                    f"DATA_ACCESS: user={access_log_entry['accessor']}, "
                    f"category={self.data_category}, "
                    f"subject={data_subject_id}, "
                    f"endpoint={request.path}"
                )

            # Log to database
            if self.log_to_db and request.user.is_authenticated:
                self._log_to_database(request, access_log_entry, data_subject_id)

            # Execute the original function
            return func(request, *args, **kwargs)

        return wrapper

    def _log_to_database(
        self,
        request: HttpRequest,
        log_entry: dict,
        data_subject_id: Optional[str],
    ):
        """Log the data access to the database."""
        try:
            from core.privacy.models import PrivacyAuditLog
            from django.contrib.auth import get_user_model

            tenant = get_current_tenant()
            if not tenant:
                return

            User = get_user_model()
            data_subject = None

            if data_subject_id:
                try:
                    data_subject = User.objects.get(pk=data_subject_id)
                except (User.DoesNotExist, ValueError):
                    pass

            PrivacyAuditLog.objects.create(
                tenant=tenant,
                action=PrivacyAuditLog.ActionType.DATA_ACCESSED,
                description=f"Accessed {self.data_category} data",
                actor=request.user,
                data_subject=data_subject,
                ip_address=log_entry['ip_address'],
                user_agent=log_entry['user_agent'],
                context={
                    'category': self.data_category,
                    'fields': self.fields,
                    'endpoint': log_entry['endpoint'],
                    'reason': log_entry['access_reason'],
                },
            )

        except Exception as e:
            logger.warning(f"Failed to log data access to database: {e}")


class anonymize_in_logs:
    """
    Decorator to anonymize PII in log output.

    Prevents sensitive data from appearing in log files by
    redacting or hashing PII fields.

    Usage:
        @anonymize_in_logs(['email', 'phone', 'ssn'])
        def process_application(request, email, phone):
            logger.info(f"Processing for {email}")  # Will be redacted
            ...

        @anonymize_in_logs(hash_fields=['user_id'], redact_fields=['password'])
        def authenticate_user(request, user_id, password):
            ...
    """

    # Patterns for auto-detecting PII
    PII_PATTERNS = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'phone': r'(\+?1?[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
        'ssn': r'\d{3}[-\s]?\d{2}[-\s]?\d{4}',
        'sin': r'\d{3}[-\s]?\d{3}[-\s]?\d{3}',
        'credit_card': r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}',
        'ip_address': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    }

    REDACTED = '[REDACTED]'

    def __init__(
        self,
        redact_fields: Optional[List[str]] = None,
        hash_fields: Optional[List[str]] = None,
        auto_detect: bool = True,
    ):
        """
        Initialize the log anonymizer.

        Args:
            redact_fields: Fields to completely redact.
            hash_fields: Fields to hash (preserves uniqueness).
            auto_detect: Auto-detect common PII patterns.
        """
        self.redact_fields = redact_fields or []
        self.hash_fields = hash_fields or []
        self.auto_detect = auto_detect

    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Create a custom log filter for this context
            filter_instance = _PIILogFilter(
                redact_fields=self.redact_fields,
                hash_fields=self.hash_fields,
                auto_detect=self.auto_detect,
                patterns=self.PII_PATTERNS,
            )

            # Add filter to root logger
            root_logger = logging.getLogger()
            root_logger.addFilter(filter_instance)

            try:
                return func(*args, **kwargs)
            finally:
                # Remove filter after function execution
                root_logger.removeFilter(filter_instance)

        return wrapper


class _PIILogFilter(logging.Filter):
    """Custom log filter that anonymizes PII in log messages."""

    def __init__(
        self,
        redact_fields: List[str],
        hash_fields: List[str],
        auto_detect: bool,
        patterns: dict,
    ):
        super().__init__()
        self.redact_fields = redact_fields
        self.hash_fields = hash_fields
        self.auto_detect = auto_detect
        self.patterns = patterns

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter and modify log record to anonymize PII."""
        # Modify the message
        if hasattr(record, 'msg'):
            record.msg = self._anonymize_string(str(record.msg))

        # Modify args if present
        if hasattr(record, 'args') and record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: self._anonymize_string(str(v)) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    self._anonymize_string(str(arg)) if isinstance(arg, str) else arg
                    for arg in record.args
                )

        return True  # Always allow the record through

    def _anonymize_string(self, text: str) -> str:
        """Anonymize PII in a string."""
        result = text

        # Redact specified fields (simple word matching)
        for field in self.redact_fields:
            pattern = rf'\b{field}\s*[=:]\s*["\']?([^"\'\s,]+)["\']?'
            result = re.sub(pattern, f'{field}=[REDACTED]', result, flags=re.IGNORECASE)

        # Hash specified fields
        for field in self.hash_fields:
            pattern = rf'\b{field}\s*[=:]\s*["\']?([^"\'\s,]+)["\']?'
            matches = re.finditer(pattern, result, flags=re.IGNORECASE)
            for match in matches:
                original = match.group(1)
                hashed = hashlib.sha256(original.encode()).hexdigest()[:12]
                result = result.replace(original, f'[HASH:{hashed}]')

        # Auto-detect common PII patterns
        if self.auto_detect:
            for pii_type, pattern in self.patterns.items():
                result = re.sub(pattern, f'[{pii_type.upper()}:REDACTED]', result)

        return result


def consent_required_api(purpose: Union[str, List[str]]) -> Callable:
    """
    Simplified consent decorator for DRF views.

    Usage:
        class MarketingViewSet(viewsets.ViewSet):
            @consent_required_api('marketing_email')
            def send_newsletter(self, request):
                ...
    """
    return requires_consent(
        purpose=purpose,
        api_response=True,
        allow_anonymous=False,
    )


def audit_pii_access(
    category: str,
    fields: Optional[List[str]] = None
) -> Callable:
    """
    Simplified data access logging decorator.

    Usage:
        @audit_pii_access('candidate_profile')
        def get_candidate(request, pk):
            ...
    """
    return log_data_access(
        data_category=category,
        fields=fields,
        log_to_db=True,
        log_to_file=True,
    )


class privacy_context:
    """
    Context manager for privacy-aware operations.

    Usage:
        with privacy_context(user=request.user, purpose='data_export') as ctx:
            # Operations here are logged and consent-checked
            data = get_user_data(user_id)
            ctx.log_access('profile', ['name', 'email'])
    """

    def __init__(
        self,
        user,
        purpose: str,
        tenant=None,
    ):
        """
        Initialize privacy context.

        Args:
            user: The user performing the operation.
            purpose: The purpose of the data processing.
            tenant: Optional tenant context.
        """
        self.user = user
        self.purpose = purpose
        self.tenant = tenant or get_current_tenant()
        self.access_log = []
        self.start_time = None

    def __enter__(self):
        self.start_time = timezone.now()
        logger.debug(f"Privacy context started: {self.purpose}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (timezone.now() - self.start_time).total_seconds()
        logger.debug(
            f"Privacy context ended: {self.purpose}, "
            f"duration={duration:.2f}s, accesses={len(self.access_log)}"
        )

        # Log aggregated access if any
        if self.access_log and self.tenant:
            self._log_aggregated_access()

        return False  # Don't suppress exceptions

    def log_access(
        self,
        category: str,
        fields: Optional[List[str]] = None,
        subject_id: Optional[str] = None,
    ):
        """Log a data access within this context."""
        self.access_log.append({
            'timestamp': timezone.now(),
            'category': category,
            'fields': fields or [],
            'subject_id': subject_id,
        })

    def check_consent(self, consent_type: str) -> bool:
        """Check if the user has given consent."""
        if not self.tenant:
            return False

        from core.privacy.services import ConsentService
        consent_service = ConsentService(self.tenant)
        return consent_service.check_consent(self.user, consent_type)

    def _log_aggregated_access(self):
        """Log all accesses from this context to database."""
        try:
            from core.privacy.models import PrivacyAuditLog

            categories = list(set(a['category'] for a in self.access_log))
            all_fields = list(set(
                f for a in self.access_log for f in a.get('fields', [])
            ))

            PrivacyAuditLog.objects.create(
                tenant=self.tenant,
                action=PrivacyAuditLog.ActionType.DATA_ACCESSED,
                description=f"Privacy context: {self.purpose}",
                actor=self.user if self.user and self.user.is_authenticated else None,
                context={
                    'purpose': self.purpose,
                    'categories': categories,
                    'fields': all_fields,
                    'access_count': len(self.access_log),
                    'duration_seconds': (timezone.now() - self.start_time).total_seconds(),
                },
            )

        except Exception as e:
            logger.warning(f"Failed to log aggregated access: {e}")
