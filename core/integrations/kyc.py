"""
KYC Provider Integration - Onfido implementation.

This module provides KYC (Know Your Customer) verification via Onfido.

Features:
- Document verification (passport, driver's license, ID cards)
- Facial recognition comparison
- Address verification
- Webhook handling for async verification results
- Audit logging for compliance

Usage:
    from core.integrations.kyc import OnfidoProvider

    kyc = OnfidoProvider()
    applicant = kyc.create_applicant(user)
    check = kyc.create_check(applicant_id, documents=['passport', 'facial_similarity'])
    status = kyc.get_check_status(check_id)

Configuration:
    Set in settings.py:
    - ONFIDO_API_TOKEN: Your Onfido API token
    - ONFIDO_WEBHOOK_TOKEN: Token for webhook signature verification
    - ONFIDO_SANDBOX: True for sandbox mode, False for production
"""

import hashlib
import hmac
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

import requests
from django.conf import settings

logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security.kyc')


class VerificationStatus(Enum):
    """KYC verification status."""
    PENDING = 'pending'
    IN_PROGRESS = 'in_progress'
    COMPLETE = 'complete'
    FAILED = 'failed'
    REQUIRES_REVIEW = 'requires_review'
    EXPIRED = 'expired'


class DocumentType(Enum):
    """Supported document types for verification."""
    PASSPORT = 'passport'
    DRIVING_LICENCE = 'driving_licence'
    NATIONAL_IDENTITY_CARD = 'national_identity_card'
    RESIDENCE_PERMIT = 'residence_permit'
    VISA = 'visa'


@dataclass
class KYCResult:
    """Result from a KYC check."""
    check_id: str
    status: VerificationStatus
    result: Optional[str]  # 'clear', 'consider', or None
    sub_results: Dict[str, Any]
    breakdown: Dict[str, Any]
    created_at: datetime
    completed_at: Optional[datetime]
    error: Optional[str] = None


class KYCProvider(ABC):
    """Abstract base class for KYC providers."""

    @abstractmethod
    def create_applicant(
        self,
        first_name: str,
        last_name: str,
        email: str,
        dob: Optional[str] = None,
        country: Optional[str] = None,
        **kwargs
    ) -> str:
        """Create an applicant and return the applicant ID."""
        pass

    @abstractmethod
    def create_check(
        self,
        applicant_id: str,
        report_types: List[str],
        **kwargs
    ) -> str:
        """Create a verification check and return the check ID."""
        pass

    @abstractmethod
    def get_check_status(self, check_id: str) -> KYCResult:
        """Get the status of a verification check."""
        pass

    @abstractmethod
    def generate_sdk_token(self, applicant_id: str) -> str:
        """Generate SDK token for client-side document capture."""
        pass

    @abstractmethod
    def verify_webhook_signature(
        self,
        payload: bytes,
        signature: str
    ) -> bool:
        """Verify webhook signature for authenticity."""
        pass


class OnfidoProvider(KYCProvider):
    """
    Onfido KYC Provider implementation.

    Provides real integration with Onfido API for identity verification.
    """

    BASE_URL = "https://api.onfido.com/v3"
    SANDBOX_URL = "https://api.onfido.com/v3"  # Sandbox uses same URL

    def __init__(self):
        """Initialize Onfido provider with configuration from settings."""
        self.api_token = getattr(settings, 'ONFIDO_API_TOKEN', '')
        self.webhook_token = getattr(settings, 'ONFIDO_WEBHOOK_TOKEN', '')
        self.sandbox = getattr(settings, 'ONFIDO_SANDBOX', True)

        if not self.api_token:
            logger.warning("ONFIDO_API_TOKEN not configured")

        self.headers = {
            'Authorization': f'Token token={self.api_token}',
            'Content-Type': 'application/json',
        }

    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make authenticated request to Onfido API."""
        url = f"{self.BASE_URL}/{endpoint}"

        try:
            response = requests.request(
                method,
                url,
                json=data,
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as e:
            error_data = {}
            try:
                error_data = response.json()
            except Exception:
                pass

            security_logger.error(
                f"ONFIDO_API_ERROR: endpoint={endpoint} "
                f"status={response.status_code} error={error_data}"
            )
            raise KYCAPIError(
                f"Onfido API error: {response.status_code}",
                error_data
            )

        except requests.exceptions.RequestException as e:
            security_logger.error(f"ONFIDO_REQUEST_ERROR: {str(e)}")
            raise KYCAPIError(f"Request failed: {str(e)}")

    def create_applicant(
        self,
        first_name: str,
        last_name: str,
        email: str,
        dob: Optional[str] = None,
        country: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        Create an Onfido applicant.

        Args:
            first_name: Applicant's first name
            last_name: Applicant's last name
            email: Applicant's email address
            dob: Date of birth (YYYY-MM-DD format)
            country: 3-letter ISO country code

        Returns:
            Applicant ID from Onfido
        """
        data = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
        }

        if dob:
            data['dob'] = dob

        if country:
            data['country'] = country

        # Add any additional fields
        for key in ['address', 'phone_number', 'id_numbers']:
            if key in kwargs:
                data[key] = kwargs[key]

        result = self._request('POST', 'applicants', data)
        applicant_id = result.get('id')

        security_logger.info(
            f"ONFIDO_APPLICANT_CREATED: applicant_id={applicant_id} "
            f"email={email}"
        )

        return applicant_id

    def create_check(
        self,
        applicant_id: str,
        report_types: Optional[List[str]] = None,
        document_ids: Optional[List[str]] = None,
        **kwargs
    ) -> str:
        """
        Create a verification check for an applicant.

        Args:
            applicant_id: Onfido applicant ID
            report_types: List of report types to run
                - 'document': Document verification
                - 'facial_similarity_photo': Face match with document
                - 'identity_enhanced': Enhanced identity check
            document_ids: Optional list of document IDs to check

        Returns:
            Check ID from Onfido
        """
        if report_types is None:
            report_types = ['document', 'facial_similarity_photo']

        data = {
            'applicant_id': applicant_id,
            'report_names': report_types,
        }

        if document_ids:
            data['document_ids'] = document_ids

        # Async by default for webhook-based flow
        data['asynchronous'] = kwargs.get('asynchronous', True)

        result = self._request('POST', 'checks', data)
        check_id = result.get('id')

        security_logger.info(
            f"ONFIDO_CHECK_CREATED: check_id={check_id} "
            f"applicant_id={applicant_id} reports={report_types}"
        )

        return check_id

    def get_check_status(self, check_id: str) -> KYCResult:
        """
        Get the current status of a verification check.

        Args:
            check_id: Onfido check ID

        Returns:
            KYCResult with current status and any results
        """
        result = self._request('GET', f'checks/{check_id}')

        status = self._map_status(result.get('status', 'unknown'))
        onfido_result = result.get('result')

        # Get detailed breakdown from reports
        breakdown = {}
        sub_results = {}

        if result.get('report_ids'):
            for report_id in result['report_ids']:
                report = self._request('GET', f'reports/{report_id}')
                report_name = report.get('name', 'unknown')
                sub_results[report_name] = report.get('result')
                breakdown[report_name] = report.get('breakdown', {})

        return KYCResult(
            check_id=check_id,
            status=status,
            result=onfido_result,
            sub_results=sub_results,
            breakdown=breakdown,
            created_at=self._parse_datetime(result.get('created_at')),
            completed_at=self._parse_datetime(result.get('completed_at')),
        )

    def generate_sdk_token(
        self,
        applicant_id: str,
        referrer: Optional[str] = None
    ) -> str:
        """
        Generate an SDK token for client-side document capture.

        The SDK token is used to initialize the Onfido SDK in the browser
        for capturing documents and selfies.

        Args:
            applicant_id: Onfido applicant ID
            referrer: Optional referrer URL pattern (e.g., 'https://*.example.com/*')

        Returns:
            SDK token string
        """
        data = {
            'applicant_id': applicant_id,
        }

        if referrer:
            data['referrer'] = referrer

        result = self._request('POST', 'sdk_token', data)

        security_logger.info(
            f"ONFIDO_SDK_TOKEN_GENERATED: applicant_id={applicant_id}"
        )

        return result.get('token', '')

    def verify_webhook_signature(
        self,
        payload: bytes,
        signature: str
    ) -> bool:
        """
        Verify the signature of an Onfido webhook.

        Args:
            payload: Raw request body as bytes
            signature: X-SHA2-Signature header value

        Returns:
            True if signature is valid, False otherwise
        """
        if not self.webhook_token:
            logger.warning("ONFIDO_WEBHOOK_TOKEN not configured")
            return False

        expected_signature = hmac.new(
            self.webhook_token.encode('utf-8'),
            payload,
            hashlib.sha256
        ).hexdigest()

        is_valid = hmac.compare_digest(expected_signature, signature)

        if not is_valid:
            security_logger.warning(
                "ONFIDO_WEBHOOK_SIGNATURE_INVALID: signature verification failed"
            )

        return is_valid

    def handle_webhook(self, payload: Dict[str, Any]) -> Optional[KYCResult]:
        """
        Handle an Onfido webhook event.

        Args:
            payload: Parsed webhook JSON payload

        Returns:
            KYCResult if this is a check completion event, None otherwise
        """
        event_type = payload.get('payload', {}).get('resource_type')
        action = payload.get('payload', {}).get('action')

        if event_type == 'check' and action == 'check.completed':
            check_id = payload['payload']['object']['id']

            security_logger.info(
                f"ONFIDO_WEBHOOK_RECEIVED: type=check.completed check_id={check_id}"
            )

            return self.get_check_status(check_id)

        return None

    def _map_status(self, onfido_status: str) -> VerificationStatus:
        """Map Onfido status to internal VerificationStatus."""
        status_map = {
            'in_progress': VerificationStatus.IN_PROGRESS,
            'awaiting_applicant': VerificationStatus.PENDING,
            'complete': VerificationStatus.COMPLETE,
            'withdrawn': VerificationStatus.EXPIRED,
            'paused': VerificationStatus.REQUIRES_REVIEW,
            'reopened': VerificationStatus.IN_PROGRESS,
        }
        return status_map.get(onfido_status, VerificationStatus.PENDING)

    def _parse_datetime(self, dt_str: Optional[str]) -> Optional[datetime]:
        """Parse Onfido datetime string."""
        if not dt_str:
            return None
        try:
            # Onfido uses ISO 8601 format
            return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        except (ValueError, TypeError):
            return None


class KYCAPIError(Exception):
    """Exception raised for KYC API errors."""

    def __init__(self, message: str, error_data: Optional[Dict] = None):
        super().__init__(message)
        self.error_data = error_data or {}


class MockKYCProvider(KYCProvider):
    """
    Mock KYC provider for testing and development.

    Always returns successful verification after a short delay.
    """

    def __init__(self):
        self._applicants = {}
        self._checks = {}
        self._counter = 0

    def create_applicant(
        self,
        first_name: str,
        last_name: str,
        email: str,
        **kwargs
    ) -> str:
        """Create a mock applicant."""
        self._counter += 1
        applicant_id = f"mock_applicant_{self._counter}"
        self._applicants[applicant_id] = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            **kwargs
        }
        return applicant_id

    def create_check(
        self,
        applicant_id: str,
        report_types: Optional[List[str]] = None,
        **kwargs
    ) -> str:
        """Create a mock check."""
        self._counter += 1
        check_id = f"mock_check_{self._counter}"
        self._checks[check_id] = {
            'applicant_id': applicant_id,
            'report_types': report_types or ['document'],
            'status': 'complete',
            'result': 'clear',
        }
        return check_id

    def get_check_status(self, check_id: str) -> KYCResult:
        """Get mock check status (always complete/clear)."""
        check = self._checks.get(check_id, {})
        return KYCResult(
            check_id=check_id,
            status=VerificationStatus.COMPLETE,
            result='clear',
            sub_results={'document': 'clear', 'facial_similarity_photo': 'clear'},
            breakdown={},
            created_at=datetime.now(),
            completed_at=datetime.now(),
        )

    def generate_sdk_token(self, applicant_id: str) -> str:
        """Generate mock SDK token."""
        return f"mock_token_{applicant_id}"

    def verify_webhook_signature(self, payload: bytes, signature: str) -> bool:
        """Always return True for mock provider."""
        return True


def get_kyc_provider() -> KYCProvider:
    """
    Get the configured KYC provider.

    Returns OnfidoProvider in production, MockKYCProvider in development
    or when ONFIDO_API_TOKEN is not configured.
    """
    api_token = getattr(settings, 'ONFIDO_API_TOKEN', '')

    if settings.DEBUG and not api_token:
        logger.info("Using MockKYCProvider (DEBUG mode, no API token)")
        return MockKYCProvider()

    if not api_token:
        logger.warning("ONFIDO_API_TOKEN not configured, using MockKYCProvider")
        return MockKYCProvider()

    return OnfidoProvider()
