"""
Background Check Integration Providers

Implements background check integrations for:
- Checkr
- Sterling
"""

import logging
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

from .base import (
    BackgroundCheckProvider,
    IntegrationError,
    AuthenticationError,
    ConfigurationError,
)

logger = logging.getLogger(__name__)


class CheckrProvider(BackgroundCheckProvider):
    """
    Checkr background check integration provider.
    Uses Checkr API v1.
    """

    provider_name = 'checkr'
    display_name = 'Checkr'

    # API configuration
    api_base_url = 'https://api.checkr.com/v1'

    # Checkr uses API key authentication (Basic Auth)
    oauth_authorize_url = ''
    oauth_token_url = ''

    # Available packages
    PACKAGES = {
        'basic': 'tasker_standard',
        'standard': 'driver_standard',
        'pro': 'driver_pro',
        'comprehensive': 'comprehensive_criminal_history',
    }

    def get_headers(self) -> Dict[str, str]:
        """Get headers for Checkr API requests."""
        import base64
        creds = self.get_credentials()
        api_key = creds.get('api_key', '')
        auth = base64.b64encode(f"{api_key}:".encode()).decode()

        return {
            'Authorization': f"Basic {auth}",
            'Content-Type': 'application/json',
        }

    def test_connection(self) -> Tuple[bool, str]:
        """Test Checkr API connection."""
        try:
            response = self.make_request('GET', 'account')
            if response.status_code == 200:
                return True, "Successfully connected to Checkr"
            return False, f"Connection failed: {response.status_code}"
        except AuthenticationError as e:
            return False, f"Authentication failed: {str(e)}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get Checkr account information."""
        response = self.make_request('GET', 'account')
        if response.status_code != 200:
            raise IntegrationError("Failed to fetch account info")

        data = response.json()
        return {
            'id': data.get('id'),
            'name': data.get('name'),
            'uri': data.get('uri'),
        }

    def create_candidate(self, candidate_data: Dict) -> Dict:
        """
        Create a candidate for background check.

        Args:
            candidate_data: Candidate information with:
                - first_name: First name
                - last_name: Last name
                - middle_name: Middle name (optional)
                - email: Email address
                - phone: Phone number
                - dob: Date of birth (YYYY-MM-DD)
                - ssn: Social Security Number
                - driver_license_number: Driver's license number
                - driver_license_state: Driver's license state

        Returns:
            Dict with candidate ID and details
        """
        checkr_candidate = {
            'first_name': candidate_data.get('first_name'),
            'last_name': candidate_data.get('last_name'),
            'email': candidate_data.get('email'),
            'phone': candidate_data.get('phone'),
            'dob': candidate_data.get('dob'),
        }

        # Optional fields
        if candidate_data.get('middle_name'):
            checkr_candidate['middle_name'] = candidate_data['middle_name']
        if candidate_data.get('ssn'):
            checkr_candidate['ssn'] = candidate_data['ssn']
        if candidate_data.get('driver_license_number'):
            checkr_candidate['driver_license_number'] = candidate_data['driver_license_number']
            checkr_candidate['driver_license_state'] = candidate_data.get('driver_license_state')

        response = self.make_request('POST', 'candidates', data=checkr_candidate)

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to create candidate: {response.text}")

        data = response.json()
        return {
            'id': data.get('id'),
            'email': data.get('email'),
            'created_at': data.get('created_at'),
            'invitation_url': data.get('invitation_url'),
        }

    def create_invitation(self, candidate_id: str, package: str) -> Dict:
        """
        Create and send background check invitation.

        Args:
            candidate_id: Checkr candidate ID
            package: Package slug (basic, standard, pro, comprehensive)

        Returns:
            Dict with invitation details
        """
        package_id = self.PACKAGES.get(package, package)

        invitation_data = {
            'candidate_id': candidate_id,
            'package': package_id,
        }

        response = self.make_request('POST', 'invitations', data=invitation_data)

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to create invitation: {response.text}")

        data = response.json()
        return {
            'id': data.get('id'),
            'status': data.get('status'),
            'invitation_url': data.get('invitation_url'),
            'expires_at': data.get('expires_at'),
            'package': package,
        }

    def get_report(self, report_id: str) -> Dict:
        """
        Get background check report.

        Args:
            report_id: Checkr report ID

        Returns:
            Dict with full report details
        """
        response = self.make_request('GET', f'reports/{report_id}')

        if response.status_code != 200:
            raise IntegrationError(f"Failed to get report: {response.status_code}")

        data = response.json()
        return self._normalize_report(data)

    def get_report_status(self, report_id: str) -> Dict:
        """Get status of background check report."""
        response = self.make_request('GET', f'reports/{report_id}')

        if response.status_code != 200:
            raise IntegrationError(f"Failed to get report status: {response.status_code}")

        data = response.json()
        return {
            'id': data.get('id'),
            'status': data.get('status'),
            'adjudication': data.get('adjudication'),
            'completed_at': data.get('completed_at'),
            'estimated_completion_time': data.get('eta'),
        }

    def list_packages(self) -> List[Dict]:
        """List available background check packages."""
        response = self.make_request('GET', 'packages')

        if response.status_code != 200:
            return []

        data = response.json()
        return [
            {
                'id': pkg.get('id'),
                'name': pkg.get('name'),
                'slug': pkg.get('slug'),
                'price': pkg.get('price'),
            }
            for pkg in data.get('data', [])
        ]

    def _normalize_report(self, checkr_report: Dict) -> Dict:
        """Convert Checkr report to normalized format."""
        return {
            'id': checkr_report.get('id'),
            'status': checkr_report.get('status'),
            'adjudication': checkr_report.get('adjudication'),
            'package': checkr_report.get('package'),
            'candidate_id': checkr_report.get('candidate_id'),
            'created_at': checkr_report.get('created_at'),
            'completed_at': checkr_report.get('completed_at'),
            'turnaround_time': checkr_report.get('turnaround_time'),
            'document_ids': checkr_report.get('document_ids', []),
            'screenings': self._extract_screenings(checkr_report),
        }

    def _extract_screenings(self, report: Dict) -> List[Dict]:
        """Extract screening results from report."""
        screenings = []

        # SSN Trace
        if report.get('ssn_trace_id'):
            screenings.append({
                'type': 'ssn_trace',
                'id': report.get('ssn_trace_id'),
                'status': 'included',
            })

        # Criminal checks
        for check_type in ['county_criminal_search', 'national_criminal_search', 'federal_criminal_search']:
            check_ids = report.get(f'{check_type}_ids', [])
            for check_id in check_ids:
                screenings.append({
                    'type': check_type,
                    'id': check_id,
                    'status': 'included',
                })

        # Motor vehicle report
        if report.get('motor_vehicle_report_id'):
            screenings.append({
                'type': 'motor_vehicle_report',
                'id': report.get('motor_vehicle_report_id'),
                'status': 'included',
            })

        return screenings

    def handle_webhook(self, event_type: str, payload: Dict) -> Dict[str, Any]:
        """Handle Checkr webhook events."""
        logger.info(f"Processing Checkr webhook: {event_type}")

        if event_type == 'report.completed':
            report_id = payload.get('data', {}).get('object', {}).get('id')
            if report_id:
                return {
                    'action': 'report_completed',
                    'report_id': report_id,
                    'status': payload.get('data', {}).get('object', {}).get('status'),
                }

        elif event_type == 'candidate.created':
            candidate_id = payload.get('data', {}).get('object', {}).get('id')
            return {
                'action': 'candidate_created',
                'candidate_id': candidate_id,
            }

        return {'action': 'unhandled', 'event_type': event_type}


class SterlingProvider(BackgroundCheckProvider):
    """
    Sterling background check integration provider.
    Uses Sterling API.
    """

    provider_name = 'sterling'
    display_name = 'Sterling'

    # API configuration
    api_base_url = 'https://api.sterlingcheck.com/v2'

    # OAuth configuration for Sterling
    oauth_authorize_url = 'https://api.sterlingcheck.com/oauth/authorize'
    oauth_token_url = 'https://api.sterlingcheck.com/oauth/token'
    oauth_scopes = ['screening']

    def test_connection(self) -> Tuple[bool, str]:
        """Test Sterling API connection."""
        try:
            response = self.make_request('GET', 'account')
            if response.status_code == 200:
                return True, "Successfully connected to Sterling"
            return False, f"Connection failed: {response.status_code}"
        except AuthenticationError as e:
            return False, f"Authentication failed: {str(e)}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get Sterling account information."""
        response = self.make_request('GET', 'account')
        if response.status_code != 200:
            raise IntegrationError("Failed to fetch account info")

        data = response.json()
        return {
            'id': data.get('accountId'),
            'name': data.get('accountName'),
            'status': data.get('status'),
        }

    def create_candidate(self, candidate_data: Dict) -> Dict:
        """Create a candidate for Sterling background check."""
        sterling_candidate = {
            'firstName': candidate_data.get('first_name'),
            'lastName': candidate_data.get('last_name'),
            'email': candidate_data.get('email'),
            'phone': candidate_data.get('phone'),
            'dateOfBirth': candidate_data.get('dob'),
            'ssn': candidate_data.get('ssn'),
            'address': {
                'street1': candidate_data.get('address_line1'),
                'city': candidate_data.get('city'),
                'state': candidate_data.get('state'),
                'postalCode': candidate_data.get('postal_code'),
                'country': candidate_data.get('country', 'US'),
            },
        }

        response = self.make_request('POST', 'candidates', data=sterling_candidate)

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to create candidate: {response.text}")

        data = response.json()
        return {
            'id': data.get('candidateId'),
            'email': data.get('email'),
            'created_at': data.get('createdAt'),
        }

    def create_invitation(self, candidate_id: str, package: str) -> Dict:
        """Create background check screening order."""
        order_data = {
            'candidateId': candidate_id,
            'packageId': package,
            'invitationType': 'EMAIL',
        }

        response = self.make_request('POST', 'screenings', data=order_data)

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to create screening: {response.text}")

        data = response.json()
        return {
            'id': data.get('screeningId'),
            'status': data.get('status'),
            'order_number': data.get('orderNumber'),
            'invitation_url': data.get('invitationUrl'),
        }

    def get_report(self, report_id: str) -> Dict:
        """Get Sterling background check report."""
        response = self.make_request('GET', f'screenings/{report_id}')

        if response.status_code != 200:
            raise IntegrationError(f"Failed to get report: {response.status_code}")

        data = response.json()
        return self._normalize_report(data)

    def get_report_status(self, report_id: str) -> Dict:
        """Get status of Sterling background check."""
        response = self.make_request('GET', f'screenings/{report_id}/status')

        if response.status_code != 200:
            raise IntegrationError(f"Failed to get status: {response.status_code}")

        data = response.json()
        return {
            'id': report_id,
            'status': data.get('status'),
            'result': data.get('result'),
            'completed_at': data.get('completedAt'),
        }

    def _normalize_report(self, sterling_report: Dict) -> Dict:
        """Convert Sterling report to normalized format."""
        return {
            'id': sterling_report.get('screeningId'),
            'status': sterling_report.get('status'),
            'result': sterling_report.get('result'),
            'candidate_id': sterling_report.get('candidateId'),
            'order_number': sterling_report.get('orderNumber'),
            'created_at': sterling_report.get('createdAt'),
            'completed_at': sterling_report.get('completedAt'),
            'components': sterling_report.get('components', []),
            'documents': sterling_report.get('documents', []),
        }

    def handle_webhook(self, event_type: str, payload: Dict) -> Dict[str, Any]:
        """Handle Sterling webhook events."""
        logger.info(f"Processing Sterling webhook: {event_type}")

        if event_type == 'screening.completed':
            screening_id = payload.get('screeningId')
            return {
                'action': 'screening_completed',
                'screening_id': screening_id,
                'status': payload.get('status'),
                'result': payload.get('result'),
            }

        elif event_type == 'screening.updated':
            return {
                'action': 'screening_updated',
                'screening_id': payload.get('screeningId'),
                'status': payload.get('status'),
            }

        return {'action': 'unhandled', 'event_type': event_type}
