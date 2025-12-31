"""
E-Signature Integration Providers

Implements e-signature integrations for:
- DocuSign
- HelloSign (Dropbox Sign)
"""

import logging
import base64
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

from .base import (
    ESignProvider,
    IntegrationError,
    AuthenticationError,
    ConfigurationError,
)

logger = logging.getLogger(__name__)


class DocuSignProvider(ESignProvider):
    """
    DocuSign e-signature integration provider.
    Uses DocuSign eSignature REST API v2.1.
    """

    provider_name = 'docusign'
    display_name = 'DocuSign'

    # API configuration - use demo for sandbox, www for production
    api_base_url = 'https://demo.docusign.net/restapi/v2.1'

    # OAuth configuration
    oauth_authorize_url = 'https://account-d.docusign.com/oauth/auth'
    oauth_token_url = 'https://account-d.docusign.com/oauth/token'
    oauth_scopes = ['signature', 'extended']

    def get_oauth_config(self) -> Dict[str, str]:
        """Get DocuSign OAuth configuration."""
        from django.conf import settings
        return {
            'client_id': getattr(settings, 'DOCUSIGN_CLIENT_ID', ''),
            'client_secret': getattr(settings, 'DOCUSIGN_CLIENT_SECRET', ''),
            'redirect_uri': getattr(settings, 'DOCUSIGN_REDIRECT_URI', ''),
        }

    def get_headers(self) -> Dict[str, str]:
        """Get headers for DocuSign API requests."""
        creds = self.get_credentials()
        return {
            'Authorization': f"Bearer {creds.get('access_token')}",
            'Content-Type': 'application/json',
        }

    @property
    def account_id(self) -> str:
        """Get DocuSign account ID from credentials."""
        if self.integration and hasattr(self.integration, 'credentials'):
            return self.integration.credentials.external_account_id
        return ''

    def test_connection(self) -> Tuple[bool, str]:
        """Test DocuSign API connection."""
        try:
            response = self.make_request('GET', f'accounts/{self.account_id}')
            if response.status_code == 200:
                return True, "Successfully connected to DocuSign"
            return False, f"Connection failed: {response.status_code}"
        except AuthenticationError as e:
            return False, f"Authentication failed: {str(e)}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get DocuSign account information."""
        # First get user info to get account ID if not stored
        user_response = self.make_request(
            'GET',
            'https://account-d.docusign.com/oauth/userinfo',
        )

        if user_response.status_code != 200:
            raise IntegrationError("Failed to fetch user info")

        user_data = user_response.json()
        accounts = user_data.get('accounts', [])
        default_account = next(
            (acc for acc in accounts if acc.get('is_default')),
            accounts[0] if accounts else {}
        )

        return {
            'user_id': user_data.get('sub'),
            'name': user_data.get('name'),
            'email': user_data.get('email'),
            'account_id': default_account.get('account_id'),
            'account_name': default_account.get('account_name'),
            'base_uri': default_account.get('base_uri'),
        }

    def create_envelope(self, document_data: Dict, signers: List[Dict]) -> Dict:
        """
        Create a DocuSign envelope for signing.

        Args:
            document_data: Document data with:
                - name: Document name
                - content: Base64 encoded document content
                - file_extension: File extension (pdf, docx, etc.)
            signers: List of signer dicts with:
                - email: Signer email
                - name: Signer name
                - routing_order: Signing order (1, 2, etc.)
                - tabs: Optional signature/initial tab positions

        Returns:
            Dict with envelope ID and status
        """
        # Build documents array
        documents = [{
            'documentBase64': document_data.get('content'),
            'name': document_data.get('name'),
            'fileExtension': document_data.get('file_extension', 'pdf'),
            'documentId': '1',
        }]

        # Build recipients
        recipients = {'signers': []}
        for i, signer in enumerate(signers, 1):
            signer_data = {
                'email': signer.get('email'),
                'name': signer.get('name'),
                'recipientId': str(i),
                'routingOrder': str(signer.get('routing_order', i)),
            }

            # Add tabs if specified
            if signer.get('tabs'):
                signer_data['tabs'] = signer['tabs']
            else:
                # Default signature tab
                signer_data['tabs'] = {
                    'signHereTabs': [{
                        'documentId': '1',
                        'pageNumber': '1',
                        'xPosition': '200',
                        'yPosition': '400',
                    }]
                }

            recipients['signers'].append(signer_data)

        envelope_data = {
            'emailSubject': document_data.get('subject', 'Please sign this document'),
            'emailBlurb': document_data.get('message', ''),
            'documents': documents,
            'recipients': recipients,
            'status': 'sent',  # 'created' for draft, 'sent' to send immediately
        }

        response = self.make_request(
            'POST',
            f'accounts/{self.account_id}/envelopes',
            data=envelope_data
        )

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to create envelope: {response.text}")

        data = response.json()
        return {
            'envelope_id': data.get('envelopeId'),
            'status': data.get('status'),
            'status_date': data.get('statusDateTime'),
            'uri': data.get('uri'),
        }

    def get_envelope_status(self, envelope_id: str) -> Dict:
        """Get envelope/document signing status."""
        response = self.make_request(
            'GET',
            f'accounts/{self.account_id}/envelopes/{envelope_id}'
        )

        if response.status_code != 200:
            raise IntegrationError(f"Failed to get envelope: {response.status_code}")

        data = response.json()
        return self._normalize_envelope(data)

    def download_document(self, envelope_id: str, document_id: str = 'combined') -> bytes:
        """
        Download signed document.

        Args:
            envelope_id: Envelope ID
            document_id: Document ID or 'combined' for all documents

        Returns:
            Document bytes
        """
        response = self.make_request(
            'GET',
            f'accounts/{self.account_id}/envelopes/{envelope_id}/documents/{document_id}'
        )

        if response.status_code != 200:
            raise IntegrationError(f"Failed to download document: {response.status_code}")

        return response.content

    def void_envelope(self, envelope_id: str, reason: str) -> bool:
        """Void/cancel an envelope."""
        response = self.make_request(
            'PUT',
            f'accounts/{self.account_id}/envelopes/{envelope_id}',
            data={
                'status': 'voided',
                'voidedReason': reason,
            }
        )

        return response.status_code == 200

    def get_signing_url(self, envelope_id: str, signer_email: str, signer_name: str, return_url: str) -> str:
        """
        Get embedded signing URL for a signer.

        Args:
            envelope_id: Envelope ID
            signer_email: Signer's email
            signer_name: Signer's name
            return_url: URL to redirect after signing

        Returns:
            Signing URL string
        """
        recipient_view_data = {
            'authenticationMethod': 'email',
            'email': signer_email,
            'userName': signer_name,
            'returnUrl': return_url,
        }

        response = self.make_request(
            'POST',
            f'accounts/{self.account_id}/envelopes/{envelope_id}/views/recipient',
            data=recipient_view_data
        )

        if response.status_code != 201:
            raise IntegrationError(f"Failed to get signing URL: {response.text}")

        return response.json().get('url')

    def _normalize_envelope(self, docusign_envelope: Dict) -> Dict:
        """Convert DocuSign envelope to normalized format."""
        return {
            'id': docusign_envelope.get('envelopeId'),
            'status': docusign_envelope.get('status'),
            'email_subject': docusign_envelope.get('emailSubject'),
            'created_at': docusign_envelope.get('createdDateTime'),
            'sent_at': docusign_envelope.get('sentDateTime'),
            'completed_at': docusign_envelope.get('completedDateTime'),
            'voided_at': docusign_envelope.get('voidedDateTime'),
            'voided_reason': docusign_envelope.get('voidedReason'),
            'expiry_date': docusign_envelope.get('expireDateTime'),
        }

    def handle_webhook(self, event_type: str, payload: Dict) -> Dict[str, Any]:
        """Handle DocuSign Connect webhook events."""
        logger.info(f"Processing DocuSign webhook: {event_type}")

        envelope_status = payload.get('envelopeStatus', {})

        return {
            'action': event_type,
            'envelope_id': envelope_status.get('envelopeId'),
            'status': envelope_status.get('status'),
            'time_generated': payload.get('timeGenerated'),
            'recipients': envelope_status.get('recipientStatuses', []),
        }


class HelloSignProvider(ESignProvider):
    """
    HelloSign (Dropbox Sign) e-signature integration provider.
    Uses HelloSign API v3.
    """

    provider_name = 'hellosign'
    display_name = 'HelloSign'

    # API configuration
    api_base_url = 'https://api.hellosign.com/v3'

    # HelloSign uses API key authentication
    oauth_authorize_url = 'https://app.hellosign.com/oauth/authorize'
    oauth_token_url = 'https://app.hellosign.com/oauth/token'
    oauth_scopes = ['basic_account_info', 'signature_request_access']

    def get_headers(self) -> Dict[str, str]:
        """Get headers for HelloSign API requests."""
        creds = self.get_credentials()

        if creds.get('access_token'):
            return {
                'Authorization': f"Bearer {creds.get('access_token')}",
            }
        else:
            # API key auth
            import base64
            api_key = creds.get('api_key', '')
            auth = base64.b64encode(f"{api_key}:".encode()).decode()
            return {
                'Authorization': f"Basic {auth}",
            }

    def test_connection(self) -> Tuple[bool, str]:
        """Test HelloSign API connection."""
        try:
            response = self.make_request('GET', 'account')
            if response.status_code == 200:
                return True, "Successfully connected to HelloSign"
            return False, f"Connection failed: {response.status_code}"
        except AuthenticationError as e:
            return False, f"Authentication failed: {str(e)}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get HelloSign account information."""
        response = self.make_request('GET', 'account')
        if response.status_code != 200:
            raise IntegrationError("Failed to fetch account info")

        data = response.json().get('account', {})
        return {
            'account_id': data.get('account_id'),
            'email': data.get('email_address'),
            'is_paid': data.get('is_paid_hs'),
            'quota': data.get('quota', {}),
        }

    def create_envelope(self, document_data: Dict, signers: List[Dict]) -> Dict:
        """
        Create a HelloSign signature request.

        Args:
            document_data: Document data with name, content (base64), file_extension
            signers: List of signer dicts with email, name, routing_order

        Returns:
            Dict with signature request ID and details
        """
        # HelloSign uses multipart form data
        import io

        files = {
            'file[0]': (
                document_data.get('name', 'document.pdf'),
                base64.b64decode(document_data.get('content')),
                'application/pdf'
            )
        }

        form_data = {
            'title': document_data.get('name', 'Signature Request'),
            'subject': document_data.get('subject', 'Please sign this document'),
            'message': document_data.get('message', ''),
            'test_mode': '0' if not document_data.get('test_mode') else '1',
        }

        # Add signers
        for i, signer in enumerate(signers):
            form_data[f'signers[{i}][email_address]'] = signer.get('email')
            form_data[f'signers[{i}][name]'] = signer.get('name')
            form_data[f'signers[{i}][order]'] = str(signer.get('routing_order', i))

        # Make request with form data
        response = self.session.post(
            f'{self.api_base_url}/signature_request/send',
            data=form_data,
            files=files,
            headers={'Authorization': self.get_headers()['Authorization']},
            timeout=self.request_timeout
        )

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to create signature request: {response.text}")

        data = response.json().get('signature_request', {})
        return {
            'envelope_id': data.get('signature_request_id'),
            'status': 'sent' if data.get('has_error') is False else 'error',
            'signing_url': data.get('signing_url'),
            'details_url': data.get('details_url'),
        }

    def get_envelope_status(self, envelope_id: str) -> Dict:
        """Get signature request status."""
        response = self.make_request('GET', f'signature_request/{envelope_id}')

        if response.status_code != 200:
            raise IntegrationError(f"Failed to get signature request: {response.status_code}")

        data = response.json().get('signature_request', {})
        return self._normalize_signature_request(data)

    def download_document(self, envelope_id: str, document_id: str = None) -> bytes:
        """Download signed document."""
        response = self.make_request('GET', f'signature_request/files/{envelope_id}')

        if response.status_code != 200:
            raise IntegrationError(f"Failed to download document: {response.status_code}")

        return response.content

    def void_envelope(self, envelope_id: str, reason: str) -> bool:
        """Cancel a signature request."""
        response = self.make_request(
            'POST',
            f'signature_request/cancel/{envelope_id}'
        )

        return response.status_code in [200, 204]

    def get_signing_url(self, envelope_id: str, signature_id: str) -> str:
        """
        Get embedded signing URL.

        Args:
            envelope_id: Signature request ID
            signature_id: Individual signature ID for the signer

        Returns:
            Signing URL
        """
        response = self.make_request(
            'GET',
            f'embedded/sign_url/{signature_id}'
        )

        if response.status_code != 200:
            raise IntegrationError(f"Failed to get signing URL: {response.text}")

        return response.json().get('embedded', {}).get('sign_url')

    def _normalize_signature_request(self, hellosign_request: Dict) -> Dict:
        """Convert HelloSign request to normalized format."""
        return {
            'id': hellosign_request.get('signature_request_id'),
            'title': hellosign_request.get('title'),
            'status': self._map_status(hellosign_request),
            'is_complete': hellosign_request.get('is_complete'),
            'created_at': hellosign_request.get('created_at'),
            'signing_url': hellosign_request.get('signing_url'),
            'files_url': hellosign_request.get('files_url'),
            'signatures': [
                {
                    'signature_id': sig.get('signature_id'),
                    'signer_email': sig.get('signer_email_address'),
                    'signer_name': sig.get('signer_name'),
                    'status': sig.get('status_code'),
                    'signed_at': sig.get('signed_at'),
                }
                for sig in hellosign_request.get('signatures', [])
            ],
        }

    def _map_status(self, request: Dict) -> str:
        """Map HelloSign status to normalized status."""
        if request.get('is_complete'):
            return 'completed'
        if request.get('is_declined'):
            return 'declined'
        if request.get('has_error'):
            return 'error'
        return 'pending'

    def handle_webhook(self, event_type: str, payload: Dict) -> Dict[str, Any]:
        """Handle HelloSign webhook events."""
        logger.info(f"Processing HelloSign webhook: {event_type}")

        event = payload.get('event', {})
        signature_request = payload.get('signature_request', {})

        return {
            'action': event.get('event_type'),
            'envelope_id': signature_request.get('signature_request_id'),
            'event_time': event.get('event_time'),
            'event_hash': event.get('event_hash'),
        }
