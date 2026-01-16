"""
Webhook Handlers

Handles incoming webhooks from third-party services.
Includes signature verification, deduplication, and async processing.
"""

import json
import hmac
import hashlib
import logging
from typing import Dict, Any, Optional

from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .models import (
    Integration,
    WebhookEndpoint,
    WebhookDelivery,
    IntegrationEvent,
)

logger = logging.getLogger(__name__)


class WebhookValidator:
    """
    Validates webhook signatures from various providers.

    Supports multiple signature schemes:
    - HMAC-SHA256 (default)
    - HMAC-SHA1
    - Custom header-based validation
    """

    def __init__(self, endpoint: WebhookEndpoint):
        self.endpoint = endpoint
        self.secret_key = endpoint.secret_key

    def validate_signature(self, payload: bytes, headers: Dict[str, str]) -> bool:
        """
        Validate webhook signature against the payload.

        Args:
            payload: Raw request body bytes
            headers: Request headers dict

        Returns:
            True if signature is valid, False otherwise
        """
        if not self.secret_key:
            return True  # No secret configured, skip validation

        # Try common signature header names
        signature_headers = [
            'X-Hub-Signature-256',  # GitHub
            'X-Signature-256',
            'X-Webhook-Signature',
            'Stripe-Signature',
            'X-Slack-Signature',
            'X-Twilio-Signature',
        ]

        signature = None
        for header in signature_headers:
            if header in headers:
                signature = headers[header]
                break

        if not signature:
            # Check case-insensitive
            headers_lower = {k.lower(): v for k, v in headers.items()}
            for header in signature_headers:
                if header.lower() in headers_lower:
                    signature = headers_lower[header.lower()]
                    break

        if not signature:
            logger.warning(f"No signature header found for endpoint {self.endpoint.id}")
            return False

        # Calculate expected signature
        expected = self._calculate_signature(payload)

        # Handle different signature formats
        if signature.startswith('sha256='):
            signature = signature[7:]
        elif signature.startswith('sha1='):
            signature = signature[5:]

        return hmac.compare_digest(signature, expected)

    def _calculate_signature(self, payload: bytes) -> str:
        """Calculate HMAC-SHA256 signature."""
        secret = self.secret_key.encode('utf-8') if isinstance(self.secret_key, str) else self.secret_key
        return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def get_client_ip(request) -> str:
    """Extract client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


@method_decorator(csrf_exempt, name='dispatch')
class IncomingWebhookView(View):
    """
    Handle incoming webhooks from third-party services.

    URL: /api/integrations/webhooks/<provider>/<endpoint_key>/

    Supports:
    - Signature verification
    - Event deduplication
    - Async processing
    """

    def post(self, request, provider: str, endpoint_key: str):
        """Process incoming webhook POST request."""
        try:
            # Find webhook endpoint
            endpoint = WebhookEndpoint.objects.select_related('integration').get(
                endpoint_path__endswith=endpoint_key,
                integration__provider=provider,
                is_enabled=True,
            )
        except WebhookEndpoint.DoesNotExist:
            logger.warning(f"Webhook endpoint not found: {provider}/{endpoint_key}")
            return JsonResponse(
                {'error': 'Endpoint not found'},
                status=404
            )

        # Check if integration is active
        if endpoint.integration.status != 'active':
            logger.warning(f"Integration not active for webhook: {endpoint.integration.name}")
            return JsonResponse(
                {'error': 'Integration not active'},
                status=503
            )

        # Parse payload
        try:
            if request.content_type == 'application/json':
                payload = json.loads(request.body)
            else:
                payload = dict(request.POST)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        # Get event type
        event_type = self._extract_event_type(provider, request, payload)

        # Get event ID for deduplication
        event_id = self._extract_event_id(provider, request, payload)

        # Get signature
        signature = self._extract_signature(provider, request, endpoint)

        # Create delivery record
        delivery = WebhookDelivery.objects.create(
            endpoint=endpoint,
            event_type=event_type,
            event_id=event_id,
            headers=dict(request.headers),
            payload=payload,
            signature_received=signature,
            source_ip=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )

        # Check for duplicates
        if delivery.is_duplicate():
            logger.info(f"Duplicate webhook event: {event_id}")
            delivery.status = 'delivered'
            delivery.status_message = 'Duplicate event - already processed'
            delivery.processed_at = timezone.now()
            delivery.save()
            return JsonResponse({'status': 'duplicate'}, status=200)

        # Verify signature
        signature_valid = self._verify_signature(
            provider,
            request.body,
            signature,
            endpoint,
            request
        )
        delivery.signature_valid = signature_valid

        if not signature_valid:
            logger.warning(f"Invalid webhook signature for {provider}")
            delivery.status = 'failed'
            delivery.status_message = 'Invalid signature'
            delivery.save()
            return JsonResponse({'error': 'Invalid signature'}, status=401)

        # Check event subscription filter
        if endpoint.subscribed_events and event_type not in endpoint.subscribed_events:
            logger.info(f"Ignoring unsubscribed event: {event_type}")
            delivery.status = 'delivered'
            delivery.status_message = f'Event type {event_type} not subscribed'
            delivery.processed_at = timezone.now()
            delivery.save()
            return JsonResponse({'status': 'ignored'}, status=200)

        # Process webhook (sync for now, can be made async)
        try:
            result = process_webhook_delivery(delivery)
            return JsonResponse({'status': 'processed', 'result': result}, status=200)
        except Exception as e:
            logger.error(f"Webhook processing failed: {e}")
            delivery.mark_failed(str(e), schedule_retry=True)
            return JsonResponse({'status': 'queued_for_retry'}, status=202)

    def get(self, request, provider: str, endpoint_key: str):
        """
        Handle GET requests for webhook verification challenges.
        Some providers (like Slack) send GET requests for URL verification.
        """
        # Handle Slack URL verification
        if provider == 'slack':
            challenge = request.GET.get('challenge')
            if challenge:
                return HttpResponse(challenge, content_type='text/plain')

        # Handle Facebook/Meta webhook verification
        if provider in ['facebook', 'instagram']:
            verify_token = request.GET.get('hub.verify_token')
            challenge = request.GET.get('hub.challenge')

            try:
                endpoint = WebhookEndpoint.objects.get(
                    endpoint_path__endswith=endpoint_key,
                    integration__provider=provider,
                )
                if verify_token == endpoint.secret_key:
                    return HttpResponse(challenge, content_type='text/plain')
            except WebhookEndpoint.DoesNotExist:
                pass

            return HttpResponse('Verification failed', status=403)

        return HttpResponse('OK', status=200)

    def _extract_event_type(self, provider: str, request, payload: Dict) -> str:
        """Extract event type from webhook based on provider."""
        if provider == 'slack':
            # Slack sends type in different places
            if payload.get('type') == 'event_callback':
                return payload.get('event', {}).get('type', 'unknown')
            return payload.get('type', 'unknown')

        elif provider == 'zoom':
            return payload.get('event', 'unknown')

        elif provider == 'docusign':
            return request.headers.get('X-DocuSign-WebhookEvent', 'unknown')

        elif provider == 'hellosign':
            return payload.get('event', {}).get('event_type', 'unknown')

        elif provider in ['checkr', 'sterling']:
            return payload.get('type', payload.get('event', 'unknown'))

        elif provider == 'bamboohr':
            return request.headers.get('X-BambooHR-Webhook-Type', 'unknown')

        elif provider in ['google_calendar', 'outlook_calendar']:
            return payload.get('type', 'notification')

        elif provider == 'stripe':
            return payload.get('type', 'unknown')

        # Default: try common patterns
        return (
            payload.get('event_type') or
            payload.get('event') or
            payload.get('type') or
            payload.get('action') or
            'unknown'
        )

    def _extract_event_id(self, provider: str, request, payload: Dict) -> str:
        """Extract event ID for deduplication."""
        if provider == 'slack':
            return payload.get('event_id', '')

        elif provider == 'zoom':
            return payload.get('payload', {}).get('object', {}).get('uuid', '')

        elif provider == 'docusign':
            return request.headers.get('X-DocuSign-Connect-Envelope-ID', '')

        elif provider == 'hellosign':
            return payload.get('event', {}).get('event_hash', '')

        elif provider == 'stripe':
            return payload.get('id', '')

        # Default patterns
        return (
            payload.get('event_id') or
            payload.get('id') or
            payload.get('uuid') or
            ''
        )

    def _extract_signature(self, provider: str, request, endpoint: WebhookEndpoint) -> str:
        """Extract signature from request headers."""
        if provider == 'slack':
            return request.headers.get('X-Slack-Signature', '')

        elif provider == 'zoom':
            return request.headers.get('x-zm-signature', '')

        elif provider == 'docusign':
            return request.headers.get('X-DocuSign-Signature-1', '')

        elif provider == 'hellosign':
            return ''  # HelloSign uses hash in payload

        elif provider == 'stripe':
            return request.headers.get('Stripe-Signature', '')

        elif provider == 'github':
            return request.headers.get('X-Hub-Signature-256', '')

        # Use configured header
        return request.headers.get(endpoint.signature_header, '')

    def _verify_signature(
        self,
        provider: str,
        payload: bytes,
        signature: str,
        endpoint: WebhookEndpoint,
        request
    ) -> bool:
        """Verify webhook signature based on provider."""
        import hmac
        import hashlib

        secret = endpoint.secret_key

        if provider == 'slack':
            # Slack uses timestamp + body
            timestamp = request.headers.get('X-Slack-Request-Timestamp', '')
            sig_basestring = f"v0:{timestamp}:{payload.decode()}"
            expected = 'v0=' + hmac.new(
                secret.encode(),
                sig_basestring.encode(),
                hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(expected, signature)

        elif provider == 'zoom':
            # Zoom signature verification
            timestamp = request.headers.get('x-zm-request-timestamp', '')
            message = f"v0:{timestamp}:{payload.decode()}"
            expected = 'v0=' + hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(expected, signature)

        elif provider == 'stripe':
            # Stripe signature verification
            import time
            parts = dict(p.split('=', 1) for p in signature.split(','))
            timestamp = parts.get('t', '')
            sig_v1 = parts.get('v1', '')

            signed_payload = f"{timestamp}.{payload.decode()}"
            expected = hmac.new(
                secret.encode(),
                signed_payload.encode(),
                hashlib.sha256
            ).hexdigest()

            # Also check timestamp is within tolerance
            if abs(int(timestamp) - int(time.time())) > 300:
                return False

            return hmac.compare_digest(expected, sig_v1)

        elif provider == 'github':
            # GitHub signature (sha256)
            if signature.startswith('sha256='):
                signature = signature[7:]
            expected = hmac.new(
                secret.encode(),
                payload,
                hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(expected, signature)

        elif provider == 'hellosign':
            # HelloSign uses event_hash in payload for verification
            # The secret is used to compute the hash
            return True  # Simplified - implement full verification

        else:
            # Generic HMAC verification
            return endpoint.verify_signature(payload, signature, secret)


def process_webhook_delivery(delivery: WebhookDelivery) -> Dict[str, Any]:
    """
    Process a webhook delivery by dispatching to the appropriate handler.

    Args:
        delivery: WebhookDelivery instance to process

    Returns:
        Processing result dictionary
    """
    from .views import get_provider_class

    delivery.mark_processing()

    integration = delivery.endpoint.integration
    provider_class = get_provider_class(integration.provider)

    if not provider_class:
        result = {'status': 'error', 'message': f'Provider not supported: {integration.provider}'}
        delivery.mark_failed(result['message'])
        return result

    try:
        provider = provider_class(integration)
        result = provider.handle_webhook(delivery.event_type, delivery.payload)

        # Handle the result based on action
        action = result.get('action', 'unknown')

        # Log event
        IntegrationEvent.objects.create(
            integration=integration,
            event_type='webhook_received',
            message=f"Processed webhook: {delivery.event_type}",
            details={
                'event_type': delivery.event_type,
                'action': action,
                'delivery_id': str(delivery.uuid),
            }
        )

        # Call domain-specific handlers
        _dispatch_webhook_action(integration, action, result, delivery)

        delivery.mark_delivered(result)
        return result

    except Exception as e:
        logger.error(f"Webhook processing error: {e}")
        delivery.mark_failed(str(e), schedule_retry=True)
        raise


def _dispatch_webhook_action(integration, action: str, result: Dict, delivery: WebhookDelivery):
    """
    Dispatch webhook action to domain-specific handlers.
    This is where you connect webhooks to your business logic.
    """
    provider = integration.provider

    # Background check completion handlers
    if provider in ['checkr', 'sterling'] and action in ['report_completed', 'screening_completed']:
        _handle_background_check_complete(integration, result)

    # E-signature handlers
    elif provider in ['docusign', 'hellosign'] and 'envelope' in action:
        _handle_esign_event(integration, result)

    # Calendar event handlers
    elif provider in ['google_calendar', 'outlook_calendar']:
        _handle_calendar_event(integration, result)

    # HRIS handlers
    elif provider in ['bamboohr', 'workday']:
        _handle_hris_event(integration, result)

    # Slack interaction handlers
    elif provider == 'slack' and action == 'challenge':
        # URL verification - already handled
        pass


def _handle_background_check_complete(integration, result: Dict):
    """
    Handle background check completion event from Checkr/Sterling.

    Called when a background check report completes.
    Extracts report ID from webhook payload and updates BackgroundCheck record.

    Args:
        integration: Integration instance (Checkr/Sterling)
        result: Parsed webhook result containing report data
    """
    from ats.background_checks import BackgroundCheckService
    from ats.models import BackgroundCheck

    logger.info(f"Processing background check completion webhook from {integration.provider}")

    try:
        # Extract report ID from result
        # Checkr sends: result['data']['object']['id']
        # Sterling sends: result['screening']['id']
        payload = result.get('payload', result)

        if integration.provider == 'checkr':
            report_id = payload.get('data', {}).get('object', {}).get('id')
        elif integration.provider == 'sterling':
            report_id = payload.get('screening', {}).get('id')
        else:
            report_id = payload.get('report_id') or payload.get('id')

        if not report_id:
            logger.error(f"No report ID found in background check webhook payload: {payload}")
            return

        # Find background check by external report ID
        try:
            background_check = BackgroundCheck.objects.get(external_report_id=report_id)
        except BackgroundCheck.DoesNotExist:
            logger.error(f"Background check not found for report_id={report_id}")
            return

        # Call BackgroundCheckService to process the webhook
        service = BackgroundCheckService(tenant=background_check.tenant)
        service.handle_webhook_result(
            report_id=report_id,
            payload=payload,
            provider_name=integration.provider
        )

        logger.info(
            f"Background check webhook processed successfully: "
            f"check_id={background_check.id}, report_id={report_id}, "
            f"result={background_check.result}"
        )

    except Exception as e:
        logger.error(f"Error handling background check webhook: {e}", exc_info=True)
        raise  # Re-raise to trigger retry


def _handle_esign_event(integration, result: Dict):
    """Handle e-signature event."""
    logger.info(f"E-signature event: {result}")

    # Example: Update document status
    # envelope_id = result.get('envelope_id')
    # status = result.get('status')
    #
    # from documents.models import SignatureRequest
    # try:
    #     sig_request = SignatureRequest.objects.get(external_id=envelope_id)
    #     sig_request.status = status
    #     if status == 'completed':
    #         sig_request.completed_at = timezone.now()
    #     sig_request.save()
    # except SignatureRequest.DoesNotExist:
    #     pass


def _handle_calendar_event(integration, result: Dict):
    """Handle calendar event notification."""
    logger.info(f"Calendar event: {result}")

    # Example: Sync interview updates
    # This would typically trigger a sync to pull latest calendar data


def _handle_hris_event(integration, result: Dict):
    """Handle HRIS event."""
    logger.info(f"HRIS event: {result}")

    # Example: Sync employee changes
    # employee_id = result.get('employee_id') or result.get('worker_id')
    # action = result.get('action')
    #
    # if action in ['created', 'updated']:
    #     # Trigger employee sync
    #     from .tasks import run_integration_sync
    #     run_integration_sync.delay(integration.uuid.hex)


# Webhook verification helpers for specific providers

def verify_slack_request(request, signing_secret: str) -> bool:
    """Verify Slack request signature."""
    import hmac
    import hashlib
    import time

    timestamp = request.headers.get('X-Slack-Request-Timestamp', '')
    signature = request.headers.get('X-Slack-Signature', '')

    # Check timestamp is within 5 minutes
    if abs(int(time.time()) - int(timestamp)) > 300:
        return False

    sig_basestring = f"v0:{timestamp}:{request.body.decode()}"
    expected = 'v0=' + hmac.new(
        signing_secret.encode(),
        sig_basestring.encode(),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


def verify_stripe_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify Stripe webhook signature."""
    import hmac
    import hashlib
    import time

    parts = dict(p.split('=', 1) for p in signature.split(','))
    timestamp = parts.get('t', '')
    sig_v1 = parts.get('v1', '')

    # Check timestamp
    if abs(int(timestamp) - int(time.time())) > 300:
        return False

    signed_payload = f"{timestamp}.{payload.decode()}"
    expected = hmac.new(
        secret.encode(),
        signed_payload.encode(),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, sig_v1)
