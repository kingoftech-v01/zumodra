"""
Tests for webhook security fixes.

Tests the critical security and idempotency fixes made to the webhook system:
1. Signature verification rejects missing secret keys
2. Event ID extraction with fallback hash generation
3. Unique constraint prevents duplicate processing
4. Provider-specific signature validation
"""

import json
import hashlib
import hmac
import time
import pytest
from datetime import timedelta
from unittest.mock import Mock, patch, MagicMock

from django.utils import timezone
from django.test import TestCase, RequestFactory
from django.http import JsonResponse

from integrations.models import (
    Integration, WebhookEndpoint, WebhookDelivery, IntegrationEvent
)
from integrations.webhooks import (
    WebhookValidator, IncomingWebhookView, process_webhook_delivery
)
from tenants.models import Tenant


@pytest.mark.security
class TestWebhookSignatureVerification(TestCase):
    """Test webhook signature verification."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.tenant = Tenant.objects.create(
            name='Test Tenant',
            slug='test-tenant',
            schema_name='test_tenant'
        )
        self.integration = Integration.objects.create(
            tenant=self.tenant,
            provider='stripe',
            name='Stripe Integration',
            integration_type='payment',
            status='active'
        )
        self.endpoint = WebhookEndpoint.objects.create(
            integration=self.integration,
            name='Stripe Webhook',
            secret_key='test_secret_key_12345'
        )

    def test_missing_secret_key_rejects_webhook(self):
        """Signature validation should reject webhooks when secret key is missing."""
        # Create endpoint without secret key
        endpoint_no_secret = WebhookEndpoint.objects.create(
            integration=self.integration,
            name='No Secret Webhook',
            secret_key=''
        )

        validator = WebhookValidator(endpoint_no_secret)
        payload = b'test payload'
        headers = {'X-Webhook-Signature': 'any_signature'}

        # Should reject, not accept
        result = validator.validate_signature(payload, headers)
        self.assertFalse(result, "Should reject webhook without secret key")

    def test_valid_stripe_signature_accepted(self):
        """Valid Stripe signatures should be accepted."""
        payload = b'{"type":"charge.completed"}'
        timestamp = str(int(time.time()))

        # Generate valid Stripe signature
        signed_content = f"{timestamp}.{payload.decode()}"
        expected_sig = hmac.new(
            self.endpoint.secret_key.encode(),
            signed_content.encode(),
            hashlib.sha256
        ).hexdigest()

        headers = {'Stripe-Signature': f't={timestamp},v1={expected_sig}'}

        request = self.factory.post(
            '/webhook/',
            data=payload,
            content_type='application/json'
        )
        request.headers = headers
        request.body = payload

        validator = WebhookValidator(self.endpoint)
        # Note: Need to check _verify_signature directly for Stripe logic
        result = validator._verify_signature(
            'stripe', payload, f't={timestamp},v1={expected_sig}',
            self.endpoint, request
        )
        self.assertTrue(result, "Valid Stripe signature should be accepted")

    def test_invalid_stripe_signature_rejected(self):
        """Invalid Stripe signatures should be rejected."""
        payload = b'{"type":"charge.completed"}'
        timestamp = str(int(time.time()))

        # Use wrong signature
        headers = {'Stripe-Signature': f't={timestamp},v1=invalid_signature'}

        request = self.factory.post(
            '/webhook/',
            data=payload,
            content_type='application/json'
        )
        request.headers = headers
        request.body = payload

        validator = WebhookValidator(self.endpoint)
        result = validator._verify_signature(
            'stripe', payload, f't={timestamp},v1=invalid_signature',
            self.endpoint, request
        )
        self.assertFalse(result, "Invalid signature should be rejected")

    def test_stripe_signature_timestamp_validation(self):
        """Stripe signatures with old timestamps should be rejected."""
        payload = b'{"type":"charge.completed"}'
        # Timestamp 6 minutes old (> 300 seconds)
        old_timestamp = str(int(time.time()) - 400)

        # Generate signature for old timestamp
        signed_content = f"{old_timestamp}.{payload.decode()}"
        sig = hmac.new(
            self.endpoint.secret_key.encode(),
            signed_content.encode(),
            hashlib.sha256
        ).hexdigest()

        request = self.factory.post('/webhook/', data=payload)
        request.body = payload
        request.headers = {}

        validator = WebhookValidator(self.endpoint)
        result = validator._verify_signature(
            'stripe', payload, f't={old_timestamp},v1={sig}',
            self.endpoint, request
        )
        self.assertFalse(result, "Old timestamp should be rejected")


@pytest.mark.security
class TestEventIdExtraction(TestCase):
    """Test event ID extraction and fallback mechanisms."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.tenant = Tenant.objects.create(
            name='Test Tenant',
            slug='test-tenant',
            schema_name='test_tenant'
        )
        self.integration = Integration.objects.create(
            tenant=self.tenant,
            provider='slack',
            name='Slack Integration',
            integration_type='messaging',
            status='active'
        )
        self.endpoint = WebhookEndpoint.objects.create(
            integration=self.integration,
            name='Slack Webhook',
            secret_key='test_secret'
        )

    def test_slack_event_id_extraction(self):
        """Slack event IDs should be extracted correctly."""
        view = IncomingWebhookView()
        payload = {
            'event_id': 'Ev123456',
            'type': 'event_callback',
            'event': {'type': 'message'}
        }
        request = self.factory.post('/webhook/')

        event_id = view._extract_event_id('slack', request, payload)
        self.assertEqual(event_id, 'Ev123456', "Should extract Slack event_id")

    def test_missing_event_id_generates_hash(self):
        """Missing native event_id should generate deterministic hash."""
        view = IncomingWebhookView()
        payload = {
            'data': 'some_data',
            'type': 'unknown'
        }
        request = self.factory.post('/webhook/')

        event_id = view._extract_event_id('custom_provider', request, payload)

        # Should be hash-based
        self.assertTrue(
            event_id.startswith('hash_'),
            "Should generate hash-based event_id when native ID missing"
        )
        self.assertEqual(
            len(event_id), 21,  # 'hash_' + 16 hex chars
            "Hash event_id should be consistent length"
        )

    def test_event_id_hash_is_deterministic(self):
        """Event ID hash should be deterministic for same payload."""
        view = IncomingWebhookView()
        payload = {'data': 'test_data', 'type': 'test'}
        request = self.factory.post('/webhook/')

        event_id_1 = view._extract_event_id('custom', request, payload)
        event_id_2 = view._extract_event_id('custom', request, payload)

        self.assertEqual(
            event_id_1, event_id_2,
            "Hash should be deterministic for same payload"
        )


@pytest.mark.integration
class TestDuplicateEventHandling(TestCase):
    """Test duplicate event detection and prevention."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.tenant = Tenant.objects.create(
            name='Test Tenant',
            slug='test-tenant',
            schema_name='test_tenant'
        )
        self.integration = Integration.objects.create(
            tenant=self.tenant,
            provider='stripe',
            name='Stripe Integration',
            integration_type='payment',
            status='active'
        )
        self.endpoint = WebhookEndpoint.objects.create(
            integration=self.integration,
            name='Stripe Webhook',
            secret_key='test_secret'
        )

    def test_duplicate_delivery_detection(self):
        """Duplicate events should be detected."""
        payload_data = {'id': 'evt_12345', 'type': 'charge.completed'}

        # Create first delivery
        delivery_1 = WebhookDelivery.objects.create(
            endpoint=self.endpoint,
            event_type='charge.completed',
            event_id='evt_12345',
            payload=payload_data,
            status='delivered'
        )

        # Create second with same event_id
        delivery_2 = WebhookDelivery(
            endpoint=self.endpoint,
            event_type='charge.completed',
            event_id='evt_12345',
            payload=payload_data,
            status='pending'
        )

        # Should be detected as duplicate
        is_dup = delivery_2.is_duplicate()
        self.assertTrue(is_dup, "Should detect duplicate event_id")

    def test_unique_constraint_prevents_race_condition(self):
        """Database unique constraint should prevent race condition duplicates."""
        # Create first delivery
        delivery_1 = WebhookDelivery.objects.create(
            endpoint=self.endpoint,
            event_type='charge.completed',
            event_id='evt_12345',
            payload={'id': 'evt_12345'},
            status='delivered'
        )

        # Try to create duplicate - should fail at database level
        delivery_2 = WebhookDelivery(
            endpoint=self.endpoint,
            event_type='charge.completed',
            event_id='evt_12345',
            payload={'id': 'evt_12345'},
            status='pending'
        )

        from django.db import IntegrityError
        with self.assertRaises(IntegrityError):
            delivery_2.save()

    def test_empty_event_id_not_constrained(self):
        """Empty event_id should not trigger unique constraint."""
        # Multiple deliveries can have empty event_id
        delivery_1 = WebhookDelivery.objects.create(
            endpoint=self.endpoint,
            event_type='unknown',
            event_id='',
            payload={}
        )

        delivery_2 = WebhookDelivery.objects.create(
            endpoint=self.endpoint,
            event_type='unknown',
            event_id='',
            payload={}
        )

        # Both should exist
        self.assertEqual(
            WebhookDelivery.objects.filter(endpoint=self.endpoint, event_id='').count(),
            2,
            "Multiple empty event_id allowed"
        )


@pytest.mark.security
class TestProviderSpecificVerification(TestCase):
    """Test provider-specific signature verification."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.tenant = Tenant.objects.create(
            name='Test Tenant',
            slug='test-tenant',
            schema_name='test_tenant'
        )

    def test_hellosign_verification_implemented(self):
        """HelloSign verification should actually validate signatures."""
        integration = Integration.objects.create(
            tenant=self.tenant,
            provider='hellosign',
            name='HelloSign',
            integration_type='esign',
            status='active'
        )
        endpoint = WebhookEndpoint.objects.create(
            integration=integration,
            name='HelloSign Webhook',
            secret_key='test_secret_key'
        )

        view = IncomingWebhookView()

        # Create valid HelloSign-like payload
        event_data = {
            'event_hash': '',
            'type': 'signature_request_signed',
            'signature_request_id': 'test_123'
        }

        # Generate correct hash
        import json
        signed_payload = json.dumps(event_data, separators=(',', ':'), sort_keys=False)
        correct_hash = hmac.new(
            endpoint.secret_key.encode(),
            signed_payload.encode(),
            hashlib.sha256
        ).hexdigest()

        event_data['event_hash'] = correct_hash
        payload = {'event': event_data}

        request = self.factory.post('/webhook/')
        request.body = json.dumps(payload).encode()

        validator = WebhookValidator(endpoint)
        result = validator._verify_signature(
            'hellosign',
            request.body,
            '',  # signature extracted from payload
            endpoint,
            request
        )

        # Should verify actual signature, not just return True
        self.assertTrue(result, "Valid HelloSign signature should be accepted")

    def test_hellosign_rejects_invalid_signature(self):
        """HelloSign should reject invalid signatures."""
        integration = Integration.objects.create(
            tenant=self.tenant,
            provider='hellosign',
            name='HelloSign',
            integration_type='esign',
            status='active'
        )
        endpoint = WebhookEndpoint.objects.create(
            integration=integration,
            name='HelloSign Webhook',
            secret_key='test_secret_key'
        )

        view = IncomingWebhookView()

        # Create payload with wrong hash
        event_data = {
            'event_hash': 'wrong_hash_value',
            'type': 'signature_request_signed',
            'signature_request_id': 'test_123'
        }

        payload = {'event': event_data}

        request = self.factory.post('/webhook/')
        request.body = json.dumps(payload).encode()

        validator = WebhookValidator(endpoint)
        result = validator._verify_signature(
            'hellosign',
            request.body,
            '',
            endpoint,
            request
        )

        # Should reject invalid signature, not accept blindly
        self.assertFalse(result, "Invalid HelloSign signature should be rejected")


@pytest.mark.integration
class TestWebhookSignalErrorHandling(TestCase):
    """Test webhook signal error handling improvements."""

    def setUp(self):
        """Set up test fixtures."""
        self.tenant = Tenant.objects.create(
            name='Test Tenant',
            slug='test-tenant',
            schema_name='test_tenant'
        )

    def test_import_error_logged_as_debug(self):
        """ImportError during setup should be debug-level, not warning."""
        from integrations.webhook_signals import dispatch_webhook_for_model

        # Mock instance
        instance = Mock()
        instance.pk = 1
        instance.tenant_id = self.tenant.id

        # Mock dispatch to raise ImportError
        with patch('integrations.webhook_signals.dispatch_webhook') as mock_dispatch:
            mock_dispatch.side_effect = ImportError("OutboundWebhook table not exists")

            with patch('integrations.webhook_signals.logger') as mock_logger:
                dispatch_webhook_for_model(instance, 'jobs', 'job.created')

                # Should use debug logging, not warning
                mock_logger.debug.assert_called_once()
                mock_logger.warning.assert_not_called()

    def test_real_error_logged_as_error(self):
        """Real runtime errors should be logged as errors."""
        from integrations.webhook_signals import dispatch_webhook_for_model

        instance = Mock()
        instance.pk = 1
        instance.tenant_id = self.tenant.id

        # Mock dispatch to raise real error
        with patch('integrations.webhook_signals.dispatch_webhook') as mock_dispatch:
            mock_dispatch.side_effect = RuntimeError("Database connection lost")

            with patch('integrations.webhook_signals.logger') as mock_logger:
                dispatch_webhook_for_model(instance, 'jobs', 'job.created')

                # Should use error logging
                mock_logger.error.assert_called_once()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
