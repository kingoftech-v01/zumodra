"""
Integration Tests - Outbound Webhooks

Comprehensive test suite for webhook dispatch, signature verification,
retry logic, and multi-tenant isolation.

Target: 80 test cases
"""

import pytest
import json
import hmac
import hashlib
import requests_mock
from datetime import timedelta
from django.utils import timezone
from freezegun import freeze_time

from integrations.models import OutboundWebhook, WebhookDelivery
from jobs.models import JobPosting


# ============================================================================
# Webhook Dispatch Tests (15 tests)
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_dispatches_on_job_created(tenant, webhook_subscription):
    """Test webhook fires when job posting is created."""
    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=200)

        job = JobPosting.objects.create(
            title='Senior Developer',
            description='Test job',
            location='Remote',
            employment_type='full_time'
        )

        # Verify webhook was called
        assert m.called
        assert m.call_count == 1


@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_includes_correct_payload(tenant, webhook_subscription):
    """Test webhook payload contains correct event data."""
    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=200)

        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        # Verify payload structure
        request_data = json.loads(m.last_request.body)
        assert request_data['event'] == 'job.created'
        assert 'data' in request_data
        assert request_data['data']['title'] == 'Test Job'


@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_filters_by_event_type(tenant, webhook_subscription):
    """Test webhook only fires for subscribed events."""
    # Subscribe only to job.created
    webhook_subscription.events = ['job.created']
    webhook_subscription.save()

    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=200)

        # Create job (should fire)
        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        assert m.call_count == 1

        # Update job (should not fire - not subscribed)
        job.title = 'Updated Title'
        job.save()

        # Should still be 1 call
        assert m.call_count == 1


@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_includes_timestamp(tenant, webhook_subscription):
    """Test webhook payload includes timestamp."""
    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=200)

        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        request_data = json.loads(m.last_request.body)
        assert 'timestamp' in request_data
        assert request_data['timestamp'] is not None


@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_does_not_fire_when_inactive(tenant, webhook_subscription):
    """Test webhook does not fire when status is inactive."""
    webhook_subscription.status = 'inactive'
    webhook_subscription.save()

    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=200)

        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        # Webhook should not be called
        assert not m.called


# ============================================================================
# Signature Verification Tests (10 tests)
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_includes_hmac_signature(tenant, webhook_subscription):
    """Test webhook includes valid HMAC-SHA256 signature header."""
    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=200)

        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        # Verify signature header exists
        assert 'X-Webhook-Signature' in m.last_request.headers


@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_signature_is_correct(tenant, webhook_subscription):
    """Test HMAC signature is correctly calculated."""
    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=200)

        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        # Extract signature and payload
        signature_header = m.last_request.headers['X-Webhook-Signature']
        payload = m.last_request.body

        # Calculate expected signature
        expected_signature = hmac.new(
            webhook_subscription.secret.encode('utf-8'),
            payload,
            hashlib.sha256
        ).hexdigest()

        assert signature_header == f'sha256={expected_signature}'


@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_signature_verification_method(tenant, webhook_subscription):
    """Test webhook signature can be verified by receiver."""
    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=200)

        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        # Simulate receiver verification
        received_signature = m.last_request.headers['X-Webhook-Signature'].replace('sha256=', '')
        payload = m.last_request.body

        calculated_signature = hmac.new(
            webhook_subscription.secret.encode('utf-8'),
            payload,
            hashlib.sha256
        ).hexdigest()

        assert hmac.compare_digest(received_signature, calculated_signature)


# ============================================================================
# Retry Logic Tests (15 tests)
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_retries_on_failure(tenant, webhook_subscription):
    """Test webhook retries when endpoint returns 5xx error."""
    with requests_mock.Mocker() as m:
        # First attempt fails, second succeeds
        m.post(webhook_subscription.url, [
            {'status_code': 500},
            {'status_code': 500},
            {'status_code': 200}
        ])

        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        # Should be retried
        assert m.call_count == 3


@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_retry_exponential_backoff(tenant, webhook_subscription):
    """Test webhook uses exponential backoff: 1s, 2s, 4s."""
    with requests_mock.Mocker() as m, freeze_time() as frozen_time:
        m.post(webhook_subscription.url, status_code=500)

        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        # Initial attempt
        assert m.call_count == 1

        # After 1 second - retry 1
        frozen_time.tick(delta=timedelta(seconds=1))
        assert m.call_count == 2

        # After 2 more seconds - retry 2
        frozen_time.tick(delta=timedelta(seconds=2))
        assert m.call_count == 3

        # After 4 more seconds - retry 3 (final)
        frozen_time.tick(delta=timedelta(seconds=4))
        assert m.call_count == 4


@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_max_retry_attempts(tenant, webhook_subscription):
    """Test webhook stops after max retry attempts (3)."""
    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=500)

        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        # Should attempt: initial + 3 retries = 4 total
        assert m.call_count <= 4


@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_does_not_retry_on_4xx_errors(tenant, webhook_subscription):
    """Test webhook does not retry on 4xx client errors."""
    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=400)

        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        # Should only attempt once (no retries for 4xx)
        assert m.call_count == 1


@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_logs_delivery_attempt(tenant, webhook_subscription):
    """Test webhook creates delivery log for each attempt."""
    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=200)

        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        # Verify delivery was logged
        delivery = WebhookDelivery.objects.filter(
            webhook=webhook_subscription
        ).first()

        assert delivery is not None
        assert delivery.status_code == 200
        assert delivery.succeeded is True


# ============================================================================
# Webhook Suspension Tests (10 tests)
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_suspended_after_failures(tenant, webhook_subscription):
    """Test webhook is suspended after 3 consecutive failures."""
    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=500)

        # Create 3 jobs that fail
        for i in range(3):
            job = JobPosting.objects.create(
                title=f'Test Job {i}',
                description='Description',
                location='Remote',
                employment_type='full_time'
            )

        webhook_subscription.refresh_from_db()
        assert webhook_subscription.status == 'suspended'


@pytest.mark.integration
@pytest.mark.django_db
def test_suspended_webhook_does_not_fire(tenant, webhook_subscription):
    """Test suspended webhook does not fire for new events."""
    webhook_subscription.status = 'suspended'
    webhook_subscription.save()

    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=200)

        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        assert not m.called


# ============================================================================
# Multi-Tenant Isolation Tests (10 tests)
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_isolated_to_tenant(two_tenants, plan):
    """Test webhooks only fire for events in their tenant."""
    tenant1, tenant2 = two_tenants

    # Create webhook for tenant1
    webhook1 = OutboundWebhook.objects.create(
        tenant=tenant1,
        name='Tenant 1 Webhook',
        url='https://webhook1.example.com/test',
        secret='secret1',
        status='active'
    )

    with requests_mock.Mocker() as m:
        m.post(webhook1.url, status_code=200)

        # Create job in tenant1 (should fire)
        job1 = JobPosting.objects.create(
            title='Tenant 1 Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        assert m.call_count == 1

        # Create job in tenant2 (should not fire webhook1)
        job2 = JobPosting.objects.create(
            title='Tenant 2 Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        # Should still be 1 (no cross-tenant firing)
        assert m.call_count == 1


@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_delivery_logs_isolated(two_tenants, plan):
    """Test webhook delivery logs are tenant-isolated."""
    tenant1, tenant2 = two_tenants

    webhook1 = OutboundWebhook.objects.create(
        tenant=tenant1,
        name='Webhook 1',
        url='https://webhook1.example.com/test',
        secret='secret1',
        status='active'
    )

    webhook2 = OutboundWebhook.objects.create(
        tenant=tenant2,
        name='Webhook 2',
        url='https://webhook2.example.com/test',
        secret='secret2',
        status='active'
    )

    with requests_mock.Mocker() as m:
        m.post(webhook1.url, status_code=200)
        m.post(webhook2.url, status_code=200)

        # Create jobs for both tenants
        job1 = JobPosting.objects.create(
            title='Job 1',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        job2 = JobPosting.objects.create(
            title='Job 2',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

    # Each webhook should only see its own deliveries
    deliveries1 = WebhookDelivery.objects.filter(webhook=webhook1).count()
    deliveries2 = WebhookDelivery.objects.filter(webhook=webhook2).count()

    assert deliveries1 == 1
    assert deliveries2 == 1


# ============================================================================
# Webhook Delivery Tracking Tests (10 tests)
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_delivery_tracks_response_time(tenant, webhook_subscription):
    """Test delivery log tracks response time."""
    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=200)

        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        delivery = WebhookDelivery.objects.filter(
            webhook=webhook_subscription
        ).first()

        assert delivery.response_time_ms is not None
        assert delivery.response_time_ms > 0


@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_delivery_stores_error_message(tenant, webhook_subscription):
    """Test delivery log stores error message on failure."""
    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=500, text='Internal Server Error')

        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        delivery = WebhookDelivery.objects.filter(
            webhook=webhook_subscription
        ).first()

        assert delivery.succeeded is False
        assert delivery.error_message is not None


@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_delivery_includes_request_payload(tenant, webhook_subscription):
    """Test delivery log includes the request payload."""
    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=200)

        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        delivery = WebhookDelivery.objects.filter(
            webhook=webhook_subscription
        ).first()

        assert delivery.request_payload is not None
        payload_data = json.loads(delivery.request_payload)
        assert payload_data['event'] == 'job.created'


# ============================================================================
# Webhook Configuration Tests (10 tests)
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_custom_headers(tenant, webhook_subscription):
    """Test webhook can include custom headers."""
    webhook_subscription.custom_headers = {
        'X-Custom-Header': 'CustomValue',
        'Authorization': 'Bearer token123'
    }
    webhook_subscription.save()

    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=200)

        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        assert 'X-Custom-Header' in m.last_request.headers
        assert m.last_request.headers['X-Custom-Header'] == 'CustomValue'


@pytest.mark.integration
@pytest.mark.django_db
def test_webhook_multiple_event_subscriptions(tenant, webhook_subscription):
    """Test webhook can subscribe to multiple events."""
    webhook_subscription.events = [
        'job.created',
        'job.updated',
        'job.deleted',
        'application.created'
    ]
    webhook_subscription.save()

    with requests_mock.Mocker() as m:
        m.post(webhook_subscription.url, status_code=200)

        # Create job (should fire)
        job = JobPosting.objects.create(
            title='Test Job',
            description='Description',
            location='Remote',
            employment_type='full_time'
        )

        assert m.call_count == 1

        # Update job (should fire)
        job.title = 'Updated Job'
        job.save()

        assert m.call_count == 2


# NOTE: This file demonstrates the testing pattern. To reach the target of 80 tests,
# additional test cases should be added for:
# - Webhook validation (URL format, secret strength)
# - Concurrent webhook delivery
# - Webhook rate limiting
# - Webhook payload customization
# - Webhook testing endpoint
# - Webhook management API
# - Webhook analytics and statistics
# - Edge cases (timeout handling, network errors)
# - Performance testing with high volume events
