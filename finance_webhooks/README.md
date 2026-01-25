# Finance Webhooks App

## Overview

Centralized webhook handling for all finance integrations (Stripe, Avalara, QuickBooks).

**Schema**: TENANT (tenant-specific webhook events)

## Models

- **WebhookEvent**: Incoming webhook log
- **WebhookRetry**: Failed webhook retry tracking
- **WebhookSignature**: Signature verification
- **WebhookEventType**: Event type catalog

## Key Features

- **Stripe webhooks**: payment.succeeded, subscription.updated, etc.
- **Avalara webhooks**: Tax rate updates
- **QuickBooks webhooks**: Data sync events
- HMAC signature verification
- Automatic retry with exponential backoff
- Event replay capability

## Webhook Endpoints

- `POST /webhooks/stripe/` - Stripe webhook receiver
- `POST /webhooks/avalara/` - Avalara webhook receiver
- `POST /webhooks/quickbooks/` - QuickBooks webhook receiver

## API Endpoints (Admin)

- `GET /api/v1/webhooks/events/` - Webhook event log
- `GET /api/v1/webhooks/events/<id>/` - Event details
- `POST /api/v1/webhooks/events/<id>/retry/` - Manual retry
- `GET /api/v1/webhooks/events/<id>/payload/` - View payload

## Security

- HMAC-SHA256 signature verification
- Request timestamp validation
- Replay attack protection
- IP whitelist (optional)

## Handlers

```python
# stripe_handler.py
def handle_payment_succeeded(event):
    # Update payment status
    pass

def handle_subscription_updated(event):
    # Update subscription
    pass

# avalara_handler.py
def handle_tax_rate_update(event):
    # Update tax rates
    pass

# quickbooks_handler.py
def handle_data_change(event):
    # Sync changes
    pass
```

## Configuration

- `STRIPE_WEBHOOK_SECRET`: Stripe webhook signing secret
- `AVALARA_WEBHOOK_SECRET`: Avalara webhook secret
- `QUICKBOOKS_WEBHOOK_TOKEN`: QuickBooks verification token

## Testing

```bash
pytest finance_webhooks/tests/
pytest finance_webhooks/tests/test_stripe_webhooks.py
```

## Monitoring

All webhook events are logged for monitoring and debugging:
- Success/failure tracking
- Retry counts
- Processing time
- Error messages
