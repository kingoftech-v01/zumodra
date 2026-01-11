# Integrations App

## Overview

Manages all third-party integrations including payment processors, communication services, calendar systems, KYC providers, and webhooks.

## Supported Integrations

### Payment & Finance
- **Stripe**: Payment processing and Connect
- **Stripe Connect**: Marketplace payouts
- **Tax Services**: Avalara (planned)

### Communication
- **SendGrid**: Email delivery
- **Twilio**: SMS notifications
- **Twilio Verify**: 2FA codes

### Calendar & Scheduling
- **Google Calendar**: Calendar sync (planned)
- **Microsoft 365**: Calendar sync (planned)
- **Calendly**: Interview scheduling (planned)

### KYC & Verification
- **Sumsub**: Identity verification (planned)
- **Onfido**: Identity verification (planned)
- **Checkr**: Background checks (planned)

### Document Signing
- **DocuSign**: E-signatures (planned)
- **HelloSign**: E-signatures (planned)

### HR & Payroll
- **Silae**: French payroll (planned)
- **Papaya Global**: Global payroll (planned)
- **Lucca**: HR software (planned)

## Architecture

### Webhook System

Located in `integrations/webhooks/`:

```python
# Inbound webhooks
/webhooks/stripe/
/webhooks/twilio/
/webhooks/sendgrid/

# Outbound webhooks
integrations.send_webhook(
    tenant=tenant,
    event='application.created',
    payload=data
)
```

### Webhook Security
- HMAC-SHA256 signature verification
- Request IP validation
- Replay attack prevention
- Rate limiting

## Models

| Model | Description |
|-------|-------------|
| **Integration** | Integration configurations |
| **WebhookEndpoint** | Tenant webhook URLs |
| **WebhookEvent** | Event log |
| **WebhookDelivery** | Delivery tracking |
| **APIKey** | Integration API keys |

## Views

- `IntegrationListView` - Available integrations
- `IntegrationConfigureView` - Configure integration
- `WebhookManageView` - Manage webhooks
- `WebhookLogView` - Webhook delivery logs

## Future Improvements

### High Priority

1. **Calendar Integration**
   - Google Calendar sync
   - Microsoft 365 sync
   - Auto-create interview events
   - Availability checking

2. **Complete KYC Integration**
   - Sumsub API integration
   - Onfido API integration
   - Document upload
   - Verification workflows

3. **E-Signature Integration**
   - DocuSign API
   - HelloSign API
   - Template management
   - Signature tracking

4. **Job Board Posting**
   - Indeed integration
   - LinkedIn Jobs
   - Glassdoor
   - Auto-posting

5. **ATS Data Import**
   - LinkedIn Recruiter
   - Greenhouse import
   - Lever import
   - CSV/Excel import

### Medium Priority

6. **Payroll Integration**: Silae, Papaya Global
7. **HRIS Integration**: Lucca, BambooHR
8. **Video Interview**: Zoom, Google Meet
9. **Background Checks**: Checkr, Sterling
10. **Slack Integration**: Notifications to Slack

## Security

- Encrypted API keys
- Webhook signature verification
- IP whitelist support
- Audit logging
- Secret rotation

## Testing

```
tests/
├── test_stripe_integration.py
├── test_webhooks.py
├── test_sendgrid.py
├── test_twilio.py
└── test_webhook_security.py
```

---

**Status:** Production (core integrations)
**In Development:** Calendar, KYC, E-signature
