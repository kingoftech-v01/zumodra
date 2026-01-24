# Integrations App

## Overview

Third-party service integrations (LinkedIn, Stripe, Avalara, QuickBooks, Xero).

**Schema**: TENANT (each tenant has own integration configs)

## Integrations Supported

### Recruitment
- **LinkedIn**: Job posting, candidate search

### Finance
- **Stripe**: Payment processing (managed via stripe_connect)
- **Avalara**: Tax calculation (managed via tax app)
- **QuickBooks**: Accounting sync (managed via accounting app)
- **Xero**: Accounting sync (managed via accounting app)

### Communication
- **Mailchimp**: Email campaigns (managed via marketing_campaigns)

## API Endpoints

### Configuration
- **GET/POST** `/api/v1/integrations/configs/` - Integration configs
- **PUT/PATCH** `/api/v1/integrations/configs/<id>/` - Update config
- **POST** `/api/v1/integrations/configs/<id>/test/` - Test connection

### Webhooks
- **GET/POST** `/api/v1/integrations/webhooks/` - Outbound webhooks
- **POST** `/api/v1/integrations/webhooks/<id>/test/` - Test webhook

### OAuth
- **GET** `/api/v1/integrations/oauth/authorize/?provider=linkedin` - OAuth flow
- **GET** `/api/v1/integrations/oauth/callback/?provider=linkedin` - OAuth callback

## Features

- OAuth 2.0 authentication
- API key management (encrypted)
- Webhook configuration
- Connection testing
- Sync status tracking
- Error logging

## Permissions

- `IsIntegrationsAdmin`: Manage integrations
- Only PDG/Supervisor can configure integrations

## Tasks (Celery)

- `sync_integrations_data`: Sync with external services
- `daily_integrations_cleanup`: Clean old logs

## Signals

- `integration_connected`: Trigger initial sync
- `integration_disconnected`: Clean up webhooks

## Testing

```bash
pytest integrations/tests/
```

## Security

- API keys encrypted at rest
- OAuth tokens refreshed automatically
- Webhook signatures verified (HMAC-SHA256)
