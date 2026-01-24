# Marketing Campaigns App

## Overview

Unified marketing and email campaigns (merged from `marketing` + `newsletter` apps in Phase 8).

**Schema**: TENANT (each tenant has own contacts and campaigns)

## Models

- **Contact**: Unified contacts (leads + subscribers)
- **MarketingCampaign**: Email campaigns and newsletters
- **CampaignMessage**: Rich email content
- **MessageArticle**: Content blocks for emails
- **CampaignTracking**: Opens, clicks, conversions
- **VisitEvent**: Anonymous visitor tracking
- **ConversionEvent**: Conversion tracking
- **ContactSegment**: Contact segmentation
- **AggregatedStats**: Campaign analytics

## Key Features

- Contact management (leads + subscribers)
- Email campaign builder
- Rich email templates (from newsletter app)
- Mailchimp integration (per-tenant)
- Campaign tracking (opens, clicks, conversions)
- Visitor tracking with UTM params
- Contact segmentation
- Double opt-in for subscribers
- Campaign analytics

## API Endpoints

### Contacts
- **GET/POST** `/api/v1/marketing-campaigns/contacts/`
- **GET/PUT/PATCH/DELETE** `/api/v1/marketing-campaigns/contacts/<id>/`
- **POST** `/api/v1/marketing-campaigns/contacts/import/` - Bulk import

### Campaigns
- **GET/POST** `/api/v1/marketing-campaigns/campaigns/`
- **GET** `/api/v1/marketing-campaigns/campaigns/<id>/`
- **POST** `/api/v1/marketing-campaigns/campaigns/<id>/send/` - Send campaign
- **POST** `/api/v1/marketing-campaigns/campaigns/<id>/schedule/` - Schedule send

### Tracking
- **GET** `/api/v1/marketing-campaigns/tracking/` - Campaign analytics
- **GET** `/api/v1/marketing-campaigns/visits/` - Visitor analytics
- **GET** `/api/v1/marketing-campaigns/conversions/` - Conversion tracking

### Public Endpoints (No Auth)
- **POST** `/api/v1/marketing-campaigns/subscribe/` - Newsletter signup
- **GET** `/api/v1/marketing-campaigns/unsubscribe/<token>/` - Unsubscribe

## Workflow

1. **Visitor** → Anonymous visit tracked with UTM params
2. **Lead** → Contact created (form submission, import)
3. **Subscriber** → Contact status changed to "subscribed" (double opt-in)
4. **Customer** → Conversion event tracked

## Integration

- **Mailchimp**: Auto-sync contacts with Mailchimp lists
- **Email**: Send campaigns via Mailchimp or internal SMTP
- **Analytics**: Track opens, clicks, conversions

## Permissions

- `IsMarketingCampaignsAdmin`: Campaign management
- `CanManageContacts`: Contact CRUD

## Tasks (Celery)

- `sync_marketing_campaigns_data`: Sync with Mailchimp
- `daily_marketing_campaigns_cleanup`: Clean old tracking data

## Signals

- `contact_saved`: Sync to Mailchimp if subscribed
- `campaign_sent`: Track send event

## Configuration

Environment variables:
- `MAILCHIMP_API_KEY`: Per-tenant Mailchimp API key
- `MAILCHIMP_LIST_ID`: Default Mailchimp list

## Testing

```bash
pytest marketing_campaigns/tests/
```

## Migration from Old Apps

This app merged `marketing/` + `newsletter/` (Phase 8):
- `marketing.Prospect` → `Contact` (status: "lead")
- `newsletter.Subscription` → `Contact` (status: "subscribed")
- `newsletter.Message` → `CampaignMessage`
- Mailchimp integration retained from newsletter app
