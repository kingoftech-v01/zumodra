# Marketing App

## Overview

The Marketing app provides comprehensive marketing analytics, visit tracking, lead capture, and newsletter campaign management for the Zumodra platform. It tracks visitor behavior, captures leads through forms, manages newsletter campaigns, and provides detailed analytics on marketing performance with privacy-compliant anonymous tracking.

## Key Features

### Completed Features

- **Visit Tracking**: Anonymous visitor tracking with marketing ID cookies
- **UTM Parameter Capture**: Full campaign attribution tracking (source, medium, campaign, content, term)
- **Device & Browser Analytics**: User agent parsing for device type, browser, and OS detection
- **GeoIP Analytics**: Country-based visitor tracking using GeoLite2
- **Lead Capture**: Prospect/lead management with status tracking
- **Newsletter Management**: Campaign creation, scheduling, and subscriber management
- **Email Tracking**: Open and click tracking for newsletter campaigns
- **Conversion Tracking**: Event-based conversion tracking with value attribution
- **Marketing Dashboard**: Staff-only analytics dashboard with key metrics
- **Data Aggregation**: Pre-computed stats for performance optimization

### In Development

- **A/B Testing**: Campaign variant testing with statistical analysis
- **Lead Scoring**: Automated lead quality scoring
- **Campaign Automation**: Triggered campaigns based on user behavior
- **Advanced Analytics**: Funnel visualization, cohort analysis
- **Integration with Email Services**: SendGrid, Mailchimp integration

## Architecture

### Models

Located in `marketing/models.py`:

| Model | Description | Key Fields |
|-------|-------------|------------|
| **VisitEvent** | Individual visit records | marketing_id, ip_address, country, device_type, browser, os, path, utm_* fields |
| **AggregatedStats** | Pre-computed daily statistics | date, country, device_type, total_visits |
| **Prospect** | Lead/prospect records | email, first_name, last_name, company, phone, source, status, added_on |
| **NewsletterCampaign** | Email campaigns | title, subject, content, scheduled_for, sent, sent_on |
| **NewsletterSubscriber** | Email subscribers | email, subscribed_on, unsubscribed_on, active |
| **NewsletterTracking** | Campaign engagement | subscriber, campaign, opened, opened_on, clicked, clicked_on |
| **ConversionEvent** | Conversion tracking | marketing_id, event_name, value, timestamp, metadata |

### Prospect Status Workflow

Prospects progress through the following stages:

1. **new** - New lead captured
2. **contacted** - Initial contact made
3. **qualified** - Lead meets qualification criteria
4. **converted** - Successfully converted to customer
5. **disqualified** - Lead does not meet criteria

### Views

#### Frontend Views (`marketing/views.py`)

**Dashboard & Analytics:**
- `MarketingDashboardView` - Main marketing analytics dashboard (staff only)
  - Traffic stats and visitor metrics
  - Traffic by source, country, device
  - Prospect management and conversion tracking
  - Newsletter campaign performance
  - Conversion rate calculations

**Prospect Management:**
- `ProspectsListView` - Prospect list with filtering
  - Filter by status, source, search query
  - Status breakdown statistics
  - Bulk actions support

**Campaign Management:**
- `CampaignsListView` - Newsletter campaign list
  - Campaign performance metrics
  - Open rate and click rate tracking
  - Filter by sent status

#### API Views (`marketing/api/viewsets.py`)

```python
# Visit Tracking
/api/v1/marketing/visits/
/api/v1/marketing/visits/by_source/
/api/v1/marketing/visits/by_country/
/api/v1/marketing/visits/by_device/

# Aggregated Stats
/api/v1/marketing/stats/

# Prospects/Leads
/api/v1/marketing/prospects/
/api/v1/marketing/prospects/{id}/mark_contacted/
/api/v1/marketing/prospects/{id}/mark_qualified/
/api/v1/marketing/prospects/{id}/mark_converted/
/api/v1/marketing/prospects/{id}/disqualify/
/api/v1/marketing/prospects/by_status/

# Newsletter Campaigns
/api/v1/marketing/campaigns/
/api/v1/marketing/campaigns/{id}/send/
/api/v1/marketing/campaigns/{id}/tracking/
/api/v1/marketing/campaigns/stats/

# Newsletter Subscribers
/api/v1/marketing/subscribers/
/api/v1/marketing/subscribers/{id}/unsubscribe/
/api/v1/marketing/subscribers/{id}/resubscribe/

# Conversions
/api/v1/marketing/conversions/
/api/v1/marketing/conversions/by_event/
/api/v1/marketing/conversions/revenue/

# Analytics
/api/v1/marketing/analytics/
```

### URL Structure

```python
# Frontend URLs (namespace: 'marketing')
marketing:dashboard           # Marketing analytics dashboard
marketing:prospects-list      # Prospects management
marketing:campaigns-list      # Newsletter campaigns

# API URLs (namespace: 'marketing-api')
# See API Views section above for complete endpoint list
```

### Middleware

Located in `marketing/marketingMidleware.py`:

**MarketingMiddleware** (Basic tracking):
- Marketing ID cookie management
- UTM parameter capture
- Referral tracking
- Session-based first visit tracking

**AdvancedMarketingMiddleware** (Full analytics):
- All basic middleware features
- Device and browser detection (user-agents library)
- GeoIP country detection (geoip2 library)
- Extended event logging
- IP address extraction from proxies

### Celery Tasks

Located in `marketing/tasks.py`:

| Task | Schedule | Purpose |
|------|----------|---------|
| `process_scheduled_campaigns` | Hourly | Process and send scheduled newsletter campaigns |
| `calculate_conversion_metrics` | Daily | Calculate daily conversion rates and metrics |
| `cleanup_old_visits` | Weekly | Remove visit data older than 90 days (GDPR compliance) |
| `sync_newsletter_subscribers` | Hourly | Sync subscribers with external email service |
| `calculate_lead_scores` | Daily | Calculate and update lead quality scores |
| `update_campaign_analytics` | Hourly | Update campaign performance metrics |
| `analyze_ab_tests` | Daily | Analyze A/B test results and determine winners |

### Serializers

Located in `marketing/serializers.py`:

**Visit Tracking:**
- `VisitEventListSerializer` - List view
- `VisitEventDetailSerializer` - Detail view

**Prospects:**
- `ProspectListSerializer` - List view with full_name
- `ProspectDetailSerializer` - Detail view
- `ProspectCreateSerializer` - Lead capture
- `ProspectUpdateSerializer` - Status updates

**Campaigns:**
- `NewsletterCampaignListSerializer` - List with stats
- `NewsletterCampaignDetailSerializer` - Detail with full stats
- `NewsletterCampaignCreateSerializer` - Campaign creation

**Subscribers:**
- `NewsletterSubscriberListSerializer` - Subscriber list
- `NewsletterSubscriberDetailSerializer` - Detail with campaign count
- `NewsletterSubscriberCreateSerializer` - New subscribers

**Analytics:**
- `MarketingAnalyticsSerializer` - Dashboard metrics
- `TrafficBySourceSerializer` - Source breakdown
- `TrafficByCountrySerializer` - Country breakdown
- `TrafficByDeviceSerializer` - Device breakdown

## Integration Points

### With Other Apps

- **Public Site**: Visit tracking middleware on all public pages
- **Analytics**: Marketing data feeds into platform-wide analytics
- **Newsletter**: Integration with newsletter app for campaign management
- **Accounts**: Lead conversion to user accounts
- **Dashboard**: Marketing metrics in main dashboard
- **Finance**: Revenue attribution to marketing campaigns

### External Services

- **GeoLite2**: Country detection for visitor analytics
- **Email Service Providers** (Planned): SendGrid, Mailchimp, etc.
- **Analytics Tools** (Planned): Google Analytics, Mixpanel integration

## Security & Permissions

### Access Control

- **Visit Tracking**: Anonymous (no authentication required)
- **Analytics Dashboard**: Staff members only (`@staff_member_required`)
- **API Endpoints**: Admin users only (`IsAdminUser` permission)
- **Prospect Management**: Admin/marketing team only

### Privacy Compliance

- **GDPR Compliant**:
  - Anonymous marketing IDs (no PII)
  - 90-day data retention for visits
  - Subscriber opt-out support
  - Right to erasure support

- **Cookie Consent**:
  - Marketing ID cookie (non-essential)
  - 1-year cookie expiration
  - Session-based referral tracking

- **Data Protection**:
  - IP addresses hashed for privacy
  - No personal data in visit events
  - Subscriber data encrypted at rest
  - Secure unsubscribe mechanism

### Security Features

- **Rate Limiting**: API endpoints rate limited
- **Input Validation**: All form inputs sanitized
- **CSRF Protection**: All forms protected
- **XSS Prevention**: Output escaped in templates
- **Audit Logging**: Campaign sends and data exports logged

## Performance Optimization

### Current Optimizations

- **Database Indexes**:
  - marketing_id (VisitEvent)
  - country (VisitEvent, AggregatedStats)
  - timestamp (VisitEvent)
  - device_type (VisitEvent)
  - date (AggregatedStats)

- **Aggregated Stats**: Pre-computed daily stats for faster dashboard loading
- **Query Optimization**: Select_related and prefetch_related for related data
- **Caching**: Daily metrics cached in Redis (86400s TTL)

### Planned Optimizations

- **Visit Event Batching**: Batch insert visit events
- **Background Processing**: Async event processing via Celery
- **TimescaleDB**: Time-series database for visit data
- **CDN Integration**: Static asset optimization

## Analytics Features

### Traffic Analytics

- **Total Visits**: Overall visitor count
- **Unique Visitors**: Unique marketing IDs
- **Traffic Sources**: UTM source breakdown with percentages
- **Geographic Distribution**: Top countries by visits
- **Device Breakdown**: Mobile, tablet, desktop split
- **Browser Analytics**: Browser family distribution
- **Path Analysis**: Most visited pages

### Lead Analytics

- **Total Prospects**: All-time lead count
- **New Prospects**: Leads by date range
- **Qualified Leads**: Conversion funnel tracking
- **Lead Sources**: Attribution to campaigns
- **Status Distribution**: Pipeline visualization
- **Conversion Rate**: Visit-to-lead conversion

### Campaign Analytics

- **Total Campaigns**: Campaign count
- **Campaigns Sent**: Successfully delivered
- **Open Rate**: Email open tracking
- **Click Rate**: Link click tracking
- **Subscriber Growth**: New subscribers over time
- **Unsubscribe Rate**: Churn tracking

### Conversion Analytics

- **Total Conversions**: All conversion events
- **Revenue Tracking**: Purchase value attribution
- **Conversion by Type**: Signup, purchase, etc.
- **Conversion Rate**: Visitor-to-customer rate
- **ROI Metrics**: Marketing spend efficiency

## Future Improvements

### High Priority

1. **Enhanced Campaign Tracking**
   - Multi-channel attribution
   - Customer journey mapping
   - Cross-device tracking
   - Campaign ROI dashboard
   - Attribution modeling (first-touch, last-touch, linear)

2. **A/B Testing Platform**
   - Landing page A/B tests
   - Email subject line testing
   - CTA button testing
   - Statistical significance calculator
   - Auto-promote winning variants

3. **Conversion Funnels**
   - Visual funnel builder
   - Drop-off analysis
   - Funnel optimization insights
   - Multi-step conversion tracking
   - Cohort funnel analysis

4. **Advanced Lead Scoring**
   - ML-based lead quality prediction
   - Engagement score calculation
   - Best-time-to-contact predictions
   - Lead decay modeling
   - Automated lead routing

5. **Marketing Automation**
   - Drip campaigns
   - Behavioral triggers
   - Lead nurturing workflows
   - Automated follow-ups
   - Smart segmentation

### Medium Priority

6. **Email Service Integration**
   - SendGrid API integration
   - Mailchimp sync
   - Amazon SES support
   - Postmark integration
   - Bounce and complaint handling

7. **Advanced Analytics**
   - Cohort analysis
   - Retention curves
   - LTV prediction
   - Churn prediction
   - Predictive analytics

8. **Landing Page Builder**
   - Drag-and-drop editor
   - Template library
   - A/B testing integration
   - Conversion optimization
   - Mobile responsiveness

9. **Social Media Integration**
   - Social media tracking
   - Campaign attribution
   - Social analytics
   - Influencer tracking
   - Viral coefficient calculation

10. **Referral Program**
    - Referral link generation
    - Reward tracking
    - Viral loop optimization
    - Referral attribution
    - Reward automation

### Low Priority

11. **Heatmaps & Session Recording**
    - Click heatmaps
    - Scroll depth tracking
    - Session replay
    - Form abandonment tracking
    - User flow visualization

12. **Marketing Attribution**
    - Multi-touch attribution
    - Time-decay models
    - Custom attribution models
    - Cross-channel attribution
    - Attribution reporting

13. **Content Marketing**
    - Blog post analytics
    - Content engagement tracking
    - SEO keyword tracking
    - Content ROI measurement
    - Topic clustering

## Testing

### Test Coverage

Target: 85%+ coverage for marketing analytics and privacy compliance

### Test Structure

```
tests/
├── test_visit_tracking.py      # Visit event tests
├── test_prospects.py            # Prospect management tests
├── test_campaigns.py            # Newsletter campaign tests
├── test_conversions.py          # Conversion tracking tests
├── test_analytics.py            # Analytics calculation tests
├── test_middleware.py           # Middleware tests
├── test_privacy.py              # Privacy compliance tests
└── test_tasks.py                # Celery task tests
```

### Key Test Scenarios

- Anonymous visit tracking (no PII exposure)
- UTM parameter capture and storage
- Marketing ID cookie lifecycle
- Prospect status workflow
- Campaign send workflow
- Email open/click tracking
- Conversion event attribution
- Data retention and cleanup
- Subscriber opt-out flow
- GDPR compliance verification

## Configuration

### Required Settings

```python
# settings.py

# GeoIP Database Path
GEOIP_PATH = '/usr/share/GeoIP'

# Marketing Settings
MARKETING_ID_COOKIE_NAME = 'marketing_id'
MARKETING_ID_COOKIE_AGE = 60 * 60 * 24 * 365  # 1 year

# Visit Data Retention
MARKETING_VISIT_RETENTION_DAYS = 90

# Email Service (for newsletters)
EMAIL_SERVICE_PROVIDER = 'sendgrid'  # or 'mailchimp', 'ses'
EMAIL_SERVICE_API_KEY = env('EMAIL_SERVICE_API_KEY')

# Newsletter Settings
NEWSLETTER_FROM_EMAIL = 'newsletter@zumodra.com'
NEWSLETTER_REPLY_TO = 'support@zumodra.com'

# Lead Scoring
LEAD_SCORING_ENABLED = True
LEAD_SCORE_UPDATE_FREQUENCY = 'daily'
```

### Middleware Configuration

```python
# settings.py

MIDDLEWARE = [
    # ...
    'marketing.marketingMidleware.MarketingMiddleware',
    # OR for advanced analytics:
    # 'marketing.marketingMidleware.AdvancedMarketingMiddleware',
    # ...
]
```

### Celery Beat Schedule

```python
# celery_beat_schedule.py

CELERY_BEAT_SCHEDULE = {
    'process-scheduled-campaigns': {
        'task': 'marketing.tasks.process_scheduled_campaigns',
        'schedule': crontab(minute=0),  # Hourly
    },
    'calculate-conversion-metrics': {
        'task': 'marketing.tasks.calculate_conversion_metrics',
        'schedule': crontab(hour=1, minute=0),  # Daily at 1 AM
    },
    'cleanup-old-visits': {
        'task': 'marketing.tasks.cleanup_old_visits',
        'schedule': crontab(day_of_week='sunday', hour=2, minute=0),  # Weekly
    },
    'sync-newsletter-subscribers': {
        'task': 'marketing.tasks.sync_newsletter_subscribers',
        'schedule': crontab(minute='*/30'),  # Every 30 minutes
    },
    'calculate-lead-scores': {
        'task': 'marketing.tasks.calculate_lead_scores',
        'schedule': crontab(hour=3, minute=0),  # Daily at 3 AM
    },
}
```

## Migration Notes

When modifying marketing models:

```bash
# Marketing is a shared app (not tenant-specific)
python manage.py makemigrations marketing

# Apply to shared schema
python manage.py migrate_schemas --shared

# Verify migration
python manage.py check
```

## Usage Examples

### Capturing a Lead via API

```python
# POST /api/v1/marketing/prospects/
{
    "email": "lead@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "company": "Acme Corp",
    "phone": "+1-555-0123",
    "source": "Contact Form - Pricing Page"
}
```

### Tracking a Conversion

```python
# POST /api/v1/marketing/conversions/
{
    "marketing_id": "abc123xyz789",
    "event_name": "purchase",
    "value": 499.99,
    "metadata": {
        "product_id": "prod_123",
        "plan": "professional"
    }
}
```

### Creating a Newsletter Campaign

```python
# POST /api/v1/marketing/campaigns/
{
    "title": "February Product Update",
    "subject": "New features just launched!",
    "content": "Hello {{first_name}},\n\nWe're excited to announce...",
    "scheduled_for": "2026-02-15T10:00:00Z"
}
```

### Retrieving Analytics

```python
# GET /api/v1/marketing/analytics/?days=30
{
    "total_visits": 15420,
    "unique_visitors": 8932,
    "total_prospects": 342,
    "new_prospects": 89,
    "conversion_rate": 2.43,
    "total_revenue": 24899.50,
    "total_subscribers": 1234,
    "active_subscribers": 1198,
    "campaigns_sent": 4,
    "avg_open_rate": 28.5,
    "avg_click_rate": 4.2
}
```

## Contributing

When adding features to Marketing:

1. Maintain privacy compliance (GDPR, CCPA)
2. Always anonymize visitor data
3. Test data retention policies
4. Document new analytics metrics
5. Update API documentation
6. Ensure staff-only access for sensitive data

## Support

For questions or issues:
- Review Django session/cookie documentation
- Check geoip2 and user-agents library docs
- Consult privacy compliance guidelines
- Review [PRIVACY.md](../docs/PRIVACY.md) for data handling

---

**Last Updated:** January 2026
**Module Version:** 1.0
**Status:** Production
