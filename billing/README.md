# Billing App

## Overview

**Platform billing** - Zumodra charges tenants for platform usage (NOT tenant charging their clients).

**Schema**: PUBLIC (platform-wide subscription plans)

## Models

- **SubscriptionPlan**: Platform pricing tiers (Starter, Pro, Enterprise)
- **TenantSubscription**: Tenant's subscription to Zumodra
- **PlatformInvoice**: Invoices from Zumodra to tenants
- **BillingHistory**: Subscription change history

## Key Features

- Multi-tier pricing (Starter, Professional, Enterprise)
- Usage-based billing (seats, storage, API calls)
- Trial periods (default: 14 days)
- Automatic billing via Stripe
- Prorated plan changes

## API Endpoints

- `GET /api/v1/billing/plans/` - Available plans (public)
- `GET /api/v1/billing/my-subscription/` - Current tenant subscription
- `POST /api/v1/billing/upgrade/` - Upgrade plan
- `POST /api/v1/billing/downgrade/` - Downgrade plan
- `GET /api/v1/billing/invoices/` - Platform invoices

## Integration

- **tenants**: Tenant model
- Stripe Billing API

## Configuration

- `STRIPE_PRICE_ID_STARTER_MONTHLY`: Stripe price ID
- `STRIPE_PRICE_ID_PRO_MONTHLY`: Stripe price ID
- `TRIAL_PERIOD_DAYS`: Default trial (14)

## Testing

```bash
pytest billing/tests/
```

## Note

This handles **Zumodra billing tenants**. For tenant billing their own clients, see `subscriptions` app.
