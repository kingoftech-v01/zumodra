# Subscriptions App

## Overview

Tenant's own subscription products for selling recurring services to their clients (SaaS tenants selling to customers).

**Schema**: TENANT (each tenant has own subscription products)

## Models

- **SubscriptionProduct**: Tenant's products (e.g., software licenses)
- **SubscriptionTier**: Pricing tiers (Basic, Pro, Enterprise)
- **CustomerSubscription**: Client subscriptions to tenant's products
- **SubscriptionInvoice**: Recurring invoices
- **UsageRecord**: Usage-based billing tracking

## Key Features

- Multi-tier pricing
- Usage-based billing
- Metered billing
- Proration on plan changes
- Trial periods
- Subscription analytics (MRR, ARR, churn)

## API Endpoints

- `GET /api/v1/subscriptions/products/` - Product catalog
- `GET/POST /api/v1/subscriptions/customer-subscriptions/` - Subscriptions
- `POST /api/v1/subscriptions/customer-subscriptions/<id>/cancel/` - Cancel
- `POST /api/v1/subscriptions/customer-subscriptions/<id>/upgrade/` - Upgrade tier
- `GET /api/v1/subscriptions/invoices/` - Recurring invoices

## Integration

- **payments**: Recurring billing
- **billing**: Different from platform billing (tenant's own products)
- Stripe Billing API

## Testing

```bash
pytest subscriptions/tests/
```

## Note

This is for **tenant subscription products** (tenant sells to clients), NOT platform billing (Zumodra billing tenants - see `billing` app).
