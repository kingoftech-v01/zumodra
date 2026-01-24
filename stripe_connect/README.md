# Stripe Connect App

## Overview

Stripe Connect integration for marketplace payments - enables service providers to receive payouts directly.

**Schema**: TENANT

## Models

- **ConnectedAccount**: Stripe Connect Express accounts for providers
- **StripeConnectOnboarding**: Onboarding flow tracking
- **PlatformFee**: Marketplace commission configuration
- **PayoutSchedule**: Payout frequency settings
- **Transfer**: Transfer tracking to connected accounts
- **BalanceTransaction**: Balance history

## Key Features

- Stripe Connect Express onboarding
- Automated provider payouts
- Platform fee/commission deduction
- Payout scheduling (daily, weekly, monthly)
- Balance tracking
- Tax form generation (1099)

## API Endpoints

- `POST /api/v1/stripe-connect/accounts/create/` - Create connected account
- `GET /api/v1/stripe-connect/accounts/<id>/dashboard-link/` - Stripe dashboard access
- `POST /api/v1/stripe-connect/onboarding/<id>/create-link/` - Onboarding URL
- `GET /api/v1/stripe-connect/transfers/` - Transfer history

## Integration

- **escrow**: Payout from escrow to providers
- **payments**: Payment processing
- Stripe Connect API

## Configuration

- `STRIPE_CONNECT_CLIENT_ID`: Stripe Connect client ID
- `PLATFORM_FEE_PERCENTAGE`: Default platform fee (e.g., 10%)

## Testing

```bash
pytest stripe_connect/tests/
```
