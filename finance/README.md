# Finance App

## Overview

Manages all financial operations including Stripe payments, subscription billing, escrow for marketplace contracts, invoicing, and payment tracking.

## Key Features

- **Stripe Integration**: Payment processing via Stripe
- **Subscription Management**: Tenant subscription billing
- **Escrow System**: Secure funds holding for contracts
- **Invoice Generation**: Automated invoicing
- **Payment Tracking**: Transaction history and status
- **Refunds**: Refund processing and tracking
- **Payout Management**: Stripe Connect payouts

## Models

| Model | Description |
|-------|-------------|
| **Payment** | Payment records |
| **Subscription** | Tenant subscriptions |
| **Invoice** | Generated invoices |
| **Transaction** | Payment transactions |
| **EscrowAccount** | Contract escrow accounts |
| **Payout** | Provider payouts |
| **Refund** | Refund records |

## Stripe Architecture

### Subscription Flow
```
Tenant → Subscription → Stripe Customer → Payment Method → Charges
```

### Escrow Flow
```
Client Payment → Platform Account (Hold) → Escrow → Provider Connect Account
```

### Payment Methods
- Credit/Debit Cards
- Bank Transfers
- ACH (US)
- SEPA (EU)

## Views

- `SubscriptionManageView` - Manage subscriptions
- `PaymentHistoryView` - View payment history
- `InvoiceListView` - Invoice management
- `EscrowDashboardView` - Escrow overview
- `PayoutListView` - Provider payouts

## Integration Points

- **Tenants**: Subscription management
- **Services**: Escrow for contracts
- **Accounts**: Payment methods
- **Notifications**: Payment confirmations

## External Services

- **Stripe**: Payment processing
- **Stripe Connect**: Marketplace payments
- **Tax Services**: Avalara (planned)
- **Accounting**: QuickBooks (planned)

## Future Improvements

### High Priority

1. **Multi-Currency Support**: Global currency handling
2. **Tax Automation**: Automated tax calculation
3. **Recurring Billing**: Advanced subscription features
4. **Payment Analytics**: Revenue dashboards
5. **Dispute Management**: Chargeback handling

### Medium Priority

6. **Payment Plans**: Installment payments
7. **Wallet System**: Platform credits
8. **Expense Tracking**: Business expense management
9. **Financial Reports**: P&L, balance sheets
10. **Accounting Integration**: QuickBooks, Xero

## Security

- PCI-DSS compliance via Stripe
- Encrypted payment data
- No card storage on server
- Secure webhook signatures
- Fraud detection

## Testing

Critical: 100% coverage for payment flows

```
tests/
├── test_payments.py
├── test_subscriptions.py
├── test_escrow.py
├── test_refunds.py
└── test_stripe_webhooks.py
```

---

**Status:** Production
**Critical Component:** Financial transactions
