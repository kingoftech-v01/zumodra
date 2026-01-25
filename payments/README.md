# Payments App

## Overview

The `payments` app handles all tenant payment processing including multi-currency support, payment methods, refunds, and payment intents. This is part of the Phase 11 finance refactoring that split the monolithic `finance` app into 10 specialized apps.

**Schema**: TENANT (each tenant has isolated payment data)

## Models

### Currency
- **Purpose**: Supported currencies for multi-currency transactions
- **Key Fields**: code (USD, EUR, CAD), name, symbol, decimal_places
- **Features**: Active/inactive flag for enabling/disabling currencies

### ExchangeRate
- **Purpose**: Historical exchange rates for accurate currency conversion
- **Key Fields**: from_currency, to_currency, rate, date
- **Features**: Daily updates via Celery task, historical tracking

### PaymentTransaction
- **Purpose**: Individual payment records with full multi-currency support
- **Key Fields**:
  - amount, currency, exchange_rate, amount_usd (normalized)
  - payer, payee (User ForeignKeys)
  - status (pending, processing, succeeded, failed, refunded)
  - payment_method, stripe_payment_intent_id, stripe_charge_id
  - Generic FK to related object (appointment, project, invoice, etc.)
- **Features**: Multi-currency, Stripe integration, audit trail

### PaymentMethod
- **Purpose**: Stored payment methods (cards, bank accounts)
- **Key Fields**: user, type, provider, token, is_default, last_four
- **Features**: PCI-compliant tokenization via Stripe

### RefundRequest
- **Purpose**: Refund tracking and processing
- **Key Fields**: payment_transaction, amount, reason, status, processed_at
- **Features**: Partial refunds, reason tracking, approval workflow

### PaymentIntent
- **Purpose**: Stripe payment intent tracking
- **Key Fields**: transaction, intent_id, status, amount, client_secret
- **Features**: 3D Secure support, payment confirmation

## Views

### Frontend (template_views.py)
- **PaymentDashboardView**: Overview of payment activity
- **PaymentListView**: List all payments (with filters)
- **PaymentDetailView**: Individual payment details
- **PaymentMethodListView**: Manage payment methods
- **RefundRequestListView**: View refund requests

### API (api/viewsets.py)
- **CurrencyViewSet**: List supported currencies (read-only)
- **ExchangeRateViewSet**: Exchange rate history (read-only)
- **PaymentMethodViewSet**: CRUD for payment methods
- **PaymentTransactionViewSet**: Payment history (read + create)
- **RefundRequestViewSet**: Refund management
- **PaymentIntentViewSet**: Payment intent tracking

## API Endpoints

### Currencies
- **GET** `/api/v1/payments/currencies/` - List supported currencies
- **GET** `/api/v1/payments/currencies/<code>/` - Get currency details

### Exchange Rates
- **GET** `/api/v1/payments/exchange-rates/` - Historical rates
- **GET** `/api/v1/payments/exchange-rates/<id>/` - Specific rate

### Payment Methods
- **GET** `/api/v1/payments/payment-methods/` - List user's payment methods
- **POST** `/api/v1/payments/payment-methods/` - Add new payment method
- **GET** `/api/v1/payments/payment-methods/<id>/` - Get details
- **PUT/PATCH** `/api/v1/payments/payment-methods/<id>/` - Update
- **DELETE** `/api/v1/payments/payment-methods/<id>/` - Remove
- **POST** `/api/v1/payments/payment-methods/<id>/set-default/` - Set as default
- **POST** `/api/v1/payments/payment-methods/<id>/verify/` - Verify payment method

### Payment Transactions
- **GET** `/api/v1/payments/transactions/` - List payments
- **POST** `/api/v1/payments/transactions/` - Create payment
- **GET** `/api/v1/payments/transactions/<id>/` - Get details
- **GET** `/api/v1/payments/transactions/my-payments/` - Current user's payments
- **POST** `/api/v1/payments/transactions/<id>/refund/` - Request refund
- **POST** `/api/v1/payments/transactions/<id>/confirm/` - Confirm payment intent

### Refund Requests
- **GET** `/api/v1/payments/refunds/` - List refund requests
- **POST** `/api/v1/payments/refunds/` - Create refund request
- **GET** `/api/v1/payments/refunds/<id>/` - Get details
- **POST** `/api/v1/payments/refunds/<id>/approve/` - Approve refund (admin)
- **POST** `/api/v1/payments/refunds/<id>/reject/` - Reject refund (admin)

## Permissions

- **IsPaymentParticipant**: User is payer or payee of the transaction
- **CanManagePaymentMethods**: User can manage own payment methods
- **CanApproveRefunds**: Admin/owner can approve refunds

## Tasks (Celery)

- **update_exchange_rates**: Daily task to fetch latest exchange rates from external API
- **process_pending_payments**: Process queued payment transactions
- **sync_payment_to_stripe**: Sync payment data with Stripe
- **generate_payment_receipt**: Generate PDF receipt for payment

## Signals

- **payment_succeeded**: Triggered when payment completes successfully
- **payment_failed**: Triggered when payment fails
- **refund_processed**: Triggered when refund is completed

## Configuration

Environment variables:
- `STRIPE_SECRET_KEY`: Stripe API secret key
- `STRIPE_PUBLISHABLE_KEY`: Stripe publishable key
- `EXCHANGE_RATE_API_KEY`: External exchange rate API key
- `DEFAULT_CURRENCY`: Default currency (default: CAD)

## Integration Points

**Integrates with**:
- `interviews` app - Appointment payments
- `projects` app - Project milestone payments via escrow
- `subscriptions` app - Recurring subscription payments
- `payroll` app - Employee payments
- `expenses` app - Expense reimbursements

## Multi-Currency Features

**Supported currencies** (configurable):
- USD (US Dollar)
- CAD (Canadian Dollar)
- EUR (Euro)
- GBP (British Pound)
- AUD (Australian Dollar)

**Exchange rate updates**:
- Automatic daily updates via Celery
- Historical rate preservation for accurate reporting
- Normalized USD amounts for consistent analytics

## Security

- **PCI Compliance**: No card data stored directly (tokenized via Stripe)
- **Encryption**: Sensitive payment data encrypted at rest
- **Audit Trail**: All payment actions logged
- **HMAC Signatures**: Webhook verification for Stripe events

## Testing

```bash
# Run tests
pytest payments/tests/

# Test coverage
pytest --cov=payments payments/tests/

# Specific test suites
pytest payments/tests/test_multi_currency.py
pytest payments/tests/test_payment_flow.py
pytest payments/tests/test_refunds.py
```

## Dependencies

- **Stripe**: Payment processing
- **django-money**: Multi-currency support
- **requests**: Exchange rate API calls
- **celery**: Async tasks (exchange rate updates)

## Migration from Old Finance App

This app was created from the monolithic `finance` app models:
- ✅ `PaymentTransaction` (migrated)
- ✅ `PaymentMethod` (migrated)
- ✅ `RefundRequest` (migrated)
- ✅ Added: `Currency`, `ExchangeRate`, `PaymentIntent` (new)

All data preserved during migration with foreign key integrity maintained.
