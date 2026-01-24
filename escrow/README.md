# Escrow App

## Overview

The `escrow` app manages secure funds holding for marketplace contracts between service providers and clients. It ensures safe transactions by holding funds until work is delivered and approved.

**Schema**: TENANT (each tenant has isolated escrow data)

## Models

### EscrowTransaction
- **Purpose**: Secure funds holding for services and projects
- **Key Fields**:
  - payer, payee (User ForeignKeys)
  - amount, currency, status
  - service or project (Generic FK)
  - held_at, released_at
- **Features**: Multi-party escrow, automatic release, dispute handling

### MilestonePayment
- **Purpose**: Project milestone-based payments
- **Key Fields**:
  - escrow_transaction, milestone (Project FK)
  - amount, status, due_date
  - completed_at, approved_at
- **Features**: Conditional release on milestone completion

### EscrowRelease
- **Purpose**: Controlled fund release tracking
- **Key Fields**:
  - escrow_transaction, amount, released_to
  - release_type (full, partial, milestone)
  - authorized_by, released_at
- **Features**: Audit trail, approval workflow

### Dispute
- **Purpose**: Escrow dispute management
- **Key Fields**:
  - escrow_transaction, raised_by
  - reason, status, resolution
  - evidence (JSONField), resolved_at
- **Features**: Evidence submission, admin resolution, refund/release outcomes

### EscrowPayout
- **Purpose**: Payout execution tracking
- **Key Fields**:
  - escrow_transaction, amount, paid_to
  - payout_method, status, processed_at
- **Features**: Stripe payout integration, failure retry

### EscrowAudit
- **Purpose**: Complete audit trail for escrow actions
- **Key Fields**:
  - escrow_transaction, action, performed_by
  - before_status, after_status, metadata
- **Features**: Immutable log, compliance reporting

## Views

### Frontend (template_views.py)
- **EscrowDashboardView**: Overview of escrow activity
- **EscrowListView**: List all escrow transactions
- **EscrowDetailView**: Individual escrow details with timeline
- **MilestoneListView**: Project milestones with payment status
- **DisputeListView**: View and manage disputes

### API (api/viewsets.py)
- **EscrowTransactionViewSet**: CRUD for escrow (participant-only access)
- **MilestonePaymentViewSet**: Milestone payment management
- **EscrowReleaseViewSet**: Release history (read-only)
- **DisputeViewSet**: Dispute management
- **EscrowPayoutViewSet**: Payout tracking (read-only)
- **EscrowAuditViewSet**: Audit log (enterprise feature)

## API Endpoints

### Escrow Transactions
- **GET** `/api/v1/escrow/transactions/` - List escrow transactions
- **POST** `/api/v1/escrow/transactions/` - Create escrow (fund holding)
- **GET** `/api/v1/escrow/transactions/<id>/` - Get details
- **POST** `/api/v1/escrow/transactions/<id>/fund/` - Fund escrow
- **POST** `/api/v1/escrow/transactions/<id>/release/` - Release funds
- **POST** `/api/v1/escrow/transactions/<id>/refund/` - Refund to payer
- **POST** `/api/v1/escrow/transactions/<id>/mark-complete/` - Mark work complete

### Milestone Payments
- **GET** `/api/v1/escrow/milestones/` - List milestones
- **POST** `/api/v1/escrow/milestones/` - Create milestone payment
- **GET** `/api/v1/escrow/milestones/<id>/` - Get details
- **POST** `/api/v1/escrow/milestones/<id>/mark-completed/` - Provider marks complete
- **POST** `/api/v1/escrow/milestones/<id>/approve/` - Client approves
- **POST** `/api/v1/escrow/milestones/<id>/reject/` - Client rejects

### Disputes
- **GET** `/api/v1/escrow/disputes/` - List disputes
- **POST** `/api/v1/escrow/disputes/` - Open dispute
- **GET** `/api/v1/escrow/disputes/<id>/` - Get details
- **POST** `/api/v1/escrow/disputes/<id>/add-evidence/` - Submit evidence
- **POST** `/api/v1/escrow/disputes/<id>/resolve/` - Admin resolves
- **POST** `/api/v1/escrow/disputes/<id>/escalate/` - Escalate to support

## Permissions

- **IsEscrowParticipant**: User is payer or payee
- **CanReleaseEscrow**: Payer can release funds
- **CanOpenDispute**: Either party can open dispute
- **CanResolveDispute**: Admin/owner can resolve disputes

## Tasks (Celery)

- **process_escrow_releases**: Process scheduled escrow releases
- **auto_release_escrow**: Auto-release after approval period
- **notify_milestone_due**: Notify parties of upcoming milestone deadlines
- **escalate_unresolved_disputes**: Auto-escalate old disputes

## Signals

- **escrow_funded**: Triggered when escrow is funded
- **escrow_released**: Triggered when funds are released
- **dispute_opened**: Triggered when dispute is opened
- **dispute_resolved**: Triggered when dispute is resolved

## Escrow Workflow

```
1. Contract Created → Escrow Transaction Created (status: pending)
2. Payer Funds Escrow → Status: funded
3. Work Delivered → Provider marks complete
4. Client Reviews:
   a. Approves → Escrow Released → Status: released
   b. Disputes → Dispute Opened → Admin Resolution
5. Funds Released → Payout Processed → Status: completed
```

## Configuration

Environment variables:
- `ESCROW_AUTO_RELEASE_DAYS`: Days before auto-release (default: 7)
- `ESCROW_DISPUTE_RESOLUTION_SLA`: Max days for dispute resolution (default: 14)
- `ESCROW_MIN_AMOUNT`: Minimum escrow amount (default: 50.00)

## Integration Points

**Integrates with**:
- `services` app - Service contracts
- `projects` app - Project milestones
- `payments` app - Payment processing
- `stripe_connect` app - Marketplace payouts

## Security

- **Funds Safety**: Funds held in separate Stripe account
- **Access Control**: Only participants can view/act on escrow
- **Audit Trail**: All actions logged immutably
- **Dispute Evidence**: Encrypted storage of sensitive documents

## Testing

```bash
# Run tests
pytest escrow/tests/

# Test escrow workflow
pytest escrow/tests/test_escrow_workflow.py

# Test dispute resolution
pytest escrow/tests/test_disputes.py
```

## Dependencies

- **Stripe Connect**: Marketplace fund holding
- **payments** app: Payment processing
- **celery**: Scheduled releases and notifications

## Migration from Old Finance App

Migrated from monolithic `finance` app:
- ✅ `EscrowTransaction` (migrated)
- ✅ `Dispute` (migrated)
- ✅ `EscrowPayout` (migrated)
- ✅ `EscrowAudit` (migrated)
- ✅ Added: `MilestonePayment`, `EscrowRelease` (new)
