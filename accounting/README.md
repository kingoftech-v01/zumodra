# Accounting App

## Overview

Accounting integration (QuickBooks, Xero) and financial reporting with double-entry bookkeeping.

**Schema**: TENANT (each tenant has own books)

## Models

- **AccountingProvider**: QuickBooks, Xero configuration
- **ChartOfAccounts**: Account mapping
- **JournalEntry**: Double-entry bookkeeping
- **JournalEntryLine**: Debit/credit lines
- **AccountingSyncLog**: Sync history
- **FinancialReport**: P&L, Balance Sheet, Cash Flow
- **ReconciliationRecord**: Bank reconciliation

## Key Features

- **QuickBooks Online** integration via OAuth
- **Xero** integration via OAuth
- Automatic journal entry creation
- Financial reports (P&L, Balance Sheet, Cash Flow)
- Bank reconciliation
- Multi-currency support

## API Endpoints

- `GET/POST /api/v1/accounting/providers/` - Accounting provider config
- `POST /api/v1/accounting/providers/<id>/connect/` - OAuth flow
- `POST /api/v1/accounting/providers/<id>/sync/` - Sync data
- `GET/POST /api/v1/accounting/journal-entries/` - Journal entries
- `GET /api/v1/accounting/reports/` - Financial reports
- `POST /api/v1/accounting/reports/generate/` - Generate report

## Integration

- **payments**: Revenue journal entries
- **payroll**: Payroll expense entries
- **expenses**: Expense entries
- **tax**: Tax liability entries
- QuickBooks Online API
- Xero API

## Configuration

- `QUICKBOOKS_CLIENT_ID`: QuickBooks OAuth client ID
- `QUICKBOOKS_CLIENT_SECRET`: QuickBooks OAuth secret
- `XERO_CLIENT_ID`: Xero OAuth client ID
- `XERO_CLIENT_SECRET`: Xero OAuth secret

## Testing

```bash
pytest accounting/tests/
pytest accounting/tests/test_quickbooks_sync.py
pytest accounting/tests/test_journal_entries.py
```

## Reports Available

- **Profit & Loss Statement** (P&L)
- **Balance Sheet**
- **Cash Flow Statement**
- **Accounts Receivable Aging**
- **Accounts Payable Aging**
- **General Ledger**
