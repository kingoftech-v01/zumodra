# Expenses App

## Overview

Business expense tracking, approval workflows, and employee reimbursement management.

**Schema**: TENANT

## Models

- **ExpenseCategory**: Categorization (travel, meals, supplies)
- **ExpenseReport**: Employee expense submissions
- **ExpenseLineItem**: Individual expenses
- **ExpenseApproval**: Multi-level approval workflow
- **Reimbursement**: Employee payouts
- **MileageRate**: IRS/CRA mileage rates

## Key Features

- Multi-level approval workflow
- Receipt upload and OCR
- Mileage tracking
- Policy enforcement
- Reimbursement via `payments` app
- Expense analytics and reporting

## API Endpoints

- `GET/POST /api/v1/expenses/reports/` - Expense reports
- `POST /api/v1/expenses/reports/<id>/submit/` - Submit for approval
- `POST /api/v1/expenses/approvals/<id>/approve/` - Approve
- `POST /api/v1/expenses/approvals/<id>/reject/` - Reject
- `GET /api/v1/expenses/reports/my-reports/` - Employee view

## Integration

- **hr_core**: Employee data
- **payments**: Reimbursement processing
- **accounting**: Expense journal entries

## Testing

```bash
pytest expenses/tests/
```
