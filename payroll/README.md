# Payroll App

## Overview

Employee payroll processing with automated tax calculation, direct deposit, and pay stub generation.

**Schema**: TENANT (each tenant manages own employee payroll)

## Models

- **PayrollRun**: Payroll cycle (weekly, biweekly, monthly)
- **EmployeePayment**: Individual employee payment records
- **DirectDeposit**: Bank account information for payments
- **PayStub**: Generated pay stubs (PDF)
- **PayrollDeduction**: Benefits, 401k, garnishments
- **PayrollTax**: Tax withholding tracking

## Key Features

- Automated payroll processing
- Tax calculation via `tax` app integration
- Direct deposit via Stripe/bank transfer
- Pay stub PDF generation
- Deductions management (benefits, 401k)
- Year-end tax forms (T4, W-2)

## API Endpoints

- `GET/POST /api/v1/payroll/runs/` - Payroll cycles
- `POST /api/v1/payroll/runs/<id>/approve/` - Approve payroll
- `POST /api/v1/payroll/runs/<id>/process/` - Execute payroll
- `GET /api/v1/payroll/payments/my-payments/` - Employee view
- `GET /api/v1/payroll/paystubs/<id>/download/` - Download PDF

## Integration

- **hr_core** app: Employee data (base_salary, deductions)
- **tax** app: Tax calculation
- **payments** app: Payment processing
- **accounting** app: Journal entries for payroll

## Testing

```bash
pytest payroll/tests/
pytest payroll/tests/test_payroll_processing.py
```
