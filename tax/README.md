# Tax App

## Overview

Tax calculation, compliance, and Avalara integration for automated sales tax management.

**Schema**: TENANT (each tenant has own tax obligations)

## Models

- **AvalaraConfig**: Per-tenant Avalara settings
- **TaxRate**: Tax rates by jurisdiction
- **TaxCalculation**: Calculated taxes per transaction
- **TaxExemption**: Tax-exempt customers
- **TaxRemittance**: Tax payments to authorities
- **TaxReport**: Quarterly/annual tax reports

## Key Features

- **Avalara AvaTax Integration**: Real-time tax calculation
- **Multi-jurisdiction**: Handles complex tax nexus
- **Auto-updates**: Tax rates update automatically
- **Tax exemption certificates**
- **Compliance reporting**: Generate tax reports

## API Endpoints

- `GET/POST /api/v1/tax/config/` - Avalara configuration
- `POST /api/v1/tax/calculate/` - Calculate tax for transaction
- `GET /api/v1/tax/rates/` - Tax rates by jurisdiction
- `GET /api/v1/tax/reports/` - Tax reports
- `POST /api/v1/tax/reports/<id>/file/` - File tax return

## Integration

- **payments**: Tax calculation on transactions
- **accounting**: Tax liability journal entries
- Avalara AvaTax API

## Configuration

- `AVALARA_ACCOUNT_ID`: Avalara account ID
- `AVALARA_LICENSE_KEY`: Avalara license key (encrypted)
- `AVALARA_COMPANY_CODE`: Company code
- `AVALARA_ENVIRONMENT`: production/sandbox

## Testing

```bash
pytest tax/tests/
pytest tax/tests/test_avalara_integration.py
```
