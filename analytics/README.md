# Analytics App

## Overview

Analytics dashboards and reporting for recruitment, finance, and services.

**Schema**: TENANT

## Features

- Recruitment analytics (time-to-hire, source effectiveness)
- Financial analytics (revenue, MRR, churn)
- Services analytics (provider performance)
- HR analytics (turnover, time-off trends)
- Custom report generation (PDF, CSV, Excel)

## API Endpoints

### Dashboards
- **GET** `/api/v1/analytics/recruitment/` - Recruitment metrics
- **GET** `/api/v1/analytics/financial/` - Financial metrics
- **GET** `/api/v1/analytics/services/` - Services metrics
- **GET** `/api/v1/analytics/hr/` - HR metrics

### Reports
- **POST** `/api/v1/analytics/reports/generate/` - Generate report
- **GET** `/api/v1/analytics/reports/` - List reports
- **GET** `/api/v1/analytics/reports/<id>/download/` - Download report

## Metrics Tracked

**Recruitment**:
- Time-to-hire
- Source effectiveness
- Candidate pipeline conversion
- Interview-to-offer ratio

**Financial**:
- MRR (Monthly Recurring Revenue)
- ARR (Annual Recurring Revenue)
- Churn rate
- Revenue by service/product

**Services**:
- Provider performance
- Service completion rate
- Average ratings
- Revenue per provider

**HR**:
- Employee turnover
- Time-off utilization
- Department headcount
- Compensation trends

## Permissions

- `IsAnalyticsAdmin`: Full access to all analytics
- Standard users: Limited to their own data

## Tasks (Celery)

- `sync_analytics_data`: Update analytics aggregations
- `daily_analytics_cleanup`: Archive old reports

## Testing

```bash
pytest analytics/tests/
```
