# HR Core App

## Overview

The HR Core app provides comprehensive human resources management functionality including employee directory, time-off management, onboarding workflows, organizational charts, and HR analytics. It integrates seamlessly with the Jobs app to convert hired candidates into employees.

## Key Features

### Completed Features

- **Employee Directory**: Searchable employee directory with filtering
- **Employee Profiles**: Comprehensive employee records with documents
- **Time-Off Management**: Leave requests, approvals, balance tracking
- **Time-Off Calendar**: Visual calendar showing team absences
- **Onboarding Workflows**: Task-based onboarding checklists
- **Organizational Chart**: Interactive org chart visualization
- **Department Management**: Department structure and hierarchy

### In Development

- **Performance Reviews**: 360-degree feedback system
- **Resignation Workflows**: Notice period tracking, offboarding
- **HR Analytics**: Diversity metrics, turnover analysis, absence analytics
- **Payroll Integration**: Integration with Silae/Papaya
- **Benefits Management**: Health insurance, retirement plans
- **Training Management**: Course enrollment, certification tracking

## Architecture

### Models

Located in `hr_core/models.py`:

| Model | Description | Key Fields |
|-------|-------------|------------|
| **Employee** | Employee records | user, tenant, employee_id, department, position, hire_date, manager |
| **Department** | Departments | name, tenant, parent, manager, budget |
| **TimeOffPolicy** | Leave policies | name, tenant, days_per_year, accrual_type, carry_over |
| **TimeOffRequest** | Leave requests | employee, policy, start_date, end_date, status, reason, approver |
| **TimeOffBalance** | Leave balances | employee, policy, available_days, used_days, year |
| **OnboardingTemplate** | Onboarding checklist | name, tenant, department, tasks |
| **OnboardingTask** | Onboarding tasks | template, employee, title, description, due_date, completed |
| **Document** | Employee documents | employee, type, file, upload_date, expires_at |
| **PerformanceReview** | Reviews | employee, reviewer, period, rating, comments, status |
| **Goal** | Employee goals | employee, title, description, target_date, status, progress |

### Views

#### Frontend Views (`hr_core/template_views.py`)

**Employee Management:**
- `EmployeeDirectoryView` - Employee listing with search
- `EmployeeDetailView` - Employee profile page
- `EmployeeEditView` - Create/edit employee
- `EmployeeExportView` - Export employee data

**Time-Off:**
- `TimeOffCalendarView` - Visual absence calendar
- `TimeOffRequestView` - Submit leave request
- `MyTimeOffView` - Personal time-off dashboard
- `TimeOffApprovalView` - Approve/reject requests
- `TimeOffBalanceView` - View leave balances

**Onboarding:**
- `OnboardingDashboardView` - Onboarding overview
- `OnboardingDetailView` - Individual onboarding progress
- `OnboardingTaskCompleteView` - Mark task complete

**Organization:**
- `OrgChartView` - Organization chart page
- `OrgChartDataView` - JSON data for org chart
- `DepartmentListView` - Department management

**Analytics:**
- `HRAnalyticsView` - HR metrics dashboard
- `DiversityReportView` - Diversity analytics
- `AbsenceAnalyticsView` - Absence trends
- `TurnoverAnalyticsView` - Turnover analysis

#### API Views (`hr_core/api/`)

```
/api/v1/hr/employees/
/api/v1/hr/departments/
/api/v1/hr/time-off/
/api/v1/hr/onboarding/
/api/v1/hr/performance/
/api/v1/hr/analytics/
```

### URL Structure

```python
# Employees
frontend:hr:employee-directory
frontend:hr:employee-detail (pk)
frontend:hr:employee-create
frontend:hr:employee-edit (pk)

# Time-Off
frontend:hr:time-off-calendar
frontend:hr:time-off-request
frontend:hr:my-time-off
frontend:hr:time-off-approval (pk)

# Onboarding
frontend:hr:onboarding-dashboard
frontend:hr:onboarding-detail (pk)
frontend:hr:onboarding-task-complete (pk)

# Organization
frontend:hr:org-chart
frontend:hr:org-chart-data
```

### Templates

Located in `templates/hr_core/`:

**Employee:**
- `employee_directory.html` - Employee listing
- `employee_detail.html` - Employee profile
- `employee_form.html` - Employee create/edit

**Time-Off:**
- `time_off_calendar.html` - Calendar view
- `time_off_request.html` - Request form
- `my_time_off.html` - Personal dashboard

**Onboarding:**
- `onboarding_dashboard.html` - Overview
- `onboarding_detail.html` - Progress tracking

**Organization:**
- `org_chart.html` - Org chart visualization

## Integration Points

### With Other Apps

- **ATS**: Convert accepted offers to employee records
- **Accounts**: Employee user accounts and profiles
- **Tenants**: Multi-tenant isolation, department structure
- **Finance**: Payroll integration (planned)
- **Dashboard**: HR statistics and quick actions
- **Analytics**: HR metrics and reporting
- **Notifications**: Leave approval notifications

### External Services

- **Email**: Leave request notifications
- **Calendar**: Google Calendar/Microsoft 365 sync
- **Payroll**: Silae, Papaya (planned)
- **HRIS**: Lucca, HRWorks integration (planned)
- **Benefits**: Health insurance providers (planned)

## Security & Permissions

### Role-Based Access

| Role | Permissions |
|------|-------------|
| **PDG/CEO** | Full HR access, all employees, budgets |
| **HR Manager** | Manage employees, approve leaves, analytics |
| **Supervisor** | View team, approve team leaves |
| **Employee** | View own profile, request time-off |
| **Viewer** | Read-only access to directory |

### Data Privacy

- Salary information restricted to HR/CEO
- Personal data (SSN, medical) encrypted
- Document access logs
- GDPR data export/erasure support

## Database Considerations

### Indexes

Key indexes:
- Employee: `(tenant, department, is_active)`
- TimeOffRequest: `(employee, status, start_date)`
- OnboardingTask: `(employee, completed, due_date)`

### Relationships

```
Employee (N) ←→ (1) Department
Employee (1) ←→ (N) TimeOffRequest
Employee (1) ←→ (N) TimeOffBalance
Employee (1) ←→ (N) OnboardingTask
Employee (1) ←→ (N) PerformanceReview
Employee (1) ←→ (N) Document
```

## Future Improvements

### High Priority

1. **Resignation & Offboarding Automation**
   - Resignation request form
   - Notice period calculation
   - Automated offboarding checklist
   - Equipment return tracking
   - Exit interview scheduling
   - Access revocation workflows
   - Knowledge transfer tasks

2. **HR Analytics Dashboard**
   - Real-time diversity metrics (gender, age, seniority)
   - Absence rate and trends
   - Turnover rate by department
   - Headcount planning
   - Company health KPIs
   - Manager/employee ratio
   - Customizable dashboards

3. **Performance Review System**
   - Review cycles and templates
   - 360-degree feedback
   - Goal setting and tracking
   - Performance ratings
   - Development plans
   - Calibration meetings
   - Review reminders

4. **Payroll Integration**
   - Silae API integration (France)
   - Papaya Global integration
   - Automated payroll export
   - Salary slip uploads
   - Tax document management
   - Benefits deduction tracking

5. **Advanced Time-Off Features**
   - Partial day requests
   - Medical certificate uploads
   - Team capacity warnings
   - Conflict detection
   - Automatic accrual calculations
   - Carry-over policies
   - Leave forecasting

### Medium Priority

6. **Benefits Management**
   - Health insurance enrollment
   - Retirement plan management
   - Benefits comparison
   - Open enrollment periods
   - Dependent management
   - Wellness programs

7. **Training & Development**
   - Course catalog
   - Enrollment workflows
   - Certification tracking
   - Training budget management
   - Skills gap analysis
   - Compliance training

8. **Compensation Management**
   - Salary bands by role
   - Compensation planning
   - Bonus calculations
   - Equity management
   - Pay equity analysis
   - Salary review cycles

9. **Workforce Planning**
   - Headcount forecasting
   - Budget planning
   - Succession planning
   - Skills inventory
   - Resource allocation
   - Contingent workforce tracking

10. **Employee Self-Service**
    - Personal info updates
    - Document downloads
    - Benefits selection
    - Directory search
    - Org chart navigation
    - Time tracking

### Low Priority

11. **Mobile HR App**
    - Leave requests on mobile
    - Time clock check-in/out
    - Push notifications
    - Team directory
    - Org chart mobile view

12. **Advanced Analytics**
    - Predictive turnover modeling
    - Flight risk detection
    - Burnout indicators
    - Engagement surveys
    - Sentiment analysis

13. **Compliance Tools**
    - Labor law compliance checks
    - Audit trail reports
    - Document retention policies
    - E-verify integration
    - Background check tracking

## Testing

### Test Coverage

Target: 90%+ coverage for all HR workflows

### Test Structure

```
tests/
├── test_hr_models.py         # Model tests
├── test_hr_views.py          # View tests
├── test_hr_api.py            # API tests
├── test_time_off.py          # Time-off workflow tests
├── test_onboarding.py        # Onboarding tests
├── test_hr_permissions.py    # Permission tests
└── test_hr_integration.py    # Integration tests
```

### Key Test Scenarios

- Employee creation from ATS offer
- Time-off request and approval flow
- Accrual calculations
- Onboarding task completion
- Permission enforcement
- Tenant isolation
- Calendar sync

## Performance Optimization

### Current Optimizations

- Employee queries with department prefetch
- Time-off calendar view caching
- Org chart data caching
- Pagination for large employee lists

### Planned Optimizations

- Redis caching for org chart
- Elasticsearch for employee search
- Background accrual calculations
- Async notification sending

## Compliance Requirements

### Data Retention

- Employee records: 7 years post-termination
- Payroll records: 7 years
- Benefits records: 6 years
- Performance reviews: 3 years
- Time-off records: 3 years

### Regulatory Compliance

- **GDPR** (EU): Right to access, rectify, erase
- **PIPEDA** (Canada): Consent for data collection
- **Labor Standards**: Minimum leave requirements
- **Tax Compliance**: T4/W2 forms, deductions
- **ACA** (US): Benefits reporting

## Migration Notes

When modifying HR models:

```bash
# Create migrations
python manage.py makemigrations hr_core

# Apply to all tenant schemas
python manage.py migrate_schemas --tenant

# Verify
python manage.py check
```

## Contributing

When adding HR features:

1. Consider compliance implications
2. Ensure data privacy protection
3. Test permission boundaries
4. Document data retention policies
5. Update analytics if adding metrics
6. Maintain tenant isolation

## Support

For questions or issues:
- Review labor law requirements for your jurisdiction
- Check GDPR compliance checklist
- Consult [SECURITY.md](../docs/SECURITY.md) for data protection

---

**Last Updated:** January 2026
**Module Version:** 1.0
**Status:** Production
