# Zumodra TODO Index

**Last Updated:** 2026-01-17
**Total TODOs:** 16 (15 documented + 1 future audit scheduled)
**Status:** Active tracking

## Quick Stats

- **Critical Priority:** 1 item (comprehensive TODO audit - scheduled)
- **High Priority:** 6 items (critical features, user-facing gaps)
- **Medium Priority:** 4 items (test coverage, enhancements)
- **Low Priority:** 5 items (abstract methods, edge cases)
- **Completed:** 1 item (openpyxl dependency)

---

## By Priority

### Critical Priority (Project-Wide)

17. **[Project] Comprehensive TODO Audit** → Scheduled for future
   _Audit all 429 files with TODO/FIXME comments, filter out dependencies/migrations, document remaining actionable items_

### High Priority (Core Features)

1. **[Appointment] Cancellation Logic** → [appointment/TODO.md#TODO-APPT-001](appointment/TODO.md#todo-appt-001)
   _Complete customer cancellation workflow with refunds and notifications_

2. **[ATS] Placeholder Views** → [ats/TODO.md#TODO-ATS-001](ats/TODO.md#todo-ats-001)
   _Implement 5 commented-out views: candidate edit, import, notes, tags, application list_

3. **[Careers] Geocoding for Locations** → [careers/TODO.md#TODO-CAREERS-001](careers/TODO.md#todo-careers-001)
   _Add map markers for company locations via geocoding API_

4. **[Careers] Project Proposal Counts** → [careers/TODO.md#TODO-CAREERS-002](careers/TODO.md#todo-careers-002)
   _Display actual proposal counts instead of hardcoded 0_

5. **[Careers] Client Spending Amounts** → [careers/TODO.md#TODO-CAREERS-003](careers/TODO.md#todo-careers-003)
   _Show actual client spending on projects_

6. **[Tenants] EIN Verification API** → [tenants/TODO.md#TODO-TENANTS-001](tenants/TODO.md#todo-tenants-001)
   _Integrate real EIN verification service (currently stubbed)_

### Medium Priority (Enhancements)

7. **[Newsletter] Subscription Test Coverage** → [newsletter/TODO.md#TODO-NEWSLETTER-TEST-001](newsletter/TODO.md#todo-newsletter-test-001)
   _Test coverage for subscription view else branch_

8. **[Newsletter] Exception Handling Tests** → [newsletter/TODO.md#TODO-NEWSLETTER-TEST-002](newsletter/TODO.md#todo-newsletter-test-002)
   _Test coverage for message sending exception handler_

9. **[Appointment] Date Formatting Enhancement** → [appointment/TODO.md#TODO-APPT-002](appointment/TODO.md#todo-appt-002)
    _Consider using Django's FORMAT_MODULE_PATH for better i18n_

10. **[Integrations] Unsupported Calendar Providers** → [integrations/TODO.md#TODO-INTEGRATIONS-001](integrations/TODO.md#todo-integrations-001)
    _Add support for additional calendar providers beyond Google/Outlook_

### Low Priority (Nice-to-Have)

11. **[Newsletter] Abstract Subscription Generator** → [newsletter/TODO.md#TODO-NEWSLETTER-002](newsletter/TODO.md#todo-newsletter-002)
    _Abstract method - subclasses must implement (by design)_

12. **[Appointment] Night Shift Edge Case** → [appointment/TODO.md#TODO-APPT-TEST-001](appointment/TODO.md#todo-appt-test-001)
    _Consider supporting businesses with night shifts (start time > end time)_

13. **[Core] Sync Service Abstract Methods** → [core/TODO.md#TODO-CORE-001](core/TODO.md#todo-core-001)
    _Abstract base class - subclasses must implement (by design)_

14. **[Integrations] Unsupported Job Board Providers** → [integrations/TODO.md#TODO-INTEGRATIONS-002](integrations/TODO.md#todo-integrations-002)
    _Add support for job boards beyond LinkedIn and Indeed_

15. **[Integrations] Token Refresh Implementation** → [integrations/TODO.md#TODO-INTEGRATIONS-003](integrations/TODO.md#todo-integrations-003)
    _Provider-specific token refresh (abstract method)_

---

## By Category

### Project Management (1 item)

- **[TODO-PROJECT-001]** Comprehensive TODO audit (429 files) → Critical (scheduled)

### Features (7 items)

- **[TODO-APPT-001]** Appointment cancellation logic → High
- **[TODO-ATS-001]** ATS placeholder views → High
- **[TODO-CAREERS-001]** Geocoding for locations → High
- **[TODO-CAREERS-002]** Project proposal counts → High
- **[TODO-CAREERS-003]** Client spending amounts → High
- **[TODO-TENANTS-001]** EIN verification API → High
- **[TODO-INTEGRATIONS-001]** Additional calendar providers → Medium
- **[TODO-INTEGRATIONS-002]** Additional job board providers → Low

### Bug Fixes (0 items)

_No bug fixes tracked at this time_

### Test Coverage (4 items)

- **[TODO-NEWSLETTER-TEST-001]** Subscription view test coverage → Medium
- **[TODO-NEWSLETTER-TEST-002]** Exception handling test coverage → Medium
- **[TODO-APPT-TEST-001]** Night shift edge case test → Low

### Documentation (1 item)

- **[TODO-APPT-002]** Date formatting documentation → Medium

### Technical Debt (0 items)

_No technical debt tracked at this time_

### Dependencies (3 items)

- **[TODO-NEWSLETTER-002]** Abstract subscription generator → Low (by design)
- **[TODO-CORE-001]** Sync service abstract methods → Low (by design)
- **[TODO-INTEGRATIONS-003]** Token refresh abstract method → Low (by design)

---

## By App

| App | Total | High | Medium | Low | Link |
|-----|-------|------|--------|-----|------|
| **accounts** | 0 | 0 | 0 | 0 | [accounts/TODO.md](accounts/TODO.md) |
| **admin_honeypot** | 0 | 0 | 0 | 0 | [admin_honeypot/TODO.md](admin_honeypot/TODO.md) |
| **ai_matching** | 0 | 0 | 0 | 0 | [ai_matching/TODO.md](ai_matching/TODO.md) |
| **analytics** | 0 | 0 | 0 | 0 | [analytics/TODO.md](analytics/TODO.md) |
| **appointment** | 3 | 1 | 1 | 1 | [appointment/TODO.md](appointment/TODO.md) |
| **ats** | 1 | 1 | 0 | 0 | [ats/TODO.md](ats/TODO.md) |
| **blog** | 0 | 0 | 0 | 0 | [blog/TODO.md](blog/TODO.md) |
| **careers** | 3 | 3 | 0 | 0 | [careers/TODO.md](careers/TODO.md) |
| **configurations** | 0 | 0 | 0 | 0 | [configurations/TODO.md](configurations/TODO.md) |
| **core** | 1 | 0 | 0 | 1 | [core/TODO.md](core/TODO.md) |
| **custom_account_u** | 0 | 0 | 0 | 0 | [custom_account_u/TODO.md](custom_account_u/TODO.md) |
| **dashboard** | 0 | 0 | 0 | 0 | [dashboard/TODO.md](dashboard/TODO.md) |
| **dashboard_service** | 0 | 0 | 0 | 0 | [dashboard_service/TODO.md](dashboard_service/TODO.md) |
| **finance** | 0 | 0 | 0 | 0 | [finance/TODO.md](finance/TODO.md) |
| **hr_core** | 0 | 0 | 0 | 0 | [hr_core/TODO.md](hr_core/TODO.md) |
| **integrations** | 3 | 0 | 1 | 2 | [integrations/TODO.md](integrations/TODO.md) |
| **main** | 0 | 0 | 0 | 0 | [main/TODO.md](main/TODO.md) |
| **marketing** | 0 | 0 | 0 | 0 | [marketing/TODO.md](marketing/TODO.md) |
| **messages_sys** | 0 | 0 | 0 | 0 | [messages_sys/TODO.md](messages_sys/TODO.md) |
| **newsletter** | 3 | 0 | 2 | 1 | [newsletter/TODO.md](newsletter/TODO.md) |
| **notifications** | 0 | 0 | 0 | 0 | [notifications/TODO.md](notifications/TODO.md) |
| **services** | 0 | 0 | 0 | 0 | [services/TODO.md](services/TODO.md) |
| **tenants** | 1 | 1 | 0 | 0 | [tenants/TODO.md](tenants/TODO.md) |

---

## Completion Tracking

**Overall Progress:**

```
[████████████████░░░░] 80% (18/23 apps fully documented)
```

- **Apps with TODOs:** 8 apps
- **Apps without TODOs:** 15 apps
- **Total Items:** 15 across all apps

---

## How to Use This Index

1. **Find TODOs by priority:** Check "By Priority" section for critical items
2. **Find TODOs by category:** Check "By Category" for features, bugs, tests, etc.
3. **Find TODOs by app:** Check "By App" table and follow the link
4. **Update TODOs:** Edit the specific app's TODO.md file, then update this index
5. **Complete TODOs:** Mark as completed in app TODO.md and move to "Completed" section

---

## Contributing

When adding new TODOs:

1. **Never add inline TODO comments** in code
2. Add to the appropriate `{app}/TODO.md` file first
3. Assign unique ID: `TODO-{APP}-XXX` (e.g., `TODO-ATS-042`)
4. Update this central index with links
5. In code, reference: `# See TODO-{APP}-XXX in {app}/TODO.md`

---

## Related Documentation

- [CLAUDE.md](CLAUDE.md) - Project development guidelines
- [README.md](README.md) - Project overview and quick start
- [docs/DOCUMENTATION_GUIDE.md](docs/DOCUMENTATION_GUIDE.md) - Documentation standards

---

**Note:** This is a living document. Update it whenever TODOs are added, modified, or completed.
