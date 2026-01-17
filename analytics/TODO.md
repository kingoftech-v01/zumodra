# Analytics App TODO

**Last Updated:** 2026-01-16
**Total Items:** 1
**Status:** Production

## Overview
The analytics app provides comprehensive reporting, data visualization, metrics tracking, and export capabilities for all platform modules (ATS, HR, Finance, Services).

## High Priority

### [TODO-ANALYTICS-001] Add openpyxl Dependency to Requirements
- **Priority:** High
- **Category:** Dependencies
- **Status:** Not Started
- **Effort:** Trivial (15min)
- **File:** `analytics/services.py:1522`
- **Description:**
  Add `openpyxl` package to requirements.txt to enable Excel export functionality in analytics reports.
- **Context:**
  The `export_to_excel()` method in AnalyticsService attempts to import openpyxl but raises `NotImplementedError` if the package is not installed. Excel export is a core feature expected by users.
- **Acceptance Criteria:**
  - [ ] Add `openpyxl>=3.1.0` to requirements/base.txt
  - [ ] Verify version compatibility with current Python version (3.11+)
  - [ ] Update requirements.txt (if separate from requirements/base.txt)
  - [ ] Test Excel export functionality works after installation
  - [ ] Remove or update the NotImplementedError exception handling
  - [ ] Rebuild Docker images with new dependency
  - [ ] Update documentation mentioning Excel export capabilities
- **Dependencies:**
  - None (standard package)
- **Notes:**
  - Line 1518-1522 in services.py
  - Currently wrapped in try/except ImportError
  - Excel export is commonly requested feature
  - Consider adding xlsxwriter as alternative (lighter weight)
  - openpyxl supports both .xlsx reading and writing
  - Latest stable version is 3.1.x series

---

## Completed Items
_Completed TODOs will be moved here with completion date._

---

**Note:** When adding new TODOs, use format `[TODO-ANALYTICS-XXX]` and update the central [TODO.md](../TODO.md) index.
