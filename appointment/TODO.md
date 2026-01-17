# Appointment App TODO

**Last Updated:** 2026-01-16
**Total Items:** 3
**Status:** Production

## Overview
The appointment app provides booking system functionality with staff scheduling, time slots, service management, and customer appointment workflows.

## High Priority

### [TODO-APPT-001] Implement Complete Cancellation Logic
- **Priority:** High
- **Category:** Feature
- **Status:** Not Started
- **Effort:** Large (6-8h)
- **File:** `appointment/views_customer.py:156`
- **Description:**
  Implement full customer appointment cancellation workflow including policy checks, refunds, notifications, and status updates.
- **Context:**
  Currently the cancellation endpoint returns a placeholder message directing users to contact support. This is incomplete user experience and creates manual work for support staff.
- **Acceptance Criteria:**
  - [ ] Implement cancellation policy checks (e.g., 24-hour notice requirement)
  - [ ] Calculate refund amounts based on cancellation policy and timing
  - [ ] Integrate with payment/finance app for refund processing
  - [ ] Update appointment status to 'cancelled'
  - [ ] Send cancellation confirmation email to customer
  - [ ] Send cancellation notification to assigned staff member
  - [ ] Log cancellation in appointment history/audit trail
  - [ ] Handle edge cases (same-day appointments, no-show policy)
  - [ ] Add cancellation reason field (optional text input)
  - [ ] Create Celery task for async refund processing
  - [ ] Add admin dashboard view of cancelled appointments
  - [ ] Write comprehensive test coverage for all scenarios
- **Dependencies:**
  - finance app refund processing functionality
  - notification system for email/SMS alerts
  - Celery for async task processing
- **Notes:**
  - Current placeholder in views_customer.py lines 156-167
  - May need new model fields: cancellation_reason, cancelled_at, cancelled_by
  - Consider partial refunds based on cancellation timing
  - Some businesses may want non-refundable appointments

## Medium Priority

### [TODO-APPT-002] Consider Using Django's FORMAT_MODULE_PATH
- **Priority:** Medium
- **Category:** Documentation / Enhancement
- **Status:** Not Started
- **Effort:** Small (1-2h)
- **File:** `appointment/views.py:221`
- **Description:**
  Evaluate and document whether to migrate from custom DATE_FORMATS dictionary to Django's official FORMAT_MODULE_PATH for better i18n support.
- **Context:**
  Currently uses custom dictionary in utils.date_time.py to handle different date formats per language (French vs English punctuation). Developer notes this is "ugly but necessary" because Django's DATE_FORMAT doesn't include weekdays.
- **Acceptance Criteria:**
  - [ ] Research Django's FORMAT_MODULE_PATH approach
  - [ ] Compare complexity vs current dictionary approach
  - [ ] Test weekday formatting in target languages (en, fr, etc.)
  - [ ] Document pros/cons of each approach
  - [ ] Make recommendation in this TODO
  - [ ] If migrating, create format files per language
  - [ ] Update DATE_FORMATS usage across app
  - [ ] Add contributor documentation for adding new languages
- **Dependencies:**
  - None
- **Notes:**
  - Current approach is in appointment/utils/date_time.py
  - Used in lines 221-230 of views.py
  - Trade-off: simplicity vs "official" Django way
  - Current format examples: French "jeu 14 août 2025", English "Thu, August 14, 2025"

## Low Priority

### [TODO-APPT-TEST-001] Night Shift Edge Case Test Coverage
- **Priority:** Low
- **Category:** Test Coverage
- **Status:** Not Started
- **Effort:** Small (1-2h)
- **File:** `appointment/tests/models/test_config.py:114`
- **Description:**
  Consider adding support and test coverage for businesses with night shifts where start time > end time (e.g., 10 PM to 6 AM).
- **Context:**
  Current validation requires lead_time < finish_time, which prevents night shift configurations. Developer notes uncertainty about whether clients will need this feature.
- **Acceptance Criteria:**
  - [ ] Gather user research on night shift business needs
  - [ ] If needed, update Config model validation to allow start > end
  - [ ] Handle date rollovers (appointment spans midnight)
  - [ ] Update slot generation logic for cross-midnight ranges
  - [ ] Add test cases for night shift scenarios
  - [ ] Document night shift configuration in admin docs
- **Dependencies:**
  - User research/product decision on priority
- **Notes:**
  - Test exists at line 114 of test_config.py
  - Current validation: lead_time must be < finish_time
  - Examples: late-night restaurants, 24-hour services, overnight shifts
  - May need to distinguish "next day" vs "same day" appointments
  - Consider timezone complications

---

## Completed Items
_Completed TODOs will be moved here with completion date._

---

**Note:** When adding new TODOs, use format `[TODO-APPT-XXX]` and update the central [TODO.md](../TODO.md) index.
