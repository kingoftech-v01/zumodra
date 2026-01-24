# Appointment App TODO

**Last Updated:** 2026-01-17
**Total Items:** 2 (2 remaining)
**Status:** Production

## Overview
The appointment app provides booking system functionality with staff scheduling, time slots, service management, and customer appointment workflows.

## High Priority

No high priority items at this time.

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

### [TODO-APPT-001] Implement Complete Cancellation Logic ✅

- **Completed:** 2026-01-17
- **Priority:** High
- **Category:** Feature
- **Effort:** Large (6-8h)
- **Files:**
  - `appointment/models.py` (lines 605-681, 851-949)
  - `appointment/migrations/0002_add_cancellation_fields.py`
  - `appointment/tasks.py` (lines 79-326)
  - `appointment/views_customer.py` (lines 150-195)
  - `templates/email_sender/cancellation_confirmation.html`
  - `templates/email_sender/staff_cancellation_notice.html`

- **Description:**
  Implemented complete appointment cancellation workflow with policy checks, automatic refund calculation, async processing, and email notifications.

- **Resolution:**
  - ✅ Added status field to Appointment model (pending, confirmed, completed, cancelled, no_show)
  - ✅ Added cancellation tracking fields: cancelled_at, cancelled_by, cancellation_reason
  - ✅ Added refund tracking fields: refund_amount, refund_status, refund_processed_at
  - ✅ Implemented cancellation policy checks via can_be_cancelled() method (24-hour notice)
  - ✅ Implemented tiered refund calculation via calculate_refund_amount() method
  - ✅ Created Celery task process_appointment_cancellation for async processing
  - ✅ Integrated with finance app for refund processing (with graceful fallback)
  - ✅ Updated cancellation view to use async task processing
  - ✅ Created customer cancellation confirmation email template
  - ✅ Created staff cancellation notification email template
  - ✅ Added database indexes for query performance (status, refund_status)
  - ✅ Implemented edge case handling (past appointments, already cancelled, etc.)

- **Implementation Notes:**

  **Cancellation Policy:**
  - Full refund (100%): More than 24 hours notice
  - Partial refund (50%): 12-24 hours notice
  - No refund: Less than 12 hours notice

  **Model Fields Added:**
  - `status`: CharField with choices (pending, confirmed, completed, cancelled, no_show)
  - `cancelled_at`: DateTimeField for cancellation timestamp
  - `cancelled_by`: ForeignKey to User who cancelled
  - `cancellation_reason`: TextField for optional reason
  - `refund_amount`: DecimalField for calculated refund
  - `refund_status`: CharField (none, pending, processed, failed)
  - `refund_processed_at`: DateTimeField for refund completion

  **Helper Methods:**
  - `is_cancelled()`: Check if appointment is cancelled
  - `can_be_cancelled(policy_hours=24)`: Validate cancellation eligibility
  - `calculate_refund_amount(policy_hours=24)`: Calculate refund based on timing
  - `get_hours_until_appointment()`: Get time remaining until appointment

  **Celery Task:**
  - Async processing with 2-second delay for transaction commit
  - Automatic retries (3 attempts) with exponential backoff
  - Graceful fallback if finance app unavailable (manual review queue)
  - Email notifications sent asynchronously

  **Email Templates:**
  - Customer: Cancellation confirmation with refund details
  - Staff: Cancellation notice to update schedule

- **Usage:**

  ```python
  # Cancel appointment via API
  POST /api/appointments/{id}/cancel/
  {
      "reason": "Personal emergency"  # Optional
  }

  # Response includes refund info
  {
      "success": true,
      "message": "Appointment cancelled. Refund of $50.00 USD...",
      "data": {
          "appointment_id": 123,
          "refund_amount": 50.00,
          "task_id": "abc123"
      }
  }
  ```

- **Testing Notes:**
  - Comprehensive test coverage still needed (acceptance criterion not met)
  - Manual testing recommended for refund processing flow
  - Test cancellation at different time intervals (>24h, 12-24h, <12h)

- **Future Enhancements:**
  - Admin dashboard view for cancelled appointments
  - Customizable cancellation policies per service/business
  - SMS notifications option
  - Audit log integration

---

**Note:** When adding new TODOs, use format `[TODO-APPT-XXX]` and update the central [TODO.md](../TODO.md) index.
