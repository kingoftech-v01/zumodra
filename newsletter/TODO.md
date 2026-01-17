# Newsletter App TODO

**Last Updated:** 2026-01-16
**Total Items:** 3
**Status:** Production

## Overview
The newsletter app provides email newsletter subscription management, message creation, submission scheduling, and multi-channel delivery for tenant communication.

## Medium Priority

### [TODO-NEWSLETTER-TEST-001] Add Test Coverage for Subscription View Else Branch
- **Priority:** Medium
- **Category:** Test Coverage
- **Status:** Not Started
- **Effort:** Small (1h)
- **File:** `newsletter/views.py:521`
- **Description:**
  Add test case covering the else branch in `get_initial()` method when no activation_code is present.
- **Context:**
  The `UpdateSubscriptionView.get_initial()` method has an else branch (line 521) that returns `None` when `self.activation_code` is not set. This branch lacks test coverage.
- **Acceptance Criteria:**
  - [ ] Create test case instantiating UpdateSubscriptionView without activation_code
  - [ ] Call `get_initial()` and assert it returns None
  - [ ] Verify form renders correctly with None initial data
  - [ ] Add docstring explaining what scenario this tests
  - [ ] Run coverage report to verify branch is now covered
- **Dependencies:**
  - None
- **Notes:**
  - Line 520-522 in views.py
  - Simple test, good for code coverage improvement
  - Part of subscription activation workflow

### [TODO-NEWSLETTER-TEST-002] Add Test Coverage for Message Send Exception Handler
- **Priority:** Medium
- **Category:** Test Coverage
- **Status:** Not Started
- **Effort:** Small (1-2h)
- **File:** `newsletter/models.py:752`
- **Description:**
  Add test case covering the exception handler in `Submission.send_message()` method when message sending fails.
- **Context:**
  The `send_message()` method has a try/except block (line 749-758) that logs errors when `message.send()` fails. This exception path is not covered by tests.
- **Acceptance Criteria:**
  - [ ] Create test that mocks `message.send()` to raise an exception
  - [ ] Verify error is logged with correct message format
  - [ ] Assert subscription is marked appropriately (if applicable)
  - [ ] Test various exception types (SMTPException, ConnectionError, etc.)
  - [ ] Verify submission state remains consistent after failure
  - [ ] Run coverage report to verify exception branch is covered
- **Dependencies:**
  - Mock library for simulating send failures
- **Notes:**
  - Lines 749-758 in models.py
  - Error logging uses gettext for i18n
  - Important for production reliability testing
  - May reveal need for retry logic or dead letter queue

## Low Priority

### [TODO-NEWSLETTER-002] Abstract Subscription Generator Method
- **Priority:** Low
- **Category:** Architecture (By Design)
- **Status:** Not Started (Expected Behavior)
- **Effort:** N/A
- **File:** `newsletter/models.py:603`
- **Description:**
  The `generate_subscriptions()` method in `NewsletterListManager` raises `NotImplementedError` - this is intentional abstract method behavior.
- **Context:**
  This is an abstract base class. Subclasses are expected to implement `generate_subscriptions()` with their own logic for generating subscription lists from different sources.
- **Resolution:**
  - This is working as designed - no action needed
  - Abstract methods must be overridden by concrete implementations
  - Consider if explicit ABC (Abstract Base Class) inheritance would clarify intent
- **Possible Enhancement:**
  - [ ] Inherit from `abc.ABC` and mark method with `@abstractmethod` decorator
  - [ ] Add docstring examples showing how subclasses should implement
  - [ ] Update any existing subclasses to confirm they implement this method
- **Dependencies:**
  - None
- **Notes:**
  - Line 598-603 in models.py
  - Not a bug - architectural pattern
  - Low priority since current implementation works correctly

---

## Completed Items
_Completed TODOs will be moved here with completion date._

---

**Note:** When adding new TODOs, use format `[TODO-NEWSLETTER-XXX]` and update the central [TODO.md](../TODO.md) index.
