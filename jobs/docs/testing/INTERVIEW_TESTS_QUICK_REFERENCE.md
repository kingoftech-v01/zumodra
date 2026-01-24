# Interview Workflow Tests - Quick Reference

**Total Tests:** 70+
**File:** `/c/Users/techn/OneDrive/Documents/zumodra/test_interview_workflow.py`

---

## Test Index by Category

### 1. Interview Creation Tests (6 tests)

```bash
pytest test_interview_workflow.py::TestInterviewCreation -v
```

| Test | What It Tests | Expected Result |
|------|---------------|-----------------|
| `test_create_basic_interview` | Basic interview creation | Interview created with correct fields |
| `test_create_interview_with_all_types` | All 10 interview types | All types creatable (phone, video, technical, panel, etc.) |
| `test_create_interview_with_meeting_providers` | 5 meeting providers | All providers supported (zoom, teams, meet, webex, custom) |
| `test_interview_duration_calculation` | Duration in minutes | 90 minutes calculated correctly for 1.5-hour interview |
| `test_interview_with_timezone` | Timezone handling | Timezone and candidate timezone stored correctly |
| `test_interview_with_template` | Template application | Template applied, interview type and duration set |

---

### 2. Form Validation Tests (7 tests)

```bash
pytest test_interview_workflow.py::TestInterviewFormValidation -v
```

| Test | What It Tests | Expected Result |
|------|---------------|-----------------|
| `test_interview_schedule_form_valid` | Valid form data | Form is valid, no errors |
| `test_interview_schedule_form_invalid_end_before_start` | End time validation | Form rejects end time before start time |
| `test_interview_schedule_form_invalid_meeting_link` | URL validation | Form rejects URL without http:// or https:// |
| `test_interview_schedule_form_xss_sanitization` | XSS prevention | Script tags removed from title |
| `test_interview_feedback_form_valid` | Valid feedback | Form accepts all fields correctly |
| `test_interview_feedback_form_invalid_rating` | Rating validation | Form rejects rating > 5 or < 1 |
| `test_interview_feedback_form_missing_recommendation` | Required fields | Form rejects feedback without recommendation |

---

### 3. Scheduling Tests (7 tests)

```bash
pytest test_interview_workflow.py::TestInterviewScheduling -v
```

| Test | What It Tests | Expected Result |
|------|---------------|-----------------|
| `test_schedule_interview_basic` | Basic scheduling | Interview status is "scheduled", times set |
| `test_schedule_interview_with_multiple_interviewers` | Panel interviews | Multiple interviewers added to M2M relationship |
| `test_schedule_interview_sends_notifications` | Notifications | candidate_notified and interviewers_notified flags set |
| `test_interview_calendar_event_tracking` | Calendar integration | calendar_event_id and calendar_provider stored |
| `test_interview_confirmed_by_candidate` | Candidate confirmation | Status changes to "confirmed", confirmed_at timestamp set |
| `test_interview_start_tracking` | Mark as in progress | Status changes to "in_progress", actual_start timestamp set |
| `test_interview_completion_tracking` | Mark as completed | Status changes to "completed", actual_end timestamp set |

---

### 4. Rescheduling Tests (4 tests)

```bash
pytest test_interview_workflow.py::TestInterviewRescheduling -v
```

| Test | What It Tests | Expected Result |
|------|---------------|-----------------|
| `test_reschedule_interview_basic` | Basic reschedule | scheduled_start/end updated, reschedule_count=1 |
| `test_reschedule_interview_multiple_times` | Multiple reschedules | reschedule_count incremented each time |
| `test_reschedule_resets_reminder_flags` | Reminder reset | All reminder flags set to False |
| `test_reschedule_sends_notifications` | Notifications sent | Reschedule notifications sent to candidates/interviewers |

---

### 5. Cancellation Tests (4 tests)

```bash
pytest test_interview_workflow.py::TestInterviewCancellation -v
```

| Test | What It Tests | Expected Result |
|------|---------------|-----------------|
| `test_cancel_interview_basic` | Basic cancellation | Status="cancelled", cancelled_at timestamp set |
| `test_cancel_interview_preserves_reason` | Reason tracking | cancellation_reason field populated |
| `test_cancel_interview_removes_reminders` | Reminder prevention | needs_1day_reminder returns False for cancelled interview |
| `test_cancel_interview_sends_notifications` | Notifications | Cancellation notifications sent |

---

### 6. Feedback Tests (7 tests)

```bash
pytest test_interview_workflow.py::TestInterviewFeedback -v
```

| Test | What It Tests | Expected Result |
|------|---------------|-----------------|
| `test_create_feedback_basic` | Basic feedback | Feedback object created with ratings and notes |
| `test_create_feedback_with_ratings` | Detailed ratings | All 5 rating fields saved (overall, technical, communication, cultural fit, problem-solving) |
| `test_feedback_recommendations` | All recommendations | All 5 recommendation options work (strong_yes, yes, maybe, no, strong_no) |
| `test_feedback_unique_per_interviewer` | Unique constraint | Database constraint prevents duplicate feedback from same interviewer |
| `test_multiple_interviewers_feedback` | Panel feedback | Multiple interviewers can submit feedback on same interview |
| `test_all_feedback_submitted_check` | Completion check | all_feedback_submitted property returns True when all interviewers submit feedback |
| `test_feedback_with_custom_ratings` | Custom criteria | custom_ratings JSON field stores additional rating criteria |

---

### 7. Reminder Tests (5 tests)

```bash
pytest test_interview_workflow.py::TestInterviewReminders -v
```

| Test | What It Tests | Expected Result |
|------|---------------|-----------------|
| `test_interview_needs_1day_reminder` | 1-day reminder detection | needs_1day_reminder returns True for interviews 23-25 hours away |
| `test_interview_needs_1hour_reminder` | 1-hour reminder detection | needs_1hour_reminder returns True for interviews 55-65 minutes away |
| `test_interview_no_reminder_if_already_sent` | Deduplication | Reminder not needed if reminder_sent flag already True |
| `test_interview_no_reminder_if_cancelled` | Cancellation check | Cancelled interviews skip reminders |
| `test_mark_reminder_sent` | Flag management | mark_reminder_sent() sets appropriate flag |

---

### 8. Properties Tests (5 tests)

```bash
pytest test_interview_workflow.py::TestInterviewProperties -v
```

| Test | What It Tests | Expected Result |
|------|---------------|-----------------|
| `test_interview_is_upcoming` | Upcoming detection | is_upcoming=True for scheduled/confirmed interviews in future |
| `test_interview_is_past` | Past detection | is_past=True for completed/past interviews |
| `test_interview_is_today` | Today detection | is_today=True for interviews scheduled today |
| `test_actual_duration_minutes` | Duration calculation | actual_duration_minutes calculated correctly |
| `test_interview_clean_validation` | Model validation | clean() raises ValidationError if end time before start |

---

### 9. Panel Management Tests (5 tests)

```bash
pytest test_interview_workflow.py::TestInterviewPanelManagement -v
```

| Test | What It Tests | Expected Result |
|------|---------------|-----------------|
| `test_add_single_interviewer` | Single interviewer | Interviewer added to M2M relationship |
| `test_add_multiple_interviewers` | Panel setup | Multiple interviewers added (3+) |
| `test_remove_interviewer` | Remove from panel | Interviewer removed from M2M relationship |
| `test_interview_with_organizer` | Organizer tracking | Organizer field tracks who scheduled interview |
| `test_panel_interview_type` | Panel interviews | Panel interview type supports multiple interviewers |

---

### 10. Permission Tests (4 tests)

```bash
pytest test_interview_workflow.py::TestInterviewPermissions -v
```

| Test | What It Tests | Expected Result |
|------|---------------|-----------------|
| `test_interview_tenant_access_valid` | Valid tenant access | validate_tenant_access() returns True for correct tenant |
| `test_interview_tenant_access_invalid` | Cross-tenant blocked | validate_tenant_access() returns False for different tenant |
| `test_feedback_tenant_access_valid` | Feedback access valid | Feedback accessible only to same tenant |
| `test_feedback_tenant_access_invalid` | Feedback cross-tenant | Cross-tenant feedback access returns False |

---

### 11. Database Operation Tests (4 tests)

```bash
pytest test_interview_workflow.py::TestInterviewDatabaseOperations -v
```

| Test | What It Tests | Expected Result |
|------|---------------|-----------------|
| `test_interview_queryset_filtering` | Basic filtering | Queryset filtering by tenant and status works |
| `test_upcoming_interviews_manager` | Manager method | upcoming() returns interviews in future, not past |
| `test_interviews_for_interviewer` | Interviewer filter | for_interviewer() returns only that person's interviews |
| `test_interview_feedback_queryset` | Feedback filtering | Feedback filtered correctly by tenant |

---

### 12. Error Handling Tests (4 tests)

```bash
pytest test_interview_workflow.py::TestInterviewErrorHandling -v
```

| Test | What It Tests | Expected Result |
|------|---------------|-----------------|
| `test_interview_no_show` | No-show status | Status can be set to "no_show" |
| `test_interview_with_empty_description` | Optional fields | Optional fields (description, location, etc.) can be empty |
| `test_interview_candidate_local_time` | Timezone conversion | get_candidate_local_time() converts time zone correctly |
| `test_interview_meeting_url_display` | URL preference | meeting_url_display returns meeting_link if available, else meeting_url |

---

## Running Tests by Feature

### Run All Interview Tests
```bash
pytest test_interview_workflow.py -v
```

### Run by Test Class
```bash
# Interview Creation
pytest test_interview_workflow.py::TestInterviewCreation -v

# Forms
pytest test_interview_workflow.py::TestInterviewFormValidation -v

# Scheduling
pytest test_interview_workflow.py::TestInterviewScheduling -v

# Rescheduling
pytest test_interview_workflow.py::TestInterviewRescheduling -v

# Cancellation
pytest test_interview_workflow.py::TestInterviewCancellation -v

# Feedback
pytest test_interview_workflow.py::TestInterviewFeedback -v

# Reminders
pytest test_interview_workflow.py::TestInterviewReminders -v

# Properties
pytest test_interview_workflow.py::TestInterviewProperties -v

# Panel Management
pytest test_interview_workflow.py::TestInterviewPanelManagement -v

# Permissions
pytest test_interview_workflow.py::TestInterviewPermissions -v

# Database
pytest test_interview_workflow.py::TestInterviewDatabaseOperations -v

# Error Handling
pytest test_interview_workflow.py::TestInterviewErrorHandling -v
```

### Run by Marker
```bash
# Integration tests
pytest test_interview_workflow.py -m integration -v

# Workflow tests
pytest test_interview_workflow.py -m workflow -v

# Security tests
pytest test_interview_workflow.py -m security -v
```

### Run Single Test
```bash
pytest test_interview_workflow.py::TestInterviewCreation::test_create_basic_interview -v
```

---

## Test Naming Convention

All tests follow the naming pattern:
```
test_<feature>_<scenario>_<expected_outcome>
```

Examples:
- `test_create_interview_with_all_types` - Tests feature "create interview" with scenario "all types"
- `test_interview_schedule_form_invalid_end_before_start` - Tests "form validation" for "invalid end before start"
- `test_feedback_unique_per_interviewer` - Tests "unique constraint" on feedback

---

## Test Fixtures Used

All tests use fixtures defined in `conftest.py`:

```python
# User fixtures
@pytest.fixture
def user_factory(db):
    return UserFactory

# Tenant fixture
@pytest.fixture
def tenant_factory(db):
    return TenantFactory

# Job fixtures
@pytest.fixture
def job_factory(db):
    return JobFactory

# Candidate fixture
@pytest.fixture
def candidate_factory(db):
    return CandidateFactory

# Application fixture
@pytest.fixture
def application_factory(db):
    return ApplicationFactory

# Interview fixtures
@pytest.fixture
def interview_factory(db):
    return InterviewFactory

@pytest.fixture
def interview_feedback_factory(db):
    return InterviewFeedbackFactory
```

Custom fixtures defined in test file:
```python
@pytest.fixture
def interview_context(...)
    # Provides: tenant, recruiter, hiring_manager, hr_user, candidate, job, application

@pytest.fixture
def multiple_interviewers(...)
    # Provides: technical_lead, product_manager, cto
```

---

## Common Test Patterns

### Test Interview Creation
```python
def test_create_interview(self, interview_factory, interview_context):
    interview = interview_factory(
        application=interview_context['application'],
        interview_type='technical',
        title='Interview'
    )
    assert interview.pk is not None
    assert interview.interview_type == 'technical'
```

### Test Status Transitions
```python
def test_interview_status_change(self, interview_factory):
    interview = interview_factory(status='scheduled')
    interview.confirm()
    assert interview.status == 'confirmed'
```

### Test Properties
```python
def test_interview_property(self, interview_factory):
    interview = interview_factory()
    assert interview.duration_minutes == 60
    assert interview.is_upcoming is True
```

### Test Permissions
```python
def test_tenant_isolation(self, interview_factory, interview_context, tenant_factory):
    interview = interview_factory(application=interview_context['application'])
    other_tenant = tenant_factory()
    assert interview.validate_tenant_access(interview_context['tenant']) is True
    assert interview.validate_tenant_access(other_tenant) is False
```

---

## Common Assertions

```python
# Status checks
assert interview.status == 'scheduled'
assert interview.status in ['scheduled', 'confirmed']

# Timestamp checks
assert interview.confirmed_at is not None
assert interview.cancelled_at is None

# Relationship checks
assert interview.interviewers.count() == 3
assert interview.feedback.count() == 3

# Property checks
assert interview.is_upcoming is True
assert interview.all_feedback_submitted is True

# Validation checks
assert form.is_valid()
assert 'field_name' in form.errors

# Constraint checks
with pytest.raises(IntegrityError):
    # Duplicate creation
```

---

## Expected Test Output

```
test_interview_workflow.py::TestInterviewCreation::test_create_basic_interview PASSED [1%]
test_interview_workflow.py::TestInterviewCreation::test_create_interview_with_all_types PASSED [2%]
...
test_interview_workflow.py::TestInterviewErrorHandling::test_interview_meeting_url_display PASSED [100%]

======================== 70 passed in 45.23s ========================
```

---

## Debugging Failed Tests

### Check Database State
```python
# Inspect the created object
interview = Interview.objects.get(uuid=uuid)
print(interview.__dict__)
print(f"Status: {interview.status}")
print(f"Created at: {interview.created_at}")
```

### Check Form Errors
```python
if not form.is_valid():
    print(form.errors)
    print(form.non_field_errors())
```

### Check Relationships
```python
interview.interviewers.all()
interview.feedback.all()
interview.application.tenant
```

### Enable Query Logging
```bash
# Add to conftest.py or test file
import logging
logging.getLogger('django.db.backends').setLevel(logging.DEBUG)
```

---

## Performance Notes

- Each test class creates fresh database state (transactional)
- Tests are isolated and can run in parallel
- Use `db` fixture for database access
- Factories create minimal required objects
- No external API calls (mocked where needed)

**Expected runtime:** ~45 seconds for all 70+ tests

---

## Continuous Integration

### GitHub Actions / GitLab CI Example
```yaml
test:interview-workflow:
  script:
    - pytest test_interview_workflow.py -v --cov=ats
  coverage: '/TOTAL.*?\s+(\d+%)$/'
```

### Pre-commit Hook
```bash
# .git/hooks/pre-commit
pytest test_interview_workflow.py --co -q || exit 1
```

---

## Related Documentation

- **Full Test Report:** `INTERVIEW_WORKFLOW_TEST_REPORT.md`
- **API Integration Guide:** `INTERVIEW_API_INTEGRATION_TEST_GUIDE.md`
- **Issues & Findings:** `INTERVIEW_WORKFLOW_ISSUES_FINDINGS.md`
- **Executive Summary:** `INTERVIEW_WORKFLOW_TEST_SUMMARY.md`

---

**Last Updated:** January 16, 2026
**Status:** COMPLETE ✅

