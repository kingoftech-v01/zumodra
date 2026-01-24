# Interview Scheduling - API & Integration Test Guide

**Date:** January 16, 2026
**Status:** Integration Test Guide Complete
**Version:** 1.0

---

## API Endpoints Summary

### Interview CRUD Operations

#### 1. List Interviews
```
GET /api/v1/jobs/interviews/
```

**Query Parameters:**
- `status` - Filter by status (scheduled, confirmed, completed, cancelled, etc.)
- `interview_type` - Filter by type (phone, video, in_person, technical, panel, etc.)
- `scheduled_start__gte` - Filter interviews starting after date
- `scheduled_start__lte` - Filter interviews starting before date
- `application_id` - Filter by application ID
- `search` - Full-text search on title and candidate name
- `ordering` - Order by field (scheduled_start, created_at, etc.)

**Example Request:**
```bash
curl -X GET "http://localhost:8002/api/v1/jobs/interviews/?status=scheduled&interview_type=video" \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "count": 25,
  "next": "http://localhost:8002/api/v1/jobs/interviews/?page=2",
  "previous": null,
  "results": [
    {
      "id": 1,
      "uuid": "550e8400-e29b-41d4-a716-446655440000",
      "title": "Technical Interview Round 1",
      "interview_type": "technical",
      "status": "scheduled",
      "scheduled_start": "2026-01-20T14:00:00Z",
      "scheduled_end": "2026-01-20T15:00:00Z",
      "duration_minutes": 60,
      "application": {
        "id": 5,
        "candidate": {
          "id": 3,
          "first_name": "John",
          "last_name": "Doe",
          "full_name": "John Doe"
        },
        "job": {
          "id": 2,
          "title": "Senior Software Engineer"
        }
      },
      "organizer": {
        "id": 7,
        "first_name": "Jane",
        "last_name": "Smith",
        "email": "jane@company.com"
      },
      "interviewers": [
        {
          "id": 8,
          "first_name": "Bob",
          "last_name": "Johnson",
          "email": "bob@company.com"
        }
      ],
      "location": "Virtual - Zoom",
      "meeting_provider": "zoom",
      "meeting_url": "https://zoom.us/j/123456789",
      "confirmed_at": null,
      "candidate_notified": true,
      "interviewers_notified": true,
      "reminder_sent_1day": false,
      "reminder_sent_1hour": false,
      "reminder_sent_15min": false,
      "created_at": "2026-01-15T10:00:00Z",
      "updated_at": "2026-01-15T10:00:00Z"
    }
  ]
}
```

---

#### 2. Get Single Interview
```
GET /api/v1/jobs/interviews/{uuid}/
```

**Example Request:**
```bash
curl -X GET "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/" \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "id": 1,
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "title": "Technical Interview Round 1",
  "interview_type": "technical",
  "status": "scheduled",
  "description": "Assess system design and problem-solving skills",
  "scheduled_start": "2026-01-20T14:00:00Z",
  "scheduled_end": "2026-01-20T15:00:00Z",
  "timezone": "America/Toronto",
  "candidate_timezone": "America/New_York",
  "duration_minutes": 60,
  "actual_start": null,
  "actual_end": null,
  "actual_duration_minutes": null,
  "application": {
    "id": 5,
    "status": "interviewing",
    "candidate": {
      "id": 3,
      "first_name": "John",
      "last_name": "Doe",
      "email": "john@example.com",
      "phone": "+1-555-0123",
      "full_name": "John Doe"
    },
    "job": {
      "id": 2,
      "title": "Senior Software Engineer"
    }
  },
  "organizer": {
    "id": 7,
    "first_name": "Jane",
    "last_name": "Smith",
    "email": "jane@company.com"
  },
  "interviewers": [
    {
      "id": 8,
      "first_name": "Bob",
      "last_name": "Johnson",
      "email": "bob@company.com"
    },
    {
      "id": 9,
      "first_name": "Alice",
      "last_name": "Williams",
      "email": "alice@company.com"
    }
  ],
  "interview_template": {
    "id": 1,
    "name": "Technical Interview Template",
    "interview_type": "technical",
    "default_duration": "01:00:00"
  },
  "location": "Virtual - Zoom",
  "meeting_provider": "zoom",
  "meeting_url": "https://zoom.us/j/123456789",
  "meeting_id": "123456789",
  "meeting_password": "password123",
  "meeting_link": "https://zoom.us/j/123456789",
  "calendar_event_id": "google_event_123abc",
  "calendar_provider": "google",
  "candidate_calendar_event_id": "google_event_456def",
  "candidate_notified": true,
  "interviewers_notified": true,
  "reminder_sent_1day": false,
  "reminder_sent_1hour": false,
  "reminder_sent_15min": false,
  "preparation_notes": "Study the company's recent projects",
  "interview_guide": "Focus on system design patterns",
  "cancellation_reason": null,
  "reschedule_count": 0,
  "confirmed_at": null,
  "cancelled_at": null,
  "is_upcoming": true,
  "is_past": false,
  "is_today": false,
  "all_feedback_submitted": false,
  "feedback": [],
  "created_at": "2026-01-15T10:00:00Z",
  "updated_at": "2026-01-15T10:00:00Z"
}
```

---

#### 3. Create Interview
```
POST /api/v1/jobs/interviews/
```

**Request Body:**
```json
{
  "application_id": 5,
  "interview_type": "technical",
  "title": "Technical Interview Round 1",
  "description": "Assess system design and problem-solving",
  "scheduled_start": "2026-01-20T14:00:00Z",
  "scheduled_end": "2026-01-20T15:00:00Z",
  "timezone": "America/Toronto",
  "candidate_timezone": "America/New_York",
  "location": "Virtual - Zoom",
  "meeting_provider": "zoom",
  "meeting_url": "https://zoom.us/j/123456789",
  "interview_template_id": 1,
  "preparation_notes": "Study the company's recent projects",
  "interview_guide": "Focus on system design patterns",
  "interviewer_ids": [8, 9]
}
```

**Success Response (201 Created):**
```json
{
  "id": 1,
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "title": "Technical Interview Round 1",
  "interview_type": "technical",
  "status": "scheduled",
  "scheduled_start": "2026-01-20T14:00:00Z",
  "scheduled_end": "2026-01-20T15:00:00Z",
  "application_id": 5,
  "organizer_id": 7,
  "interviewers": [8, 9],
  "created_at": "2026-01-15T10:00:00Z",
  "updated_at": "2026-01-15T10:00:00Z"
}
```

**Error Response (400 Bad Request):**
```json
{
  "application_id": ["This field is required."],
  "scheduled_start": ["Ensure this value is >= now."],
  "scheduled_end": ["End time must be after start time."]
}
```

**Error Response (403 Forbidden - Permission):**
```json
{
  "detail": "You do not have permission to perform this action."
}
```

---

#### 4. Update Interview
```
PATCH /api/v1/jobs/interviews/{uuid}/
```

**Request Body:**
```json
{
  "title": "Updated Technical Interview",
  "description": "Assessment of advanced system design",
  "location": "Conference Room A",
  "preparation_notes": "Updated notes"
}
```

**Response (200 OK):**
```json
{
  "id": 1,
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "title": "Updated Technical Interview",
  "description": "Assessment of advanced system design",
  "location": "Conference Room A",
  "preparation_notes": "Updated notes",
  "updated_at": "2026-01-16T10:00:00Z"
}
```

---

#### 5. Delete Interview
```
DELETE /api/v1/jobs/interviews/{uuid}/
```

**Response (204 No Content):**
```
[Empty response body]
```

**Error Response (403 Forbidden - Only admins can delete):**
```json
{
  "detail": "You do not have permission to perform this action."
}
```

---

### Interview Actions (Custom Endpoints)

#### 6. Reschedule Interview
```
POST /api/v1/jobs/interviews/{uuid}/reschedule/
```

**Request Body:**
```json
{
  "scheduled_start": "2026-01-21T10:00:00Z",
  "scheduled_end": "2026-01-21T11:00:00Z",
  "reason": "Candidate requested different time"
}
```

**Response (200 OK):**
```json
{
  "id": 1,
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "status": "rescheduled",
  "scheduled_start": "2026-01-21T10:00:00Z",
  "scheduled_end": "2026-01-21T11:00:00Z",
  "reschedule_count": 1,
  "reminder_sent_1day": false,
  "reminder_sent_1hour": false,
  "reminder_sent_15min": false,
  "updated_at": "2026-01-16T10:00:00Z"
}
```

**Error Response (400 Bad Request):**
```json
{
  "scheduled_end": ["End time must be after start time."],
  "scheduled_start": ["Ensure this value is >= now."]
}
```

---

#### 7. Complete Interview
```
POST /api/v1/jobs/interviews/{uuid}/complete/
```

**Request Body:**
```json
{}
```

**Response (200 OK):**
```json
{
  "id": 1,
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "actual_start": "2026-01-20T14:00:00Z",
  "actual_end": "2026-01-20T15:00:00Z",
  "actual_duration_minutes": 60,
  "updated_at": "2026-01-20T15:00:00Z"
}
```

---

#### 8. Cancel Interview
```
POST /api/v1/jobs/interviews/{uuid}/cancel/
```

**Request Body:**
```json
{
  "reason": "Candidate declined participation"
}
```

**Response (200 OK):**
```json
{
  "id": 1,
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "status": "cancelled",
  "cancellation_reason": "Candidate declined participation",
  "cancelled_at": "2026-01-16T10:00:00Z",
  "updated_at": "2026-01-16T10:00:00Z"
}
```

---

#### 9. Get Interview Feedback
```
GET /api/v1/jobs/interviews/{uuid}/feedback/
```

**Response (200 OK):**
```json
[
  {
    "id": 1,
    "uuid": "660e8400-e29b-41d4-a716-446655440000",
    "interview_id": 1,
    "interviewer": {
      "id": 8,
      "first_name": "Bob",
      "last_name": "Johnson",
      "email": "bob@company.com"
    },
    "overall_rating": 5,
    "technical_skills": 5,
    "communication": 4,
    "cultural_fit": 4,
    "problem_solving": 5,
    "recommendation": "strong_yes",
    "strengths": "Excellent problem solver",
    "weaknesses": "Limited leadership experience",
    "notes": "Great fit for the role",
    "private_notes": "Recommend for senior level",
    "custom_ratings": {
      "system_design": 5,
      "coding_quality": 4
    },
    "submitted_at": "2026-01-20T16:00:00Z",
    "created_at": "2026-01-20T16:00:00Z",
    "updated_at": "2026-01-20T16:00:00Z"
  }
]
```

---

#### 10. Submit Interview Feedback
```
POST /api/v1/jobs/interviews/{uuid}/feedback/
```

**Request Body:**
```json
{
  "overall_rating": 5,
  "technical_skills": 5,
  "communication": 4,
  "cultural_fit": 4,
  "problem_solving": 5,
  "recommendation": "strong_yes",
  "strengths": "Excellent problem solver with strong system design skills",
  "weaknesses": "Limited experience with distributed systems",
  "notes": "Great fit for the senior role, recommend for second round",
  "private_notes": "Consider for tech lead track",
  "custom_ratings": {
    "system_design": 5,
    "coding_quality": 4,
    "communication": 4
  }
}
```

**Response (201 Created):**
```json
{
  "id": 1,
  "uuid": "660e8400-e29b-41d4-a716-446655440000",
  "interview_id": 1,
  "interviewer_id": 8,
  "overall_rating": 5,
  "technical_skills": 5,
  "communication": 4,
  "cultural_fit": 4,
  "problem_solving": 5,
  "recommendation": "strong_yes",
  "strengths": "Excellent problem solver with strong system design skills",
  "weaknesses": "Limited experience with distributed systems",
  "notes": "Great fit for the senior role, recommend for second round",
  "private_notes": "Consider for tech lead track",
  "custom_ratings": {
    "system_design": 5,
    "coding_quality": 4,
    "communication": 4
  },
  "submitted_at": "2026-01-20T16:00:00Z",
  "created_at": "2026-01-20T16:00:00Z",
  "updated_at": "2026-01-20T16:00:00Z"
}
```

**Error Response (400 Bad Request - Already submitted):**
```json
{
  "non_field_errors": ["Interviewer has already submitted feedback for this interview."]
}
```

---

#### 11. Get My Interviews
```
GET /api/v1/jobs/interviews/my_interviews/
```

**Query Parameters:**
- `ordering` - Order by field (scheduled_start, created_at, etc.)
- `search` - Full-text search on title and candidate name

**Response (200 OK):**
```json
{
  "count": 5,
  "results": [
    {
      "id": 1,
      "uuid": "550e8400-e29b-41d4-a716-446655440000",
      "title": "Technical Interview Round 1",
      "interview_type": "technical",
      "status": "scheduled",
      "scheduled_start": "2026-01-20T14:00:00Z",
      "scheduled_end": "2026-01-20T15:00:00Z",
      "application": {
        "candidate": {
          "full_name": "John Doe"
        },
        "job": {
          "title": "Senior Software Engineer"
        }
      }
    }
  ]
}
```

---

#### 12. Get Upcoming Interviews (Next 7 Days)
```
GET /api/v1/jobs/interviews/upcoming/
```

**Response (200 OK):**
```json
{
  "count": 3,
  "results": [
    {
      "id": 1,
      "uuid": "550e8400-e29b-41d4-a716-446655440000",
      "title": "Technical Interview Round 1",
      "interview_type": "technical",
      "status": "scheduled",
      "scheduled_start": "2026-01-17T14:00:00Z",
      "scheduled_end": "2026-01-17T15:00:00Z",
      "application": {
        "candidate": {
          "full_name": "John Doe"
        }
      }
    }
  ]
}
```

---

## Integration Test Scenarios

### Scenario 1: Complete Interview Workflow

**Use Case:** Schedule, confirm, complete, and provide feedback on a technical interview

**Steps:**

1. **Create Interview**
```bash
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/" \
  -H "Authorization: Bearer <recruiter_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "application_id": 5,
    "interview_type": "technical",
    "title": "Technical Interview Round 1",
    "scheduled_start": "2026-01-20T14:00:00Z",
    "scheduled_end": "2026-01-20T15:00:00Z",
    "location": "Virtual",
    "meeting_provider": "zoom",
    "meeting_url": "https://zoom.us/j/123",
    "interviewer_ids": [8, 9]
  }'
```

**Expected:**
- Interview created with status "scheduled"
- Notifications sent to candidate and interviewers
- Reminder flags initialized to False

2. **Candidate Confirms Attendance**
```bash
# This would be done via candidate portal (not shown here)
# Interview status changes from SCHEDULED → CONFIRMED
```

3. **Interview Day: Mark as In Progress**
```bash
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/start/" \
  -H "Authorization: Bearer <recruiter_token>"
```

**Expected:**
- Status changed to "in_progress"
- actual_start set to current time

4. **Interview Complete: Mark as Completed**
```bash
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/complete/" \
  -H "Authorization: Bearer <recruiter_token>"
```

**Expected:**
- Status changed to "completed"
- actual_end set to current time
- actual_duration_minutes calculated

5. **Interviewer 1 Submits Feedback**
```bash
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/feedback/" \
  -H "Authorization: Bearer <interviewer1_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "overall_rating": 5,
    "technical_skills": 5,
    "communication": 4,
    "cultural_fit": 4,
    "problem_solving": 5,
    "recommendation": "strong_yes",
    "strengths": "Excellent problem solver",
    "weaknesses": "Limited leadership experience",
    "notes": "Recommend for senior position"
  }'
```

**Expected:**
- Feedback created and linked to interviewer
- submitted_at timestamp set
- Can retrieve feedback via GET /interviews/{uuid}/feedback/

6. **Interviewer 2 Submits Feedback**
```bash
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/feedback/" \
  -H "Authorization: Bearer <interviewer2_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "overall_rating": 4,
    "technical_skills": 4,
    "communication": 5,
    "cultural_fit": 5,
    "problem_solving": 4,
    "recommendation": "yes",
    "strengths": "Great communicator, strong cultural fit",
    "weaknesses": "Some gaps in advanced algorithms",
    "notes": "Solid candidate, recommend for offer"
  }'
```

**Expected:**
- Second feedback created
- Interview.all_feedback_submitted now returns True
- Hiring decision can proceed

---

### Scenario 2: Reschedule Interview Due to Conflict

**Use Case:** Interviewer has conflict, reschedule to different time

**Steps:**

1. **Check Current Interview**
```bash
curl -X GET "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/" \
  -H "Authorization: Bearer <recruiter_token>"
```

**Expected:**
- scheduled_start: "2026-01-20T14:00:00Z"
- reschedule_count: 0
- reminder_sent_1day: False

2. **Reschedule to New Time**
```bash
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/reschedule/" \
  -H "Authorization: Bearer <recruiter_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "scheduled_start": "2026-01-21T10:00:00Z",
    "scheduled_end": "2026-01-21T11:00:00Z",
    "reason": "Interviewer availability conflict"
  }'
```

**Expected:**
- scheduled_start updated: "2026-01-21T10:00:00Z"
- status changed to "rescheduled"
- reschedule_count: 1
- All reminder flags reset to False
- Reschedule notifications sent to candidate and interviewers

3. **Verify Changes**
```bash
curl -X GET "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/" \
  -H "Authorization: Bearer <recruiter_token>"
```

**Expected:**
```json
{
  "scheduled_start": "2026-01-21T10:00:00Z",
  "status": "rescheduled",
  "reschedule_count": 1,
  "reminder_sent_1day": false,
  "reminder_sent_1hour": false,
  "reminder_sent_15min": false
}
```

---

### Scenario 3: Cancel Interview with Reason Tracking

**Use Case:** Candidate declines participation, cancel interview and record reason

**Steps:**

1. **Cancel Interview**
```bash
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/cancel/" \
  -H "Authorization: Bearer <recruiter_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Candidate declined participation - pursuing other opportunities"
  }'
```

**Expected:**
- Status changed to "cancelled"
- cancellation_reason populated
- cancelled_at timestamp set
- Cancellation notifications sent

2. **Verify Cancellation**
```bash
curl -X GET "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/" \
  -H "Authorization: Bearer <recruiter_token>"
```

**Expected:**
```json
{
  "status": "cancelled",
  "cancellation_reason": "Candidate declined participation - pursuing other opportunities",
  "cancelled_at": "2026-01-16T10:00:00Z"
}
```

3. **Verify Reminders Won't Send**
```bash
# Interview.needs_1day_reminder property returns False because:
# status == CANCELLED (checks this first)
```

---

### Scenario 4: Panel Interview with Multiple Interviewers

**Use Case:** Schedule panel interview with 3 interviewers, collect feedback from each

**Steps:**

1. **Create Panel Interview**
```bash
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/" \
  -H "Authorization: Bearer <recruiter_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "application_id": 5,
    "interview_type": "panel",
    "title": "Final Round Panel Interview",
    "scheduled_start": "2026-01-22T09:00:00Z",
    "scheduled_end": "2026-01-22T10:30:00Z",
    "location": "Conference Room A",
    "interviewer_ids": [8, 9, 10]
  }'
```

**Expected:**
- Interview created with type "panel"
- 3 interviewers assigned

2. **Get My Interviews (Interviewer Perspective)**
```bash
curl -X GET "http://localhost:8002/api/v1/jobs/interviews/my_interviews/" \
  -H "Authorization: Bearer <interviewer1_token>"
```

**Expected:**
- Panel interview appears in their interview list

3. **All Three Interviewers Submit Feedback**

Interviewer 1:
```bash
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/feedback/" \
  -H "Authorization: Bearer <interviewer1_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "overall_rating": 5,
    "recommendation": "strong_yes"
  }'
```

Interviewer 2:
```bash
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/feedback/" \
  -H "Authorization: Bearer <interviewer2_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "overall_rating": 4,
    "recommendation": "yes"
  }'
```

Interviewer 3:
```bash
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/feedback/" \
  -H "Authorization: Bearer <interviewer3_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "overall_rating": 4,
    "recommendation": "yes"
  }'
```

4. **Check All Feedback Submitted**
```bash
curl -X GET "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/" \
  -H "Authorization: Bearer <recruiter_token>"
```

**Expected:**
```json
{
  "interviewers": [8, 9, 10],
  "all_feedback_submitted": true,
  "feedback": [
    {"interviewer": 8, "overall_rating": 5, "recommendation": "strong_yes"},
    {"interviewer": 9, "overall_rating": 4, "recommendation": "yes"},
    {"interviewer": 10, "overall_rating": 4, "recommendation": "yes"}
  ]
}
```

---

### Scenario 5: Permission & Tenant Isolation Test

**Use Case:** Verify that users from different tenants cannot access each other's interviews

**Steps:**

1. **User A (Tenant 1) Creates Interview**
```bash
curl -X GET "http://localhost:8002/api/v1/jobs/interviews/" \
  -H "Authorization: Bearer <tenant1_user_token>"
```

**Expected:** Interview visible, count: 1

2. **User B (Tenant 2) Attempts to Access Same Interview**
```bash
# Using interview UUID from Tenant 1
curl -X GET "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/" \
  -H "Authorization: Bearer <tenant2_user_token>"
```

**Expected (404 Not Found):**
```json
{
  "detail": "Not found."
}
```

3. **Tenant 2 Lists Interviews - Should Be Empty**
```bash
curl -X GET "http://localhost:8002/api/v1/jobs/interviews/" \
  -H "Authorization: Bearer <tenant2_user_token>"
```

**Expected:**
```json
{
  "count": 0,
  "results": []
}
```

---

### Scenario 6: Error Handling - Invalid Data

**Use Case:** Verify proper error responses for invalid input

**Steps:**

1. **Invalid: End Time Before Start Time**
```bash
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/" \
  -H "Authorization: Bearer <recruiter_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "application_id": 5,
    "interview_type": "phone",
    "title": "Test",
    "scheduled_start": "2026-01-20T15:00:00Z",
    "scheduled_end": "2026-01-20T14:00:00Z"
  }'
```

**Expected (400 Bad Request):**
```json
{
  "scheduled_end": ["End time must be after start time."]
}
```

2. **Invalid: Missing Required Field**
```bash
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/" \
  -H "Authorization: Bearer <recruiter_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "application_id": 5,
    "interview_type": "phone",
    "title": "Test"
  }'
```

**Expected (400 Bad Request):**
```json
{
  "scheduled_start": ["This field is required."],
  "scheduled_end": ["This field is required."]
}
```

3. **Invalid: XSS Attempt in Title**
```bash
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/" \
  -H "Authorization: Bearer <recruiter_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "application_id": 5,
    "interview_type": "phone",
    "title": "Interview<script>alert(1)</script>",
    "scheduled_start": "2026-01-20T14:00:00Z",
    "scheduled_end": "2026-01-20T15:00:00Z"
  }'
```

**Expected:**
- Accepted (400 error or sanitized depending on form validation)
- XSS payload removed/sanitized before storage

4. **Invalid: Feedback Rating Out of Range**
```bash
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/feedback/" \
  -H "Authorization: Bearer <interviewer_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "overall_rating": 10,
    "recommendation": "yes"
  }'
```

**Expected (400 Bad Request):**
```json
{
  "overall_rating": ["Ensure this value is less than or equal to 5."]
}
```

5. **Invalid: Duplicate Feedback Submission**
```bash
# First submission
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/feedback/" \
  -H "Authorization: Bearer <interviewer_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "overall_rating": 5,
    "recommendation": "strong_yes"
  }'

# Second submission (duplicate)
curl -X POST "http://localhost:8002/api/v1/jobs/interviews/550e8400-e29b-41d4-a716-446655440000/feedback/" \
  -H "Authorization: Bearer <interviewer_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "overall_rating": 4,
    "recommendation": "yes"
  }'
```

**Expected (400 Bad Request - Database Constraint):**
```json
{
  "non_field_errors": ["Interviewer has already submitted feedback for this interview."]
}
```

---

## Performance Test Scenarios

### Query Optimization Test

**Scenario:** List all interviews with related data

**Without Optimization (N+1 queries):**
```python
interviews = Interview.objects.all()
for interview in interviews:
    print(interview.application.candidate.full_name)  # N additional queries
    print(interview.organizer.email)                   # N additional queries
    for interviewer in interview.interviewers.all():   # N additional queries
        print(interviewer.name)
```

**With Optimization (2 queries total):**
```python
interviews = Interview.objects.select_related(
    'application__candidate',
    'application__job',
    'organizer'
).prefetch_related(
    'interviewers'
)
for interview in interviews:
    print(interview.application.candidate.full_name)  # From cache
    print(interview.organizer.email)                   # From cache
    for interviewer in interview.interviewers.all():   # From cache
        print(interviewer.name)
```

**Expected:** ViewSet uses optimized pattern automatically

---

## Security Test Scenarios

### Tenant Isolation Test

**Test:** Ensure database queries respect tenant boundaries

```python
# User from Tenant A
user_a = User.objects.get(id=1)  # tenant=A
tenant_a = user_a.tenant

# User from Tenant B
user_b = User.objects.get(id=2)  # tenant=B
tenant_b = user_b.tenant

# User A lists interviews - should only see Tenant A interviews
interviews_a = Interview.objects.filter(application__tenant=tenant_a)
# count == 5 (Tenant A's interviews)

# User B lists interviews - should only see Tenant B interviews
interviews_b = Interview.objects.filter(application__tenant=tenant_b)
# count == 3 (Tenant B's interviews)

# Cross-tenant access should return 404
interview_a = interviews_a.first()
user_b.can_view_interview(interview_a)  # False
```

### XSS Prevention Test

**Test:** Ensure user inputs are sanitized

```python
# Input with XSS payload
xss_payload = 'Interview<script>alert("xss")</script>'

# Form validation should remove/sanitize
form = InterviewScheduleForm(data={'title': xss_payload, ...})
if form.is_valid():
    # Title should be sanitized
    assert '<script>' not in form.cleaned_data['title']

# Stored value should be safe
interview = form.save()
assert '<script>' not in interview.title
```

### SQL Injection Prevention Test

**Test:** Ensure inputs cannot be used for SQL injection

```python
# Input with SQL payload
sql_payload = "'; DROP TABLE interviews; --"

# Form validation should prevent
form = InterviewScheduleForm(data={'title': sql_payload, ...})
# Should be valid but sanitized, or rejected

# Should not execute any database commands
interview = Interview.objects.create(title=sql_payload, ...)
# Table still exists, data intact
```

---

## Rate Limiting & Throttling

**Expected Behavior:**

```
GET /api/v1/jobs/interviews/ - Standard rate limit (depending on tier)
```

**Response Headers:**
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1234567890
```

**After Rate Limit Exceeded (429 Too Many Requests):**
```json
{
  "detail": "Request was throttled. Expected available in 60 seconds."
}
```

---

## Caching Behavior

**Expected:**

- Interview list responses cached with ETag
- Cache invalidated on create/update/delete
- Individual interview detail cached
- Feedback list cached per interview
- Cache key includes tenant ID for isolation

---

## Conclusion

This integration test guide provides comprehensive API scenarios, request/response examples, and test cases for the complete interview scheduling workflow. All endpoints support proper error handling, security measures, and follow RESTful conventions.

