# ATS (Applicant Tracking System)

## Overview

The ATS app is Zumodra's core recruitment module, providing a complete hiring pipeline from job posting to offer acceptance. It enables recruiters to manage jobs, candidates, applications, interviews, and offers within a customizable pipeline system.

## Key Features

### Completed Features

- **Job Management**: Full CRUD operations (create, edit, duplicate, delete, publish, close)
- **Candidate Management**: Candidate profiles, CV uploads, manual candidate creation, job assignment
- **Application Processing**: Pipeline stage management, bulk actions, notes, activity tracking
- **Interview Management**: Schedule, reschedule, cancel interviews with feedback collection
- **Offer Management**: Create, send, accept/decline job offers
- **Pipeline Customization**: Drag-and-drop Kanban boards with custom stages
- **Email Communication**: Compose and send emails to candidates
- **Team Collaboration**: Team member search and assignment

### In Development

- Advanced ATS filters with Boolean search
- CV parsing and auto-extraction
- AI-powered candidate matching
- Automated interview scheduling (Calendly/Google Calendar integration)
- Progressive data revelation system
- Career page builder

## Architecture

### Models

Located in `ats/models.py`:

| Model | Description | Key Fields |
|-------|-------------|------------|
| **JobPosting** | Job listings | title, description, department, location, salary_min/max, status, pipeline |
| **Candidate** | Candidate profiles | first_name, last_name, email, phone, resume, skills, experience |
| **Application** | Job applications | candidate, job_posting, current_stage, status, source |
| **PipelineStage** | Recruitment stages | name, order, stage_type (new/screening/interview/offer/hired/rejected) |
| **Interview** | Interview scheduling | application, scheduled_start/end, interviewer, status, meeting_link |
| **InterviewFeedback** | Interview feedback | interview, interviewer, rating, recommendation, comments |
| **Offer** | Job offers | application, salary, start_date, status, terms |
| **ApplicationActivity** | Activity log | application, activity_type, description, performed_by |
| **ApplicationNote** | Application notes | application, note, created_by |

### Views

#### Frontend Views (`ats/template_views.py`)

**Job Views:**
- `JobListView` - List all jobs with filtering
- `JobDetailView` - Job details page
- `JobCreateView` - Create new job
- `JobEditView` - Edit existing job
- `JobDuplicateView` - Duplicate job posting
- `JobDeleteView` - Soft delete job
- `JobPublishView` - Publish job to career pages
- `JobCloseView` - Close job to new applications

**Candidate Views:**
- `CandidateListView` - List candidates with search
- `CandidateDetailView` - Candidate profile page
- `CandidateCreateView` - Manual candidate creation
- `CandidateAddToJobView` - Assign candidate to job

**Pipeline Views:**
- `PipelineBoardView` - Kanban board for applications
- `ApplicationMoveView` - Move application between stages
- `ApplicationBulkActionView` - Bulk application actions

**Application Views:**
- `ApplicationDetailView` - Application details
- `ApplicationNoteView` - Add notes to application
- `ApplicationRejectView` - Reject application with reason
- `EmailComposeView` - Compose email to candidate

**Interview Views:**
- `InterviewListView` - List interviews with filtering
- `InterviewDetailView` - Interview details
- `InterviewScheduleView` - Schedule new interview
- `InterviewRescheduleView` - Reschedule interview
- `InterviewCancelView` - Cancel interview
- `InterviewFeedbackView` - Submit interview feedback

**Offer Views:**
- `OfferListView` - List all offers
- `OfferDetailView` - Offer details
- `OfferCreateView` - Create job offer
- `OfferActionView` - Send/accept/decline offer

**Utility Views:**
- `TeamMemberSearchView` - JSON search for team members

#### API Views (`ats/api/`)

RESTful API endpoints using Django REST Framework:

```
/api/v1/ats/jobs/
/api/v1/ats/candidates/
/api/v1/ats/applications/
/api/v1/ats/interviews/
/api/v1/ats/offers/
/api/v1/ats/pipelines/
```

### URL Structure

#### Frontend URLs (`frontend:ats:*`)

```python
# Jobs
frontend:ats:job_list
frontend:ats:job_create
frontend:ats:job_detail (pk)
frontend:ats:job_edit (pk)
frontend:ats:job_duplicate (pk)
frontend:ats:job_delete (pk)
frontend:ats:job_publish (pk)
frontend:ats:job_close (pk)

# Candidates
frontend:ats:candidate_list
frontend:ats:candidate_create
frontend:ats:candidate_detail (pk)
frontend:ats:candidate_add_to_job (pk)

# Pipeline
frontend:ats:pipeline_board

# Applications
frontend:ats:application_detail (pk)
frontend:ats:application_add_note (application_pk)
frontend:ats:application_reject (pk)

# Interviews
frontend:ats:interview_list
frontend:ats:interview_detail (pk)
frontend:ats:interview_reschedule (pk)
frontend:ats:interview_cancel (pk)

# Offers
frontend:ats:offer_list
frontend:ats:offer_detail (pk)
frontend:ats:offer_create (application_pk)
frontend:ats:offer_action (pk, action)

# HTMX Endpoints
frontend:ats:email_compose
frontend:ats:application_move (pk)
frontend:ats:application_bulk_action
frontend:ats:interview_schedule
frontend:ats:interview_feedback (interview_pk)
frontend:ats:team_member_search
```

### Templates

Located in `templates/ats/`:

**Main Templates:**
- `job_list.html` - Job listings page
- `job_detail.html` - Job details page
- `job_form.html` - Job create/edit form
- `candidate_list.html` - Candidate directory
- `candidate_detail.html` - Candidate profile
- `candidate_form.html` - Candidate creation form
- `pipeline_board.html` - Kanban pipeline board
- `application_detail.html` - Application details
- `interview_list.html` - Interview calendar
- `interview_detail.html` - Interview details
- `offer_list.html` - Offers overview
- `offer_detail.html` - Offer details

**Partials (`templates/ats/partials/`):**
- `_candidate_add_to_job.html` - Add candidate to job modal
- `_email_compose.html` - Email composition modal
- `_interview_reschedule_form.html` - Interview reschedule modal

## Integration Points

### With Other Apps

- **Accounts**: User authentication, recruiter/HR manager roles
- **Tenants**: Multi-tenant isolation, tenant-specific pipelines
- **Notifications**: Email/SMS notifications for interviews, offers
- **HR Core**: Convert accepted offers to employee records
- **Dashboard**: ATS statistics and quick actions
- **Analytics**: Recruitment metrics, time-to-hire, conversion rates
- **Integrations**: Calendly for scheduling, SendGrid for emails

### External Services

- **Email**: SendGrid/Django email backend
- **Calendar**: Google Calendar, Microsoft 365 (planned)
- **Video**: Zoom/Google Meet links for remote interviews
- **Storage**: S3/local storage for resumes and documents

## Security & Permissions

### Role-Based Access

| Role | Permissions |
|------|-------------|
| **PDG/CEO** | Full access to all ATS features |
| **HR Manager** | Manage jobs, candidates, interviews, offers |
| **Recruiter** | Manage assigned jobs, view candidates, schedule interviews |
| **Hiring Manager** | View candidates for their jobs, participate in interviews |
| **Viewer** | Read-only access to ATS data |

### Tenant Isolation

- All queries scoped to `request.tenant`
- Pipeline stages are tenant-specific
- Candidates cannot be shared across tenants
- Applications are tenant-isolated

## Database Considerations

### Indexes

Key indexes for performance:
- JobPosting: `(tenant, status, created_at)`
- Application: `(job_posting, current_stage, status)`
- Candidate: `(tenant, email)` (unique)
- Interview: `(scheduled_start, status)`

### Relationships

```
JobPosting (1) ←→ (N) Application
Candidate (1) ←→ (N) Application
Application (1) ←→ (N) Interview
Application (1) ←→ (1) Offer
Application (1) ←→ (N) ApplicationActivity
Application (1) ←→ (N) ApplicationNote
Interview (1) ←→ (N) InterviewFeedback
```

## Future Improvements

### High Priority

1. **Advanced Filtering System**
   - Boolean search (AND, OR, NOT operators)
   - 30+ filter options (skills, location, salary, experience)
   - Saved searches
   - Smart filters based on job requirements

2. **CV Parsing & Auto-Extraction**
   - Automatic skill extraction from CVs
   - Work history parsing
   - Education detection
   - Contact information extraction
   - Support for multiple CV formats (PDF, DOCX, TXT)

3. **AI-Powered Candidate Matching**
   - Semantic similarity between job descriptions and CVs
   - Skills graph for related skills
   - Match score with breakdown
   - "Hidden gem" suggestions

4. **Automated Interview Scheduling**
   - Calendly/Google Calendar integration
   - Auto-propose available slots
   - Timezone-aware scheduling
   - SMS/Email confirmations via Twilio/SendGrid

5. **Progressive Data Revelation**
   - Stage 1: Name, experience summary, skills
   - Stage 2: Phone, LinkedIn, salary expectations
   - Stage 3: Full address, references
   - Stage 4: SSN, medical docs (post-offer only)

### Medium Priority

6. **Career Page Builder**
   - Customizable career pages per tenant
   - Job listing widgets
   - SEO optimization
   - Application form customization

7. **Bulk Import/Export**
   - CSV/Excel candidate import
   - LinkedIn profile import
   - Application data export
   - Bulk CV upload (100+ at once)

8. **Interview Scorecards**
   - Customizable evaluation forms
   - Rating categories
   - Weighted scoring
   - Interviewer calibration

9. **Talent Pool Management**
   - Save candidates for future roles
   - Alumni/former candidates tracking
   - Engagement campaigns
   - Re-engagement automation

10. **Recruitment Analytics**
    - Time-to-hire metrics
    - Source quality analysis
    - Pipeline conversion rates
    - Bottleneck detection
    - Diversity analytics

### Low Priority

11. **Multi-Language Support**
    - Job postings in multiple languages
    - Translated email templates
    - Localized career pages

12. **Video Interviewing**
    - Built-in video interview platform
    - Recording and playback
    - AI sentiment analysis
    - Automated transcription

13. **Background Checks**
    - Checkr/Sterling integration
    - Automated background check requests
    - Status tracking
    - Compliance management

14. **E-Signature Integration**
    - DocuSign/HelloSign for offer letters
    - Onboarding document signing
    - Audit trail

15. **Mobile App**
    - Recruiter mobile app
    - Candidate mobile experience
    - Push notifications
    - Offline mode

## Testing

### Test Coverage

Target: 90%+ coverage for all ATS views and models

### Test Structure

```
tests/
├── test_ats_models.py       # Model tests
├── test_ats_views.py         # View tests
├── test_ats_api.py           # API tests
├── test_ats_permissions.py   # Permission tests
├── test_ats_workflows.py     # End-to-end workflows
└── test_ats_integration.py   # Integration tests
```

### Key Test Scenarios

- Job creation and publishing workflow
- Candidate application process
- Pipeline stage progression
- Interview scheduling and rescheduling
- Offer creation and acceptance
- Permission enforcement
- Tenant isolation
- Email notifications

## Performance Optimization

### Current Optimizations

- `select_related()` for foreign keys
- `prefetch_related()` for many-to-many
- Pagination for large lists
- Database indexes on frequent queries
- View-level caching for static data

### Planned Optimizations

- Redis caching for candidate search
- Elasticsearch for full-text search
- Background jobs for CV parsing
- CDN for resume files
- Database query optimization

## Migration Notes

When modifying models:

```bash
# Create migrations
python manage.py makemigrations ats

# Apply to all tenant schemas
python manage.py migrate_schemas --tenant

# Apply to shared schema (if shared models)
python manage.py migrate_schemas --shared
```

## Contributing

When adding features to the ATS app:

1. Follow existing patterns in `template_views.py`
2. Add URL patterns to `urls_frontend.py`
3. Create/update templates in `templates/ats/`
4. Add API endpoints to `api/` subdirectory
5. Write tests for new functionality
6. Update this README with changes
7. Ensure tenant isolation is maintained

## Support

For questions or issues related to the ATS app:
- Check existing tests for usage examples
- Review `template_views.py` for view implementations
- Consult the main [CLAUDE.md](../CLAUDE.md) for project guidelines

---

**Last Updated:** January 2026
**Module Version:** 1.0
**Status:** Production
