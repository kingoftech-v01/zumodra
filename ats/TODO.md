# ATS App TODO

**Last Updated:** 2026-01-16
**Total Items:** 1
**Status:** Production

## Overview
The ATS (Applicant Tracking System) app provides complete recruitment workflows including job postings, candidate management, application pipelines, interview scheduling, and offer management.

## High Priority

### [TODO-ATS-001] Implement 5 Placeholder Views
- **Priority:** High
- **Category:** Feature
- **Status:** Not Started
- **Effort:** Large (10-12h)
- **File:** `ats/urls_frontend.py:137-145`
- **Description:**
  Implement 5 commented-out URL patterns that are referenced in templates but have no backing views yet.
- **Context:**
  These routes are commented out in urls_frontend.py to prevent import errors. Templates reference these URLs but they currently 404. This is incomplete core ATS functionality.
- **Missing Views:**
  1. **CandidateEditView** - Edit candidate profile and details
  2. **CandidateImportView** - Bulk import candidates from CSV/Excel
  3. **CandidateAddNoteView** - Add recruiter notes to candidate
  4. **CandidateEditTagsView** - Manage candidate tags/labels
  5. **ApplicationListView** - List all applications across jobs
- **Acceptance Criteria:**

  **CandidateEditView** (`candidates/<uuid:pk>/edit/`):
  - [ ] Create view class inheriting from UpdateView
  - [ ] Form for editing: name, email, phone, resume, cover letter, status
  - [ ] Permission check: PDG, Supervisor, HR Manager, Recruiter only
  - [ ] Audit log on candidate update
  - [ ] Redirect to candidate detail on success
  - [ ] Template: ats/candidate_edit.html

  **CandidateImportView** (`candidates/import/`):
  - [ ] Create view for file upload (CSV, Excel formats)
  - [ ] Parse uploaded file with pandas or csv module
  - [ ] Map columns to candidate fields (with preview)
  - [ ] Validate data before import (email format, required fields)
  - [ ] Bulk create candidates with error handling
  - [ ] Show import summary (created, skipped, errors)
  - [ ] Template: ats/candidate_import.html
  - [ ] Celery task for large imports

  **CandidateAddNoteView** (`candidates/<uuid:pk>/add-note/`):
  - [ ] Create view for adding note to candidate
  - [ ] HTMX-powered modal form (no page reload)
  - [ ] Note model fields: text, author, created_at, is_private
  - [ ] Permission check: only assigned recruiters or HR managers
  - [ ] Return updated notes list (HTMX swap)
  - [ ] Template: ats/candidate_note_form.html (modal)

  **CandidateEditTagsView** (`candidates/<uuid:pk>/edit-tags/`):
  - [ ] Create view for managing candidate tags
  - [ ] HTMX-powered inline edit UI
  - [ ] Tag autocomplete from existing tags
  - [ ] Create new tags on the fly
  - [ ] Many-to-many relationship handling
  - [ ] Return updated tag display (HTMX swap)
  - [ ] Template: ats/candidate_tags_form.html (inline)

  **ApplicationListView** (`applications/`):
  - [ ] Create view listing all applications across jobs
  - [ ] Filters: status, job, date range, recruiter
  - [ ] Search by candidate name or email
  - [ ] Sorting: date, status, job title
  - [ ] Pagination (50 per page)
  - [ ] Export to CSV functionality
  - [ ] Permission check: PDG, Supervisor, HR Manager, Recruiter
  - [ ] Template: ats/application_list.html

- **Dependencies:**
  - May need new models: CandidateNote, Tag (or use existing)
  - File parsing library: pandas or openpyxl for imports
  - HTMX for modal and inline interactions
- **Notes:**
  - Uncomment URL patterns in urls_frontend.py lines 141-145
  - Templates may already exist and reference these URLs
  - Consider existing ATS views as implementation examples
  - Audit logging via django-auditlog for all changes
  - Ensure tenant isolation (SchemaManager) in all queries

---

## Completed Items
_Completed TODOs will be moved here with completion date._

---

**Note:** When adding new TODOs, use format `[TODO-ATS-XXX]` and update the central [TODO.md](../TODO.md) index.
