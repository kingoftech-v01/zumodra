# Configurations App

## Overview

The Configurations app is Zumodra's core organizational taxonomy and content management module. It provides centralized management of skills, company structure, basic job board functionality, HR operations, and website content. This app serves as the foundation for organizational hierarchy and shared taxonomies used across ATS, HR Core, and Services apps.

## Key Features

### Completed Features

- **Skill Taxonomy**: Centralized skill management used across services, ATS, and HR
- **Company Structure**: Companies, sites, departments, roles, and memberships
- **Basic Job Board**: Simple job postings and applications (separate from enterprise ATS)
- **HR Operations**: Employee records, leave requests, timesheets, onboarding checklists
- **Website Content**: FAQs, testimonials, partnerships, trusted companies
- **Interview Management**: Interview scheduling and feedback for basic job board
- **Candidate Profiles**: Work experience, education, certifications

### In Development

- Configuration versioning and rollback
- Audit trail for all configuration changes
- Import/export functionality for configurations
- Advanced role-based permission templates
- Skill recommendation engine
- Multi-language support for website content

## Architecture

### Models

Located in `configurations/models.py`:

#### Skill Taxonomy
| Model | Description | Key Fields |
|-------|-------------|------------|
| **Skill** | Skills/competencies | name, slug, description, category, is_verified |

#### Company Structure
| Model | Description | Key Fields |
|-------|-------------|------------|
| **Company** | Organizations | name, slug, domain, industry, logo, website, employee_count, founded_year, is_verified |
| **Site** | Company locations | company, name, address, city, country, is_main_office, is_active |
| **CompanyProfile** | Extended company info | company, site, description, social_urls, culture_description, benefits_description |
| **Department** | Departments | company, name, description, manager, parent |
| **Role** | Business roles | company, name, description, group, permissions, is_default |
| **Membership** | User-company links | user, company, department, role, job_title, is_active |

#### Basic Job Board
| Model | Description | Key Fields |
|-------|-------------|------------|
| **CandidateProfile** | Simple candidate profiles | user, resume, bio, phone, linkedin_url, github_url, portfolio_url, skills |
| **JobPosition** | Position templates | company, site, department, title, description, is_open |
| **Job** | Job listings | company, position, title, description, requirements, salary_from/to, currency, is_active |
| **JobApplication** | Applications | candidate, job, cover_letter, status (pending/reviewed/interview/offered/accepted/rejected/withdrawn) |
| **WorkExperience** | Work history | candidate, job_title, company_name, location, start_date, end_date, is_current |
| **Education** | Education history | candidate, school_name, degree, field_of_study, start_date, end_date, gpa |
| **Certification** | Certifications | candidate, name, issuing_authority, credential_id, issue_date, expiry_date |
| **CandidateDocument** | Candidate docs | candidate, document_type, title, file, description |
| **ApplicationNote** | Internal notes | application, author, note, is_private |
| **ApplicationMessage** | Recruiter-candidate messages | application, sender, message, is_from_candidate, read_at |

#### HR Operations
| Model | Description | Key Fields |
|-------|-------------|------------|
| **EmployeeRecord** | Employee records | membership, employee_id, hire_date, contract_type, salary, status, termination_date |
| **ContractDocument** | Employment contracts | employee_record, title, document, signed_at, expires_at |
| **Interview** | Interviews | application, interviewer, scheduled_at, duration_minutes, location, meeting_url, mode, status, summary |
| **InterviewNote** | Interview notes | interview, author, note, rating |
| **OnboardingChecklist** | Onboarding tasks | employee_record, item, description, completed, completed_at, due_date, assigned_to |
| **LeaveRequest** | Time-off requests | employee_record, leave_type, start_date, end_date, reason, status, reviewed_by |
| **Timesheet** | Weekly timesheets | employee_record, week_start, hours_worked, notes, approved, approved_by |
| **EmployeeDocument** | Employee documents | employee_record, title, document, description, document_type |
| **InternalNotification** | Company announcements | company, created_by, title, message, target_roles, is_urgent, is_published, expires_at |

#### Website Content
| Model | Description | Key Fields |
|-------|-------------|------------|
| **FAQEntry** | FAQ items | question, answer, category, sort_order, is_published |
| **Partnership** | Partner organizations | name, logo, website, description, is_featured, sort_order |
| **Testimonial** | Customer testimonials | author_name, author_title, author_company, content, author_photo, rating, is_featured, is_published |
| **TrustedCompany** | Trusted companies (logos) | name, logo, website, sort_order |

### Views

#### Frontend Views (`configurations/views.py`)

**Configuration Management:**
- `ConfigurationsDashboardView` - Overview dashboard with stats
- `SkillsListView` - Skills management with filtering
- `CompanyListView` - Company management
- `FAQListView` - FAQ management
- `TestimonialsListView` - Testimonials management

### API

#### API ViewSets (`configurations/api/viewsets.py`)

```
/api/v1/configurations/skills/
/api/v1/configurations/companies/
/api/v1/configurations/sites/
/api/v1/configurations/departments/
/api/v1/configurations/roles/
/api/v1/configurations/memberships/
/api/v1/configurations/jobs/
/api/v1/configurations/job-applications/
/api/v1/configurations/candidates/
/api/v1/configurations/leave-requests/
/api/v1/configurations/notifications/
/api/v1/configurations/faqs/
/api/v1/configurations/testimonials/
/api/v1/configurations/partnerships/
/api/v1/configurations/trusted-companies/
```

**Key ViewSets:**
- `SkillViewSet` - CRUD for skills with caching
- `CompanyViewSet` - Company management
- `SiteViewSet` - Site/branch management
- `DepartmentViewSet` - Department hierarchy
- `RoleViewSet` - Role and permission management
- `MembershipViewSet` - User-company relationships
- `JobViewSet` - Basic job board listings
- `JobApplicationViewSet` - Application management
- `CandidateProfileViewSet` - Candidate profiles
- `LeaveRequestViewSet` - Time-off management
- `InternalNotificationViewSet` - Company announcements
- `FAQViewSet` - FAQ management
- `TestimonialViewSet` - Testimonial management
- `PartnershipViewSet` - Partnership management
- `TrustedCompanyViewSet` - Trusted company logos

### URL Structure

```python
# Frontend URLs (configurations/urls.py)
configurations:dashboard
configurations:skills-list
configurations:company-list
configurations:faq-list
configurations:testimonials-list

# API URLs (configurations/api/urls.py)
configurations-api:skill-list
configurations-api:skill-detail (pk)
configurations-api:company-list
configurations-api:company-detail (pk)
configurations-api:job-list
configurations-api:job-application-list
configurations-api:faq-list
configurations-api:testimonial-list
```

### Serializers

Located in `configurations/serializers.py`:

**Skill Serializers:**
- `SkillListSerializer` - List view with basic fields
- `SkillDetailSerializer` - Detail view with full information
- `SkillCreateSerializer` - Create new skills

**Company Serializers:**
- `CompanyListSerializer` - Company list with counts
- `CompanyDetailSerializer` - Company details with sites
- `CompanyCreateSerializer` - Create companies

**Job Serializers:**
- `JobListSerializer` - Job listings with applications count
- `JobDetailSerializer` - Full job details
- `JobApplicationListSerializer` - Application list
- `JobApplicationDetailSerializer` - Application details

**Content Serializers:**
- `FAQListSerializer` / `FAQDetailSerializer` / `FAQCreateSerializer`
- `TestimonialListSerializer` / `TestimonialDetailSerializer` / `TestimonialCreateSerializer`
- `PartnershipSerializer` - Partnership management
- `TrustedCompanySerializer` - Trusted company logos

### Forms

Located in `configurations/forms.py`:

- `SkillForm` - Skill creation and editing
- `CompanyForm` - Company management
- Additional forms for all configuration models

## Integration Points

### Used By
- **ATS App**: Imports `Skill` model for candidate skills
- **HR Core App**: Uses `Skill`, `Department`, `Role`, `Membership` for employee management
- **Services App**: Uses `Skill` for provider skills and matching
- **Dashboard App**: Displays configuration statistics
- **Careers App**: Public job listings from `Job` model

### Uses
- **Tenants App**: All models inherit from `TenantAwareModel`
- **Accounts App**: Links users to companies via `Membership`
- **Core App**: Caching, validation, base classes

## Security & Permissions

### Access Control
- **Admin-only operations**: Configuration changes restricted to admin users
- **Tenant isolation**: All models are tenant-scoped via `TenantAwareManager`
- **Role-based access**: Permissions controlled via `Role` model and Django groups
- **Membership-based permissions**: `Membership.get_all_permissions()` aggregates role and user permissions

### Audit & Logging
- Security logger tracks configuration changes in `configurations.tasks`
- All sensitive operations logged to `security.configurations.tasks`
- Admin actions logged via Django admin integration

### Data Validation
- Unique constraints on tenant-scoped slugs
- Email validation on user-facing fields
- File upload restrictions on documents and images
- URL validation on external links

## Caching

### Cached Data
- **Skills list**: 10-minute TTL (tenant-aware)
- **FAQs**: 10-minute TTL (tenant-aware)
- **Testimonials**: 10-minute TTL (tenant-aware)
- **Company stats**: 30-minute TTL
- **Configuration cache warming**: Background task via Celery

### Cache Keys
```python
from core.cache import TenantCache

tenant_cache = TenantCache(tenant_id)
tenant_cache.get(f"skills:list:{filter_hash}")
tenant_cache.get(f"company_{company_id}:stats")
tenant_cache.get(f"config:skills:active")
tenant_cache.get(f"config:categories:tree")
```

## Background Tasks

Located in `configurations/tasks.py`:

### Scheduled Tasks
- `sync_skills_from_external` - Sync skills from external APIs (placeholder)
- `cleanup_unused_categories` - Remove orphaned categories (90+ days inactive)
- `update_company_stats` - Update employee counts, job counts, ratings
- `check_data_integrity` - Validate data consistency
- `warm_configuration_cache` - Pre-warm frequently accessed data
- `sync_site_settings` - Synchronize tenant settings
- `update_faq_stats` - Update FAQ helpfulness scores

### Task Configuration
```python
# Celery Beat Schedule
'configurations.sync_skills': {
    'task': 'configurations.tasks.sync_skills_from_external',
    'schedule': crontab(hour=2, minute=0),  # Daily at 2 AM
}

'configurations.update_company_stats': {
    'task': 'configurations.tasks.update_company_stats',
    'schedule': crontab(hour=3, minute=0),  # Daily at 3 AM
}
```

## Tenant Awareness

All models inherit from `TenantAwareModel` and use `TenantAwareManager`:

```python
from core.db.models import TenantAwareModel
from core.db.managers import TenantAwareManager

class Skill(TenantAwareModel):
    name = models.CharField(max_length=100)
    objects = TenantAwareManager()
```

### Tenant Filtering
- Automatic tenant filtering in all queries
- Unique constraints include `tenant` field
- Foreign keys respect tenant boundaries

## Testing

### Test Coverage
- Model validation tests
- API endpoint tests
- Permission and security tests
- Caching behavior tests
- Background task tests

### Running Tests
```bash
# Run all configurations tests
pytest configurations/tests/

# Run with coverage
pytest --cov=configurations configurations/tests/

# Run specific test markers
pytest -m integration configurations/tests/
pytest -m security configurations/tests/
```

## Future Improvements

### Planned Features
1. **Configuration Versioning**
   - Track changes to all configuration models
   - Rollback capability for accidental changes
   - Change history with diff view

2. **Import/Export**
   - Bulk import skills, companies, FAQs
   - Export configurations as JSON/CSV
   - Configuration templates for common setups

3. **Advanced Role Templates**
   - Pre-built role templates (Manager, HR, Recruiter, etc.)
   - Permission presets for common scenarios
   - Role inheritance and composition

4. **Skill Intelligence**
   - AI-powered skill recommendations
   - Skill gap analysis
   - Market demand insights
   - Skill taxonomy auto-categorization

5. **Multi-language Support**
   - Translatable FAQ entries
   - Localized testimonials
   - Multi-language skill descriptions

6. **Enhanced Analytics**
   - Configuration usage metrics
   - Popular skills tracking
   - Company growth trends
   - Job board performance metrics

### Known Limitations
- Job board is basic; for enterprise features use `ats` app
- No built-in approval workflow for configuration changes
- Limited bulk operations support
- FAQ search is simple text matching (no full-text search)

## Related Documentation

- [ATS App README](../ats/README.md) - Enterprise recruitment features
- [HR Core App README](../hr_core/README.md) - Advanced HR operations
- [Services App README](../services/README.md) - Freelance marketplace
- [Tenants App README](../tenants/README.md) - Multi-tenancy architecture
- [Core Module README](../core/README.md) - Base classes and utilities

## Notes

### Relationship to Other Apps
- **configurations vs. ats**: Configurations provides basic job board; ATS provides enterprise recruitment
- **configurations vs. hr_core**: Configurations has basic HR models; HR Core has advanced features
- **Skill Taxonomy**: The `Skill` model is the canonical source for skills across all apps

### Backwards Compatibility
- `Patnership` typo alias maintained for backwards compatibility (line 971 in models.py)
- Models support both configurations app and legacy integrations

### Admin Interface
- Admin registration commented out in `admin.py`
- Uncomment and customize admin classes as needed for production use
