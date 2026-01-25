# Projects App

> **Multi-tenant project marketplace for time-bound missions with deliverables**

The `projects` app manages project missions in Zumodra's platform. Unlike the `services` app (which handles ongoing service offerings), this app focuses on **specific, time-bound projects** with clear deliverables, budgets, and milestones.

## Table of Contents

- [Overview](#overview)
- [Key Concepts](#key-concepts)
- [Models](#models)
- [API Endpoints](#api-endpoints)
- [Frontend Views](#frontend-views)
- [Workflows](#workflows)
- [Public Catalog Integration](#public-catalog-integration)
- [Usage Examples](#usage-examples)

## Overview

### What is a Project?

A **Project** is a specific mandate/mission with:
- Clear start and end dates
- Defined deliverables and scope
- Fixed budget or milestone-based payments
- Proposal workflow (companies bid on projects)
- Milestone tracking and payment releases

### Projects vs Services

| Aspect | Project | Service |
|--------|---------|---------|
| **Duration** | Time-bound (start/end dates) | Ongoing/continuous |
| **Scope** | Specific deliverables | General capability offering |
| **Pricing** | Fixed budget or milestones | Hourly rate or packages |
| **Example** | "Redesign company website by Q2" | "Web design services available" |
| **Workflow** | Proposal → Contract → Milestones → Delivery | Direct booking or request |

## Key Concepts

### ProjectProvider

Companies or teams that bid on and complete project missions. A provider profile includes:
- Portfolio and past projects
- Skills and expertise
- Team size and capacity
- Average ratings and completion rate
- Availability status

### Project Lifecycle

```
DRAFT → OPEN → IN_PROGRESS → REVIEW → COMPLETED
         ↓
    (Proposals submitted)
         ↓
    (Proposal accepted → Contract created)
```

### Proposal Workflow

1. **Company posts project** in DRAFT status
2. **Company publishes project** → Status: OPEN
3. **Providers submit proposals** with budget/timeline
4. **Company reviews proposals** and accepts one
5. **Contract created** with milestones
6. **Project starts** → Status: IN_PROGRESS
7. **Milestones delivered** and approved
8. **Project completed** → Status: COMPLETED
9. **Reviews exchanged**

## Models

### ProjectCategory

Hierarchical categorization for projects.

```python
class ProjectCategory(models.Model):
    name = models.CharField(max_length=100)
    slug = models.SlugField(max_length=120, unique=True)
    parent = models.ForeignKey('self', null=True, blank=True)
    icon = models.CharField(max_length=50, blank=True)
    color = models.CharField(max_length=7, default='#3B82F6')
    project_count = models.PositiveIntegerField(default=0)
    display_order = models.PositiveIntegerField(default=0)
```

### ProjectProvider

Provider profile for companies offering project services.

```python
class ProjectProvider(TenantAwareModel, TimestampedModel):
    name = models.CharField(max_length=255)
    description = models.TextField()
    tagline = models.CharField(max_length=200, blank=True)
    categories = models.ManyToManyField(ProjectCategory)
    skills = models.JSONField(default=list)
    portfolio_url = models.URLField(blank=True)
    portfolio_images = models.JSONField(default=list)

    # Location
    city = models.CharField(max_length=100, blank=True)
    country = models.CharField(max_length=100, blank=True)
    remote_only = models.BooleanField(default=False)

    # Availability
    is_active = models.BooleanField(default=True)
    is_accepting_projects = models.BooleanField(default=True)
    max_concurrent_projects = models.PositiveIntegerField(default=5)

    # Stats
    completed_projects = models.PositiveIntegerField(default=0)
    total_earnings = models.DecimalField(max_digits=12, decimal_places=2)
    average_rating = models.DecimalField(max_digits=3, decimal_places=2)
    total_reviews = models.PositiveIntegerField(default=0)
```

### Project

Time-bound project mission with specific deliverables.

```python
class Project(TenantAwareModel, TimestampedModel):
    class Status(models.TextChoices):
        DRAFT = 'DRAFT', _('Draft')
        OPEN = 'OPEN', _('Open for Proposals')
        IN_PROGRESS = 'IN_PROGRESS', _('In Progress')
        REVIEW = 'REVIEW', _('Under Review')
        COMPLETED = 'COMPLETED', _('Completed')
        CANCELLED = 'CANCELLED', _('Cancelled')

    title = models.CharField(max_length=255)
    description = models.TextField()
    short_description = models.CharField(max_length=500, blank=True)
    category = models.ForeignKey(ProjectCategory, on_delete=models.PROTECT)

    # Requirements
    required_skills = models.JSONField(default=list)
    experience_level = models.CharField(max_length=20, choices=ExperienceLevel.choices)

    # Timeline
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    estimated_duration_weeks = models.PositiveIntegerField(null=True, blank=True)
    deadline = models.DateTimeField(null=True, blank=True)

    # Budget
    budget_type = models.CharField(max_length=20, choices=BudgetType.choices)
    budget_min = models.DecimalField(max_digits=10, decimal_places=2)
    budget_max = models.DecimalField(max_digits=10, decimal_places=2)
    budget_currency = models.CharField(max_length=3, default='CAD')

    # Deliverables
    deliverables = models.JSONField(default=list)

    # Status
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.DRAFT)
    is_published = models.BooleanField(default=False)
    published_at = models.DateTimeField(null=True, blank=True)
    published_to_catalog = models.BooleanField(default=False)

    # Assignment
    assigned_provider = models.ForeignKey(ProjectProvider, null=True, blank=True)
    assigned_at = models.DateTimeField(null=True, blank=True)
    contract = models.OneToOneField('ProjectContract', null=True, blank=True)

    # Application settings
    max_proposals = models.PositiveIntegerField(default=20)
    proposal_deadline = models.DateTimeField(null=True, blank=True)
```

### ProjectProposal

Provider's bid on a project.

```python
class ProjectProposal(TimestampedModel):
    class Status(models.TextChoices):
        DRAFT = 'DRAFT', _('Draft')
        SUBMITTED = 'SUBMITTED', _('Submitted')
        UNDER_REVIEW = 'UNDER_REVIEW', _('Under Review')
        ACCEPTED = 'ACCEPTED', _('Accepted')
        REJECTED = 'REJECTED', _('Rejected')
        WITHDRAWN = 'WITHDRAWN', _('Withdrawn')

    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    provider = models.ForeignKey(ProjectProvider, on_delete=models.CASCADE)
    freelancer_profile = models.ForeignKey('tenant_profiles.FreelancerProfile', null=True)

    # Proposal content
    cover_letter = models.TextField()
    approach = models.TextField()
    proposed_budget = models.DecimalField(max_digits=10, decimal_places=2)
    budget_currency = models.CharField(max_length=3, default='CAD')
    proposed_duration_weeks = models.PositiveIntegerField()
    proposed_start_date = models.DateField(null=True, blank=True)
    proposed_completion_date = models.DateField(null=True, blank=True)
    proposed_milestones = models.JSONField(default=list)

    # Portfolio
    portfolio_links = models.JSONField(default=list)
    attachments = models.JSONField(default=list)

    # Status
    status = models.CharField(max_length=20, choices=Status.choices)
    submitted_at = models.DateTimeField(null=True, blank=True)
```

### ProjectMilestone

Payment checkpoint within a project.

```python
class ProjectMilestone(TimestampedModel):
    class Status(models.TextChoices):
        PENDING = 'PENDING', _('Pending')
        IN_PROGRESS = 'IN_PROGRESS', _('In Progress')
        SUBMITTED = 'SUBMITTED', _('Submitted for Review')
        APPROVED = 'APPROVED', _('Approved')
        PAID = 'PAID', _('Paid')
        REJECTED = 'REJECTED', _('Rejected')

    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    contract = models.ForeignKey('ProjectContract', on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    description = models.TextField()
    order = models.PositiveIntegerField()
    deliverables = models.JSONField(default=list)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='CAD')
    due_date = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices)
```

## API Endpoints

All API endpoints follow REST conventions with DRF ViewSets.

### Base URL
```
/api/v1/projects/
```

### Endpoints

#### Categories
```
GET    /api/v1/projects/categories/           # List categories
GET    /api/v1/projects/categories/{id}/      # Category detail
GET    /api/v1/projects/categories/tree/      # Hierarchical tree
```

#### Providers
```
GET    /api/v1/projects/providers/            # List providers
GET    /api/v1/projects/providers/{uuid}/     # Provider detail
POST   /api/v1/projects/providers/            # Create provider
PATCH  /api/v1/projects/providers/{uuid}/     # Update provider
DELETE /api/v1/projects/providers/{uuid}/     # Delete provider
GET    /api/v1/projects/providers/{uuid}/stats/ # Provider statistics
```

#### Projects
```
GET    /api/v1/projects/projects/             # List projects
GET    /api/v1/projects/projects/{uuid}/      # Project detail
POST   /api/v1/projects/projects/             # Create project
PATCH  /api/v1/projects/projects/{uuid}/      # Update project
DELETE /api/v1/projects/projects/{uuid}/      # Delete project
POST   /api/v1/projects/projects/{uuid}/publish/   # Publish project
POST   /api/v1/projects/projects/{uuid}/unpublish/ # Unpublish project
POST   /api/v1/projects/projects/{uuid}/close/     # Close to proposals
GET    /api/v1/projects/projects/stats/       # Overall statistics
```

#### Proposals
```
GET    /api/v1/projects/proposals/            # List proposals
GET    /api/v1/projects/proposals/{uuid}/     # Proposal detail
POST   /api/v1/projects/proposals/            # Create proposal
PATCH  /api/v1/projects/proposals/{uuid}/     # Update proposal
POST   /api/v1/projects/proposals/{uuid}/submit/  # Submit proposal
POST   /api/v1/projects/proposals/{uuid}/accept/  # Accept proposal
POST   /api/v1/projects/proposals/{uuid}/reject/  # Reject proposal
```

### Filtering & Search

Projects API supports extensive filtering:

```
GET /api/v1/projects/projects/?status=OPEN
GET /api/v1/projects/projects/?category=5
GET /api/v1/projects/projects/?budget_type=FIXED
GET /api/v1/projects/projects/?experience_level=MID
GET /api/v1/projects/projects/?location_type=REMOTE
GET /api/v1/projects/projects/?search=website redesign
GET /api/v1/projects/projects/?ordering=-published_at
```

## Frontend Views

All frontend views follow the URL_AND_VIEW_CONVENTIONS.md pattern.

### URL Namespace
```
frontend:projects:*
```

### Available Views

```python
# Dashboard
/projects/dashboard/                    # project_dashboard

# Project CRUD
/projects/                              # project_list
/projects/<uuid>/                       # project_detail
/projects/create/                       # project_create
/projects/<uuid>/edit/                  # project_update
/projects/<uuid>/delete/                # project_delete

# Actions
/projects/<uuid>/publish/               # project_publish
/projects/<uuid>/unpublish/             # project_unpublish

# Proposals
/projects/proposals/                    # proposal_list
/projects/proposals/<uuid>/             # proposal_detail
/projects/<uuid>/proposals/create/      # proposal_create
/projects/proposals/<uuid>/accept/      # proposal_accept
/projects/proposals/<uuid>/reject/      # proposal_reject

# Milestones
/projects/milestones/                   # milestone_list
/projects/milestones/<uuid>/            # milestone_detail
```

## Workflows

### 1. Post a Project

```python
from projects.models import Project, ProjectCategory

# Create project in DRAFT
project = Project.objects.create(
    tenant=tenant,
    title="Redesign Company Website",
    description="Complete redesign of our corporate website...",
    category=ProjectCategory.objects.get(slug='web-development'),
    budget_type=Project.BudgetType.FIXED,
    budget_min=10000,
    budget_max=15000,
    budget_currency='CAD',
    estimated_duration_weeks=8,
    deliverables=['Figma designs', 'Responsive HTML/CSS', 'CMS integration'],
    required_skills=['React', 'Node.js', 'UX Design'],
    experience_level=Project.ExperienceLevel.SENIOR,
    max_proposals=10,
)

# Publish when ready
project.publish()
```

### 2. Submit a Proposal

```python
from projects.models import ProjectProposal

proposal = ProjectProposal.objects.create(
    project=project,
    provider=provider,
    cover_letter="We specialize in modern web development...",
    approach="Phase 1: Discovery and wireframes...",
    proposed_budget=12500,
    proposed_duration_weeks=6,
    proposed_milestones=[
        {"title": "Discovery & Design", "percentage": 30},
        {"title": "Development", "percentage": 50},
        {"title": "Testing & Launch", "percentage": 20},
    ],
    portfolio_links=["https://example.com/portfolio"],
)

# Submit for review
proposal.submit()
```

### 3. Accept Proposal & Create Contract

```python
# Accept the proposal
proposal.accept()

# Project automatically assigns provider
project.assigned_provider = proposal.provider
project.status = Project.Status.IN_PROGRESS
project.save()

# Contract with milestones is created
contract = project.contract
```

### 4. Complete Milestone

```python
from projects.models import ProjectMilestone

milestone = project.milestones.first()

# Provider marks as submitted
milestone.status = ProjectMilestone.Status.SUBMITTED
milestone.submitted_at = timezone.now()
milestone.save()

# Client approves
milestone.status = ProjectMilestone.Status.APPROVED
milestone.approved_at = timezone.now()
milestone.save()

# Payment processed
milestone.status = ProjectMilestone.Status.PAID
milestone.paid_at = timezone.now()
milestone.save()
```

## Public Catalog Integration

Projects automatically sync to the `projects_public` app for cross-tenant browsing.

### How Sync Works

1. **Project published** → Signal fired
2. **Celery task** denormalizes data
3. **PublicProjectCatalog** entry created/updated in public schema
4. **Public API** serves fast, read-only access

### Sync Trigger

```python
# projects/signals.py
@receiver(post_save, sender=Project)
def project_saved(sender, instance, created, **kwargs):
    if instance.is_published and instance.status == Project.Status.OPEN:
        from .tasks import sync_project_to_public_catalog
        sync_project_to_public_catalog.delay(instance.id)
```

### Sync Task

```python
# projects/tasks.py
@shared_task(bind=True, max_retries=3)
def sync_project_to_public_catalog(self, project_id):
    project = Project.objects.get(id=project_id)

    PublicProjectCatalog.objects.update_or_create(
        tenant_id=project.tenant.id,
        tenant_project_id=project.id,
        defaults={
            'title': project.title,
            'description': project.description,
            'budget_min': project.budget_min,
            'budget_max': project.budget_max,
            'company_name': project.tenant.name,
            # ... all public fields
        }
    )
```

## Usage Examples

### Example 1: Create Provider Profile

```python
from projects.models import ProjectProvider, ProjectCategory

provider = ProjectProvider.objects.create(
    tenant=tenant,
    name="DigitalCraft Solutions",
    description="Full-service digital agency specializing in web and mobile...",
    tagline="Building digital experiences that matter",
    city="Toronto",
    country="Canada",
    remote_only=True,
    skills=['React', 'Python', 'AWS', 'Docker'],
    is_accepting_projects=True,
    max_concurrent_projects=3,
)

provider.categories.add(
    ProjectCategory.objects.get(slug='web-development'),
    ProjectCategory.objects.get(slug='mobile-apps'),
)
```

### Example 2: Browse Open Projects

```python
from projects.models import Project

# Get all open projects
open_projects = Project.objects.filter(
    status=Project.Status.OPEN,
    is_published=True,
    tenant=request.tenant,
).select_related('category', 'assigned_provider')

# Filter by budget range
affordable_projects = open_projects.filter(
    budget_max__lte=5000
)

# Filter by skills
react_projects = open_projects.filter(
    required_skills__contains=['React']
)

# Order by deadline
urgent_projects = open_projects.order_by('deadline')
```

### Example 3: Track Project Progress

```python
from projects.models import Project, ProjectMilestone

project = Project.objects.get(uuid=project_uuid)

# Get completion percentage
total_milestones = project.milestones.count()
completed_milestones = project.milestones.filter(
    status=ProjectMilestone.Status.PAID
).count()
completion_percentage = (completed_milestones / total_milestones) * 100

# Get next milestone
next_milestone = project.milestones.filter(
    status__in=[
        ProjectMilestone.Status.PENDING,
        ProjectMilestone.Status.IN_PROGRESS,
    ]
).order_by('order').first()
```

## Security

### Permissions

- **Projects**: Only tenant members can create/edit
- **Proposals**: Only provider team members can submit
- **Milestones**: Only contract participants can update
- **Reviews**: Only after project completion

### Validation

- Budget validation (max >= min)
- Date validation (end > start)
- Proposal limits (max_proposals enforced)
- Skill requirements validation

### Audit Logging

All critical operations are logged:
- Project publication
- Proposal acceptance
- Milestone approvals
- Contract changes

## Related Apps

- [`projects_public/`](../projects_public/) - Public project catalog
- [`services/`](../services/) - Ongoing service offerings
- [`accounts/`](../accounts/) - FreelancerProfile for individuals
- [`finance/`](../finance/) - Payment processing for milestones
- [`jobs/`](../jobs/) - Recruitment integration

## Testing

Run project-specific tests:

```bash
pytest projects/tests/
pytest -m projects
```

---

**Status**: Active
**Last Updated**: January 2026
**Maintainers**: Zumodra Platform Team
