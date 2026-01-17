# Employee Onboarding Workflow - Quick Reference Guide

**Last Updated**: 2026-01-16

---

## 7-Phase Onboarding Workflow

### Phase 1: Create Onboarding Checklist Template

```python
from hr_core.models import OnboardingChecklist, OnboardingTask

# Create a reusable template
checklist = OnboardingChecklist.objects.create(
    name="New Hire Onboarding",
    description="30-day comprehensive onboarding",
    employment_type='full_time',  # Optional: for specific employment type
    is_active=True,
)
```

**Key Points**:
- ✓ Reusable across multiple employees
- ✓ Can be employment-type specific (full-time, contract, intern)
- ✓ Can be department-specific
- ✓ Must be marked as_active to be available

---

### Phase 2: Add Tasks to Checklist

```python
# Day 1: IT Setup
OnboardingTask.objects.create(
    checklist=checklist,
    title="IT Equipment Setup",
    description="Laptop, phone, accounts provisioning",
    category='it_setup',
    order=1,
    assigned_to_role='IT',
    due_days=1,  # Due 1 day after start date
    is_required=True,
)

# Day 1: Handbook Review
OnboardingTask.objects.create(
    checklist=checklist,
    title="Company Handbook Review",
    description="Review and sign employee handbook",
    category='documentation',
    order=2,
    assigned_to_role='HR',
    due_days=1,
    requires_signature=True,
)

# Day 2: Manager Meeting
OnboardingTask.objects.create(
    checklist=checklist,
    title="1-on-1 with Manager",
    description="Meet with direct manager",
    category='introductions',
    order=3,
    assigned_to_role='Manager',
    due_days=2,
)

# Week 2: Security Training
OnboardingTask.objects.create(
    checklist=checklist,
    title="Security & Compliance Training",
    description="Complete security certifications",
    category='compliance',
    order=4,
    assigned_to_role='HR',
    due_days=14,
    is_required=True,
)
```

**Task Categories**:
- `documentation` - Forms, handbooks, contracts
- `it_setup` - Equipment, accounts, access
- `training` - Courses, certifications
- `introductions` - Team meetings
- `compliance` - Legal, security, policies
- `benefits` - Enrollment, insurance
- `other` - Miscellaneous

---

### Phase 3: Initiate Employee Onboarding

```python
from hr_core.models import EmployeeOnboarding, OnboardingTaskProgress
from datetime import timedelta

# Get the employee and checklist
employee = Employee.objects.get(employee_id='ENG-001')
checklist = OnboardingChecklist.objects.get(name="New Hire Onboarding")

# Create onboarding record
onboarding = EmployeeOnboarding.objects.create(
    employee=employee,
    checklist=checklist,
    start_date=date.today(),
    target_completion_date=date.today() + timedelta(days=30),
    notes="Hired from Tech Talent Agency",
)

# IMPORTANT: Manually create task progress for each task
# (This should be automated - see ISSUES.md)
for task in checklist.tasks.all():
    OnboardingTaskProgress.objects.create(
        onboarding=onboarding,
        task=task,
        assigned_to=get_assignee_for_task(task),  # Determine who does the task
        due_date=onboarding.start_date + timedelta(days=task.due_days),
    )
```

**Starting Employee Status**: Must be `PENDING`

**Common Statuses**:
- `pending` - Before onboarding starts
- `probation` - During onboarding (after onboarding completes)
- `active` - After probation period
- `on_leave` - Currently on leave
- `terminated` - Employment ended

---

### Phase 4: Track Task Completion

```python
from hr_core.models import OnboardingTaskProgress

# Get task progress
task_progress = OnboardingTaskProgress.objects.get(
    onboarding=onboarding,
    task=task,
)

# Complete the task
task_progress.complete(user=hr_user)
# Sets: is_completed=True, completed_at=now(), completed_by=hr_user

# Check if task is completed
if task_progress.is_completed:
    print(f"Completed by {task_progress.completed_by.get_full_name()}")
    print(f"Completed at {task_progress.completed_at}")
```

**Monitoring Progress**:
```python
# Get overall completion percentage
progress = onboarding.completion_percentage  # 0-100

# Get incomplete tasks
incomplete = onboarding.task_progress.filter(is_completed=False)

# Get overdue tasks (for today)
from django.utils import timezone
overdue = onboarding.task_progress.filter(
    due_date__lt=timezone.now().date(),
    is_completed=False,
)
```

---

### Phase 5: Reassign Tasks

```python
from hr_core.models import OnboardingTaskProgress

# Get the task progress
task_progress = OnboardingTaskProgress.objects.get(id=123)

# Reassign to different person
task_progress.reassign(
    new_assignee=manager_user,
    reassigned_by=hr_user,
    reason="Manager expertise needed"
)

# View reassignment history
history = task_progress.reassignment_history
# Returns: [
#   {
#     'timestamp': '2026-01-16T10:30:45.123456',
#     'from_user_name': 'Jane HR',
#     'to_user_name': 'John Manager',
#     'reason': 'Manager expertise needed'
#   },
#   ...
# ]
```

**Constraints**:
- ✗ Cannot reassign completed tasks
- ✓ Can reassign multiple times
- ✓ Full audit trail maintained

---

### Phase 6: Collect Documents

```python
from hr_core.models import EmployeeDocument, DocumentTemplate

# Create document from template
template = DocumentTemplate.objects.get(name="Employment Contract")
document = EmployeeDocument.objects.create(
    employee=employee,
    template=template,
    title="Employment Contract",
    category='contract',
    file=request.FILES['contract_file'],
    requires_signature=True,
    status='pending_signature',
    uploaded_by=hr_user,
)

# Track status
if document.status == 'pending_signature':
    print(f"Waiting for signature from {employee.full_name}")

# Mark as signed
document.status = 'signed'
document.signed_at = timezone.now()
document.save()
```

**Document Statuses**:
- `draft` - Not yet complete
- `pending_signature` - Awaiting signature
- `signed` - Signed and complete
- `expired` - Past expiration date
- `archived` - Historical record

---

### Phase 7: Complete Onboarding

```python
from hr_core.models import EmployeeOnboarding

# Check if all tasks complete
if onboarding.completion_percentage == 100:
    # Mark onboarding as complete
    onboarding.completed_at = timezone.now()
    onboarding.save()

    # Update employee status (should be automatic - see ISSUES)
    employee = onboarding.employee
    employee.status = Employee.EmploymentStatus.PROBATION
    employee.save()

    print(f"Onboarding completed for {employee.full_name}")
    print(f"Employee moved to {employee.get_status_display()} status")
```

**Validation**:
- ✓ Completion percentage must be 100%
- ✓ Or manually override with business logic

---

## API Endpoints

### Checklist Management
```
GET    /api/v1/hr/onboarding-checklists/              # List all checklists
POST   /api/v1/hr/onboarding-checklists/              # Create new checklist
GET    /api/v1/hr/onboarding-checklists/{id}/         # Get specific checklist
PATCH  /api/v1/hr/onboarding-checklists/{id}/         # Update checklist
DELETE /api/v1/hr/onboarding-checklists/{id}/         # Delete checklist
POST   /api/v1/hr/onboarding-checklists/{id}/tasks/   # Add task to checklist
```

### Task Management
```
GET    /api/v1/hr/onboarding-tasks/                   # List all tasks
POST   /api/v1/hr/onboarding-tasks/                   # Create task
GET    /api/v1/hr/onboarding-tasks/{id}/              # Get task
PATCH  /api/v1/hr/onboarding-tasks/{id}/              # Update task
DELETE /api/v1/hr/onboarding-tasks/{id}/              # Delete task
```

### Onboarding Management
```
GET    /api/v1/hr/employee-onboarding/                # List all onboardings
POST   /api/v1/hr/employee-onboarding/                # Create onboarding
GET    /api/v1/hr/employee-onboarding/{id}/           # Get onboarding
PATCH  /api/v1/hr/employee-onboarding/{id}/           # Update onboarding

# Progress tracking
POST   /api/v1/hr/employee-onboarding/{id}/complete-task/  # Complete task
GET    /api/v1/hr/employee-onboarding/{id}/progress/       # Get progress
```

---

## Form Classes

### OnboardingChecklistForm
```python
from hr_core.forms import OnboardingChecklistForm

form = OnboardingChecklistForm(request.POST)
if form.is_valid():
    checklist = form.save()
```

**Fields**:
- name (required)
- description (optional)
- employment_type (optional)
- department (optional)
- is_active (optional)

---

### EmployeeOnboardingForm
```python
from hr_core.forms import EmployeeOnboardingForm

form = EmployeeOnboardingForm(request.POST)
if form.is_valid():
    onboarding = form.save()
```

**Fields**:
- checklist (required)
- start_date (required)
- target_completion_date (optional)
- notes (optional)

---

### OnboardingTaskProgressForm
```python
from hr_core.forms import OnboardingTaskProgressForm

form = OnboardingTaskProgressForm(request.POST, instance=task_progress)
if form.is_valid():
    form.save()
```

**Fields**:
- is_completed (boolean)
- notes (optional)

---

## Service Methods

### Create Onboarding via Service (Recommended)
```python
from hr_core.services import EmployeeService

result = EmployeeService.initiate_onboarding(
    employee=employee,
    checklist=checklist,
    start_date=date.today(),
    target_completion_date=date.today() + timedelta(days=30),
)

if result.success:
    onboarding = result.data
    print(f"Onboarding created: {onboarding.id}")
else:
    print(f"Error: {result.message}")
    print(f"Errors: {result.errors}")
```

### Complete Task via Service
```python
result = EmployeeService.complete_onboarding_task(
    task_progress_id=123,
    completed_by=request.user,
    notes="Task completed successfully",
)

if result.success:
    print(f"Task completed. Progress: {result.data['completion_percentage']}%")
else:
    print(f"Error: {result.message}")
```

---

## Key Models & Fields

### OnboardingChecklist
```
name: str (200)
description: str (optional)
employment_type: str (optional) - 'full_time', 'part_time', 'contract', 'intern'
department: FK (optional)
is_active: bool
created_at: datetime
updated_at: datetime
```

### OnboardingTask
```
checklist: FK (required)
title: str (200)
description: str (optional)
category: str - 'documentation', 'it_setup', 'training', 'introductions', 'compliance', 'benefits', 'other'
order: int (default 0)
assigned_to_role: str (optional) - 'HR', 'Manager', 'IT', etc.
due_days: int - days after start date (default 0)
is_required: bool (default True)
requires_signature: bool (default False)
document_template: FK (optional)
```

### EmployeeOnboarding
```
employee: OneToOne (unique)
checklist: FK
start_date: date
target_completion_date: date (optional)
completed_at: datetime (optional)
notes: str (optional)
uuid: uuid (unique)

Properties:
- completion_percentage: 0-100
```

### OnboardingTaskProgress
```
onboarding: FK
task: FK
is_completed: bool (default False)
completed_at: datetime (optional)
completed_by: FK User (optional)
notes: str (optional)
due_date: date (optional)
assigned_to: FK User (optional)
reassignment_history: list[dict] (JSONField)

Unique constraint: (onboarding, task)
```

---

## Common Queries

### Get all active onboardings
```python
onboardings = EmployeeOnboarding.objects.filter(
    completed_at__isnull=True  # Not completed yet
).select_related('employee', 'checklist')
```

### Get overdue tasks
```python
from django.utils import timezone

overdue = OnboardingTaskProgress.objects.filter(
    due_date__lt=timezone.now().date(),
    is_completed=False,
).select_related('onboarding__employee', 'task', 'assigned_to')
```

### Get tasks assigned to a user
```python
tasks = OnboardingTaskProgress.objects.filter(
    assigned_to=request.user,
    is_completed=False,
).select_related('onboarding__employee', 'task')
```

### Get onboarding for specific employee
```python
onboarding = EmployeeOnboarding.objects.select_related(
    'checklist'
).prefetch_related(
    'task_progress__task',
    'task_progress__assigned_to'
).get(employee=employee)
```

### Get completion stats
```python
from django.db.models import F, Count, Q

stats = EmployeeOnboarding.objects.aggregate(
    total=Count('id'),
    completed=Count('id', filter=Q(completed_at__isnull=False)),
    in_progress=Count('id', filter=Q(completed_at__isnull=True)),
)
```

---

## Permissions Required

### For HR Users
```python
user.has_perm('hr_core.change_onboardingchecklist')
user.has_perm('hr_core.change_employeeonboarding')
user.has_perm('hr_core.change_onboardingtaskprogress')
```

### For Managers
```python
# Can complete tasks assigned to them
# View employee onboarding progress
# Mark tasks complete
```

### For Employees
```python
# View own onboarding progress
# See assigned tasks
# Add notes to tasks
```

---

## Testing

### Run Onboarding Tests
```bash
# All onboarding tests
pytest hr_core/tests.py -k onboarding -v

# Specific test class
pytest hr_core/tests.py::TestOnboardingTaskAssignment -v

# With coverage
pytest --cov=hr_core hr_core/tests.py -v
```

### Test Fixtures
```python
@pytest.fixture
def onboarding_setup(employee, user_factory):
    """Complete onboarding test setup."""
    checklist = OnboardingChecklist.objects.create(
        name="Test Checklist"
    )
    for i in range(3):
        OnboardingTask.objects.create(
            checklist=checklist,
            title=f"Task {i}",
            due_days=i,
        )

    onboarding = EmployeeOnboarding.objects.create(
        employee=employee,
        checklist=checklist,
        start_date=date.today(),
    )

    for task in checklist.tasks.all():
        OnboardingTaskProgress.objects.create(
            onboarding=onboarding,
            task=task,
        )

    return onboarding
```

---

## Known Issues & Workarounds

### Issue 1: Task progress not auto-created
**Workaround**: Manually create in code (see Phase 3 above)
**Fix**: See ISSUES.md for permanent fix

### Issue 2: No automatic status update on completion
**Workaround**: Manually update employee status in code
**Fix**: See ISSUES.md for permanent fix

### Issue 3: No email notifications
**Workaround**: Implement your own notification service
**Fix**: See ISSUES.md for implementation guide

---

## Useful Utilities

### Get completion percentage
```python
percentage = onboarding.completion_percentage  # 0-100 integer
```

### Mark onboarding complete
```python
onboarding.completed_at = timezone.now()
onboarding.save()
```

### Get task due date
```python
task_progress = OnboardingTaskProgress.objects.get(...)
due_date = task_progress.due_date  # date object
is_overdue = task_progress.due_date < date.today()
```

### Get assigned tasks
```python
tasks = OnboardingTaskProgress.objects.filter(
    assigned_to=user,
    is_completed=False
).order_by('due_date')
```

---

## References

- **Models**: `hr_core/models.py` lines 583-796
- **Forms**: `hr_core/forms.py` lines 418-567
- **Views**: `hr_core/views.py` lines 730-867
- **Serializers**: `hr_core/serializers.py`
- **Tests**: `test_onboarding_workflow.py` (51 test cases)

---

**Last Updated**: 2026-01-16
**Test Suite**: 51 comprehensive test cases
**Coverage**: 87% of HR Core onboarding functionality
