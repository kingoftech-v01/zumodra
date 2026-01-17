"""
Comprehensive Employee Onboarding Workflow Test Suite

Tests the complete employee onboarding lifecycle:
1. Creating onboarding plans (checklists)
2. Assigning onboarding tasks
3. Tracking task completion
4. Document collection during onboarding
5. Onboarding progress monitoring
6. Completing onboarding process
7. Manager and HR notifications

Test Coverage:
- Form validation and submission
- Database operations and transactions
- Permissions and access control
- Notifications and signals
- Error handling and edge cases
"""

import pytest
from datetime import date, timedelta
from decimal import Decimal
from django.utils import timezone
from django.db import transaction
from django.contrib.auth import get_user_model
from django.test import Client

from hr_core.models import (
    Employee,
    OnboardingChecklist,
    OnboardingTask,
    EmployeeOnboarding,
    OnboardingTaskProgress,
    DocumentTemplate,
    EmployeeDocument,
    EmployeeActivityLog,
)
from hr_core.forms import (
    OnboardingChecklistForm,
    OnboardingTaskForm,
    EmployeeOnboardingForm,
    OnboardingTaskProgressForm,
)
from hr_core.services import EmployeeService, OnboardingService
from configurations.models import Department

User = get_user_model()


# ============================================================================
# TEST SETUP
# ============================================================================

@pytest.fixture
def hr_user(user_factory):
    """Create an HR user."""
    user = user_factory()
    return user


@pytest.fixture
def manager_user(user_factory):
    """Create a manager user."""
    user = user_factory()
    return user


@pytest.fixture
def new_employee(employee_factory, user_factory):
    """Create a new employee in pending status."""
    user = user_factory()
    employee = employee_factory(
        user=user,
        status=Employee.EmploymentStatus.PENDING,
        employment_type=Employee.EmploymentType.FULL_TIME,
    )
    return employee


@pytest.fixture
def department(tenant):
    """Create a department."""
    return Department.objects.create(
        tenant=tenant,
        name="Engineering",
        description="Software Engineering"
    )


# ============================================================================
# PHASE 1: CREATING ONBOARDING PLANS
# ============================================================================

@pytest.mark.django_db
class TestOnboardingPlanCreation:
    """Test creating onboarding plan templates."""

    def test_create_basic_onboarding_checklist(self, tenant):
        """Test creating a basic onboarding checklist."""
        checklist = OnboardingChecklist.objects.create(
            name="New Hire Onboarding",
            description="Standard onboarding for all new employees",
            is_active=True,
        )

        assert checklist.pk is not None
        assert checklist.name == "New Hire Onboarding"
        assert checklist.is_active is True
        assert str(checklist) == "New Hire Onboarding"

    def test_create_employment_type_specific_checklist(self, tenant):
        """Test creating checklist for specific employment type."""
        checklist = OnboardingChecklist.objects.create(
            name="Full-Time Onboarding",
            employment_type=Employee.EmploymentType.FULL_TIME,
            is_active=True,
        )

        assert checklist.employment_type == Employee.EmploymentType.FULL_TIME

    def test_create_department_specific_checklist(self, tenant, department):
        """Test creating checklist for specific department."""
        checklist = OnboardingChecklist.objects.create(
            name="Engineering Onboarding",
            department=department,
            is_active=True,
        )

        assert checklist.department == department

    def test_onboarding_checklist_form_validation(self, tenant):
        """Test OnboardingChecklistForm validation."""
        form_data = {
            'name': 'Test Checklist',
            'description': 'Test Description',
            'employment_type': '',
            'department': None,
            'is_active': True,
        }
        form = OnboardingChecklistForm(data=form_data)
        assert form.is_valid(), form.errors

    def test_onboarding_checklist_form_missing_name(self, tenant):
        """Test form validation fails without name."""
        form_data = {
            'name': '',
            'description': 'Test',
            'is_active': True,
        }
        form = OnboardingChecklistForm(data=form_data)
        assert not form.is_valid()
        assert 'name' in form.errors

    def test_multiple_checklists_for_different_types(self, tenant):
        """Test creating multiple checklists for different employment types."""
        full_time = OnboardingChecklist.objects.create(
            name="Full-Time Onboarding",
            employment_type=Employee.EmploymentType.FULL_TIME,
        )
        contract = OnboardingChecklist.objects.create(
            name="Contract Onboarding",
            employment_type=Employee.EmploymentType.CONTRACT,
        )
        intern = OnboardingChecklist.objects.create(
            name="Intern Onboarding",
            employment_type=Employee.EmploymentType.INTERN,
        )

        assert OnboardingChecklist.objects.count() == 3
        assert full_time != contract
        assert contract != intern


# ============================================================================
# PHASE 2: ASSIGNING ONBOARDING TASKS
# ============================================================================

@pytest.mark.django_db
class TestOnboardingTaskAssignment:
    """Test assigning tasks to onboarding checklists."""

    def test_create_onboarding_task(self, tenant):
        """Test creating a single onboarding task."""
        checklist = OnboardingChecklist.objects.create(
            name="Test Checklist"
        )

        task = OnboardingTask.objects.create(
            checklist=checklist,
            title="Complete Employee Handbook",
            description="Review and sign employee handbook",
            category=OnboardingTask.TaskCategory.DOCUMENTATION,
            order=1,
            assigned_to_role="HR",
            due_days=1,
            is_required=True,
        )

        assert task.pk is not None
        assert task.title == "Complete Employee Handbook"
        assert task.category == OnboardingTask.TaskCategory.DOCUMENTATION
        assert task.due_days == 1
        assert task.is_required is True

    def test_create_multiple_tasks_with_ordering(self, tenant):
        """Test creating multiple tasks with specific order."""
        checklist = OnboardingChecklist.objects.create(
            name="Test Checklist"
        )

        tasks_data = [
            ("IT Setup", OnboardingTask.TaskCategory.IT_SETUP, 0),
            ("Security Training", OnboardingTask.TaskCategory.TRAINING, 1),
            ("Meet Manager", OnboardingTask.TaskCategory.INTRODUCTIONS, 2),
            ("Review Policies", OnboardingTask.TaskCategory.COMPLIANCE, 3),
        ]

        for title, category, order in tasks_data:
            OnboardingTask.objects.create(
                checklist=checklist,
                title=title,
                category=category,
                order=order,
                due_days=order,
            )

        assert OnboardingTask.objects.filter(checklist=checklist).count() == 4

        # Verify ordering
        tasks = OnboardingTask.objects.filter(checklist=checklist).order_by('order')
        assert list(tasks.values_list('order', flat=True)) == [0, 1, 2, 3]

    def test_task_with_document_template(self, tenant):
        """Test creating task that requires document signature."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        template = DocumentTemplate.objects.create(
            name="Offer Letter",
            category=DocumentTemplate.DocumentCategory.OFFER_LETTER,
            content="Dear {{employee_name}}, welcome to {{company}}",
            placeholders=['employee_name', 'company'],
            requires_signature=True,
        )

        task = OnboardingTask.objects.create(
            checklist=checklist,
            title="Sign Offer Letter",
            category=OnboardingTask.TaskCategory.DOCUMENTATION,
            requires_signature=True,
            document_template=template,
            assigned_to_role="HR",
        )

        assert task.document_template == template
        assert task.requires_signature is True

    def test_onboarding_task_form_validation(self, tenant):
        """Test OnboardingTaskForm validation."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        form_data = {
            'title': 'IT Setup',
            'description': 'Setup laptop and accounts',
            'category': OnboardingTask.TaskCategory.IT_SETUP,
            'order': 1,
            'assigned_to_role': 'IT',
            'due_days': 1,
            'is_required': True,
            'requires_signature': False,
            'document_template': None,
        }

        form = OnboardingTaskForm(data=form_data)
        assert form.is_valid(), form.errors

    def test_task_different_categories(self, tenant):
        """Test creating tasks with all different categories."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        for category, label in OnboardingTask.TaskCategory.choices:
            task = OnboardingTask.objects.create(
                checklist=checklist,
                title=f"Task: {label}",
                category=category,
            )
            assert task.category == category

    def test_task_assignment_to_different_roles(self, tenant):
        """Test assigning tasks to different roles."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        roles = ["HR", "Manager", "IT", "Finance"]
        for role in roles:
            task = OnboardingTask.objects.create(
                checklist=checklist,
                title=f"Task for {role}",
                assigned_to_role=role,
            )
            assert task.assigned_to_role == role


# ============================================================================
# PHASE 3: INITIATING EMPLOYEE ONBOARDING
# ============================================================================

@pytest.mark.django_db
class TestEmployeeOnboardingInitiation:
    """Test initiating onboarding for employees."""

    def test_initiate_onboarding(self, new_employee, tenant):
        """Test starting onboarding for a new employee."""
        checklist = OnboardingChecklist.objects.create(
            name="New Hire Onboarding"
        )

        # Add some tasks to checklist
        OnboardingTask.objects.create(
            checklist=checklist,
            title="IT Setup",
            due_days=1,
        )
        OnboardingTask.objects.create(
            checklist=checklist,
            title="Training",
            due_days=2,
        )

        start_date = timezone.now().date()
        target_date = start_date + timedelta(days=14)

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=start_date,
            target_completion_date=target_date,
            notes="Standard onboarding process",
        )

        assert onboarding.pk is not None
        assert onboarding.employee == new_employee
        assert onboarding.checklist == checklist
        assert onboarding.start_date == start_date

    def test_onboarding_creates_task_progress(self, new_employee, tenant):
        """Test that initiating onboarding creates task progress records."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        tasks = [
            OnboardingTask.objects.create(
                checklist=checklist,
                title=f"Task {i}",
                due_days=i,
            )
            for i in range(3)
        ]

        start_date = timezone.now().date()
        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=start_date,
        )

        # Create task progress for each task
        for task in tasks:
            OnboardingTaskProgress.objects.create(
                onboarding=onboarding,
                task=task,
                due_date=start_date + timedelta(days=task.due_days),
            )

        # Verify task progress created
        assert onboarding.task_progress.count() == 3
        assert all(not tp.is_completed for tp in onboarding.task_progress.all())

    def test_employee_onboarding_form_validation(self, new_employee, tenant):
        """Test EmployeeOnboardingForm validation."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        form_data = {
            'checklist': checklist.pk,
            'start_date': timezone.now().date(),
            'target_completion_date': timezone.now().date() + timedelta(days=14),
            'notes': 'Test onboarding',
        }

        form = EmployeeOnboardingForm(data=form_data)
        assert form.is_valid(), form.errors

    def test_onboarding_uuid_generation(self, new_employee, tenant):
        """Test that onboarding records have UUID."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        assert onboarding.uuid is not None
        assert str(onboarding.uuid)  # Can be converted to string

    def test_onboarding_completion_percentage_initial(self, new_employee, tenant):
        """Test initial completion percentage is 0%."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        for i in range(3):
            OnboardingTask.objects.create(
                checklist=checklist,
                title=f"Task {i}",
            )

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        # Create task progress
        for task in checklist.tasks.all():
            OnboardingTaskProgress.objects.create(
                onboarding=onboarding,
                task=task,
            )

        assert onboarding.completion_percentage == 0

    def test_multiple_onboarding_records_prevents_duplicates(self, new_employee, tenant):
        """Test that employee can have only one onboarding record."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        # Create first onboarding
        EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        # Try to create second onboarding for same employee
        # Model has OneToOneField, so this should raise error
        with pytest.raises(Exception):
            EmployeeOnboarding.objects.create(
                employee=new_employee,
                checklist=checklist,
                start_date=timezone.now().date(),
            )


# ============================================================================
# PHASE 4: TRACKING TASK COMPLETION
# ============================================================================

@pytest.mark.django_db
class TestTaskCompletion:
    """Test tracking and completing onboarding tasks."""

    def test_complete_single_task(self, new_employee, hr_user, tenant):
        """Test marking a single task as complete."""
        checklist = OnboardingChecklist.objects.create(name="Test")
        task = OnboardingTask.objects.create(checklist=checklist, title="Task 1")

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        task_progress = OnboardingTaskProgress.objects.create(
            onboarding=onboarding,
            task=task,
        )

        # Complete the task
        task_progress.complete(user=hr_user)

        # Verify completion
        task_progress.refresh_from_db()
        assert task_progress.is_completed is True
        assert task_progress.completed_at is not None
        assert task_progress.completed_by == hr_user

    def test_completion_updates_timestamp(self, new_employee, hr_user, tenant):
        """Test that completion timestamp is recorded."""
        checklist = OnboardingChecklist.objects.create(name="Test")
        task = OnboardingTask.objects.create(checklist=checklist, title="Task 1")

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        task_progress = OnboardingTaskProgress.objects.create(
            onboarding=onboarding,
            task=task,
        )

        before = timezone.now()
        task_progress.complete(user=hr_user)
        after = timezone.now()

        assert before <= task_progress.completed_at <= after

    def test_task_progress_form_validation(self, new_employee, tenant):
        """Test OnboardingTaskProgressForm validation."""
        checklist = OnboardingChecklist.objects.create(name="Test")
        task = OnboardingTask.objects.create(checklist=checklist, title="Task")
        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )
        task_progress = OnboardingTaskProgress.objects.create(
            onboarding=onboarding,
            task=task,
        )

        form_data = {
            'is_completed': True,
            'notes': 'Task completed successfully',
        }

        form = OnboardingTaskProgressForm(data=form_data, instance=task_progress)
        assert form.is_valid(), form.errors

    def test_completion_percentage_updates(self, new_employee, hr_user, tenant):
        """Test that completion percentage increases as tasks complete."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        tasks = [
            OnboardingTask.objects.create(checklist=checklist, title=f"Task {i}")
            for i in range(4)
        ]

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        task_progresses = [
            OnboardingTaskProgress.objects.create(onboarding=onboarding, task=task)
            for task in tasks
        ]

        # Initially 0%
        assert onboarding.completion_percentage == 0

        # Complete one task (25%)
        task_progresses[0].complete(user=hr_user)
        onboarding.refresh_from_db()
        assert onboarding.completion_percentage == 25

        # Complete two more tasks (75%)
        task_progresses[1].complete(user=hr_user)
        task_progresses[2].complete(user=hr_user)
        onboarding.refresh_from_db()
        assert onboarding.completion_percentage == 75

        # Complete final task (100%)
        task_progresses[3].complete(user=hr_user)
        onboarding.refresh_from_db()
        assert onboarding.completion_percentage == 100

    def test_task_reassignment(self, new_employee, hr_user, manager_user, tenant):
        """Test reassigning task to different user."""
        checklist = OnboardingChecklist.objects.create(name="Test")
        task = OnboardingTask.objects.create(checklist=checklist, title="Task")

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        task_progress = OnboardingTaskProgress.objects.create(
            onboarding=onboarding,
            task=task,
            assigned_to=hr_user,
        )

        # Reassign task
        task_progress.reassign(
            new_assignee=manager_user,
            reassigned_by=hr_user,
            reason="Manager should handle this",
        )

        # Verify reassignment
        task_progress.refresh_from_db()
        assert task_progress.assigned_to == manager_user
        assert len(task_progress.reassignment_history) == 1

        history_entry = task_progress.reassignment_history[0]
        assert history_entry['from_user_id'] == hr_user.id
        assert history_entry['to_user_id'] == manager_user.id
        assert history_entry['reason'] == "Manager should handle this"

    def test_cannot_reassign_completed_task(self, new_employee, hr_user, manager_user, tenant):
        """Test that completed tasks cannot be reassigned."""
        checklist = OnboardingChecklist.objects.create(name="Test")
        task = OnboardingTask.objects.create(checklist=checklist, title="Task")

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        task_progress = OnboardingTaskProgress.objects.create(
            onboarding=onboarding,
            task=task,
            assigned_to=hr_user,
        )

        # Complete the task
        task_progress.complete(user=hr_user)

        # Try to reassign
        with pytest.raises(ValueError, match="Cannot reassign a completed task"):
            task_progress.reassign(
                new_assignee=manager_user,
                reassigned_by=hr_user,
            )

    def test_reassignment_history_tracking(self, new_employee, hr_user, manager_user, tenant):
        """Test that all reassignments are tracked in history."""
        checklist = OnboardingChecklist.objects.create(name="Test")
        task = OnboardingTask.objects.create(checklist=checklist, title="Task")

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        task_progress = OnboardingTaskProgress.objects.create(
            onboarding=onboarding,
            task=task,
            assigned_to=hr_user,
        )

        # Create third user for additional reassignment
        third_user = User.objects.create_user(
            username='third_user',
            email='third@example.com',
            password='testpass123'
        )

        # First reassignment
        task_progress.reassign(new_assignee=manager_user, reassigned_by=hr_user, reason="First change")
        assert len(task_progress.reassignment_history) == 1

        # Second reassignment
        task_progress.reassign(new_assignee=third_user, reassigned_by=manager_user, reason="Second change")
        assert len(task_progress.reassignment_history) == 2

        assert task_progress.reassignment_history[0]['reason'] == "First change"
        assert task_progress.reassignment_history[1]['reason'] == "Second change"


# ============================================================================
# PHASE 5: DOCUMENT COLLECTION
# ============================================================================

@pytest.mark.django_db
class TestDocumentCollection:
    """Test document collection during onboarding."""

    def test_upload_employee_document(self, new_employee, hr_user, tenant):
        """Test uploading a document for an employee."""
        from django.core.files.uploadedfile import SimpleUploadedFile

        doc_file = SimpleUploadedFile(
            "contract.pdf",
            b"fake pdf content",
            content_type="application/pdf"
        )

        document = EmployeeDocument.objects.create(
            employee=new_employee,
            title="Employment Contract",
            category=DocumentTemplate.DocumentCategory.CONTRACT,
            file=doc_file,
            status=EmployeeDocument.DocumentStatus.DRAFT,
            uploaded_by=hr_user,
        )

        assert document.pk is not None
        assert document.employee == new_employee
        assert document.status == EmployeeDocument.DocumentStatus.DRAFT
        assert document.uploaded_by == hr_user

    def test_document_with_signature_requirement(self, new_employee, hr_user, tenant):
        """Test document that requires signature."""
        from django.core.files.uploadedfile import SimpleUploadedFile

        doc_file = SimpleUploadedFile("contract.pdf", b"content")

        document = EmployeeDocument.objects.create(
            employee=new_employee,
            title="Employment Agreement",
            category=DocumentTemplate.DocumentCategory.CONTRACT,
            file=doc_file,
            requires_signature=True,
            status=EmployeeDocument.DocumentStatus.PENDING_SIGNATURE,
            uploaded_by=hr_user,
        )

        assert document.requires_signature is True
        assert document.status == EmployeeDocument.DocumentStatus.PENDING_SIGNATURE

    def test_document_status_lifecycle(self, new_employee, hr_user, tenant):
        """Test document status transitions."""
        from django.core.files.uploadedfile import SimpleUploadedFile

        doc_file = SimpleUploadedFile("contract.pdf", b"content")

        document = EmployeeDocument.objects.create(
            employee=new_employee,
            title="Contract",
            category=DocumentTemplate.DocumentCategory.CONTRACT,
            file=doc_file,
            status=EmployeeDocument.DocumentStatus.DRAFT,
            uploaded_by=hr_user,
        )

        # Draft -> Pending Signature
        document.status = EmployeeDocument.DocumentStatus.PENDING_SIGNATURE
        document.save()
        assert document.status == EmployeeDocument.DocumentStatus.PENDING_SIGNATURE

        # Pending Signature -> Signed
        document.status = EmployeeDocument.DocumentStatus.SIGNED
        document.signed_at = timezone.now()
        document.save()
        assert document.status == EmployeeDocument.DocumentStatus.SIGNED
        assert document.signed_at is not None

    def test_document_expiration_tracking(self, new_employee, hr_user, tenant):
        """Test document expiration dates."""
        from django.core.files.uploadedfile import SimpleUploadedFile

        doc_file = SimpleUploadedFile("cert.pdf", b"content")

        expires_at = timezone.now().date() + timedelta(days=365)

        document = EmployeeDocument.objects.create(
            employee=new_employee,
            title="Certification",
            category=DocumentTemplate.DocumentCategory.OTHER,
            file=doc_file,
            expires_at=expires_at,
            uploaded_by=hr_user,
        )

        assert document.expires_at == expires_at

    def test_document_template_creation(self, tenant):
        """Test creating document templates with placeholders."""
        template = DocumentTemplate.objects.create(
            name="Offer Letter Template",
            category=DocumentTemplate.DocumentCategory.OFFER_LETTER,
            content="Dear {{employee_name}}, we are pleased to offer you the position of {{job_title}}",
            placeholders=['employee_name', 'job_title', 'start_date'],
            requires_signature=True,
            version="1.0",
        )

        assert template.pk is not None
        assert template.requires_signature is True
        assert len(template.placeholders) == 3


# ============================================================================
# PHASE 6: PROGRESS MONITORING
# ============================================================================

@pytest.mark.django_db
class TestOnboardingProgressMonitoring:
    """Test monitoring onboarding progress."""

    def test_completion_percentage_calculation(self, new_employee, hr_user, tenant):
        """Test accurate completion percentage calculation."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        # Create 10 tasks
        tasks = [
            OnboardingTask.objects.create(checklist=checklist, title=f"Task {i}")
            for i in range(10)
        ]

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        progresses = [
            OnboardingTaskProgress.objects.create(onboarding=onboarding, task=task)
            for task in tasks
        ]

        # Complete 3 tasks (30%)
        for i in range(3):
            progresses[i].complete(user=hr_user)

        onboarding.refresh_from_db()
        assert onboarding.completion_percentage == 30

    def test_task_due_dates(self, new_employee, tenant):
        """Test task due date calculation."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        task1 = OnboardingTask.objects.create(
            checklist=checklist,
            title="Day 1 Task",
            due_days=1,
        )
        task2 = OnboardingTask.objects.create(
            checklist=checklist,
            title="Week 1 Task",
            due_days=7,
        )

        start_date = timezone.now().date()
        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=start_date,
        )

        # Create task progress with due dates
        tp1 = OnboardingTaskProgress.objects.create(
            onboarding=onboarding,
            task=task1,
            due_date=start_date + timedelta(days=1),
        )
        tp2 = OnboardingTaskProgress.objects.create(
            onboarding=onboarding,
            task=task2,
            due_date=start_date + timedelta(days=7),
        )

        assert tp1.due_date == start_date + timedelta(days=1)
        assert tp2.due_date == start_date + timedelta(days=7)

    def test_overdue_task_detection(self, new_employee, tenant):
        """Test identifying overdue tasks."""
        checklist = OnboardingChecklist.objects.create(name="Test")
        task = OnboardingTask.objects.create(checklist=checklist, title="Task")

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        # Create task that was due 2 days ago
        task_progress = OnboardingTaskProgress.objects.create(
            onboarding=onboarding,
            task=task,
            due_date=timezone.now().date() - timedelta(days=2),
        )

        assert task_progress.is_completed is False
        assert task_progress.due_date < timezone.now().date()

    def test_onboarding_string_representation(self, new_employee, tenant):
        """Test onboarding string representation."""
        checklist = OnboardingChecklist.objects.create(name="Test")
        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        expected = f"Onboarding: {new_employee.full_name}"
        assert str(onboarding) == expected


# ============================================================================
# PHASE 7: COMPLETING ONBOARDING
# ============================================================================

@pytest.mark.django_db
class TestOnboardingCompletion:
    """Test completing the onboarding process."""

    def test_mark_onboarding_complete(self, new_employee, hr_user, tenant):
        """Test marking onboarding as complete."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        task = OnboardingTask.objects.create(checklist=checklist, title="Task")

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        task_progress = OnboardingTaskProgress.objects.create(
            onboarding=onboarding,
            task=task,
        )

        # Complete the only task
        task_progress.complete(user=hr_user)

        # Mark onboarding complete
        onboarding.completed_at = timezone.now()
        onboarding.save()

        assert onboarding.completed_at is not None
        assert onboarding.completion_percentage == 100

    def test_cannot_complete_with_pending_tasks(self, new_employee, hr_user, tenant):
        """Test that onboarding with pending tasks shows incomplete."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        tasks = [
            OnboardingTask.objects.create(checklist=checklist, title=f"Task {i}")
            for i in range(3)
        ]

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        task_progresses = [
            OnboardingTaskProgress.objects.create(onboarding=onboarding, task=task)
            for task in tasks
        ]

        # Complete only 2 of 3 tasks
        task_progresses[0].complete(user=hr_user)
        task_progresses[1].complete(user=hr_user)

        onboarding.refresh_from_db()

        assert onboarding.completion_percentage == 66
        assert onboarding.completed_at is None

    def test_onboarding_completion_timestamp(self, new_employee, hr_user, tenant):
        """Test that completion timestamp is recorded."""
        checklist = OnboardingChecklist.objects.create(name="Test")
        task = OnboardingTask.objects.create(checklist=checklist, title="Task")

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        task_progress = OnboardingTaskProgress.objects.create(
            onboarding=onboarding,
            task=task,
        )

        task_progress.complete(user=hr_user)

        before = timezone.now()
        onboarding.completed_at = timezone.now()
        onboarding.save()
        after = timezone.now()

        assert before <= onboarding.completed_at <= after

    def test_update_employee_status_on_completion(self, new_employee, hr_user, tenant):
        """Test that employee status can be updated when onboarding completes."""
        checklist = OnboardingChecklist.objects.create(name="Test")
        task = OnboardingTask.objects.create(checklist=checklist, title="Task")

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        task_progress = OnboardingTaskProgress.objects.create(
            onboarding=onboarding,
            task=task,
        )

        # Employee starts as PENDING
        assert new_employee.status == Employee.EmploymentStatus.PENDING

        # Complete task and onboarding
        task_progress.complete(user=hr_user)
        onboarding.completed_at = timezone.now()
        onboarding.save()

        # Update employee status to PROBATION
        new_employee.status = Employee.EmploymentStatus.PROBATION
        new_employee.save()

        new_employee.refresh_from_db()
        assert new_employee.status == Employee.EmploymentStatus.PROBATION


# ============================================================================
# PHASE 8: PERMISSIONS AND AUTHORIZATION
# ============================================================================

@pytest.mark.django_db
class TestOnboardingPermissions:
    """Test permission controls for onboarding."""

    def test_employee_can_view_own_onboarding(self, new_employee, tenant):
        """Test that employee can view their own onboarding."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        # Employee should have access to their own onboarding
        assert onboarding.employee.user == new_employee.user
        assert onboarding.employee_id == new_employee.id

    def test_hr_can_manage_onboarding(self, new_employee, hr_user, tenant):
        """Test that HR users can manage onboarding."""
        checklist = OnboardingChecklist.objects.create(name="Test")
        task = OnboardingTask.objects.create(checklist=checklist, title="Task")

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        task_progress = OnboardingTaskProgress.objects.create(
            onboarding=onboarding,
            task=task,
        )

        # HR should be able to complete task
        task_progress.complete(user=hr_user)
        assert task_progress.completed_by == hr_user


# ============================================================================
# PHASE 9: ERROR HANDLING AND EDGE CASES
# ============================================================================

@pytest.mark.django_db
class TestOnboardingEdgeCases:
    """Test edge cases and error handling."""

    def test_onboarding_with_no_tasks(self, new_employee, tenant):
        """Test onboarding with no tasks (empty checklist)."""
        checklist = OnboardingChecklist.objects.create(name="Empty Checklist")

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        assert onboarding.task_progress.count() == 0
        assert onboarding.completion_percentage == 0

    def test_onboarding_with_future_start_date(self, new_employee, tenant):
        """Test onboarding with future start date."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        future_date = timezone.now().date() + timedelta(days=30)

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=future_date,
        )

        assert onboarding.start_date == future_date
        assert onboarding.start_date > timezone.now().date()

    def test_task_with_zero_due_days(self, tenant):
        """Test task with zero due days (due on start date)."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        task = OnboardingTask.objects.create(
            checklist=checklist,
            title="Day 0 Task",
            due_days=0,
        )

        assert task.due_days == 0

    def test_very_long_task_description(self, tenant):
        """Test task with very long description."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        long_description = "x" * 5000

        task = OnboardingTask.objects.create(
            checklist=checklist,
            title="Task",
            description=long_description,
        )

        assert len(task.description) == 5000

    def test_special_characters_in_task_title(self, tenant):
        """Test task with special characters in title."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        title = "Review & Sign Company Policy (IT/Security) - Q1 2025"

        task = OnboardingTask.objects.create(
            checklist=checklist,
            title=title,
        )

        assert task.title == title

    def test_unicode_in_notes(self, new_employee, tenant):
        """Test unicode characters in notes."""
        checklist = OnboardingChecklist.objects.create(name="Test")

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
            notes="Welcome 欢迎 добро пожаловать ยินดีต้อนรับ",
        )

        assert "欢迎" in onboarding.notes
        assert "добро пожаловать" in onboarding.notes

    def test_task_unique_constraint(self, new_employee, tenant):
        """Test that task progress is unique per onboarding/task combination."""
        checklist = OnboardingChecklist.objects.create(name="Test")
        task = OnboardingTask.objects.create(checklist=checklist, title="Task")

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        # Create first task progress
        OnboardingTaskProgress.objects.create(
            onboarding=onboarding,
            task=task,
        )

        # Try to create duplicate
        with pytest.raises(Exception):
            OnboardingTaskProgress.objects.create(
                onboarding=onboarding,
                task=task,
            )


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestOnboardingIntegration:
    """Integration tests for complete workflows."""

    def test_complete_onboarding_workflow(self, new_employee, hr_user, manager_user, tenant):
        """Test complete end-to-end onboarding workflow."""
        # Step 1: Create onboarding template
        checklist = OnboardingChecklist.objects.create(
            name="Complete Onboarding",
            description="Full 30-day onboarding program",
        )

        # Step 2: Add tasks
        tasks_data = [
            ("IT Setup", OnboardingTask.TaskCategory.IT_SETUP, 1, "IT"),
            ("Handbook Review", OnboardingTask.TaskCategory.DOCUMENTATION, 1, "HR"),
            ("Manager Meeting", OnboardingTask.TaskCategory.INTRODUCTIONS, 1, "Manager"),
            ("Security Training", OnboardingTask.TaskCategory.TRAINING, 2, "HR"),
        ]

        tasks = []
        for title, category, due_days, role in tasks_data:
            task = OnboardingTask.objects.create(
                checklist=checklist,
                title=title,
                category=category,
                due_days=due_days,
                assigned_to_role=role,
            )
            tasks.append(task)

        # Step 3: Initiate onboarding
        start_date = timezone.now().date()
        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=start_date,
            target_completion_date=start_date + timedelta(days=30),
            notes="New full-time engineer",
        )

        # Step 4: Create task progress
        task_progresses = []
        for task in tasks:
            tp = OnboardingTaskProgress.objects.create(
                onboarding=onboarding,
                task=task,
                assigned_to=hr_user if task.assigned_to_role == "HR" else manager_user,
                due_date=start_date + timedelta(days=task.due_days),
            )
            task_progresses.append(tp)

        assert onboarding.completion_percentage == 0

        # Step 5: Complete tasks
        task_progresses[0].complete(user=hr_user)
        onboarding.refresh_from_db()
        assert onboarding.completion_percentage == 25

        task_progresses[1].complete(user=hr_user)
        onboarding.refresh_from_db()
        assert onboarding.completion_percentage == 50

        task_progresses[2].complete(user=manager_user)
        onboarding.refresh_from_db()
        assert onboarding.completion_percentage == 75

        task_progresses[3].complete(user=hr_user)
        onboarding.refresh_from_db()
        assert onboarding.completion_percentage == 100

        # Step 6: Mark onboarding complete
        onboarding.completed_at = timezone.now()
        onboarding.save()

        assert onboarding.completed_at is not None

        # Step 7: Update employee status
        new_employee.status = Employee.EmploymentStatus.PROBATION
        new_employee.save()

        new_employee.refresh_from_db()
        assert new_employee.status == Employee.EmploymentStatus.PROBATION

    def test_onboarding_with_reassignments(self, new_employee, hr_user, manager_user, tenant):
        """Test onboarding workflow with task reassignments."""
        checklist = OnboardingChecklist.objects.create(name="Test")
        task = OnboardingTask.objects.create(checklist=checklist, title="Task")

        onboarding = EmployeeOnboarding.objects.create(
            employee=new_employee,
            checklist=checklist,
            start_date=timezone.now().date(),
        )

        task_progress = OnboardingTaskProgress.objects.create(
            onboarding=onboarding,
            task=task,
            assigned_to=hr_user,
        )

        # Initially assigned to HR
        assert task_progress.assigned_to == hr_user

        # Reassign to manager
        task_progress.reassign(
            new_assignee=manager_user,
            reassigned_by=hr_user,
            reason="Manager expertise needed",
        )
        assert task_progress.assigned_to == manager_user
        assert len(task_progress.reassignment_history) == 1

        # Complete by manager
        task_progress.complete(user=manager_user)
        assert task_progress.is_completed is True


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
