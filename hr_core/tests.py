"""
HR Core Tests - Human Resources Operations

Tests for:
- Employee CRUD operations
- Time-off request/approval workflow
- Onboarding checklist progress
- Document upload/signing
- Performance reviews
- Offboarding process
"""

import pytest
from decimal import Decimal
from datetime import timedelta, date
from django.utils import timezone
from django.db import IntegrityError

from hr_core.models import (
    Employee, TimeOffType, TimeOffRequest,
    OnboardingChecklist, OnboardingTask, EmployeeOnboarding,
    OnboardingTaskProgress, DocumentTemplate, EmployeeDocument,
    Offboarding, PerformanceReview
)


# ============================================================================
# EMPLOYEE TESTS
# ============================================================================

@pytest.mark.django_db
class TestEmployeeModel:
    """Tests for Employee model."""

    def test_create_employee(self, employee_factory):
        """Test basic employee creation."""
        employee = employee_factory()
        assert employee.pk is not None
        assert employee.uuid is not None
        assert employee.employee_id is not None
        assert employee.user is not None

    def test_employee_statuses(self, employee_factory):
        """Test different employee statuses."""
        for status, label in Employee.EmploymentStatus.choices:
            employee = employee_factory(status=status)
            assert employee.status == status

    def test_employee_types(self, employee_factory):
        """Test different employment types."""
        for emp_type, label in Employee.EmploymentType.choices:
            employee = employee_factory(employment_type=emp_type)
            assert employee.employment_type == emp_type

    def test_employee_full_name_property(self, employee_factory, user_factory):
        """Test full_name property."""
        user = user_factory(first_name='John', last_name='Doe')
        employee = employee_factory(user=user)

        assert employee.full_name == 'John Doe'

    def test_employee_first_last_name_properties(self, employee_factory, user_factory):
        """Test first_name and last_name properties."""
        user = user_factory(first_name='Jane', last_name='Smith')
        employee = employee_factory(user=user)

        assert employee.first_name == 'Jane'
        assert employee.last_name == 'Smith'

    def test_employee_is_active_employee_property(self, employee_factory):
        """Test is_active_employee property."""
        active = employee_factory(status='active')
        probation = employee_factory(status='probation')
        on_leave = employee_factory(status='on_leave')
        terminated = employee_factory(status='terminated')

        assert active.is_active_employee is True
        assert probation.is_active_employee is True
        assert on_leave.is_active_employee is True
        assert terminated.is_active_employee is False

    def test_employee_years_of_service(self, employee_factory):
        """Test years_of_service calculation."""
        start_date = timezone.now().date() - timedelta(days=730)  # 2 years ago
        employee = employee_factory(start_date=start_date)

        assert employee.years_of_service >= 1.9
        assert employee.years_of_service <= 2.1

    def test_employee_unique_id(self, employee_factory):
        """Test employee_id is unique."""
        employee_factory(employee_id='EMP001')
        with pytest.raises(IntegrityError):
            employee_factory(employee_id='EMP001')

    def test_employee_string_representation(self, employee_factory, user_factory):
        """Test employee string representation."""
        user = user_factory(first_name='John', last_name='Doe')
        employee = employee_factory(user=user, employee_id='EMP001')

        assert 'John Doe' in str(employee)
        assert 'EMP001' in str(employee)


@pytest.mark.django_db
class TestEmployeeCRUD:
    """Tests for employee CRUD operations."""

    def test_create_full_time_employee(self, employee_factory):
        """Test creating a full-time employee."""
        employee = employee_factory(
            employment_type='full_time',
            job_title='Software Developer',
            base_salary=Decimal('75000.00'),
            pto_balance=Decimal('15.00')
        )

        assert employee.employment_type == 'full_time'
        assert employee.job_title == 'Software Developer'
        assert employee.base_salary == Decimal('75000.00')

    def test_update_employee(self, employee_factory):
        """Test updating an employee."""
        employee = employee_factory(job_title='Junior Developer')

        employee.job_title = 'Senior Developer'
        employee.base_salary = Decimal('90000.00')
        employee.save()

        employee.refresh_from_db()
        assert employee.job_title == 'Senior Developer'
        assert employee.base_salary == Decimal('90000.00')

    def test_employee_manager_relationship(self, employee_factory):
        """Test employee-manager relationship."""
        manager = employee_factory(job_title='Engineering Manager')
        employee = employee_factory(manager=manager)

        assert employee.manager == manager
        assert manager.direct_reports.count() == 1

    def test_filter_active_employees(self, employee_factory):
        """Test filtering active employees."""
        employee_factory(status='active')
        employee_factory(status='active')
        employee_factory(status='terminated')
        employee_factory(status='resigned')

        active_employees = Employee.objects.filter(
            status__in=['active', 'probation', 'on_leave']
        )
        assert active_employees.count() == 2


# ============================================================================
# TIME OFF TYPE TESTS
# ============================================================================

@pytest.mark.django_db
class TestTimeOffTypeModel:
    """Tests for TimeOffType model."""

    def test_create_time_off_type(self, time_off_type_factory):
        """Test basic time off type creation."""
        time_off_type = time_off_type_factory()
        assert time_off_type.pk is not None
        assert time_off_type.name is not None
        assert time_off_type.code is not None

    def test_vacation_time_off_type(self):
        """Test vacation time off type."""
        from conftest import VacationTypeFactory
        vacation = VacationTypeFactory()

        assert vacation.name == 'Vacation'
        assert vacation.code == 'vacation'
        assert vacation.is_accrued is True
        assert vacation.is_paid is True

    def test_sick_leave_time_off_type(self):
        """Test sick leave time off type."""
        from conftest import SickLeaveTypeFactory
        sick = SickLeaveTypeFactory()

        assert sick.name == 'Sick Leave'
        assert sick.code == 'sick'
        assert sick.requires_documentation is True
        assert sick.min_notice_days == 0

    def test_time_off_type_accrual_settings(self, time_off_type_factory):
        """Test accrual settings."""
        time_off_type = time_off_type_factory(
            is_accrued=True,
            accrual_rate=Decimal('1.25'),
            max_balance=Decimal('30.00'),
            max_carryover=Decimal('5.00')
        )

        assert time_off_type.is_accrued is True
        assert time_off_type.accrual_rate == Decimal('1.25')
        assert time_off_type.max_balance == Decimal('30.00')

    def test_time_off_type_string_representation(self, time_off_type_factory):
        """Test time off type string representation."""
        time_off_type = time_off_type_factory(name='Personal Leave')
        assert str(time_off_type) == 'Personal Leave'


# ============================================================================
# TIME OFF REQUEST TESTS
# ============================================================================

@pytest.mark.django_db
class TestTimeOffRequestModel:
    """Tests for TimeOffRequest model."""

    def test_create_time_off_request(self, time_off_request_factory):
        """Test basic time off request creation."""
        request = time_off_request_factory()
        assert request.pk is not None
        assert request.uuid is not None
        assert request.employee is not None
        assert request.time_off_type is not None

    def test_time_off_request_statuses(self, time_off_request_factory):
        """Test different request statuses."""
        for status, label in TimeOffRequest.RequestStatus.choices:
            request = time_off_request_factory(status=status)
            assert request.status == status

    def test_time_off_request_half_day(self, time_off_request_factory):
        """Test half day request."""
        request = time_off_request_factory(
            is_half_day=True,
            half_day_period='am',
            total_days=Decimal('0.5')
        )

        assert request.is_half_day is True
        assert request.half_day_period == 'am'
        assert request.total_days == Decimal('0.5')

    def test_time_off_request_string_representation(self, time_off_request_factory):
        """Test request string representation."""
        request = time_off_request_factory()
        assert str(request) is not None


@pytest.mark.django_db
class TestTimeOffRequestWorkflow:
    """Tests for time off request/approval workflow."""

    def test_submit_time_off_request(self, employee_factory, time_off_type_factory):
        """Test submitting a time off request."""
        employee = employee_factory(pto_balance=Decimal('15.00'))
        vacation = time_off_type_factory(name='Vacation', code='vacation')

        request = TimeOffRequest.objects.create(
            employee=employee,
            time_off_type=vacation,
            start_date=timezone.now().date() + timedelta(days=14),
            end_date=timezone.now().date() + timedelta(days=18),
            total_days=Decimal('5.00'),
            reason='Family vacation',
            status='pending'
        )

        assert request.status == 'pending'
        assert request.total_days == Decimal('5.00')

    def test_approve_time_off_request(self, time_off_request_factory, user_factory):
        """Test approving a time off request."""
        request = time_off_request_factory(status='pending')
        approver = user_factory()
        initial_balance = request.employee.pto_balance

        request.approve(approver)

        assert request.status == 'approved'
        assert request.approver == approver
        assert request.approved_at is not None

        # Check PTO balance was deducted
        request.employee.refresh_from_db()
        expected_balance = initial_balance - request.total_days
        assert request.employee.pto_balance == expected_balance

    def test_reject_time_off_request(self, time_off_request_factory, user_factory):
        """Test rejecting a time off request."""
        request = time_off_request_factory(status='pending')
        approver = user_factory()
        initial_balance = request.employee.pto_balance

        request.reject(approver, reason='Blackout period')

        assert request.status == 'rejected'
        assert request.rejection_reason == 'Blackout period'

        # Check PTO balance was NOT deducted
        request.employee.refresh_from_db()
        assert request.employee.pto_balance == initial_balance

    def test_cancel_time_off_request(self, time_off_request_factory):
        """Test cancelling a time off request."""
        request = time_off_request_factory(status='pending')

        request.status = 'cancelled'
        request.save()

        assert request.status == 'cancelled'

    def test_time_off_insufficient_balance(self, employee_factory, time_off_type_factory):
        """Test request with insufficient balance."""
        employee = employee_factory(pto_balance=Decimal('2.00'))
        vacation = time_off_type_factory(name='Vacation', code='vacation')

        request = TimeOffRequest.objects.create(
            employee=employee,
            time_off_type=vacation,
            start_date=timezone.now().date() + timedelta(days=14),
            end_date=timezone.now().date() + timedelta(days=18),
            total_days=Decimal('5.00'),  # More than balance
            status='pending'
        )

        # Request can be created but approval should check balance
        # This would be validated in views/services
        assert request.total_days > employee.pto_balance


# ============================================================================
# ONBOARDING CHECKLIST TESTS
# ============================================================================

@pytest.mark.django_db
class TestOnboardingChecklistModel:
    """Tests for OnboardingChecklist model."""

    def test_create_onboarding_checklist(self, onboarding_checklist_factory):
        """Test basic onboarding checklist creation."""
        checklist = onboarding_checklist_factory()
        assert checklist.pk is not None
        assert checklist.name is not None

    def test_checklist_for_employment_type(self, onboarding_checklist_factory):
        """Test checklist specific to employment type."""
        checklist = onboarding_checklist_factory(employment_type='intern')
        assert checklist.employment_type == 'intern'

    def test_checklist_string_representation(self, onboarding_checklist_factory):
        """Test checklist string representation."""
        checklist = onboarding_checklist_factory(name='Engineering Onboarding')
        assert str(checklist) == 'Engineering Onboarding'


@pytest.mark.django_db
class TestOnboardingTaskModel:
    """Tests for OnboardingTask model."""

    def test_create_onboarding_task(self, onboarding_task_factory):
        """Test basic onboarding task creation."""
        task = onboarding_task_factory()
        assert task.pk is not None
        assert task.checklist is not None
        assert task.title is not None

    def test_task_categories(self, onboarding_task_factory):
        """Test different task categories."""
        for category, label in OnboardingTask.TaskCategory.choices:
            task = onboarding_task_factory(category=category)
            assert task.category == category

    def test_task_ordering(self, onboarding_checklist_factory, onboarding_task_factory):
        """Test task ordering."""
        checklist = onboarding_checklist_factory()
        task3 = onboarding_task_factory(checklist=checklist, order=3)
        task1 = onboarding_task_factory(checklist=checklist, order=1)
        task2 = onboarding_task_factory(checklist=checklist, order=2)

        tasks = list(OnboardingTask.objects.filter(checklist=checklist).order_by('order'))
        assert tasks[0].order == 1
        assert tasks[1].order == 2
        assert tasks[2].order == 3

    def test_task_string_representation(self, onboarding_checklist_factory, onboarding_task_factory):
        """Test task string representation."""
        checklist = onboarding_checklist_factory(name='New Hire')
        task = onboarding_task_factory(checklist=checklist, title='Sign NDA')

        assert 'New Hire' in str(task)
        assert 'Sign NDA' in str(task)


@pytest.mark.django_db
class TestOnboardingProgress:
    """Tests for onboarding progress tracking."""

    def test_create_employee_onboarding(self, employee_onboarding_factory):
        """Test creating employee onboarding."""
        onboarding = employee_onboarding_factory()
        assert onboarding.pk is not None
        assert onboarding.uuid is not None
        assert onboarding.employee is not None
        assert onboarding.checklist is not None

    def test_onboarding_completion_percentage_empty(self, employee_onboarding_factory):
        """Test completion percentage with no tasks."""
        onboarding = employee_onboarding_factory()
        # No task progress records
        assert onboarding.completion_percentage == 0

    def test_onboarding_completion_percentage(self, employee_with_onboarding):
        """Test completion percentage calculation."""
        employee, onboarding = employee_with_onboarding

        # Complete 2 of 4 tasks
        task_progress = list(onboarding.task_progress.all()[:2])
        for tp in task_progress:
            tp.complete()

        assert onboarding.completion_percentage == 50

    def test_complete_onboarding_task(self, employee_with_onboarding, user_factory):
        """Test completing an onboarding task."""
        employee, onboarding = employee_with_onboarding
        user = user_factory()

        task_progress = onboarding.task_progress.first()
        task_progress.complete(user=user)

        assert task_progress.is_completed is True
        assert task_progress.completed_at is not None
        assert task_progress.completed_by == user

    def test_full_onboarding_completion(self, employee_with_onboarding, user_factory):
        """Test completing all onboarding tasks."""
        employee, onboarding = employee_with_onboarding
        user = user_factory()

        # Complete all tasks
        for tp in onboarding.task_progress.all():
            tp.complete(user=user)

        assert onboarding.completion_percentage == 100


# ============================================================================
# DOCUMENT TEMPLATE TESTS
# ============================================================================

@pytest.mark.django_db
class TestDocumentTemplateModel:
    """Tests for DocumentTemplate model."""

    def test_create_document_template(self, document_template_factory):
        """Test basic document template creation."""
        template = document_template_factory()
        assert template.pk is not None
        assert template.name is not None
        assert template.content is not None

    def test_document_template_categories(self, document_template_factory):
        """Test different template categories."""
        for category, label in DocumentTemplate.DocumentCategory.choices:
            template = document_template_factory(category=category)
            assert template.category == category

    def test_template_with_placeholders(self, document_template_factory):
        """Test template with placeholders."""
        template = document_template_factory(
            content='Dear {{ employee_name }}, Welcome to {{ company_name }}!',
            placeholders=['employee_name', 'company_name', 'start_date']
        )

        assert 'employee_name' in template.placeholders
        assert 'company_name' in template.placeholders

    def test_template_string_representation(self, document_template_factory):
        """Test template string representation."""
        template = document_template_factory(name='Offer Letter', version='2.0')
        assert 'Offer Letter' in str(template)
        assert '2.0' in str(template)


# ============================================================================
# EMPLOYEE DOCUMENT TESTS
# ============================================================================

@pytest.mark.django_db
class TestEmployeeDocumentModel:
    """Tests for EmployeeDocument model."""

    def test_create_employee_document(self, employee_document_factory):
        """Test basic employee document creation."""
        document = employee_document_factory()
        assert document.pk is not None
        assert document.uuid is not None
        assert document.employee is not None

    def test_document_statuses(self, employee_document_factory):
        """Test different document statuses."""
        for status, label in EmployeeDocument.DocumentStatus.choices:
            document = employee_document_factory(status=status)
            assert document.status == status

    def test_document_with_signature_requirement(self, employee_document_factory):
        """Test document requiring signature."""
        document = employee_document_factory(
            requires_signature=True,
            status='pending_signature'
        )

        assert document.requires_signature is True
        assert document.status == 'pending_signature'

    def test_document_signed(self, employee_document_factory):
        """Test marking document as signed."""
        document = employee_document_factory(
            requires_signature=True,
            status='pending_signature'
        )

        document.status = 'signed'
        document.signed_at = timezone.now()
        document.save()

        assert document.status == 'signed'
        assert document.signed_at is not None

    def test_document_string_representation(self, employee_document_factory, employee_factory, user_factory):
        """Test document string representation."""
        user = user_factory(first_name='John', last_name='Doe')
        employee = employee_factory(user=user)
        document = employee_document_factory(
            employee=employee,
            title='Employment Contract'
        )

        assert 'Employment Contract' in str(document)


@pytest.mark.django_db
class TestDocumentUploadSigning:
    """Tests for document upload and signing workflow."""

    def test_upload_document(self, employee_factory, user_factory):
        """Test uploading a document."""
        employee = employee_factory()
        uploader = user_factory()

        document = EmployeeDocument.objects.create(
            employee=employee,
            title='Tax Form W-4',
            category='form',
            status='draft',
            requires_signature=False,
            uploaded_by=uploader
        )

        assert document.status == 'draft'
        assert document.uploaded_by == uploader

    def test_document_signing_workflow(self, employee_document_factory):
        """Test document signing workflow."""
        # Create document requiring signature
        document = employee_document_factory(
            requires_signature=True,
            status='draft'
        )

        # Send for signature
        document.status = 'pending_signature'
        document.save()
        assert document.status == 'pending_signature'

        # Document signed
        document.status = 'signed'
        document.signed_at = timezone.now()
        document.save()
        assert document.status == 'signed'
        assert document.signed_at is not None


# ============================================================================
# OFFBOARDING TESTS
# ============================================================================

@pytest.mark.django_db
class TestOffboardingModel:
    """Tests for Offboarding model."""

    def test_create_offboarding(self, offboarding_factory):
        """Test basic offboarding creation."""
        offboarding = offboarding_factory()
        assert offboarding.pk is not None
        assert offboarding.uuid is not None
        assert offboarding.employee is not None

    def test_separation_types(self, offboarding_factory):
        """Test different separation types."""
        for sep_type, label in Offboarding.SeparationType.choices:
            offboarding = offboarding_factory(separation_type=sep_type)
            assert offboarding.separation_type == sep_type

    def test_offboarding_is_complete_property(self, offboarding_factory):
        """Test is_complete property."""
        # Incomplete offboarding
        incomplete = offboarding_factory(
            knowledge_transfer_complete=True,
            equipment_returned=False,
            access_revoked=True,
            final_paycheck_processed=True
        )
        assert incomplete.is_complete is False

        # Complete offboarding
        complete = offboarding_factory(
            knowledge_transfer_complete=True,
            equipment_returned=True,
            access_revoked=True,
            final_paycheck_processed=True
        )
        assert complete.is_complete is True

    def test_offboarding_string_representation(self, offboarding_factory, employee_factory, user_factory):
        """Test offboarding string representation."""
        user = user_factory(first_name='Jane', last_name='Smith')
        employee = employee_factory(user=user)
        offboarding = offboarding_factory(employee=employee)

        assert 'Jane Smith' in str(offboarding)


@pytest.mark.django_db
class TestOffboardingWorkflow:
    """Tests for offboarding workflow."""

    def test_resignation_offboarding(self, employee_factory, user_factory):
        """Test resignation offboarding process."""
        employee = employee_factory(status='active')
        hr_user = user_factory()

        offboarding = Offboarding.objects.create(
            employee=employee,
            separation_type='resignation',
            notice_date=timezone.now().date(),
            last_working_day=timezone.now().date() + timedelta(days=14),
            processed_by=hr_user,
            eligible_for_rehire=True
        )

        assert offboarding.separation_type == 'resignation'
        assert offboarding.eligible_for_rehire is True

    def test_termination_offboarding(self, employee_factory, user_factory):
        """Test termination offboarding process."""
        employee = employee_factory(status='active')
        hr_user = user_factory()

        offboarding = Offboarding.objects.create(
            employee=employee,
            separation_type='termination',
            reason='Performance issues',
            notice_date=timezone.now().date(),
            last_working_day=timezone.now().date(),
            processed_by=hr_user,
            eligible_for_rehire=False,
            rehire_notes='Not eligible due to performance termination'
        )

        assert offboarding.separation_type == 'termination'
        assert offboarding.eligible_for_rehire is False

    def test_complete_offboarding_checklist(self, offboarding_factory):
        """Test completing offboarding checklist items."""
        offboarding = offboarding_factory()

        # Complete each item
        offboarding.knowledge_transfer_complete = True
        offboarding.equipment_returned = True
        offboarding.access_revoked = True
        offboarding.final_paycheck_processed = True
        offboarding.benefits_terminated = True
        offboarding.exit_interview_completed = True
        offboarding.completed_at = timezone.now()
        offboarding.save()

        assert offboarding.is_complete is True
        assert offboarding.completed_at is not None


# ============================================================================
# PERFORMANCE REVIEW TESTS
# ============================================================================

@pytest.mark.django_db
class TestPerformanceReviewModel:
    """Tests for PerformanceReview model."""

    def test_create_performance_review(self, performance_review_factory):
        """Test basic performance review creation."""
        review = performance_review_factory()
        assert review.pk is not None
        assert review.uuid is not None
        assert review.employee is not None
        assert review.reviewer is not None

    def test_review_types(self, performance_review_factory):
        """Test different review types."""
        for review_type, label in PerformanceReview.ReviewType.choices:
            review = performance_review_factory(review_type=review_type)
            assert review.review_type == review_type

    def test_review_statuses(self, performance_review_factory):
        """Test different review statuses."""
        for status, label in PerformanceReview.ReviewStatus.choices:
            review = performance_review_factory(status=status)
            assert review.status == status

    def test_review_ratings(self, performance_review_factory):
        """Test review ratings."""
        review = performance_review_factory(
            overall_rating=4,
            goals_met_percentage=85
        )

        assert review.overall_rating == 4
        assert review.goals_met_percentage == 85

    def test_review_string_representation(self, performance_review_factory, employee_factory, user_factory):
        """Test review string representation."""
        user = user_factory(first_name='John', last_name='Doe')
        employee = employee_factory(user=user)
        review = performance_review_factory(
            employee=employee,
            review_type='annual'
        )

        assert 'John Doe' in str(review)
        assert 'Annual' in str(review)


@pytest.mark.django_db
class TestPerformanceReviewWorkflow:
    """Tests for performance review workflow."""

    def test_create_annual_review(self, employee_factory, user_factory):
        """Test creating an annual review."""
        employee = employee_factory()
        reviewer = user_factory()
        review_end = timezone.now().date()
        review_start = review_end - timedelta(days=365)

        review = PerformanceReview.objects.create(
            employee=employee,
            reviewer=reviewer,
            review_type='annual',
            review_period_start=review_start,
            review_period_end=review_end,
            status='draft'
        )

        assert review.review_type == 'annual'
        assert review.status == 'draft'

    def test_self_assessment_submission(self, performance_review_factory):
        """Test employee self-assessment submission."""
        review = performance_review_factory(status='pending_self')

        review.self_assessment = 'I exceeded my goals this year...'
        review.status = 'pending_manager'
        review.save()

        assert review.status == 'pending_manager'
        assert review.self_assessment != ''

    def test_manager_review_submission(self, performance_review_factory):
        """Test manager review submission."""
        review = performance_review_factory(status='pending_manager')

        review.manager_feedback = 'John has been an excellent performer...'
        review.overall_rating = 4
        review.goals_met_percentage = 90
        review.accomplishments = 'Led key project...'
        review.areas_for_improvement = 'Communication skills...'
        review.goals_for_next_period = 'Lead team expansion...'
        review.salary_increase_recommended = True
        review.salary_increase_percentage = Decimal('5.00')
        review.manager_signed_at = timezone.now()
        review.status = 'pending_approval'
        review.save()

        assert review.status == 'pending_approval'
        assert review.overall_rating == 4

    def test_complete_review(self, performance_review_factory):
        """Test completing a performance review."""
        review = performance_review_factory(status='pending_approval')

        review.status = 'completed'
        review.completed_at = timezone.now()
        review.save()

        assert review.status == 'completed'
        assert review.completed_at is not None


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestHRCoreIntegration:
    """Integration tests for HR Core functionality."""

    def test_new_hire_onboarding_flow(self, user_factory):
        """Test complete new hire onboarding flow."""
        from conftest import (
            EmployeeFactory, OnboardingChecklistFactory,
            OnboardingTaskFactory, EmployeeOnboardingFactory,
            OnboardingTaskProgressFactory
        )

        user = user_factory()
        hr_user = user_factory()

        # Create employee
        employee = EmployeeFactory(
            user=user,
            status='pending',
            hire_date=timezone.now().date(),
            start_date=timezone.now().date() + timedelta(days=7)
        )

        # Create checklist and tasks
        checklist = OnboardingChecklistFactory(name='Engineering Onboarding')
        tasks = [
            OnboardingTaskFactory(checklist=checklist, title='Sign offer letter', category='documentation', order=0),
            OnboardingTaskFactory(checklist=checklist, title='Complete I-9 form', category='compliance', order=1),
            OnboardingTaskFactory(checklist=checklist, title='Setup laptop', category='it_setup', order=2),
            OnboardingTaskFactory(checklist=checklist, title='Meet the team', category='introductions', order=3),
        ]

        # Create onboarding
        onboarding = EmployeeOnboardingFactory(
            employee=employee,
            checklist=checklist,
            start_date=employee.start_date
        )

        # Create task progress
        for task in tasks:
            OnboardingTaskProgressFactory(onboarding=onboarding, task=task)

        # Complete tasks
        for tp in onboarding.task_progress.all():
            tp.complete(user=hr_user)

        assert onboarding.completion_percentage == 100

        # Update employee status
        employee.status = 'probation'
        employee.save()

        assert employee.status == 'probation'

    def test_employee_time_off_cycle(self, employee_factory, user_factory):
        """Test complete time off request cycle."""
        from conftest import VacationTypeFactory

        employee = employee_factory(pto_balance=Decimal('15.00'))
        manager = user_factory()
        vacation = VacationTypeFactory()

        # Submit request
        request = TimeOffRequest.objects.create(
            employee=employee,
            time_off_type=vacation,
            start_date=timezone.now().date() + timedelta(days=14),
            end_date=timezone.now().date() + timedelta(days=16),
            total_days=Decimal('3.00'),
            status='pending'
        )

        # Approve request
        request.approve(manager)

        employee.refresh_from_db()
        assert employee.pto_balance == Decimal('12.00')
        assert request.status == 'approved'

    def test_employee_resignation_flow(self, employee_factory, user_factory):
        """Test complete employee resignation flow."""
        employee = employee_factory(status='active')
        hr_user = user_factory()

        # Create offboarding
        offboarding = Offboarding.objects.create(
            employee=employee,
            separation_type='resignation',
            notice_date=timezone.now().date(),
            last_working_day=timezone.now().date() + timedelta(days=14),
            processed_by=hr_user
        )

        # Update employee status
        employee.status = 'notice_period'
        employee.save()

        # Complete offboarding tasks
        offboarding.knowledge_transfer_complete = True
        offboarding.equipment_returned = True
        offboarding.access_revoked = True
        offboarding.final_paycheck_processed = True
        offboarding.exit_interview_completed = True
        offboarding.save()

        assert offboarding.is_complete is True

        # Final status update
        employee.status = 'resigned'
        employee.termination_date = offboarding.last_working_day
        employee.save()

        assert employee.status == 'resigned'

    def test_annual_review_cycle(self, employee_factory, user_factory):
        """Test complete annual review cycle."""
        employee = employee_factory()
        manager = user_factory()

        review_end = timezone.now().date()
        review_start = review_end - timedelta(days=365)

        # Create review
        review = PerformanceReview.objects.create(
            employee=employee,
            reviewer=manager,
            review_type='annual',
            review_period_start=review_start,
            review_period_end=review_end,
            status='pending_self'
        )

        # Self-assessment
        review.self_assessment = 'I achieved all my goals...'
        review.status = 'pending_manager'
        review.save()

        # Manager review
        review.manager_feedback = 'Excellent performance...'
        review.overall_rating = 4
        review.goals_met_percentage = 95
        review.salary_increase_recommended = True
        review.salary_increase_percentage = Decimal('5.00')
        review.status = 'pending_approval'
        review.save()

        # HR approval
        review.status = 'completed'
        review.completed_at = timezone.now()
        review.save()

        assert review.status == 'completed'
        assert review.salary_increase_recommended is True
