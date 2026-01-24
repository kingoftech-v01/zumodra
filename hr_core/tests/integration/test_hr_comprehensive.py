"""
HR Core Tests - Comprehensive Test Suite for Human Resources Module

This module provides tests for:
1. Employee lifecycle (pending -> probation -> active -> terminated)
2. Time-off management (request, approval, rejection, balance)
3. Onboarding workflow (checklist assignment, task completion)
4. Document management (templates, generation, signatures)
5. Offboarding process (exit interviews, equipment return)
6. Performance reviews (creation, feedback, approval)
7. PTO accrual calculations
8. Manager approval workflows
9. Bulk operations
10. Reporting and analytics
"""

import pytest
from datetime import date, timedelta
from decimal import Decimal
from unittest.mock import patch, MagicMock

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from tests.base import TenantTestCase, APITenantTestCase

# Import factories from conftest
from conftest import (
    UserFactory,
    TenantFactory,
    TenantUserFactory,
    PlanFactory,
    EmployeeFactory,
    ProbationaryEmployeeFactory,
    TimeOffTypeFactory,
    VacationTypeFactory,
    SickLeaveTypeFactory,
    TimeOffRequestFactory,
    ApprovedTimeOffRequestFactory,
    OnboardingChecklistFactory,
    OnboardingTaskFactory,
    EmployeeOnboardingFactory,
    OnboardingTaskProgressFactory,
    DocumentTemplateFactory,
    EmployeeDocumentFactory,
    OffboardingFactory,
    PerformanceReviewFactory,
)


# ============================================================================
# EMPLOYEE LIFECYCLE TESTS
# ============================================================================

class TestEmployeeLifecycle(TenantTestCase):
    """Tests for employee lifecycle management (pending -> probation -> active -> terminated)."""

    def test_create_employee_with_pending_status(self):
        """Test creating a new employee with pending status."""
        with self.tenant_context():
            user = UserFactory()
            employee = EmployeeFactory(
                user=user,
                status='pending',
                hire_date=timezone.now().date(),
                start_date=timezone.now().date() + timedelta(days=14),
            )

            assert employee.status == 'pending'
            assert employee.is_active_employee is False
            assert employee.user == user

    def test_employee_transition_pending_to_probation(self):
        """Test transitioning employee from pending to probation status."""
        with self.tenant_context():
            employee = EmployeeFactory(status='pending')

            # Simulate employee starting work
            employee.status = 'probation'
            employee.start_date = timezone.now().date()
            employee.probation_end_date = timezone.now().date() + timedelta(days=90)
            employee.save()

            employee.refresh_from_db()
            assert employee.status == 'probation'
            assert employee.is_active_employee is True

    def test_employee_transition_probation_to_active(self):
        """Test transitioning employee from probation to active status."""
        with self.tenant_context():
            employee = ProbationaryEmployeeFactory()

            # Complete probation period
            employee.status = 'active'
            employee.save()

            employee.refresh_from_db()
            assert employee.status == 'active'
            assert employee.is_active_employee is True

    def test_employee_transition_active_to_on_leave(self):
        """Test transitioning employee from active to on_leave status."""
        with self.tenant_context():
            employee = EmployeeFactory(status='active')

            employee.status = 'on_leave'
            employee.save()

            employee.refresh_from_db()
            assert employee.status == 'on_leave'
            assert employee.is_active_employee is True  # Still considered active

    def test_employee_transition_to_notice_period(self):
        """Test transitioning employee to notice period before termination."""
        with self.tenant_context():
            employee = EmployeeFactory(status='active')

            employee.status = 'notice_period'
            employee.last_working_day = timezone.now().date() + timedelta(days=14)
            employee.save()

            employee.refresh_from_db()
            assert employee.status == 'notice_period'
            assert employee.is_active_employee is False

    def test_employee_transition_to_terminated(self):
        """Test transitioning employee to terminated status."""
        with self.tenant_context():
            employee = EmployeeFactory(status='active')

            employee.status = 'terminated'
            employee.termination_date = timezone.now().date()
            employee.last_working_day = timezone.now().date()
            employee.save()

            employee.refresh_from_db()
            assert employee.status == 'terminated'
            assert employee.is_active_employee is False

    def test_employee_transition_to_resigned(self):
        """Test transitioning employee to resigned status."""
        with self.tenant_context():
            employee = EmployeeFactory(status='active')

            employee.status = 'resigned'
            employee.termination_date = timezone.now().date()
            employee.save()

            employee.refresh_from_db()
            assert employee.status == 'resigned'
            assert employee.is_active_employee is False

    def test_employee_years_of_service_calculation(self):
        """Test years of service calculation for employee."""
        with self.tenant_context():
            start_date = timezone.now().date() - timedelta(days=730)  # ~2 years
            employee = EmployeeFactory(
                status='active',
                start_date=start_date,
            )

            # Should be approximately 2 years
            assert 1.9 < employee.years_of_service < 2.1

    def test_employee_years_of_service_no_start_date(self):
        """Test years of service returns 0 when no start date."""
        with self.tenant_context():
            employee = EmployeeFactory(start_date=None)

            assert employee.years_of_service == 0

    def test_employee_full_name_property(self):
        """Test employee full_name property returns correct value."""
        with self.tenant_context():
            user = UserFactory(first_name='John', last_name='Doe')
            employee = EmployeeFactory(user=user)

            assert employee.full_name == 'John Doe'
            assert employee.first_name == 'John'
            assert employee.last_name == 'Doe'

    def test_employee_str_representation(self):
        """Test employee string representation."""
        with self.tenant_context():
            user = UserFactory(first_name='Jane', last_name='Smith')
            employee = EmployeeFactory(user=user, employee_id='EMP00001')

            expected = 'Jane Smith (EMP00001)'
            assert str(employee) == expected

    def test_employee_suspended_status(self):
        """Test employee can be suspended."""
        with self.tenant_context():
            employee = EmployeeFactory(status='active')

            employee.status = 'suspended'
            employee.save()

            employee.refresh_from_db()
            assert employee.status == 'suspended'
            assert employee.is_active_employee is False


# ============================================================================
# TIME-OFF MANAGEMENT TESTS
# ============================================================================

class TestTimeOffManagement(TenantTestCase):
    """Tests for time-off request, approval, rejection, and balance management."""

    def test_create_time_off_request(self):
        """Test creating a time off request."""
        with self.tenant_context():
            employee = EmployeeFactory(pto_balance=Decimal('15.00'))
            vacation_type = VacationTypeFactory()

            request = TimeOffRequestFactory(
                employee=employee,
                time_off_type=vacation_type,
                start_date=timezone.now().date() + timedelta(days=7),
                end_date=timezone.now().date() + timedelta(days=10),
                total_days=Decimal('4.00'),
                status='pending',
            )

            assert request.status == 'pending'
            assert request.total_days == Decimal('4.00')
            assert request.employee == employee

    def test_approve_time_off_request(self):
        """Test approving a time off request deducts from balance."""
        with self.tenant_context():
            employee = EmployeeFactory(pto_balance=Decimal('15.00'))
            vacation_type = VacationTypeFactory()
            approver = UserFactory()

            request = TimeOffRequestFactory(
                employee=employee,
                time_off_type=vacation_type,
                total_days=Decimal('5.00'),
                status='pending',
            )

            request.approve(approver)

            request.refresh_from_db()
            employee.refresh_from_db()

            assert request.status == 'approved'
            assert request.approver == approver
            assert request.approved_at is not None
            assert employee.pto_balance == Decimal('10.00')  # 15 - 5

    def test_approve_time_off_insufficient_balance(self):
        """Test approving request with insufficient balance raises error."""
        with self.tenant_context():
            employee = EmployeeFactory(pto_balance=Decimal('2.00'))
            vacation_type = VacationTypeFactory()
            approver = UserFactory()

            request = TimeOffRequestFactory(
                employee=employee,
                time_off_type=vacation_type,
                total_days=Decimal('5.00'),
                status='pending',
            )

            with pytest.raises(ValidationError) as exc_info:
                request.approve(approver)

            assert 'Insufficient PTO balance' in str(exc_info.value)

    def test_reject_time_off_request(self):
        """Test rejecting a time off request."""
        with self.tenant_context():
            employee = EmployeeFactory(pto_balance=Decimal('15.00'))
            vacation_type = VacationTypeFactory()
            approver = UserFactory()

            request = TimeOffRequestFactory(
                employee=employee,
                time_off_type=vacation_type,
                total_days=Decimal('5.00'),
                status='pending',
            )

            request.reject(approver, reason='Business needs')

            request.refresh_from_db()
            employee.refresh_from_db()

            assert request.status == 'rejected'
            assert request.approver == approver
            assert request.rejection_reason == 'Business needs'
            assert employee.pto_balance == Decimal('15.00')  # Balance unchanged

    def test_time_off_request_half_day(self):
        """Test creating a half-day time off request."""
        with self.tenant_context():
            employee = EmployeeFactory()
            vacation_type = VacationTypeFactory()

            request = TimeOffRequestFactory(
                employee=employee,
                time_off_type=vacation_type,
                is_half_day=True,
                half_day_period='am',
                total_days=Decimal('0.50'),
            )

            assert request.is_half_day is True
            assert request.half_day_period == 'am'
            assert request.total_days == Decimal('0.50')

    def test_time_off_request_sick_leave(self):
        """Test creating a sick leave request."""
        with self.tenant_context():
            employee = EmployeeFactory(sick_leave_balance=Decimal('10.00'))
            sick_type = SickLeaveTypeFactory()

            request = TimeOffRequestFactory(
                employee=employee,
                time_off_type=sick_type,
                total_days=Decimal('2.00'),
                status='pending',
            )

            assert request.time_off_type.code == 'sick'
            assert request.time_off_type.requires_documentation is True

    def test_time_off_type_properties(self):
        """Test time off type properties and configuration."""
        with self.tenant_context():
            vacation_type = VacationTypeFactory(
                is_accrued=True,
                accrual_rate=Decimal('1.25'),
                max_balance=Decimal('30.00'),
                max_carryover=Decimal('5.00'),
                requires_approval=True,
                min_notice_days=1,
            )

            assert vacation_type.is_accrued is True
            assert vacation_type.accrual_rate == Decimal('1.25')
            assert vacation_type.max_balance == Decimal('30.00')
            assert vacation_type.requires_approval is True

    def test_time_off_request_cancelled(self):
        """Test cancelling a pending time off request."""
        with self.tenant_context():
            request = TimeOffRequestFactory(status='pending')

            request.status = 'cancelled'
            request.save()

            request.refresh_from_db()
            assert request.status == 'cancelled'

    def test_time_off_request_str_representation(self):
        """Test time off request string representation."""
        with self.tenant_context():
            user = UserFactory(first_name='Alice', last_name='Johnson')
            employee = EmployeeFactory(user=user)
            vacation_type = VacationTypeFactory(name='Vacation')

            request = TimeOffRequestFactory(
                employee=employee,
                time_off_type=vacation_type,
                start_date=date(2024, 6, 1),
                end_date=date(2024, 6, 5),
            )

            assert 'Alice Johnson' in str(request)
            assert 'Vacation' in str(request)


# ============================================================================
# ONBOARDING WORKFLOW TESTS
# ============================================================================

class TestOnboardingWorkflow(TenantTestCase):
    """Tests for onboarding checklist assignment and task completion."""

    def test_create_onboarding_checklist(self):
        """Test creating an onboarding checklist."""
        with self.tenant_context():
            checklist = OnboardingChecklistFactory(
                name='New Hire Onboarding',
                description='Standard onboarding for new employees',
                employment_type='full_time',
                is_active=True,
            )

            assert checklist.name == 'New Hire Onboarding'
            assert checklist.is_active is True

    def test_create_onboarding_tasks(self):
        """Test creating onboarding tasks for a checklist."""
        with self.tenant_context():
            checklist = OnboardingChecklistFactory()

            task1 = OnboardingTaskFactory(
                checklist=checklist,
                title='Sign employment contract',
                category='documentation',
                order=0,
                is_required=True,
            )
            task2 = OnboardingTaskFactory(
                checklist=checklist,
                title='IT equipment setup',
                category='it_setup',
                order=1,
                assigned_to_role='IT',
            )

            assert checklist.tasks.count() == 2
            assert task1.is_required is True
            assert task2.assigned_to_role == 'IT'

    def test_assign_onboarding_to_employee(self):
        """Test assigning onboarding checklist to an employee."""
        with self.tenant_context():
            employee = EmployeeFactory(status='pending')
            checklist = OnboardingChecklistFactory()

            onboarding = EmployeeOnboardingFactory(
                employee=employee,
                checklist=checklist,
                start_date=timezone.now().date(),
                target_completion_date=timezone.now().date() + timedelta(days=30),
            )

            assert onboarding.employee == employee
            assert onboarding.checklist == checklist
            assert onboarding.completed_at is None

    def test_onboarding_task_progress_creation(self):
        """Test creating task progress for onboarding tasks."""
        with self.tenant_context():
            checklist = OnboardingChecklistFactory()
            task = OnboardingTaskFactory(checklist=checklist, due_days=7)
            employee = EmployeeFactory(status='pending')
            onboarding = EmployeeOnboardingFactory(
                employee=employee,
                checklist=checklist,
            )

            progress = OnboardingTaskProgressFactory(
                onboarding=onboarding,
                task=task,
                is_completed=False,
                due_date=timezone.now().date() + timedelta(days=7),
            )

            assert progress.is_completed is False
            assert progress.onboarding == onboarding
            assert progress.task == task

    def test_complete_onboarding_task(self):
        """Test completing an onboarding task."""
        with self.tenant_context():
            checklist = OnboardingChecklistFactory()
            task = OnboardingTaskFactory(checklist=checklist)
            employee = EmployeeFactory(status='pending')
            onboarding = EmployeeOnboardingFactory(employee=employee, checklist=checklist)
            hr_user = UserFactory()

            progress = OnboardingTaskProgressFactory(
                onboarding=onboarding,
                task=task,
                is_completed=False,
            )

            progress.complete(user=hr_user)

            progress.refresh_from_db()
            assert progress.is_completed is True
            assert progress.completed_at is not None
            assert progress.completed_by == hr_user

    def test_onboarding_completion_percentage(self):
        """Test calculation of onboarding completion percentage."""
        with self.tenant_context():
            checklist = OnboardingChecklistFactory()
            employee = EmployeeFactory(status='pending')
            onboarding = EmployeeOnboardingFactory(employee=employee, checklist=checklist)

            # Create 4 tasks
            tasks = [OnboardingTaskFactory(checklist=checklist) for _ in range(4)]

            # Create progress for all tasks
            for i, task in enumerate(tasks):
                OnboardingTaskProgressFactory(
                    onboarding=onboarding,
                    task=task,
                    is_completed=(i < 2),  # First 2 completed
                )

            assert onboarding.completion_percentage == 50  # 2/4 = 50%

    def test_onboarding_completion_percentage_no_tasks(self):
        """Test completion percentage returns 0 when no tasks."""
        with self.tenant_context():
            checklist = OnboardingChecklistFactory()
            employee = EmployeeFactory(status='pending')
            onboarding = EmployeeOnboardingFactory(employee=employee, checklist=checklist)

            assert onboarding.completion_percentage == 0

    def test_onboarding_task_with_document_template(self):
        """Test onboarding task linked to document template."""
        with self.tenant_context():
            template = DocumentTemplateFactory(
                name='Employment Contract',
                requires_signature=True,
            )
            checklist = OnboardingChecklistFactory()

            task = OnboardingTaskFactory(
                checklist=checklist,
                title='Sign employment contract',
                requires_signature=True,
                document_template=template,
            )

            assert task.document_template == template
            assert task.requires_signature is True

    def test_onboarding_task_categories(self):
        """Test different onboarding task categories."""
        with self.tenant_context():
            checklist = OnboardingChecklistFactory()

            categories = [
                ('documentation', 'Documentation'),
                ('it_setup', 'IT Setup'),
                ('training', 'Training'),
                ('introductions', 'Introductions'),
                ('compliance', 'Compliance'),
                ('benefits', 'Benefits Enrollment'),
            ]

            for category_code, _ in categories:
                task = OnboardingTaskFactory(
                    checklist=checklist,
                    category=category_code,
                )
                assert task.category == category_code


# ============================================================================
# DOCUMENT MANAGEMENT TESTS
# ============================================================================

class TestDocumentManagement(TenantTestCase):
    """Tests for document templates, generation, and signatures."""

    def test_create_document_template(self):
        """Test creating a document template."""
        with self.tenant_context():
            template = DocumentTemplateFactory(
                name='Offer Letter Template',
                category='offer_letter',
                content='<html><body>Dear {{ employee_name }}, We offer you...</body></html>',
                placeholders=['employee_name', 'job_title', 'salary', 'start_date'],
                requires_signature=True,
                version='1.0',
            )

            assert template.name == 'Offer Letter Template'
            assert template.category == 'offer_letter'
            assert 'employee_name' in template.placeholders
            assert template.requires_signature is True

    def test_create_employee_document(self):
        """Test creating an employee document."""
        with self.tenant_context():
            employee = EmployeeFactory()
            template = DocumentTemplateFactory()
            uploader = UserFactory()

            document = EmployeeDocumentFactory(
                employee=employee,
                template=template,
                title='Employment Contract',
                category='contract',
                status='draft',
                requires_signature=True,
                uploaded_by=uploader,
            )

            assert document.employee == employee
            assert document.status == 'draft'
            assert document.requires_signature is True

    def test_document_status_transitions(self):
        """Test document status transitions."""
        with self.tenant_context():
            document = EmployeeDocumentFactory(status='draft')

            # Draft -> Pending Signature
            document.status = 'pending_signature'
            document.save()
            assert document.status == 'pending_signature'

            # Pending Signature -> Signed
            document.status = 'signed'
            document.signed_at = timezone.now()
            document.save()
            assert document.status == 'signed'

    def test_document_expiration(self):
        """Test document with expiration date."""
        with self.tenant_context():
            document = EmployeeDocumentFactory(
                expires_at=timezone.now().date() + timedelta(days=365),
            )

            assert document.expires_at is not None

    def test_document_with_signature_provider(self):
        """Test document with e-signature integration."""
        with self.tenant_context():
            document = EmployeeDocumentFactory(
                requires_signature=True,
                signature_provider='docusign',
                signature_envelope_id='env-12345',
            )

            assert document.signature_provider == 'docusign'
            assert document.signature_envelope_id == 'env-12345'

    def test_document_template_categories(self):
        """Test different document template categories."""
        with self.tenant_context():
            categories = [
                'offer_letter',
                'contract',
                'nda',
                'policy',
                'form',
                'other',
            ]

            for category in categories:
                template = DocumentTemplateFactory(category=category)
                assert template.category == category

    def test_document_archived_status(self):
        """Test archiving a document."""
        with self.tenant_context():
            document = EmployeeDocumentFactory(status='signed')

            document.status = 'archived'
            document.save()

            document.refresh_from_db()
            assert document.status == 'archived'


# ============================================================================
# OFFBOARDING PROCESS TESTS
# ============================================================================

class TestOffboardingProcess(TenantTestCase):
    """Tests for offboarding, exit interviews, and equipment return."""

    def test_create_offboarding_resignation(self):
        """Test creating offboarding for resignation."""
        with self.tenant_context():
            employee = EmployeeFactory(status='active')
            hr_user = UserFactory()

            offboarding = OffboardingFactory(
                employee=employee,
                separation_type='resignation',
                reason='Personal reasons',
                notice_date=timezone.now().date(),
                last_working_day=timezone.now().date() + timedelta(days=14),
                processed_by=hr_user,
            )

            assert offboarding.separation_type == 'resignation'
            assert offboarding.is_complete is False

    def test_create_offboarding_termination(self):
        """Test creating offboarding for termination."""
        with self.tenant_context():
            employee = EmployeeFactory(status='active')
            hr_user = UserFactory()

            offboarding = OffboardingFactory(
                employee=employee,
                separation_type='termination',
                reason='Performance issues',
                notice_date=timezone.now().date(),
                last_working_day=timezone.now().date(),
                processed_by=hr_user,
            )

            assert offboarding.separation_type == 'termination'

    def test_offboarding_checklist_completion(self):
        """Test completing offboarding checklist items."""
        with self.tenant_context():
            offboarding = OffboardingFactory(
                knowledge_transfer_complete=False,
                equipment_returned=False,
                access_revoked=False,
                final_paycheck_processed=False,
            )

            assert offboarding.is_complete is False

            # Complete all required items
            offboarding.knowledge_transfer_complete = True
            offboarding.equipment_returned = True
            offboarding.access_revoked = True
            offboarding.final_paycheck_processed = True
            offboarding.save()

            assert offboarding.is_complete is True

    def test_offboarding_exit_interview(self):
        """Test recording exit interview."""
        with self.tenant_context():
            offboarding = OffboardingFactory()

            offboarding.exit_interview_date = timezone.now().date()
            offboarding.exit_interview_notes = 'Employee leaving for better opportunity. Good experience overall.'
            offboarding.exit_interview_completed = True
            offboarding.save()

            offboarding.refresh_from_db()
            assert offboarding.exit_interview_completed is True
            assert 'better opportunity' in offboarding.exit_interview_notes

    def test_offboarding_with_severance(self):
        """Test offboarding with severance package."""
        with self.tenant_context():
            offboarding = OffboardingFactory(
                separation_type='layoff',
                severance_offered=True,
                severance_amount=Decimal('10000.00'),
            )

            assert offboarding.severance_offered is True
            assert offboarding.severance_amount == Decimal('10000.00')

    def test_offboarding_pto_payout(self):
        """Test PTO payout during offboarding."""
        with self.tenant_context():
            employee = EmployeeFactory(pto_balance=Decimal('12.50'))

            offboarding = OffboardingFactory(
                employee=employee,
                pto_payout_days=Decimal('12.50'),
            )

            assert offboarding.pto_payout_days == Decimal('12.50')

    def test_offboarding_rehire_eligibility(self):
        """Test marking rehire eligibility."""
        with self.tenant_context():
            offboarding = OffboardingFactory(
                eligible_for_rehire=False,
                rehire_notes='Policy violation - not eligible for rehire',
            )

            assert offboarding.eligible_for_rehire is False
            assert 'Policy violation' in offboarding.rehire_notes

    def test_offboarding_separation_types(self):
        """Test different separation types."""
        with self.tenant_context():
            separation_types = [
                'resignation',
                'termination',
                'layoff',
                'retirement',
                'contract_end',
                'mutual',
                'other',
            ]

            for sep_type in separation_types:
                offboarding = OffboardingFactory(separation_type=sep_type)
                assert offboarding.separation_type == sep_type

    def test_offboarding_benefits_termination(self):
        """Test marking benefits as terminated."""
        with self.tenant_context():
            offboarding = OffboardingFactory(benefits_terminated=False)

            offboarding.benefits_terminated = True
            offboarding.save()

            offboarding.refresh_from_db()
            assert offboarding.benefits_terminated is True


# ============================================================================
# PERFORMANCE REVIEW TESTS
# ============================================================================

class TestPerformanceReviews(TenantTestCase):
    """Tests for performance review creation, feedback, and approval."""

    def test_create_performance_review(self):
        """Test creating a performance review."""
        with self.tenant_context():
            employee = EmployeeFactory()
            reviewer = UserFactory()

            review = PerformanceReviewFactory(
                employee=employee,
                reviewer=reviewer,
                review_type='annual',
                review_period_start=timezone.now().date() - timedelta(days=365),
                review_period_end=timezone.now().date(),
                status='draft',
            )

            assert review.review_type == 'annual'
            assert review.status == 'draft'

    def test_performance_review_status_workflow(self):
        """Test performance review status workflow."""
        with self.tenant_context():
            review = PerformanceReviewFactory(status='draft')

            # Draft -> Pending Self Assessment
            review.status = 'pending_self'
            review.save()
            assert review.status == 'pending_self'

            # Add self assessment
            review.self_assessment = 'I met all my goals this year...'
            review.status = 'pending_manager'
            review.save()
            assert review.status == 'pending_manager'

            # Manager review
            review.manager_feedback = 'Excellent performance this year...'
            review.overall_rating = 4
            review.status = 'pending_approval'
            review.save()
            assert review.status == 'pending_approval'

            # HR approval
            review.status = 'completed'
            review.completed_at = timezone.now()
            review.save()
            assert review.status == 'completed'

    def test_performance_review_ratings(self):
        """Test performance review ratings."""
        with self.tenant_context():
            review = PerformanceReviewFactory(
                overall_rating=4,
                goals_met_percentage=85,
                competency_ratings={
                    'communication': 4,
                    'teamwork': 5,
                    'technical_skills': 4,
                    'leadership': 3,
                },
            )

            assert review.overall_rating == 4
            assert review.goals_met_percentage == 85
            assert review.competency_ratings['teamwork'] == 5

    def test_performance_review_feedback(self):
        """Test performance review written feedback."""
        with self.tenant_context():
            review = PerformanceReviewFactory(
                accomplishments='Led successful product launch...',
                areas_for_improvement='Could improve delegation skills...',
                goals_for_next_period='Lead team expansion project...',
            )

            assert 'product launch' in review.accomplishments
            assert 'delegation' in review.areas_for_improvement

    def test_performance_review_promotion_recommendation(self):
        """Test marking promotion recommendation."""
        with self.tenant_context():
            review = PerformanceReviewFactory(
                overall_rating=5,
                promotion_recommended=True,
            )

            assert review.promotion_recommended is True

    def test_performance_review_salary_increase(self):
        """Test salary increase recommendation."""
        with self.tenant_context():
            review = PerformanceReviewFactory(
                salary_increase_recommended=True,
                salary_increase_percentage=Decimal('5.00'),
            )

            assert review.salary_increase_recommended is True
            assert review.salary_increase_percentage == Decimal('5.00')

    def test_performance_review_pip_recommendation(self):
        """Test Performance Improvement Plan recommendation."""
        with self.tenant_context():
            review = PerformanceReviewFactory(
                overall_rating=2,
                pip_recommended=True,
            )

            assert review.pip_recommended is True

    def test_performance_review_signatures(self):
        """Test recording review signatures."""
        with self.tenant_context():
            review = PerformanceReviewFactory(status='completed')

            review.employee_signed_at = timezone.now()
            review.manager_signed_at = timezone.now()
            review.save()

            review.refresh_from_db()
            assert review.employee_signed_at is not None
            assert review.manager_signed_at is not None

    def test_performance_review_types(self):
        """Test different review types."""
        with self.tenant_context():
            review_types = [
                'probation',
                'annual',
                'mid_year',
                'project',
                'promotion',
            ]

            for review_type in review_types:
                review = PerformanceReviewFactory(review_type=review_type)
                assert review.review_type == review_type

    def test_performance_review_cancelled(self):
        """Test cancelling a performance review."""
        with self.tenant_context():
            review = PerformanceReviewFactory(status='draft')

            review.status = 'cancelled'
            review.save()

            review.refresh_from_db()
            assert review.status == 'cancelled'


# ============================================================================
# PTO ACCRUAL CALCULATION TESTS
# ============================================================================

class TestPTOAccrualCalculations(TenantTestCase):
    """Tests for PTO accrual calculations and balance management."""

    def test_time_off_type_accrual_settings(self):
        """Test time off type accrual configuration."""
        with self.tenant_context():
            vacation_type = VacationTypeFactory(
                is_accrued=True,
                accrual_rate=Decimal('1.25'),  # Per pay period
                max_balance=Decimal('30.00'),
                max_carryover=Decimal('5.00'),
            )

            assert vacation_type.is_accrued is True
            assert vacation_type.accrual_rate == Decimal('1.25')
            assert vacation_type.max_balance == Decimal('30.00')

    def test_non_accrued_time_off_type(self):
        """Test non-accrued time off type (e.g., bereavement)."""
        with self.tenant_context():
            bereavement = TimeOffTypeFactory(
                name='Bereavement',
                code='bereavement',
                is_accrued=False,
                accrual_rate=Decimal('0.00'),
            )

            assert bereavement.is_accrued is False
            assert bereavement.accrual_rate == Decimal('0.00')

    def test_approve_non_accrued_time_off(self):
        """Test approving non-accrued time off doesn't affect balance."""
        with self.tenant_context():
            employee = EmployeeFactory(pto_balance=Decimal('15.00'))
            bereavement = TimeOffTypeFactory(is_accrued=False)
            approver = UserFactory()

            request = TimeOffRequestFactory(
                employee=employee,
                time_off_type=bereavement,
                total_days=Decimal('3.00'),
                status='pending',
            )

            request.approve(approver)

            employee.refresh_from_db()
            # Balance unchanged for non-accrued types
            assert employee.pto_balance == Decimal('15.00')

    def test_employee_initial_pto_balance(self):
        """Test employee has initial PTO balance."""
        with self.tenant_context():
            employee = EmployeeFactory(
                pto_balance=Decimal('15.00'),
                sick_leave_balance=Decimal('10.00'),
            )

            assert employee.pto_balance == Decimal('15.00')
            assert employee.sick_leave_balance == Decimal('10.00')

    def test_pto_balance_update_after_approval(self):
        """Test PTO balance is updated after approval."""
        with self.tenant_context():
            employee = EmployeeFactory(pto_balance=Decimal('20.00'))
            vacation_type = VacationTypeFactory()
            approver = UserFactory()

            request = TimeOffRequestFactory(
                employee=employee,
                time_off_type=vacation_type,
                total_days=Decimal('3.00'),
                status='pending',
            )

            request.approve(approver)

            employee.refresh_from_db()
            assert employee.pto_balance == Decimal('17.00')

    def test_concurrent_time_off_approval(self):
        """Test concurrent time off approvals handle balance correctly."""
        with self.tenant_context():
            employee = EmployeeFactory(pto_balance=Decimal('10.00'))
            vacation_type = VacationTypeFactory()
            approver = UserFactory()

            request1 = TimeOffRequestFactory(
                employee=employee,
                time_off_type=vacation_type,
                total_days=Decimal('3.00'),
                status='pending',
            )
            request2 = TimeOffRequestFactory(
                employee=employee,
                time_off_type=vacation_type,
                total_days=Decimal('3.00'),
                status='pending',
            )

            request1.approve(approver)
            request2.approve(approver)

            employee.refresh_from_db()
            assert employee.pto_balance == Decimal('4.00')  # 10 - 3 - 3


# ============================================================================
# MANAGER APPROVAL WORKFLOW TESTS
# ============================================================================

class TestManagerApprovalWorkflows(TenantTestCase):
    """Tests for manager approval workflows."""

    def test_time_off_requires_approval(self):
        """Test time off type requires approval setting."""
        with self.tenant_context():
            vacation = VacationTypeFactory(requires_approval=True)

            assert vacation.requires_approval is True

    def test_time_off_no_approval_required(self):
        """Test time off type that doesn't require approval."""
        with self.tenant_context():
            floating_holiday = TimeOffTypeFactory(
                name='Floating Holiday',
                code='floating',
                requires_approval=False,
            )

            assert floating_holiday.requires_approval is False

    def test_employee_manager_relationship(self):
        """Test employee-manager relationship."""
        with self.tenant_context():
            manager_user = UserFactory()
            manager = EmployeeFactory(user=manager_user, status='active')

            employee_user = UserFactory()
            employee = EmployeeFactory(
                user=employee_user,
                status='active',
                manager=manager,
            )

            assert employee.manager == manager
            assert manager.direct_reports.count() == 1
            assert employee in manager.direct_reports.all()

    def test_multiple_direct_reports(self):
        """Test manager with multiple direct reports."""
        with self.tenant_context():
            manager = EmployeeFactory(status='active')

            # Create 5 direct reports
            reports = []
            for _ in range(5):
                report = EmployeeFactory(
                    status='active',
                    manager=manager,
                )
                reports.append(report)

            assert manager.direct_reports.count() == 5

    def test_time_off_approved_by_manager(self):
        """Test time off request approved by manager."""
        with self.tenant_context():
            manager_user = UserFactory()
            manager = EmployeeFactory(user=manager_user)

            employee_user = UserFactory()
            employee = EmployeeFactory(
                user=employee_user,
                manager=manager,
                pto_balance=Decimal('10.00'),
            )

            vacation = VacationTypeFactory()
            request = TimeOffRequestFactory(
                employee=employee,
                time_off_type=vacation,
                total_days=Decimal('2.00'),
                status='pending',
            )

            # Manager approves
            request.approve(manager_user)

            request.refresh_from_db()
            assert request.status == 'approved'
            assert request.approver == manager_user

    def test_time_off_min_notice_days(self):
        """Test time off type with minimum notice days requirement."""
        with self.tenant_context():
            vacation = VacationTypeFactory(min_notice_days=7)

            assert vacation.min_notice_days == 7

    def test_time_off_requires_documentation(self):
        """Test time off type that requires documentation."""
        with self.tenant_context():
            sick = SickLeaveTypeFactory(requires_documentation=True)

            assert sick.requires_documentation is True


# ============================================================================
# BULK OPERATIONS TESTS
# ============================================================================

class TestBulkOperations(TenantTestCase):
    """Tests for bulk HR operations."""

    def test_bulk_create_employees(self):
        """Test bulk creating employees."""
        with self.tenant_context():
            users = [UserFactory() for _ in range(10)]

            from hr_core.models import Employee

            employees = []
            for i, user in enumerate(users):
                employees.append(Employee(
                    user=user,
                    employee_id=f'BULK{i:05d}',
                    status='pending',
                    employment_type='full_time',
                    job_title='Software Engineer',
                    hire_date=timezone.now().date(),
                ))

            Employee.objects.bulk_create(employees)

            assert Employee.objects.filter(employee_id__startswith='BULK').count() == 10

    def test_bulk_update_employee_status(self):
        """Test bulk updating employee status."""
        with self.tenant_context():
            # Create probationary employees
            employees = [
                EmployeeFactory(status='probation')
                for _ in range(5)
            ]

            from hr_core.models import Employee

            # Bulk update to active
            employee_ids = [e.id for e in employees]
            Employee.objects.filter(id__in=employee_ids).update(status='active')

            # Verify all updated
            for emp in Employee.objects.filter(id__in=employee_ids):
                assert emp.status == 'active'

    def test_bulk_create_onboarding_tasks(self):
        """Test bulk creating onboarding tasks for checklist."""
        with self.tenant_context():
            checklist = OnboardingChecklistFactory()

            from hr_core.models import OnboardingTask

            tasks = [
                OnboardingTask(
                    checklist=checklist,
                    title=f'Task {i}',
                    category='documentation',
                    order=i,
                    is_required=True,
                )
                for i in range(10)
            ]

            OnboardingTask.objects.bulk_create(tasks)

            assert checklist.tasks.count() == 10

    def test_bulk_create_time_off_requests(self):
        """Test bulk creating time off requests."""
        with self.tenant_context():
            employees = [EmployeeFactory() for _ in range(5)]
            vacation_type = VacationTypeFactory()

            from hr_core.models import TimeOffRequest

            requests = []
            for emp in employees:
                requests.append(TimeOffRequest(
                    employee=emp,
                    time_off_type=vacation_type,
                    start_date=timezone.now().date() + timedelta(days=30),
                    end_date=timezone.now().date() + timedelta(days=31),
                    total_days=Decimal('2.00'),
                    status='pending',
                ))

            TimeOffRequest.objects.bulk_create(requests)

            assert TimeOffRequest.objects.filter(status='pending').count() >= 5

    def test_bulk_approve_time_off_requests(self):
        """Test bulk approving time off requests (via iteration)."""
        with self.tenant_context():
            approver = UserFactory()
            requests = []

            for _ in range(3):
                employee = EmployeeFactory(pto_balance=Decimal('20.00'))
                req = TimeOffRequestFactory(
                    employee=employee,
                    total_days=Decimal('1.00'),
                    status='pending',
                )
                requests.append(req)

            # Approve all (must be done individually due to balance logic)
            for req in requests:
                req.approve(approver)

            from hr_core.models import TimeOffRequest

            approved_count = TimeOffRequest.objects.filter(
                id__in=[r.id for r in requests],
                status='approved'
            ).count()

            assert approved_count == 3


# ============================================================================
# REPORTING AND ANALYTICS TESTS
# ============================================================================

class TestReportingAndAnalytics(TenantTestCase):
    """Tests for HR reporting and analytics."""

    def test_count_employees_by_status(self):
        """Test counting employees by status."""
        with self.tenant_context():
            # Create employees with different statuses
            EmployeeFactory(status='active')
            EmployeeFactory(status='active')
            EmployeeFactory(status='active')
            EmployeeFactory(status='probation')
            EmployeeFactory(status='probation')
            EmployeeFactory(status='on_leave')
            EmployeeFactory(status='terminated')

            from hr_core.models import Employee
            from django.db.models import Count

            status_counts = dict(
                Employee.objects.values('status')
                .annotate(count=Count('id'))
                .values_list('status', 'count')
            )

            assert status_counts.get('active', 0) >= 3
            assert status_counts.get('probation', 0) >= 2
            assert status_counts.get('on_leave', 0) >= 1
            assert status_counts.get('terminated', 0) >= 1

    def test_count_employees_by_employment_type(self):
        """Test counting employees by employment type."""
        with self.tenant_context():
            EmployeeFactory(employment_type='full_time')
            EmployeeFactory(employment_type='full_time')
            EmployeeFactory(employment_type='part_time')
            EmployeeFactory(employment_type='contract')

            from hr_core.models import Employee
            from django.db.models import Count

            type_counts = dict(
                Employee.objects.values('employment_type')
                .annotate(count=Count('id'))
                .values_list('employment_type', 'count')
            )

            assert type_counts.get('full_time', 0) >= 2

    def test_time_off_requests_by_status(self):
        """Test aggregating time off requests by status."""
        with self.tenant_context():
            employee = EmployeeFactory()
            vacation = VacationTypeFactory()

            TimeOffRequestFactory(employee=employee, time_off_type=vacation, status='pending')
            TimeOffRequestFactory(employee=employee, time_off_type=vacation, status='pending')
            TimeOffRequestFactory(employee=employee, time_off_type=vacation, status='approved')
            TimeOffRequestFactory(employee=employee, time_off_type=vacation, status='rejected')

            from hr_core.models import TimeOffRequest
            from django.db.models import Count

            status_counts = dict(
                TimeOffRequest.objects.values('status')
                .annotate(count=Count('id'))
                .values_list('status', 'count')
            )

            assert status_counts.get('pending', 0) >= 2
            assert status_counts.get('approved', 0) >= 1
            assert status_counts.get('rejected', 0) >= 1

    def test_performance_review_ratings_average(self):
        """Test calculating average performance ratings."""
        with self.tenant_context():
            PerformanceReviewFactory(overall_rating=5, status='completed')
            PerformanceReviewFactory(overall_rating=4, status='completed')
            PerformanceReviewFactory(overall_rating=4, status='completed')
            PerformanceReviewFactory(overall_rating=3, status='completed')

            from hr_core.models import PerformanceReview
            from django.db.models import Avg

            avg_rating = PerformanceReview.objects.filter(
                status='completed'
            ).aggregate(avg=Avg('overall_rating'))['avg']

            assert avg_rating == 4.0  # (5+4+4+3)/4 = 4.0

    def test_onboarding_completion_stats(self):
        """Test calculating onboarding completion statistics."""
        with self.tenant_context():
            checklist = OnboardingChecklistFactory()
            tasks = [OnboardingTaskFactory(checklist=checklist) for _ in range(4)]

            # Employee 1: 100% complete
            emp1 = EmployeeFactory()
            onb1 = EmployeeOnboardingFactory(employee=emp1, checklist=checklist)
            for task in tasks:
                OnboardingTaskProgressFactory(
                    onboarding=onb1,
                    task=task,
                    is_completed=True,
                )

            # Employee 2: 50% complete
            emp2 = EmployeeFactory()
            onb2 = EmployeeOnboardingFactory(employee=emp2, checklist=checklist)
            for i, task in enumerate(tasks):
                OnboardingTaskProgressFactory(
                    onboarding=onb2,
                    task=task,
                    is_completed=(i < 2),
                )

            assert onb1.completion_percentage == 100
            assert onb2.completion_percentage == 50

    def test_offboarding_by_separation_type(self):
        """Test counting offboardings by separation type."""
        with self.tenant_context():
            OffboardingFactory(separation_type='resignation')
            OffboardingFactory(separation_type='resignation')
            OffboardingFactory(separation_type='termination')
            OffboardingFactory(separation_type='layoff')

            from hr_core.models import Offboarding
            from django.db.models import Count

            type_counts = dict(
                Offboarding.objects.values('separation_type')
                .annotate(count=Count('id'))
                .values_list('separation_type', 'count')
            )

            assert type_counts.get('resignation', 0) >= 2
            assert type_counts.get('termination', 0) >= 1

    def test_employees_by_department(self):
        """Test counting employees by department."""
        with self.tenant_context():
            EmployeeFactory(team='Engineering')
            EmployeeFactory(team='Engineering')
            EmployeeFactory(team='Engineering')
            EmployeeFactory(team='Sales')
            EmployeeFactory(team='Sales')
            EmployeeFactory(team='Marketing')

            from hr_core.models import Employee
            from django.db.models import Count

            team_counts = dict(
                Employee.objects.values('team')
                .annotate(count=Count('id'))
                .values_list('team', 'count')
            )

            assert team_counts.get('Engineering', 0) >= 3
            assert team_counts.get('Sales', 0) >= 2

    def test_total_pto_days_used(self):
        """Test calculating total PTO days used."""
        with self.tenant_context():
            employee = EmployeeFactory()
            vacation = VacationTypeFactory()

            ApprovedTimeOffRequestFactory(
                employee=employee,
                time_off_type=vacation,
                total_days=Decimal('5.00'),
            )
            ApprovedTimeOffRequestFactory(
                employee=employee,
                time_off_type=vacation,
                total_days=Decimal('3.00'),
            )

            from hr_core.models import TimeOffRequest
            from django.db.models import Sum

            total_used = TimeOffRequest.objects.filter(
                employee=employee,
                status='approved',
            ).aggregate(total=Sum('total_days'))['total']

            assert total_used == Decimal('8.00')


# ============================================================================
# ADDITIONAL EDGE CASE TESTS
# ============================================================================

class TestHRCoreEdgeCases(TenantTestCase):
    """Tests for edge cases and error handling."""

    def test_employee_without_manager(self):
        """Test employee with no manager assigned."""
        with self.tenant_context():
            employee = EmployeeFactory(manager=None)

            assert employee.manager is None
            assert employee.is_active_employee is True

    def test_time_off_request_same_start_end_date(self):
        """Test time off request for single day."""
        with self.tenant_context():
            today = timezone.now().date() + timedelta(days=7)
            request = TimeOffRequestFactory(
                start_date=today,
                end_date=today,
                total_days=Decimal('1.00'),
            )

            assert request.start_date == request.end_date
            assert request.total_days == Decimal('1.00')

    def test_employee_unique_employee_id(self):
        """Test employee ID uniqueness constraint."""
        with self.tenant_context():
            from django.db import IntegrityError

            EmployeeFactory(employee_id='EMP00001')

            with pytest.raises(IntegrityError):
                EmployeeFactory(employee_id='EMP00001')

    def test_onboarding_one_to_one_constraint(self):
        """Test employee can only have one onboarding record."""
        with self.tenant_context():
            from django.db import IntegrityError

            employee = EmployeeFactory()
            checklist = OnboardingChecklistFactory()

            EmployeeOnboardingFactory(employee=employee, checklist=checklist)

            with pytest.raises(IntegrityError):
                EmployeeOnboardingFactory(employee=employee, checklist=checklist)

    def test_offboarding_one_to_one_constraint(self):
        """Test employee can only have one offboarding record."""
        with self.tenant_context():
            from django.db import IntegrityError

            employee = EmployeeFactory()

            OffboardingFactory(employee=employee)

            with pytest.raises(IntegrityError):
                OffboardingFactory(employee=employee)

    def test_performance_review_rating_validation(self):
        """Test performance review rating must be 1-5."""
        with self.tenant_context():
            from django.core.exceptions import ValidationError
            from hr_core.models import PerformanceReview

            review = PerformanceReviewFactory.build(overall_rating=6)

            with pytest.raises(ValidationError):
                review.full_clean()

    def test_employee_zero_pto_balance_approval(self):
        """Test approving time off with exactly zero balance fails."""
        with self.tenant_context():
            employee = EmployeeFactory(pto_balance=Decimal('0.00'))
            vacation = VacationTypeFactory()
            approver = UserFactory()

            request = TimeOffRequestFactory(
                employee=employee,
                time_off_type=vacation,
                total_days=Decimal('1.00'),
                status='pending',
            )

            with pytest.raises(ValidationError):
                request.approve(approver)

    def test_employee_exact_balance_approval(self):
        """Test approving time off with exact balance succeeds."""
        with self.tenant_context():
            employee = EmployeeFactory(pto_balance=Decimal('5.00'))
            vacation = VacationTypeFactory()
            approver = UserFactory()

            request = TimeOffRequestFactory(
                employee=employee,
                time_off_type=vacation,
                total_days=Decimal('5.00'),
                status='pending',
            )

            request.approve(approver)

            employee.refresh_from_db()
            assert employee.pto_balance == Decimal('0.00')

    def test_document_template_inactive(self):
        """Test inactive document template."""
        with self.tenant_context():
            template = DocumentTemplateFactory(is_active=False)

            assert template.is_active is False

    def test_time_off_type_inactive(self):
        """Test inactive time off type."""
        with self.tenant_context():
            time_off_type = TimeOffTypeFactory(is_active=False)

            assert time_off_type.is_active is False

    def test_onboarding_checklist_inactive(self):
        """Test inactive onboarding checklist."""
        with self.tenant_context():
            checklist = OnboardingChecklistFactory(is_active=False)

            assert checklist.is_active is False


# ============================================================================
# API TESTS (if API endpoints exist)
# ============================================================================

class TestHRCoreAPI(APITenantTestCase):
    """API tests for HR Core endpoints."""

    def test_api_client_authenticated(self):
        """Test that API client is properly authenticated."""
        assert self.client is not None
        assert self.user is not None
        assert self.tenant is not None

    def test_employee_exists_in_tenant_context(self):
        """Test employee can be created in tenant context."""
        with self.tenant_context():
            employee = EmployeeFactory()
            assert employee.id is not None


# ============================================================================
# TIME OFF BALANCE MODEL TESTS
# ============================================================================

class TestTimeOffBalance(TenantTestCase):
    """Tests for TimeOffBalance model operations."""

    def test_time_off_balance_accrual(self):
        """Test accruing time off balance."""
        with self.tenant_context():
            from hr_core.models import TimeOffBalance

            employee = EmployeeFactory()
            vacation = VacationTypeFactory(max_balance=Decimal('30.00'))

            balance = TimeOffBalance.objects.create(
                employee=employee,
                time_off_type=vacation,
                balance=Decimal('10.00'),
                year=timezone.now().year,
            )

            balance.accrue(Decimal('1.25'))

            balance.refresh_from_db()
            assert balance.balance == Decimal('11.25')
            assert balance.accrued_this_year == Decimal('1.25')

    def test_time_off_balance_max_cap(self):
        """Test accrual respects max balance cap."""
        with self.tenant_context():
            from hr_core.models import TimeOffBalance

            employee = EmployeeFactory()
            vacation = VacationTypeFactory(max_balance=Decimal('30.00'))

            balance = TimeOffBalance.objects.create(
                employee=employee,
                time_off_type=vacation,
                balance=Decimal('29.00'),
                year=timezone.now().year,
            )

            balance.accrue(Decimal('5.00'))  # Would exceed max

            balance.refresh_from_db()
            assert balance.balance == Decimal('30.00')  # Capped at max

    def test_time_off_balance_deduction(self):
        """Test deducting from time off balance."""
        with self.tenant_context():
            from hr_core.models import TimeOffBalance

            employee = EmployeeFactory()
            vacation = VacationTypeFactory()

            balance = TimeOffBalance.objects.create(
                employee=employee,
                time_off_type=vacation,
                balance=Decimal('15.00'),
                year=timezone.now().year,
            )

            balance.deduct(Decimal('5.00'))

            balance.refresh_from_db()
            assert balance.balance == Decimal('10.00')
            assert balance.used_this_year == Decimal('5.00')

    def test_time_off_balance_year_reset_with_carryover(self):
        """Test resetting balance for new year with carryover."""
        with self.tenant_context():
            from hr_core.models import TimeOffBalance

            employee = EmployeeFactory()
            vacation = VacationTypeFactory(max_carryover=Decimal('5.00'))

            balance = TimeOffBalance.objects.create(
                employee=employee,
                time_off_type=vacation,
                balance=Decimal('10.00'),
                accrued_this_year=Decimal('15.00'),
                used_this_year=Decimal('5.00'),
                year=timezone.now().year - 1,
            )

            balance.reset_for_new_year(carryover=True)

            balance.refresh_from_db()
            assert balance.carried_over == Decimal('5.00')  # Max carryover
            assert balance.balance == Decimal('5.00')
            assert balance.accrued_this_year == Decimal('0.00')
            assert balance.used_this_year == Decimal('0.00')

    def test_time_off_balance_year_reset_no_carryover(self):
        """Test resetting balance for new year without carryover."""
        with self.tenant_context():
            from hr_core.models import TimeOffBalance

            employee = EmployeeFactory()
            vacation = VacationTypeFactory(max_carryover=Decimal('5.00'))

            balance = TimeOffBalance.objects.create(
                employee=employee,
                time_off_type=vacation,
                balance=Decimal('10.00'),
                year=timezone.now().year - 1,
            )

            balance.reset_for_new_year(carryover=False)

            balance.refresh_from_db()
            assert balance.carried_over == Decimal('0.00')
            assert balance.balance == Decimal('0.00')


# ============================================================================
# EMPLOYEE SKILLS AND CERTIFICATIONS TESTS
# ============================================================================

class TestEmployeeSkillsAndCertifications(TenantTestCase):
    """Tests for employee skills and certifications."""

    def test_employee_skills_array_field(self):
        """Test employee skills ArrayField."""
        with self.tenant_context():
            employee = EmployeeFactory(
                skills=['Python', 'Django', 'PostgreSQL', 'REST APIs'],
            )

            assert 'Python' in employee.skills
            assert len(employee.skills) == 4

    def test_employee_certifications_json_field(self):
        """Test employee certifications JSON field."""
        with self.tenant_context():
            certifications = [
                {
                    'name': 'AWS Solutions Architect',
                    'issuer': 'Amazon Web Services',
                    'date': '2024-01-15',
                    'expiry': '2027-01-15',
                },
                {
                    'name': 'PMP',
                    'issuer': 'PMI',
                    'date': '2023-06-01',
                    'expiry': '2026-06-01',
                },
            ]

            employee = EmployeeFactory(certifications=certifications)

            assert len(employee.certifications) == 2
            assert employee.certifications[0]['name'] == 'AWS Solutions Architect'


# ============================================================================
# EMPLOYEE WORK AUTHORIZATION TESTS
# ============================================================================

class TestEmployeeWorkAuthorization(TenantTestCase):
    """Tests for employee work authorization tracking."""

    def test_employee_citizen_authorization(self):
        """Test employee with citizen work authorization."""
        with self.tenant_context():
            employee = EmployeeFactory(
                work_authorization_status='citizen',
            )

            assert employee.work_authorization_status == 'citizen'

    def test_employee_work_permit_authorization(self):
        """Test employee with work permit authorization."""
        with self.tenant_context():
            employee = EmployeeFactory(
                work_authorization_status='work_permit',
                work_permit_number='WP123456',
                work_permit_expiry=timezone.now().date() + timedelta(days=365),
            )

            assert employee.work_authorization_status == 'work_permit'
            assert employee.work_permit_number == 'WP123456'

    def test_employee_visa_authorization(self):
        """Test employee with visa work authorization."""
        with self.tenant_context():
            employee = EmployeeFactory(
                work_authorization_status='visa',
                visa_type='H-1B',
                visa_expiry=timezone.now().date() + timedelta(days=730),
            )

            assert employee.work_authorization_status == 'visa'
            assert employee.visa_type == 'H-1B'

    def test_employee_right_to_work_verification(self):
        """Test marking right to work as verified."""
        with self.tenant_context():
            verifier = UserFactory()
            employee = EmployeeFactory(
                right_to_work_verified=True,
                right_to_work_verified_date=timezone.now().date(),
                right_to_work_verified_by=verifier,
            )

            assert employee.right_to_work_verified is True
            assert employee.right_to_work_verified_by == verifier


# ============================================================================
# EMPLOYEE EMERGENCY CONTACTS TESTS
# ============================================================================

class TestEmployeeEmergencyContacts(TenantTestCase):
    """Tests for employee emergency contacts."""

    def test_employee_single_emergency_contact(self):
        """Test employee with single emergency contact."""
        with self.tenant_context():
            employee = EmployeeFactory(
                emergency_contact_name='Jane Doe',
                emergency_contact_phone='+1-555-123-4567',
                emergency_contact_relationship='Spouse',
            )

            assert employee.emergency_contact_name == 'Jane Doe'
            assert employee.emergency_contact_relationship == 'Spouse'

    def test_employee_multiple_emergency_contacts(self):
        """Test employee with multiple emergency contacts."""
        with self.tenant_context():
            contacts = [
                {
                    'name': 'Jane Doe',
                    'phone': '+1-555-123-4567',
                    'relationship': 'Spouse',
                    'is_primary': True,
                },
                {
                    'name': 'John Doe Sr.',
                    'phone': '+1-555-987-6543',
                    'relationship': 'Parent',
                    'is_primary': False,
                },
            ]

            employee = EmployeeFactory(emergency_contacts=contacts)

            assert len(employee.emergency_contacts) == 2
            assert employee.emergency_contacts[0]['is_primary'] is True
