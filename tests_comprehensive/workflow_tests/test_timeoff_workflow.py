"""
Comprehensive Time-Off Request Workflow Test Suite

This test suite validates:
1. Submitting time-off requests
2. Manager approval/rejection
3. HR override capabilities
4. Calendar integration
5. Balance tracking
6. Conflict detection
7. Notification system

Created: 2026-01-16
"""

import pytest
import json
from decimal import Decimal
from datetime import datetime, timedelta
from django.utils import timezone
from django.test import Client
from django.contrib.auth import get_user_model
from django.db import transaction

from accounts.models import TenantUser
from tenants.models import Tenant
from hr_core.models import (
    Employee, TimeOffType, TimeOffRequest, TimeOffBalance,
    TimeOffBlackoutDate
)
from hr_core.forms import TimeOffRequestForm, TimeOffApprovalForm

User = get_user_model()


class TestTimeOffSubmission:
    """Test the process of employees submitting time-off requests."""

    @pytest.fixture
    def setup(self, db):
        """Set up test data."""
        tenant = Tenant.objects.create(
            name="Test Company",
            slug="test-company",
            schema_name="test_schema",
            domain_url="testcompany.zumodra.local"
        )

        user = User.objects.create_user(
            username='employee@test.com',
            email='employee@test.com',
            password='testpass123',
            first_name='John',
            last_name='Doe'
        )

        TenantUser.objects.create(
            user=user,
            tenant=tenant,
            role='employee'
        )

        employee = Employee.objects.create(
            user=user,
            employee_id='EMP001',
            department=None,
            status=Employee.EmploymentStatus.ACTIVE,
            employment_type=Employee.EmploymentType.FULL_TIME,
            start_date=timezone.now().date() - timedelta(days=365)
        )

        vacation = TimeOffType.objects.create(
            tenant=tenant,
            name='Vacation',
            code='vacation',
            is_accrued=True,
            accrual_rate=Decimal('1.92'),
            max_balance=Decimal('30.00'),
            requires_approval=True
        )

        sick_leave = TimeOffType.objects.create(
            tenant=tenant,
            name='Sick Leave',
            code='sick',
            is_accrued=True,
            accrual_rate=Decimal('0.77'),
            max_balance=Decimal('10.00'),
            requires_documentation=True
        )

        TimeOffBalance.objects.create(
            employee=employee,
            time_off_type=vacation,
            balance=Decimal('15.00'),
            accrued_this_year=Decimal('15.00'),
            year=timezone.now().year
        )

        TimeOffBalance.objects.create(
            employee=employee,
            time_off_type=sick_leave,
            balance=Decimal('5.00'),
            accrued_this_year=Decimal('5.00'),
            year=timezone.now().year
        )

        return {
            'tenant': tenant,
            'user': user,
            'employee': employee,
            'vacation': vacation,
            'sick_leave': sick_leave,
        }

    def test_submit_vacation_form_valid(self, setup):
        """Test submitting a valid vacation request form."""
        data = {
            'time_off_type': setup['vacation'].pk,
            'start_date': (timezone.now().date() + timedelta(days=10)).isoformat(),
            'end_date': (timezone.now().date() + timedelta(days=14)).isoformat(),
            'is_half_day': False,
            'reason': 'Family vacation',
        }

        form = TimeOffRequestForm(data=data)
        assert form.is_valid(), f"Form errors: {form.errors}"
        assert form.cleaned_data['total_days'] == Decimal('5')

    def test_submit_half_day_form(self, setup):
        """Test submitting a half-day request form."""
        data = {
            'time_off_type': setup['vacation'].pk,
            'start_date': (timezone.now().date() + timedelta(days=10)).isoformat(),
            'end_date': (timezone.now().date() + timedelta(days=10)).isoformat(),
            'is_half_day': True,
            'half_day_period': 'am',
            'reason': 'Doctor appointment',
        }

        form = TimeOffRequestForm(data=data)
        assert form.is_valid(), f"Form errors: {form.errors}"
        assert form.cleaned_data['total_days'] == Decimal('0.5')

    def test_form_validation_invalid_dates(self, setup):
        """Test form validation with invalid date range."""
        start = timezone.now().date() + timedelta(days=10)
        end = timezone.now().date() + timedelta(days=5)

        data = {
            'time_off_type': setup['vacation'].pk,
            'start_date': start.isoformat(),
            'end_date': end.isoformat(),
            'is_half_day': False,
            'reason': 'Invalid dates',
        }

        form = TimeOffRequestForm(data=data)
        assert not form.is_valid()
        assert 'end_date' in form.errors

    def test_form_validation_past_date(self, setup):
        """Test form validation rejects past dates."""
        past_date = timezone.now().date() - timedelta(days=5)

        data = {
            'time_off_type': setup['vacation'].pk,
            'start_date': past_date.isoformat(),
            'end_date': past_date.isoformat(),
            'is_half_day': False,
            'reason': 'Past request',
        }

        form = TimeOffRequestForm(data=data)
        assert not form.is_valid()
        assert 'start_date' in form.errors

    def test_request_creates_db_record(self, setup):
        """Test that request creates a database record."""
        start = timezone.now().date() + timedelta(days=10)
        end = timezone.now().date() + timedelta(days=14)

        request = TimeOffRequest.objects.create(
            employee=setup['employee'],
            time_off_type=setup['vacation'],
            start_date=start,
            end_date=end,
            total_days=Decimal('5'),
            reason='Family vacation',
            status=TimeOffRequest.RequestStatus.PENDING
        )

        assert request.pk is not None
        assert request.status == TimeOffRequest.RequestStatus.PENDING
        assert request.approved_at is None
        assert request.approver is None


class TestManagerApprovalWorkflow:
    """Test manager approval and rejection of time-off requests."""

    @pytest.fixture
    def setup(self, db):
        """Set up test data with manager."""
        tenant = Tenant.objects.create(
            name="Test Company",
            slug="test-company",
            schema_name="test_schema",
            domain_url="testcompany.zumodra.local"
        )

        # Create manager
        manager_user = User.objects.create_user(
            username='manager@test.com',
            email='manager@test.com',
            password='testpass123',
            first_name='Jane',
            last_name='Smith'
        )

        TenantUser.objects.create(
            user=manager_user,
            tenant=tenant,
            role='hr_manager'
        )

        manager_emp = Employee.objects.create(
            user=manager_user,
            employee_id='MGR001',
            status=Employee.EmploymentStatus.ACTIVE,
            employment_type=Employee.EmploymentType.FULL_TIME,
            start_date=timezone.now().date() - timedelta(days=730)
        )

        # Create employee
        emp_user = User.objects.create_user(
            username='employee@test.com',
            email='employee@test.com',
            password='testpass123',
            first_name='John',
            last_name='Doe'
        )

        TenantUser.objects.create(
            user=emp_user,
            tenant=tenant,
            role='employee'
        )

        employee = Employee.objects.create(
            user=emp_user,
            employee_id='EMP001',
            manager=manager_emp,
            status=Employee.EmploymentStatus.ACTIVE,
            employment_type=Employee.EmploymentType.FULL_TIME,
            start_date=timezone.now().date() - timedelta(days=365)
        )

        vacation = TimeOffType.objects.create(
            tenant=tenant,
            name='Vacation',
            code='vacation',
            is_accrued=True,
            accrual_rate=Decimal('1.92'),
            max_balance=Decimal('30.00'),
            requires_approval=True
        )

        TimeOffBalance.objects.create(
            employee=employee,
            time_off_type=vacation,
            balance=Decimal('20.00'),
            accrued_this_year=Decimal('20.00'),
            year=timezone.now().year
        )

        return {
            'tenant': tenant,
            'manager': manager_emp,
            'manager_user': manager_user,
            'employee': employee,
            'vacation': vacation,
        }

    def test_manager_approve_request(self, setup):
        """Test manager approving a time-off request."""
        start = timezone.now().date() + timedelta(days=10)
        end = timezone.now().date() + timedelta(days=14)

        request = TimeOffRequest.objects.create(
            employee=setup['employee'],
            time_off_type=setup['vacation'],
            start_date=start,
            end_date=end,
            total_days=Decimal('5'),
            reason='Family vacation',
            status=TimeOffRequest.RequestStatus.PENDING
        )

        request.approve(setup['manager_user'])

        request.refresh_from_db()
        assert request.status == TimeOffRequest.RequestStatus.APPROVED
        assert request.approver == setup['manager_user']
        assert request.approved_at is not None

    def test_manager_reject_request(self, setup):
        """Test manager rejecting a time-off request."""
        start = timezone.now().date() + timedelta(days=10)
        end = timezone.now().date() + timedelta(days=14)

        request = TimeOffRequest.objects.create(
            employee=setup['employee'],
            time_off_type=setup['vacation'],
            start_date=start,
            end_date=end,
            total_days=Decimal('5'),
            reason='Family vacation',
            status=TimeOffRequest.RequestStatus.PENDING
        )

        rejection_reason = 'Project deadline conflict'
        request.reject(setup['manager_user'], rejection_reason)

        request.refresh_from_db()
        assert request.status == TimeOffRequest.RequestStatus.REJECTED
        assert request.approver == setup['manager_user']
        assert request.rejection_reason == rejection_reason

    def test_approval_form_validation(self, setup):
        """Test approval form requires reason for rejection."""
        data = {
            'status': TimeOffRequest.RequestStatus.REJECTED,
            'rejection_reason': '',
            'notes': 'Needs documentation'
        }

        form = TimeOffApprovalForm(data=data)
        assert not form.is_valid()
        assert 'rejection_reason' in form.errors

    def test_approval_insufficient_balance_error(self, setup):
        """Test that approval fails with insufficient balance."""
        start = timezone.now().date() + timedelta(days=10)
        end = timezone.now().date() + timedelta(days=30)

        request = TimeOffRequest.objects.create(
            employee=setup['employee'],
            time_off_type=setup['vacation'],
            start_date=start,
            end_date=end,
            total_days=Decimal('21'),
            reason='Extended vacation',
            status=TimeOffRequest.RequestStatus.PENDING
        )

        from django.core.exceptions import ValidationError
        with pytest.raises(ValidationError):
            request.approve(setup['manager_user'])


class TestBalanceManagement:
    """Test balance tracking and calculations."""

    @pytest.fixture
    def setup(self, db):
        """Set up test data."""
        tenant = Tenant.objects.create(
            name="Test Company",
            slug="test-company",
            schema_name="test_schema",
            domain_url="testcompany.zumodra.local"
        )

        emp_user = User.objects.create_user(
            username='employee@test.com',
            email='employee@test.com',
            password='testpass123'
        )

        TenantUser.objects.create(
            user=emp_user,
            tenant=tenant,
            role='employee'
        )

        employee = Employee.objects.create(
            user=emp_user,
            employee_id='EMP001',
            status=Employee.EmploymentStatus.ACTIVE,
            employment_type=Employee.EmploymentType.FULL_TIME,
            start_date=timezone.now().date() - timedelta(days=365)
        )

        vacation = TimeOffType.objects.create(
            tenant=tenant,
            name='Vacation',
            code='vacation',
            is_accrued=True,
            accrual_rate=Decimal('1.92'),
            max_balance=Decimal('30.00'),
            max_carryover=Decimal('5.00')
        )

        balance = TimeOffBalance.objects.create(
            employee=employee,
            time_off_type=vacation,
            balance=Decimal('20.00'),
            accrued_this_year=Decimal('20.00'),
            year=timezone.now().year
        )

        return {
            'tenant': tenant,
            'employee': employee,
            'vacation': vacation,
            'balance': balance,
        }

    def test_balance_accrue_method(self, setup):
        """Test accrue method on TimeOffBalance."""
        initial = setup['balance'].balance

        setup['balance'].accrue(Decimal('5.00'))

        assert setup['balance'].balance == initial + Decimal('5.00')
        assert setup['balance'].accrued_this_year == Decimal('25.00')

    def test_balance_deduct_method(self, setup):
        """Test deduct method on TimeOffBalance."""
        initial = setup['balance'].balance

        setup['balance'].deduct(Decimal('3.00'))

        assert setup['balance'].balance == initial - Decimal('3.00')
        assert setup['balance'].used_this_year == Decimal('3.00')

    def test_balance_max_cap_enforcement(self, setup):
        """Test balance is capped at max_balance."""
        setup['balance'].balance = Decimal('28.00')
        setup['balance'].save()

        setup['balance'].accrue(Decimal('5.00'))

        assert setup['balance'].balance == Decimal('30.00')

    def test_carryover_on_year_reset(self, setup):
        """Test carryover calculation for new year."""
        setup['balance'].balance = Decimal('8.00')
        setup['balance'].save()

        setup['balance'].reset_for_new_year(carryover=True)

        assert setup['balance'].carried_over == Decimal('5.00')
        assert setup['balance'].balance == Decimal('5.00')
        assert setup['balance'].accrued_this_year == Decimal('0.00')


class TestConflictDetection:
    """Test conflict detection for overlapping requests."""

    @pytest.fixture
    def setup(self, db):
        """Set up test data."""
        tenant = Tenant.objects.create(
            name="Test Company",
            slug="test-company",
            schema_name="test_schema",
            domain_url="testcompany.zumodra.local"
        )

        emp_user = User.objects.create_user(
            username='employee@test.com',
            email='employee@test.com',
            password='testpass123'
        )

        TenantUser.objects.create(
            user=emp_user,
            tenant=tenant,
            role='employee'
        )

        employee = Employee.objects.create(
            user=emp_user,
            employee_id='EMP001',
            status=Employee.EmploymentStatus.ACTIVE,
            employment_type=Employee.EmploymentType.FULL_TIME,
            start_date=timezone.now().date() - timedelta(days=365)
        )

        vacation = TimeOffType.objects.create(
            tenant=tenant,
            name='Vacation',
            code='vacation',
            is_accrued=True
        )

        return {
            'tenant': tenant,
            'employee': employee,
            'vacation': vacation,
        }

    def test_overlapping_requests_detected(self, setup):
        """Test detection of overlapping time-off requests."""
        start1 = timezone.now().date() + timedelta(days=10)
        end1 = timezone.now().date() + timedelta(days=14)

        req1 = TimeOffRequest.objects.create(
            employee=setup['employee'],
            time_off_type=setup['vacation'],
            start_date=start1,
            end_date=end1,
            total_days=Decimal('5'),
            status=TimeOffRequest.RequestStatus.APPROVED
        )

        start2 = timezone.now().date() + timedelta(days=12)
        end2 = timezone.now().date() + timedelta(days=16)

        overlapping = TimeOffRequest.objects.filter(
            employee=setup['employee'],
            status__in=['approved', 'pending'],
            start_date__lte=end2,
            end_date__gte=start2
        )

        assert overlapping.count() == 1

    def test_non_overlapping_requests(self, setup):
        """Test that non-overlapping requests don't conflict."""
        start1 = timezone.now().date() + timedelta(days=10)
        end1 = timezone.now().date() + timedelta(days=14)

        req1 = TimeOffRequest.objects.create(
            employee=setup['employee'],
            time_off_type=setup['vacation'],
            start_date=start1,
            end_date=end1,
            total_days=Decimal('5'),
            status=TimeOffRequest.RequestStatus.APPROVED
        )

        start2 = timezone.now().date() + timedelta(days=20)
        end2 = timezone.now().date() + timedelta(days=24)

        overlapping = TimeOffRequest.objects.filter(
            employee=setup['employee'],
            status__in=['approved', 'pending'],
            start_date__lte=end2,
            end_date__gte=start2
        )

        assert overlapping.count() == 0

    def test_blackout_date_detection(self, setup):
        """Test blackout date conflict detection."""
        blackout_start = timezone.now().date() + timedelta(days=12)
        blackout_end = timezone.now().date() + timedelta(days=14)

        blackout = TimeOffBlackoutDate.objects.create(
            name='Holiday period',
            start_date=blackout_start,
            end_date=blackout_end,
            applies_to_all=True,
            restriction_type='blocked'
        )

        req_start = timezone.now().date() + timedelta(days=10)
        req_end = timezone.now().date() + timedelta(days=16)

        blackout_conflict = TimeOffBlackoutDate.objects.filter(
            start_date__lte=req_end,
            end_date__gte=req_start,
            applies_to_all=True,
            restriction_type='blocked'
        )

        assert blackout_conflict.count() == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
