"""
HR Core Policies - Time Off and Leave Policy Management

This module provides configurable time-off policies:
- TimeOffPolicy: Main policy configuration
- AccrualCalculator: Calculate time-off accruals
- CarryoverPolicy: Handle year-end carryover rules
- BlackoutDateManager: Manage restricted dates

Policies can be configured per tenant, department, or employment type.
"""

import logging
from dataclasses import dataclass, field
from datetime import date, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from django.db.models import Q
from django.utils import timezone

from .models import (
    Employee,
    TimeOffType,
    TimeOffRequest,
    TimeOffBalance,
    TimeOffBlackoutDate,
)

logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ValidationResult:
    """Result of policy validation."""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class AccrualResult:
    """Result of accrual calculation."""
    base_amount: Decimal
    adjusted_amount: Decimal
    multiplier: Decimal
    factors: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CarryoverResult:
    """Result of carryover calculation."""
    previous_balance: Decimal
    carryover_amount: Decimal
    forfeited_amount: Decimal
    new_balance: Decimal


# =============================================================================
# TIME OFF POLICY
# =============================================================================

class TimeOffPolicy:
    """
    Configurable time-off policy per tenant/department.

    Handles:
    - Accrual rate calculations based on tenure/type
    - Maximum balance caps
    - Carryover rules
    - Blackout date validation
    - Request validation
    """

    # Default accrual tiers by years of service
    DEFAULT_ACCRUAL_TIERS = [
        {'min_years': 0, 'max_years': 2, 'multiplier': Decimal('1.00')},
        {'min_years': 2, 'max_years': 5, 'multiplier': Decimal('1.25')},
        {'min_years': 5, 'max_years': 10, 'multiplier': Decimal('1.50')},
        {'min_years': 10, 'max_years': None, 'multiplier': Decimal('2.00')},
    ]

    # Default policy configuration
    DEFAULT_CONFIG = {
        'base_accrual_rate': Decimal('1.25'),  # Days per month (15/year)
        'accrual_period': 'monthly',
        'max_balance': Decimal('30.00'),
        'max_carryover': Decimal('5.00'),
        'min_notice_days': 1,
        'max_consecutive_days': 15,
        'min_request_days': Decimal('0.5'),
        'allow_negative_balance': False,
        'require_approval': True,
        'part_time_multiplier': Decimal('0.5'),
        'probation_accrual': True,
        'accrual_tiers': None,  # Use default tiers
    }

    def __init__(self, policy_config: dict = None):
        """
        Initialize policy with configuration.

        Args:
            policy_config: Policy configuration dictionary
        """
        self.config = {**self.DEFAULT_CONFIG}
        if policy_config:
            self.config.update(policy_config)

        self.accrual_tiers = self.config.get('accrual_tiers') or self.DEFAULT_ACCRUAL_TIERS

    def calculate_accrual(
        self,
        employee: Employee,
        date_range: Tuple[date, date] = None
    ) -> AccrualResult:
        """
        Calculate time-off accrual for an employee.

        Args:
            employee: The employee
            date_range: Optional date range for calculation

        Returns:
            AccrualResult with calculated values
        """
        base_rate = self.config['base_accrual_rate']

        # Get tenure multiplier
        years_of_service = employee.years_of_service
        multiplier = Decimal('1.00')

        for tier in self.accrual_tiers:
            if tier['min_years'] <= years_of_service:
                if tier['max_years'] is None or years_of_service < tier['max_years']:
                    multiplier = tier['multiplier']
                    break

        # Apply employment type adjustments
        factors = {'tenure_multiplier': float(multiplier)}

        if employee.employment_type == 'part_time':
            multiplier *= self.config['part_time_multiplier']
            factors['part_time_adjustment'] = float(self.config['part_time_multiplier'])

        if employee.employment_type in ['contract', 'temporary']:
            # No accrual for contractors
            return AccrualResult(
                base_amount=base_rate,
                adjusted_amount=Decimal('0'),
                multiplier=Decimal('0'),
                factors={'employment_type': 'no_accrual'}
            )

        # Check probation status
        if employee.status == 'probation' and not self.config['probation_accrual']:
            return AccrualResult(
                base_amount=base_rate,
                adjusted_amount=Decimal('0'),
                multiplier=Decimal('0'),
                factors={'status': 'probation_no_accrual'}
            )

        adjusted_amount = base_rate * multiplier

        # Cap at max balance if specified
        if self.config['max_balance']:
            # Would need current balance to apply cap
            factors['max_balance'] = float(self.config['max_balance'])

        return AccrualResult(
            base_amount=base_rate,
            adjusted_amount=adjusted_amount,
            multiplier=multiplier,
            factors=factors
        )

    def validate_request(
        self,
        employee: Employee,
        start_date: date,
        end_date: date,
        time_off_type: TimeOffType,
        current_balance: Decimal = None
    ) -> ValidationResult:
        """
        Validate a time-off request against policy rules.

        Args:
            employee: The requesting employee
            start_date: Request start date
            end_date: Request end date
            time_off_type: Type of time off
            current_balance: Current time-off balance

        Returns:
            ValidationResult with validation status
        """
        errors = []
        warnings = []
        today = timezone.now().date()

        # Validate date range
        if start_date > end_date:
            errors.append('End date must be after start date.')

        # Check notice period
        days_notice = (start_date - today).days
        min_notice = time_off_type.min_notice_days or self.config['min_notice_days']
        if days_notice < min_notice:
            errors.append(f'Request requires at least {min_notice} days notice.')

        # Check maximum consecutive days
        request_days = (end_date - start_date).days + 1
        max_consecutive = self.config.get('max_consecutive_days', 15)
        if request_days > max_consecutive:
            errors.append(f'Maximum consecutive days allowed is {max_consecutive}.')

        # Check minimum request duration
        min_days = self.config.get('min_request_days', Decimal('0.5'))
        if Decimal(str(request_days)) < min_days:
            errors.append(f'Minimum request is {min_days} days.')

        # Check balance
        if current_balance is not None and time_off_type.is_accrued:
            if not self.config['allow_negative_balance']:
                if Decimal(str(request_days)) > current_balance:
                    errors.append(
                        f'Insufficient balance. Available: {current_balance} days, '
                        f'Requested: {request_days} days.'
                    )

        # Check blackout dates
        blackouts = self.check_blackout_dates(employee, start_date, end_date)
        if blackouts:
            for blackout in blackouts:
                if blackout['restriction_type'] == 'blocked':
                    errors.append(f"Time off blocked: {blackout['name']} ({blackout['dates']})")
                elif blackout['restriction_type'] == 'restricted':
                    warnings.append(
                        f"Time off restricted: {blackout['name']} - Manager approval required"
                    )

        # Check for overlapping requests
        overlapping = TimeOffRequest.objects.filter(
            employee=employee,
            status__in=['pending', 'approved'],
            start_date__lte=end_date,
            end_date__gte=start_date
        ).exists()

        if overlapping:
            errors.append('An overlapping time-off request already exists.')

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )

    def check_blackout_dates(
        self,
        employee: Employee,
        start_date: date,
        end_date: date
    ) -> List[Dict[str, Any]]:
        """
        Check for blackout dates that conflict with requested dates.

        Args:
            employee: The employee
            start_date: Request start date
            end_date: Request end date

        Returns:
            List of conflicting blackout dates
        """
        conflicts = []

        # Query blackout dates
        blackouts = TimeOffBlackoutDate.objects.filter(
            is_active=True,
            start_date__lte=end_date,
            end_date__gte=start_date
        )

        for blackout in blackouts:
            # Check if applies to this employee
            if blackout.applies_to_all:
                applies = True
            elif employee.department:
                applies = blackout.departments.filter(id=employee.department.id).exists()
            else:
                applies = False

            if applies:
                conflicts.append({
                    'name': blackout.name,
                    'dates': f"{blackout.start_date} - {blackout.end_date}",
                    'restriction_type': blackout.restriction_type,
                })

        return conflicts

    def get_available_balance(
        self,
        employee: Employee,
        time_off_type: TimeOffType
    ) -> Decimal:
        """
        Get available balance for an employee.

        Args:
            employee: The employee
            time_off_type: Type of time off

        Returns:
            Available balance in days
        """
        try:
            balance = TimeOffBalance.objects.get(
                employee=employee,
                time_off_type=time_off_type,
                year=timezone.now().year
            )
            return balance.balance - balance.pending
        except TimeOffBalance.DoesNotExist:
            # Return default starting balance from policy
            return Decimal('0')


# =============================================================================
# ACCRUAL CALCULATOR
# =============================================================================

class AccrualCalculator:
    """
    Calculate time-off accruals based on various schedules.

    Supports:
    - Monthly accrual (default)
    - Bi-weekly accrual
    - Anniversary-based accrual
    - Custom schedules
    """

    ACCRUAL_SCHEDULES = {
        'monthly': {
            'periods_per_year': 12,
            'description': 'Accrues on the 1st of each month',
        },
        'bi_weekly': {
            'periods_per_year': 26,
            'description': 'Accrues every two weeks',
        },
        'weekly': {
            'periods_per_year': 52,
            'description': 'Accrues every week',
        },
        'anniversary': {
            'periods_per_year': 1,
            'description': 'Accrues on employment anniversary',
        },
        'quarterly': {
            'periods_per_year': 4,
            'description': 'Accrues at start of each quarter',
        },
    }

    def __init__(self, policy: TimeOffPolicy = None):
        """
        Initialize calculator with optional policy.

        Args:
            policy: TimeOffPolicy instance
        """
        self.policy = policy or TimeOffPolicy()

    def calculate(
        self,
        employee: Employee,
        time_off_type: TimeOffType,
        period: str = 'monthly'
    ) -> Decimal:
        """
        Calculate accrual amount for a period.

        Args:
            employee: The employee
            time_off_type: Type of time off
            period: Accrual period type

        Returns:
            Accrual amount in days
        """
        # Get annual accrual from policy
        annual_result = self.policy.calculate_accrual(employee)

        if annual_result.adjusted_amount == 0:
            return Decimal('0')

        # Convert to period-based accrual
        schedule = self.ACCRUAL_SCHEDULES.get(period, self.ACCRUAL_SCHEDULES['monthly'])
        periods_per_year = schedule['periods_per_year']

        # Annual amount based on monthly rate * 12
        annual_amount = annual_result.adjusted_amount * 12

        # Divide by periods
        period_amount = annual_amount / periods_per_year

        return round(period_amount, 2)

    def calculate_ytd_accrual(
        self,
        employee: Employee,
        time_off_type: TimeOffType,
        as_of_date: date = None
    ) -> Decimal:
        """
        Calculate year-to-date accrual.

        Args:
            employee: The employee
            time_off_type: Type of time off
            as_of_date: Date to calculate up to (default: today)

        Returns:
            YTD accrual amount
        """
        if as_of_date is None:
            as_of_date = timezone.now().date()

        # Calculate monthly accrual
        monthly = self.calculate(employee, time_off_type, 'monthly')

        # Calculate months elapsed
        start_of_year = date(as_of_date.year, 1, 1)
        months_elapsed = as_of_date.month

        # Prorate for hire date
        if employee.start_date and employee.start_date > start_of_year:
            hire_month = employee.start_date.month
            months_elapsed = max(0, as_of_date.month - hire_month + 1)

        return monthly * months_elapsed

    def get_next_accrual_date(
        self,
        employee: Employee,
        period: str = 'monthly'
    ) -> date:
        """
        Get the next accrual date.

        Args:
            employee: The employee
            period: Accrual period type

        Returns:
            Next accrual date
        """
        today = timezone.now().date()

        if period == 'monthly':
            # First of next month
            if today.month == 12:
                return date(today.year + 1, 1, 1)
            return date(today.year, today.month + 1, 1)

        elif period == 'bi_weekly':
            # Next bi-weekly period (assuming starts on Monday)
            days_until_monday = (7 - today.weekday()) % 7
            next_monday = today + timedelta(days=days_until_monday or 7)
            # Get the bi-weekly Monday
            week_number = next_monday.isocalendar()[1]
            if week_number % 2 != 0:
                next_monday += timedelta(days=7)
            return next_monday

        elif period == 'weekly':
            # Next Monday
            days_until_monday = (7 - today.weekday()) % 7
            return today + timedelta(days=days_until_monday or 7)

        elif period == 'anniversary':
            # Employee's next anniversary
            if employee.start_date:
                anniversary = date(today.year, employee.start_date.month, employee.start_date.day)
                if anniversary <= today:
                    anniversary = date(today.year + 1, employee.start_date.month, employee.start_date.day)
                return anniversary
            return date(today.year + 1, 1, 1)

        elif period == 'quarterly':
            # First of next quarter
            current_quarter = (today.month - 1) // 3 + 1
            if current_quarter == 4:
                return date(today.year + 1, 1, 1)
            next_quarter_month = (current_quarter * 3) + 1
            return date(today.year, next_quarter_month, 1)

        return today + timedelta(days=30)


# =============================================================================
# CARRYOVER POLICY
# =============================================================================

class CarryoverPolicy:
    """
    Handle year-end carryover rules for time-off balances.

    Supports:
    - Maximum carryover caps
    - Use-it-or-lose-it policies
    - Extended carryover periods
    - Payout options
    """

    class CarryoverType:
        """Carryover policy types."""
        NONE = 'none'  # No carryover (use-it-or-lose-it)
        LIMITED = 'limited'  # Carryover up to cap
        UNLIMITED = 'unlimited'  # Full carryover
        EXTENDED = 'extended'  # Carryover with expiration

    def __init__(
        self,
        carryover_type: str = 'limited',
        max_carryover: Decimal = Decimal('5.00'),
        expiration_months: int = None,
        allow_payout: bool = False,
        payout_rate: Decimal = None
    ):
        """
        Initialize carryover policy.

        Args:
            carryover_type: Type of carryover policy
            max_carryover: Maximum days to carry over
            expiration_months: Months until carryover expires
            allow_payout: Allow payout of forfeited balance
            payout_rate: Rate for payout calculation
        """
        self.carryover_type = carryover_type
        self.max_carryover = max_carryover
        self.expiration_months = expiration_months
        self.allow_payout = allow_payout
        self.payout_rate = payout_rate

    def apply(
        self,
        employee: Employee,
        year: int,
        balances: Dict[str, Decimal]
    ) -> Dict[str, CarryoverResult]:
        """
        Apply carryover policy to employee balances.

        Args:
            employee: The employee
            year: Year being closed
            balances: Current balances by time-off type

        Returns:
            Dictionary of CarryoverResult by time-off type
        """
        results = {}

        for time_off_type, balance in balances.items():
            result = self._calculate_carryover(balance)
            results[time_off_type] = result

        return results

    def _calculate_carryover(self, current_balance: Decimal) -> CarryoverResult:
        """
        Calculate carryover for a single balance.

        Args:
            current_balance: Current balance

        Returns:
            CarryoverResult
        """
        if self.carryover_type == self.CarryoverType.NONE:
            return CarryoverResult(
                previous_balance=current_balance,
                carryover_amount=Decimal('0'),
                forfeited_amount=current_balance,
                new_balance=Decimal('0')
            )

        elif self.carryover_type == self.CarryoverType.UNLIMITED:
            return CarryoverResult(
                previous_balance=current_balance,
                carryover_amount=current_balance,
                forfeited_amount=Decimal('0'),
                new_balance=current_balance
            )

        elif self.carryover_type == self.CarryoverType.LIMITED:
            carryover = min(current_balance, self.max_carryover)
            forfeited = current_balance - carryover
            return CarryoverResult(
                previous_balance=current_balance,
                carryover_amount=carryover,
                forfeited_amount=forfeited,
                new_balance=carryover
            )

        elif self.carryover_type == self.CarryoverType.EXTENDED:
            # Full carryover but marks expiration
            return CarryoverResult(
                previous_balance=current_balance,
                carryover_amount=current_balance,
                forfeited_amount=Decimal('0'),
                new_balance=current_balance
            )

        return CarryoverResult(
            previous_balance=current_balance,
            carryover_amount=Decimal('0'),
            forfeited_amount=current_balance,
            new_balance=Decimal('0')
        )

    def calculate_payout(
        self,
        forfeited_amount: Decimal,
        daily_rate: Decimal
    ) -> Decimal:
        """
        Calculate payout for forfeited balance.

        Args:
            forfeited_amount: Days being forfeited
            daily_rate: Employee's daily rate

        Returns:
            Payout amount
        """
        if not self.allow_payout or forfeited_amount <= 0:
            return Decimal('0')

        rate = self.payout_rate or Decimal('1.00')
        return forfeited_amount * daily_rate * rate


# =============================================================================
# BLACKOUT DATE MANAGER
# =============================================================================

class BlackoutDateManager:
    """
    Manage time-off blackout dates.

    Handles:
    - Creating blackout periods
    - Checking conflicts
    - Department-specific blackouts
    """

    @staticmethod
    def get_blackouts_for_period(
        start_date: date,
        end_date: date,
        department=None
    ) -> List[TimeOffBlackoutDate]:
        """
        Get all blackout dates for a period.

        Args:
            start_date: Period start
            end_date: Period end
            department: Optional department filter

        Returns:
            List of blackout dates
        """
        queryset = TimeOffBlackoutDate.objects.filter(
            is_active=True,
            start_date__lte=end_date,
            end_date__gte=start_date
        )

        if department:
            queryset = queryset.filter(
                Q(applies_to_all=True) |
                Q(departments=department)
            ).distinct()
        else:
            queryset = queryset.filter(applies_to_all=True)

        return list(queryset)

    @staticmethod
    def create_blackout(
        name: str,
        start_date: date,
        end_date: date,
        restriction_type: str = 'restricted',
        applies_to_all: bool = True,
        departments: List = None,
        description: str = ''
    ) -> TimeOffBlackoutDate:
        """
        Create a new blackout period.

        Args:
            name: Blackout name
            start_date: Start date
            end_date: End date
            restriction_type: Type of restriction
            applies_to_all: Applies to all departments
            departments: Specific departments (if not all)
            description: Optional description

        Returns:
            Created TimeOffBlackoutDate
        """
        blackout = TimeOffBlackoutDate.objects.create(
            name=name,
            start_date=start_date,
            end_date=end_date,
            restriction_type=restriction_type,
            applies_to_all=applies_to_all,
            description=description
        )

        if departments and not applies_to_all:
            blackout.departments.set(departments)

        return blackout

    @staticmethod
    def is_date_blocked(
        check_date: date,
        employee: Employee = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if a specific date is blocked.

        Args:
            check_date: Date to check
            employee: Optional employee for department check

        Returns:
            Tuple of (is_blocked, reason)
        """
        queryset = TimeOffBlackoutDate.objects.filter(
            is_active=True,
            restriction_type='blocked',
            start_date__lte=check_date,
            end_date__gte=check_date
        )

        if employee and employee.department:
            queryset = queryset.filter(
                Q(applies_to_all=True) |
                Q(departments=employee.department)
            )
        else:
            queryset = queryset.filter(applies_to_all=True)

        blackout = queryset.first()

        if blackout:
            return True, blackout.name

        return False, None


# =============================================================================
# LEAVE BALANCE MANAGER
# =============================================================================

class LeaveBalanceManager:
    """
    Manage employee leave balances across time-off types.
    """

    @staticmethod
    def initialize_balances(
        employee: Employee,
        year: int = None
    ) -> List[TimeOffBalance]:
        """
        Initialize time-off balances for an employee.

        Args:
            employee: The employee
            year: Year for balances (default: current year)

        Returns:
            List of created TimeOffBalance records
        """
        if year is None:
            year = timezone.now().year

        balances = []
        time_off_types = TimeOffType.objects.filter(is_active=True)

        for tot in time_off_types:
            balance, created = TimeOffBalance.objects.get_or_create(
                employee=employee,
                time_off_type=tot,
                year=year,
                defaults={
                    'balance': tot.default_allowance or Decimal('0'),
                    'carried_over': Decimal('0'),
                }
            )
            balances.append(balance)

        return balances

    @staticmethod
    def process_year_end(
        year: int,
        carryover_policy: CarryoverPolicy = None
    ) -> Dict[str, Any]:
        """
        Process year-end for all employees.

        Args:
            year: Year being closed
            carryover_policy: Carryover policy to apply

        Returns:
            Summary of processing
        """
        if carryover_policy is None:
            carryover_policy = CarryoverPolicy()

        results = {
            'employees_processed': 0,
            'balances_processed': 0,
            'total_carryover': Decimal('0'),
            'total_forfeited': Decimal('0'),
            'errors': []
        }

        # Get all active employees
        employees = Employee.objects.filter(
            status__in=['active', 'probation', 'on_leave']
        )

        for employee in employees:
            try:
                # Get current year balances
                balances = TimeOffBalance.objects.filter(
                    employee=employee,
                    year=year
                ).select_related('time_off_type')

                for balance in balances:
                    # Apply carryover
                    carryover_result = carryover_policy._calculate_carryover(balance.balance)

                    # Create new year balance
                    new_balance, _ = TimeOffBalance.objects.get_or_create(
                        employee=employee,
                        time_off_type=balance.time_off_type,
                        year=year + 1,
                        defaults={
                            'balance': carryover_result.new_balance,
                            'carried_over': carryover_result.carryover_amount,
                        }
                    )

                    results['balances_processed'] += 1
                    results['total_carryover'] += carryover_result.carryover_amount
                    results['total_forfeited'] += carryover_result.forfeited_amount

                results['employees_processed'] += 1

            except Exception as e:
                results['errors'].append({
                    'employee_id': employee.employee_id,
                    'error': str(e)
                })

        return results
