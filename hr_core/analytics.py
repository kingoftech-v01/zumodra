"""
HR Core Analytics - HR Metrics and Analytics Service

This module provides comprehensive HR analytics:
- Turnover rate analysis
- Headcount trends
- Diversity metrics
- Compensation analysis
- Time off utilization
- Onboarding metrics
- Performance metrics

All metrics can be filtered by tenant, department, and date range.
"""

import logging
from dataclasses import dataclass, field
from datetime import date, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from django.db.models import (
    Avg, Count, F, Max, Min, Q, Sum,
    Value, Case, When, ExpressionWrapper,
    FloatField, IntegerField, DecimalField
)
from django.db.models.functions import (
    Coalesce, ExtractMonth, ExtractYear,
    TruncMonth, TruncQuarter, TruncYear
)
from django.utils import timezone

from .models import (
    Employee,
    TimeOffRequest,
    TimeOffType,
    TimeOffBalance,
    EmployeeOnboarding,
    OnboardingTaskProgress,
    PerformanceReview,
    EmployeeCompensation,
    Offboarding,
)

logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES FOR ANALYTICS RESULTS
# =============================================================================

@dataclass
class TurnoverMetrics:
    """Employee turnover metrics."""
    period_start: date
    period_end: date
    total_separations: int
    voluntary_separations: int
    involuntary_separations: int
    average_headcount: float
    turnover_rate: float
    voluntary_turnover_rate: float
    retention_rate: float
    separations_by_department: Dict[str, int] = field(default_factory=dict)
    separations_by_tenure: Dict[str, int] = field(default_factory=dict)
    average_tenure_at_separation: float = 0.0


@dataclass
class HeadcountTrends:
    """Headcount over time."""
    period_start: date
    period_end: date
    current_headcount: int
    headcount_change: int
    new_hires: int
    separations: int
    net_change: int
    trend_data: List[Dict[str, Any]] = field(default_factory=list)
    by_department: Dict[str, int] = field(default_factory=dict)
    by_employment_type: Dict[str, int] = field(default_factory=dict)


@dataclass
class DiversityMetrics:
    """Workforce diversity metrics."""
    total_employees: int
    by_gender: Dict[str, int] = field(default_factory=dict)
    by_ethnicity: Dict[str, int] = field(default_factory=dict)
    by_age_group: Dict[str, int] = field(default_factory=dict)
    by_department_gender: Dict[str, Dict[str, int]] = field(default_factory=dict)
    leadership_diversity: Dict[str, Dict[str, int]] = field(default_factory=dict)


@dataclass
class CompensationAnalysis:
    """Compensation analysis metrics."""
    total_payroll: Decimal
    average_salary: Decimal
    median_salary: Decimal
    min_salary: Decimal
    max_salary: Decimal
    salary_by_department: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    salary_by_level: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    salary_ranges: Dict[str, int] = field(default_factory=dict)
    recent_increases: int = 0
    average_increase_percentage: float = 0.0


@dataclass
class TimeOffUtilization:
    """Time off usage metrics."""
    period_start: date
    period_end: date
    total_days_taken: Decimal
    total_days_available: Decimal
    utilization_rate: float
    average_days_per_employee: Decimal
    by_type: Dict[str, Decimal] = field(default_factory=dict)
    by_department: Dict[str, Decimal] = field(default_factory=dict)
    by_month: Dict[str, Decimal] = field(default_factory=dict)
    pending_requests: int = 0
    pending_days: Decimal = Decimal('0')


@dataclass
class OnboardingMetrics:
    """Onboarding program metrics."""
    period_start: date
    period_end: date
    new_hires_count: int
    onboarding_in_progress: int
    onboarding_completed: int
    average_completion_time_days: float
    completion_rate: float
    task_completion_rate: float
    overdue_tasks: int
    by_department: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class PerformanceMetrics:
    """Performance review metrics."""
    period_start: date
    period_end: date
    reviews_completed: int
    reviews_pending: int
    average_rating: float
    rating_distribution: Dict[int, int] = field(default_factory=dict)
    by_department: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    promotion_recommendations: int = 0
    pip_recommendations: int = 0


# =============================================================================
# HR ANALYTICS SERVICE
# =============================================================================

class HRAnalyticsService:
    """
    Service for HR metrics and analytics.

    Provides comprehensive analytics across all HR domains including:
    - Workforce demographics
    - Turnover and retention
    - Compensation analysis
    - Time off patterns
    - Performance trends
    """

    @staticmethod
    def get_turnover_rate(
        tenant=None,
        period: Tuple[date, date] = None,
        department=None
    ) -> TurnoverMetrics:
        """
        Calculate employee turnover rate.

        Args:
            tenant: Tenant to filter by (optional)
            period: Date range tuple (start, end)
            department: Department to filter by (optional)

        Returns:
            TurnoverMetrics with turnover analysis
        """
        if period is None:
            period_end = timezone.now().date()
            period_start = date(period_end.year, 1, 1)
        else:
            period_start, period_end = period

        # Build base queryset
        employees = Employee.objects.all()
        offboardings = Offboarding.objects.all()

        if tenant:
            employees = employees.filter(tenant=tenant)
            offboardings = offboardings.filter(employee__tenant=tenant)

        if department:
            employees = employees.filter(department=department)
            offboardings = offboardings.filter(employee__department=department)

        # Count separations in period
        separations = offboardings.filter(
            last_working_day__gte=period_start,
            last_working_day__lte=period_end
        )

        total_separations = separations.count()
        voluntary_separations = separations.filter(
            separation_type__in=['resignation', 'retirement']
        ).count()
        involuntary_separations = total_separations - voluntary_separations

        # Calculate average headcount
        start_headcount = employees.filter(
            start_date__lte=period_start,
            status__in=['active', 'probation', 'on_leave']
        ).count()
        end_headcount = employees.filter(
            status__in=['active', 'probation', 'on_leave']
        ).count()
        average_headcount = (start_headcount + end_headcount) / 2

        # Calculate rates
        turnover_rate = (total_separations / average_headcount * 100) if average_headcount > 0 else 0
        voluntary_turnover_rate = (voluntary_separations / average_headcount * 100) if average_headcount > 0 else 0
        retention_rate = 100 - turnover_rate

        # Separations by department
        separations_by_dept = dict(
            separations.values('employee__department__name').annotate(
                count=Count('id')
            ).values_list('employee__department__name', 'count')
        )

        # Separations by tenure
        separations_by_tenure = {
            '< 1 year': 0,
            '1-2 years': 0,
            '2-5 years': 0,
            '5-10 years': 0,
            '10+ years': 0,
        }

        for offboarding in separations.select_related('employee'):
            if offboarding.employee.start_date:
                years = (offboarding.last_working_day - offboarding.employee.start_date).days / 365.25
                if years < 1:
                    separations_by_tenure['< 1 year'] += 1
                elif years < 2:
                    separations_by_tenure['1-2 years'] += 1
                elif years < 5:
                    separations_by_tenure['2-5 years'] += 1
                elif years < 10:
                    separations_by_tenure['5-10 years'] += 1
                else:
                    separations_by_tenure['10+ years'] += 1

        # Average tenure at separation
        total_tenure_days = 0
        tenure_count = 0
        for offboarding in separations.select_related('employee'):
            if offboarding.employee.start_date:
                tenure_days = (offboarding.last_working_day - offboarding.employee.start_date).days
                total_tenure_days += tenure_days
                tenure_count += 1

        avg_tenure = (total_tenure_days / tenure_count / 365.25) if tenure_count > 0 else 0

        return TurnoverMetrics(
            period_start=period_start,
            period_end=period_end,
            total_separations=total_separations,
            voluntary_separations=voluntary_separations,
            involuntary_separations=involuntary_separations,
            average_headcount=average_headcount,
            turnover_rate=round(turnover_rate, 2),
            voluntary_turnover_rate=round(voluntary_turnover_rate, 2),
            retention_rate=round(retention_rate, 2),
            separations_by_department=separations_by_dept,
            separations_by_tenure=separations_by_tenure,
            average_tenure_at_separation=round(avg_tenure, 2)
        )

    @staticmethod
    def get_headcount_trends(
        tenant=None,
        period: Tuple[date, date] = None,
        granularity: str = 'monthly'
    ) -> HeadcountTrends:
        """
        Get headcount trends over time.

        Args:
            tenant: Tenant to filter by (optional)
            period: Date range tuple (start, end)
            granularity: 'monthly', 'quarterly', or 'yearly'

        Returns:
            HeadcountTrends with trend data
        """
        if period is None:
            period_end = timezone.now().date()
            period_start = period_end - timedelta(days=365)
        else:
            period_start, period_end = period

        employees = Employee.objects.all()
        if tenant:
            employees = employees.filter(tenant=tenant)

        # Current headcount
        current_headcount = employees.filter(
            status__in=['active', 'probation', 'on_leave']
        ).count()

        # Previous period headcount
        previous_headcount = employees.filter(
            start_date__lte=period_start,
            status__in=['active', 'probation', 'on_leave', 'terminated', 'resigned']
        ).exclude(
            offboarding__last_working_day__lt=period_start
        ).count()

        headcount_change = current_headcount - previous_headcount

        # New hires in period
        new_hires = employees.filter(
            start_date__gte=period_start,
            start_date__lte=period_end
        ).count()

        # Separations in period
        separations = Offboarding.objects.filter(
            last_working_day__gte=period_start,
            last_working_day__lte=period_end
        ).count()

        net_change = new_hires - separations

        # Generate trend data
        trend_data = []

        if granularity == 'monthly':
            trunc_func = TruncMonth
        elif granularity == 'quarterly':
            trunc_func = TruncQuarter
        else:
            trunc_func = TruncYear

        # Group new hires by period
        hire_trends = employees.filter(
            start_date__gte=period_start,
            start_date__lte=period_end
        ).annotate(
            period=trunc_func('start_date')
        ).values('period').annotate(
            new_hires=Count('id')
        ).order_by('period')

        for trend in hire_trends:
            trend_data.append({
                'period': trend['period'].isoformat() if trend['period'] else None,
                'new_hires': trend['new_hires'],
            })

        # By department
        by_department = dict(
            employees.filter(
                status__in=['active', 'probation', 'on_leave']
            ).values('department__name').annotate(
                count=Count('id')
            ).values_list('department__name', 'count')
        )

        # By employment type
        by_employment_type = dict(
            employees.filter(
                status__in=['active', 'probation', 'on_leave']
            ).values('employment_type').annotate(
                count=Count('id')
            ).values_list('employment_type', 'count')
        )

        return HeadcountTrends(
            period_start=period_start,
            period_end=period_end,
            current_headcount=current_headcount,
            headcount_change=headcount_change,
            new_hires=new_hires,
            separations=separations,
            net_change=net_change,
            trend_data=trend_data,
            by_department=by_department,
            by_employment_type=by_employment_type
        )

    @staticmethod
    def get_diversity_metrics(tenant=None) -> DiversityMetrics:
        """
        Get workforce diversity metrics.

        Args:
            tenant: Tenant to filter by (optional)

        Returns:
            DiversityMetrics with diversity data
        """
        employees = Employee.objects.filter(
            status__in=['active', 'probation', 'on_leave']
        )
        if tenant:
            employees = employees.filter(tenant=tenant)

        total_employees = employees.count()

        # Note: Gender and ethnicity fields would need to be added to Employee model
        # Using placeholder aggregations

        # By gender (if field exists)
        by_gender = {}
        if hasattr(Employee, 'gender'):
            by_gender = dict(
                employees.values('gender').annotate(
                    count=Count('id')
                ).values_list('gender', 'count')
            )
        else:
            by_gender = {'Not tracked': total_employees}

        # By age group (calculated from date_of_birth if available)
        by_age_group = {
            '18-25': 0,
            '26-35': 0,
            '36-45': 0,
            '46-55': 0,
            '55+': 0,
            'Unknown': 0,
        }

        today = timezone.now().date()
        for emp in employees:
            if hasattr(emp, 'date_of_birth') and emp.date_of_birth:
                age = (today - emp.date_of_birth).days / 365.25
                if age < 26:
                    by_age_group['18-25'] += 1
                elif age < 36:
                    by_age_group['26-35'] += 1
                elif age < 46:
                    by_age_group['36-45'] += 1
                elif age < 56:
                    by_age_group['46-55'] += 1
                else:
                    by_age_group['55+'] += 1
            else:
                by_age_group['Unknown'] += 1

        return DiversityMetrics(
            total_employees=total_employees,
            by_gender=by_gender,
            by_ethnicity={},  # Would require ethnicity field
            by_age_group=by_age_group,
            by_department_gender={},  # Would cross-reference department and gender
            leadership_diversity={}  # Would filter by management level
        )

    @staticmethod
    def get_compensation_analysis(
        tenant=None,
        department=None
    ) -> CompensationAnalysis:
        """
        Analyze compensation across the organization.

        Args:
            tenant: Tenant to filter by (optional)
            department: Department to filter by (optional)

        Returns:
            CompensationAnalysis with compensation metrics
        """
        employees = Employee.objects.filter(
            status__in=['active', 'probation', 'on_leave'],
            base_salary__isnull=False,
            base_salary__gt=0
        )

        if tenant:
            employees = employees.filter(tenant=tenant)

        if department:
            employees = employees.filter(department=department)

        # Basic statistics
        salary_stats = employees.aggregate(
            total_payroll=Sum('base_salary'),
            average_salary=Avg('base_salary'),
            min_salary=Min('base_salary'),
            max_salary=Max('base_salary')
        )

        total_payroll = salary_stats['total_payroll'] or Decimal('0')
        average_salary = salary_stats['average_salary'] or Decimal('0')
        min_salary = salary_stats['min_salary'] or Decimal('0')
        max_salary = salary_stats['max_salary'] or Decimal('0')

        # Calculate median
        salary_values = list(employees.values_list('base_salary', flat=True).order_by('base_salary'))
        if salary_values:
            mid = len(salary_values) // 2
            if len(salary_values) % 2 == 0:
                median_salary = (salary_values[mid - 1] + salary_values[mid]) / 2
            else:
                median_salary = salary_values[mid]
        else:
            median_salary = Decimal('0')

        # Salary by department
        salary_by_department = {}
        dept_stats = employees.values('department__name').annotate(
            avg_salary=Avg('base_salary'),
            min_salary=Min('base_salary'),
            max_salary=Max('base_salary'),
            count=Count('id'),
            total=Sum('base_salary')
        )

        for stat in dept_stats:
            dept_name = stat['department__name'] or 'Unassigned'
            salary_by_department[dept_name] = {
                'average': float(stat['avg_salary'] or 0),
                'min': float(stat['min_salary'] or 0),
                'max': float(stat['max_salary'] or 0),
                'count': stat['count'],
                'total': float(stat['total'] or 0),
            }

        # Salary ranges distribution
        salary_ranges = {
            '< 40K': 0,
            '40K-60K': 0,
            '60K-80K': 0,
            '80K-100K': 0,
            '100K-150K': 0,
            '> 150K': 0,
        }

        for salary in salary_values:
            if salary < 40000:
                salary_ranges['< 40K'] += 1
            elif salary < 60000:
                salary_ranges['40K-60K'] += 1
            elif salary < 80000:
                salary_ranges['60K-80K'] += 1
            elif salary < 100000:
                salary_ranges['80K-100K'] += 1
            elif salary < 150000:
                salary_ranges['100K-150K'] += 1
            else:
                salary_ranges['> 150K'] += 1

        # Recent compensation changes
        today = timezone.now().date()
        year_ago = today - timedelta(days=365)

        recent_changes = EmployeeCompensation.objects.filter(
            effective_date__gte=year_ago,
            effective_date__lte=today
        )

        if department:
            recent_changes = recent_changes.filter(employee__department=department)

        recent_increases = recent_changes.exclude(
            change_reason='hire'
        ).count()

        # Average increase percentage
        increases_with_prev = recent_changes.filter(
            previous_salary__isnull=False,
            previous_salary__gt=0
        ).exclude(change_reason='hire')

        if increases_with_prev.exists():
            total_pct = sum(
                ((c.base_salary - c.previous_salary) / c.previous_salary * 100)
                for c in increases_with_prev
            )
            avg_increase_pct = total_pct / increases_with_prev.count()
        else:
            avg_increase_pct = 0.0

        return CompensationAnalysis(
            total_payroll=total_payroll,
            average_salary=average_salary,
            median_salary=median_salary,
            min_salary=min_salary,
            max_salary=max_salary,
            salary_by_department=salary_by_department,
            salary_by_level={},  # Would require job level field
            salary_ranges=salary_ranges,
            recent_increases=recent_increases,
            average_increase_percentage=round(avg_increase_pct, 2)
        )

    @staticmethod
    def get_time_off_utilization(
        tenant=None,
        period: Tuple[date, date] = None
    ) -> TimeOffUtilization:
        """
        Analyze time off utilization.

        Args:
            tenant: Tenant to filter by (optional)
            period: Date range tuple (start, end)

        Returns:
            TimeOffUtilization with usage metrics
        """
        if period is None:
            period_end = timezone.now().date()
            period_start = date(period_end.year, 1, 1)
        else:
            period_start, period_end = period

        # Get approved time off requests in period
        requests = TimeOffRequest.objects.filter(
            status='approved',
            start_date__lte=period_end,
            end_date__gte=period_start
        ).select_related('employee', 'time_off_type')

        if tenant:
            requests = requests.filter(employee__tenant=tenant)

        # Total days taken
        total_days_taken = requests.aggregate(
            total=Sum('total_days')
        )['total'] or Decimal('0')

        # Total available (from balances)
        year = period_start.year
        total_available = TimeOffBalance.objects.filter(
            year=year
        ).aggregate(
            total=Sum(F('accrued_this_year') + F('carried_over'))
        )['total'] or Decimal('0')

        # Utilization rate
        utilization_rate = (float(total_days_taken) / float(total_available) * 100) if total_available > 0 else 0

        # Active employees count
        active_employees = Employee.objects.filter(
            status__in=['active', 'probation']
        ).count()

        average_days = total_days_taken / active_employees if active_employees > 0 else Decimal('0')

        # By type
        by_type = dict(
            requests.values('time_off_type__name').annotate(
                total=Sum('total_days')
            ).values_list('time_off_type__name', 'total')
        )

        # By department
        by_department = dict(
            requests.values('employee__department__name').annotate(
                total=Sum('total_days')
            ).values_list('employee__department__name', 'total')
        )

        # By month
        by_month = {}
        monthly_data = requests.annotate(
            month=TruncMonth('start_date')
        ).values('month').annotate(
            total=Sum('total_days')
        ).order_by('month')

        for item in monthly_data:
            month_key = item['month'].strftime('%Y-%m') if item['month'] else 'Unknown'
            by_month[month_key] = item['total']

        # Pending requests
        pending = TimeOffRequest.objects.filter(
            status='pending'
        )
        pending_requests = pending.count()
        pending_days = pending.aggregate(total=Sum('total_days'))['total'] or Decimal('0')

        return TimeOffUtilization(
            period_start=period_start,
            period_end=period_end,
            total_days_taken=total_days_taken,
            total_days_available=total_available,
            utilization_rate=round(utilization_rate, 2),
            average_days_per_employee=round(average_days, 2),
            by_type=by_type,
            by_department=by_department,
            by_month=by_month,
            pending_requests=pending_requests,
            pending_days=pending_days
        )

    @staticmethod
    def get_onboarding_metrics(
        tenant=None,
        period: Tuple[date, date] = None
    ) -> OnboardingMetrics:
        """
        Analyze onboarding program effectiveness.

        Args:
            tenant: Tenant to filter by (optional)
            period: Date range tuple (start, end)

        Returns:
            OnboardingMetrics with onboarding analysis
        """
        if period is None:
            period_end = timezone.now().date()
            period_start = period_end - timedelta(days=90)
        else:
            period_start, period_end = period

        # New hires in period
        new_hires = Employee.objects.filter(
            start_date__gte=period_start,
            start_date__lte=period_end
        )
        if tenant:
            new_hires = new_hires.filter(tenant=tenant)
        new_hires_count = new_hires.count()

        # Onboarding records
        onboardings = EmployeeOnboarding.objects.filter(
            start_date__gte=period_start,
            start_date__lte=period_end
        )

        onboarding_in_progress = onboardings.filter(
            completed_at__isnull=True
        ).count()

        onboarding_completed = onboardings.filter(
            completed_at__isnull=False
        ).count()

        # Average completion time
        completed_onboardings = onboardings.filter(completed_at__isnull=False)
        if completed_onboardings.exists():
            total_days = sum(
                (ob.completed_at.date() - ob.start_date).days
                for ob in completed_onboardings
                if ob.completed_at and ob.start_date
            )
            avg_completion_days = total_days / completed_onboardings.count()
        else:
            avg_completion_days = 0.0

        # Completion rate
        completion_rate = (onboarding_completed / new_hires_count * 100) if new_hires_count > 0 else 0

        # Task completion rate
        task_progress = OnboardingTaskProgress.objects.filter(
            onboarding__in=onboardings
        )
        total_tasks = task_progress.count()
        completed_tasks = task_progress.filter(is_completed=True).count()
        task_completion_rate = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0

        # Overdue tasks
        today = timezone.now().date()
        overdue_tasks = task_progress.filter(
            is_completed=False,
            due_date__lt=today
        ).count()

        # By department
        by_department = {}
        dept_data = new_hires.values('department__name').annotate(
            total=Count('id')
        )

        for item in dept_data:
            dept_name = item['department__name'] or 'Unassigned'
            dept_hires = new_hires.filter(department__name=dept_name if item['department__name'] else None)

            dept_completed = EmployeeOnboarding.objects.filter(
                employee__in=dept_hires,
                completed_at__isnull=False
            ).count()

            by_department[dept_name] = {
                'new_hires': item['total'],
                'completed': dept_completed,
                'completion_rate': round(dept_completed / item['total'] * 100, 2) if item['total'] > 0 else 0
            }

        return OnboardingMetrics(
            period_start=period_start,
            period_end=period_end,
            new_hires_count=new_hires_count,
            onboarding_in_progress=onboarding_in_progress,
            onboarding_completed=onboarding_completed,
            average_completion_time_days=round(avg_completion_days, 1),
            completion_rate=round(completion_rate, 2),
            task_completion_rate=round(task_completion_rate, 2),
            overdue_tasks=overdue_tasks,
            by_department=by_department
        )

    @staticmethod
    def get_performance_metrics(
        tenant=None,
        period: Tuple[date, date] = None
    ) -> PerformanceMetrics:
        """
        Analyze performance review metrics.

        Args:
            tenant: Tenant to filter by (optional)
            period: Date range tuple (start, end)

        Returns:
            PerformanceMetrics with performance analysis
        """
        if period is None:
            period_end = timezone.now().date()
            period_start = date(period_end.year, 1, 1)
        else:
            period_start, period_end = period

        # Reviews in period
        reviews = PerformanceReview.objects.filter(
            review_period_end__gte=period_start,
            review_period_end__lte=period_end
        )
        if tenant:
            reviews = reviews.filter(employee__tenant=tenant)

        reviews_completed = reviews.filter(status='completed').count()
        reviews_pending = reviews.exclude(status='completed').count()

        # Average rating
        completed_reviews = reviews.filter(
            status='completed',
            overall_rating__isnull=False
        )

        avg_rating = completed_reviews.aggregate(
            avg=Avg('overall_rating')
        )['avg'] or 0.0

        # Rating distribution
        rating_distribution = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        for rating in completed_reviews.values_list('overall_rating', flat=True):
            if rating in rating_distribution:
                rating_distribution[rating] += 1

        # Recommendations
        promotion_recommendations = completed_reviews.filter(
            promotion_recommended=True
        ).count()

        pip_recommendations = completed_reviews.filter(
            pip_recommended=True
        ).count()

        # By department
        by_department = {}
        dept_reviews = reviews.filter(status='completed').values(
            'employee__department__name'
        ).annotate(
            count=Count('id'),
            avg_rating=Avg('overall_rating')
        )

        for item in dept_reviews:
            dept_name = item['employee__department__name'] or 'Unassigned'
            by_department[dept_name] = {
                'count': item['count'],
                'average_rating': round(item['avg_rating'], 2) if item['avg_rating'] else 0
            }

        return PerformanceMetrics(
            period_start=period_start,
            period_end=period_end,
            reviews_completed=reviews_completed,
            reviews_pending=reviews_pending,
            average_rating=round(avg_rating, 2),
            rating_distribution=rating_distribution,
            by_department=by_department,
            promotion_recommendations=promotion_recommendations,
            pip_recommendations=pip_recommendations
        )

    @staticmethod
    def get_workforce_summary(tenant=None) -> Dict[str, Any]:
        """
        Get a comprehensive workforce summary.

        Args:
            tenant: Tenant to filter by (optional)

        Returns:
            Dictionary with workforce summary
        """
        employees = Employee.objects.all()
        if tenant:
            employees = employees.filter(tenant=tenant)
        today = timezone.now().date()

        # Basic counts
        total_employees = employees.filter(
            status__in=['active', 'probation', 'on_leave']
        ).count()

        active_count = employees.filter(status='active').count()
        probation_count = employees.filter(status='probation').count()
        on_leave_count = employees.filter(status='on_leave').count()

        # New hires (last 30 days)
        thirty_days_ago = today - timedelta(days=30)
        new_hires = employees.filter(start_date__gte=thirty_days_ago).count()

        # Upcoming anniversaries (next 30 days)
        upcoming_anniversaries = 0
        for emp in employees.filter(status='active', start_date__isnull=False):
            anniversary = date(today.year, emp.start_date.month, emp.start_date.day)
            if today <= anniversary <= today + timedelta(days=30):
                upcoming_anniversaries += 1

        # Upcoming probation ends
        probation_ends = employees.filter(
            status='probation',
            probation_end_date__gte=today,
            probation_end_date__lte=today + timedelta(days=30)
        ).count()

        # Time off today
        time_off_today = TimeOffRequest.objects.filter(
            status='approved',
            start_date__lte=today,
            end_date__gte=today
        ).count()

        # Pending time off requests
        pending_time_off = TimeOffRequest.objects.filter(
            status='pending'
        ).count()

        # Average tenure
        active_with_start = employees.filter(
            status__in=['active', 'probation'],
            start_date__isnull=False
        )

        if active_with_start.exists():
            total_tenure_days = sum(
                (today - emp.start_date).days
                for emp in active_with_start
            )
            avg_tenure_years = total_tenure_days / active_with_start.count() / 365.25
        else:
            avg_tenure_years = 0

        return {
            'total_employees': total_employees,
            'active_employees': active_count,
            'on_probation': probation_count,
            'on_leave': on_leave_count,
            'new_hires_30_days': new_hires,
            'upcoming_anniversaries': upcoming_anniversaries,
            'probation_ends_30_days': probation_ends,
            'employees_off_today': time_off_today,
            'pending_time_off_requests': pending_time_off,
            'average_tenure_years': round(avg_tenure_years, 1),
            'as_of_date': today.isoformat(),
        }
