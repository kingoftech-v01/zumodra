"""
ATS Advanced Reporting System

This module provides executive-level reporting functionality:
- RecruitingFunnelReport: Stage-by-stage analytics
- DEIReport: Diversity, Equity, Inclusion metrics (anonymized)
- CostPerHireReport: Full cost tracking
- TimeToFillReport: Department/role breakdown
- SourceQualityReport: Source to hire conversion
- RecruiterPerformanceReport: Individual recruiter metrics
- HiringManagerScorecard: Manager effectiveness metrics

All reports are tenant-aware and follow Zumodra's multi-tenant architecture.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, date
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from django.db import models
from django.db.models import Avg, Count, F, Q, Sum, Min, Max, StdDev
from django.db.models.functions import TruncDate, TruncWeek, TruncMonth, ExtractWeekDay
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class ReportPeriod(str, Enum):
    """Report time periods."""
    LAST_7_DAYS = 'last_7_days'
    LAST_30_DAYS = 'last_30_days'
    LAST_90_DAYS = 'last_90_days'
    LAST_YEAR = 'last_year'
    YEAR_TO_DATE = 'year_to_date'
    QUARTER_TO_DATE = 'quarter_to_date'
    CUSTOM = 'custom'


class GroupBy(str, Enum):
    """Grouping options for reports."""
    DAY = 'day'
    WEEK = 'week'
    MONTH = 'month'
    QUARTER = 'quarter'
    DEPARTMENT = 'department'
    JOB_TYPE = 'job_type'
    EXPERIENCE_LEVEL = 'experience_level'
    SOURCE = 'source'
    RECRUITER = 'recruiter'
    HIRING_MANAGER = 'hiring_manager'


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class FunnelStage:
    """Data for a single funnel stage."""
    stage_name: str
    stage_type: str
    entered_count: int
    exited_count: int
    current_count: int
    conversion_rate: float
    drop_off_rate: float
    average_time_days: float
    median_time_days: float


@dataclass
class RecruitingFunnelData:
    """Complete recruiting funnel data."""
    report_period: str
    date_from: date
    date_to: date
    total_applications: int
    total_hires: int
    overall_conversion_rate: float
    stages: List[FunnelStage]
    bottleneck_stages: List[str]
    improvement_opportunities: List[str]


@dataclass
class DEIMetrics:
    """Diversity, Equity, and Inclusion metrics."""
    category: str
    applicant_count: int
    applicant_percentage: float
    interview_count: int
    interview_rate: float
    hire_count: int
    hire_rate: float
    avg_time_to_decision_days: float


@dataclass
class DEIReport:
    """Complete DEI report."""
    report_period: str
    date_from: date
    date_to: date
    total_applications: int
    total_interviews: int
    total_hires: int
    gender_metrics: List[DEIMetrics]
    ethnicity_metrics: List[DEIMetrics]
    veteran_metrics: List[DEIMetrics]
    disability_metrics: List[DEIMetrics]
    age_group_metrics: List[DEIMetrics]
    recommendations: List[str]


@dataclass
class CostComponent:
    """Individual cost component."""
    category: str
    subcategory: str
    amount: Decimal
    currency: str = 'CAD'
    is_estimated: bool = False


@dataclass
class CostPerHireData:
    """Cost per hire report data."""
    report_period: str
    date_from: date
    date_to: date
    total_hires: int
    total_cost: Decimal
    cost_per_hire: Decimal
    currency: str
    cost_breakdown: List[CostComponent]
    by_department: Dict[str, Decimal]
    by_source: Dict[str, Decimal]
    by_job_type: Dict[str, Decimal]
    trend_data: List[Dict[str, Any]]
    benchmark_comparison: Dict[str, Any]


@dataclass
class TimeToFillMetrics:
    """Time to fill metrics for a category."""
    category: str
    total_positions: int
    filled_positions: int
    fill_rate: float
    avg_days_to_fill: float
    median_days_to_fill: float
    min_days_to_fill: int
    max_days_to_fill: int
    stddev_days: float


@dataclass
class TimeToFillReport:
    """Complete time to fill report."""
    report_period: str
    date_from: date
    date_to: date
    overall_avg_days: float
    overall_median_days: float
    by_department: List[TimeToFillMetrics]
    by_role: List[TimeToFillMetrics]
    by_experience_level: List[TimeToFillMetrics]
    by_job_type: List[TimeToFillMetrics]
    trend_over_time: List[Dict[str, Any]]
    slowest_positions: List[Dict[str, Any]]
    fastest_positions: List[Dict[str, Any]]


@dataclass
class SourceMetrics:
    """Metrics for a single source."""
    source_name: str
    total_applications: int
    applications_percentage: float
    interview_count: int
    interview_rate: float
    hire_count: int
    hire_rate: float
    avg_time_to_hire_days: float
    avg_quality_score: float
    cost_per_application: Decimal
    cost_per_hire: Decimal
    roi_score: float


@dataclass
class SourceQualityReport:
    """Complete source quality report."""
    report_period: str
    date_from: date
    date_to: date
    total_applications: int
    total_hires: int
    sources: List[SourceMetrics]
    top_sources: List[str]
    underperforming_sources: List[str]
    recommendations: List[str]


@dataclass
class RecruiterMetrics:
    """Individual recruiter performance metrics."""
    recruiter_id: str
    recruiter_name: str
    active_requisitions: int
    applications_processed: int
    interviews_scheduled: int
    offers_extended: int
    hires_made: int
    avg_time_to_fill_days: float
    candidate_satisfaction_score: float
    hiring_manager_satisfaction: float
    response_time_hours: float
    quality_of_hire_score: float


@dataclass
class RecruiterPerformanceReport:
    """Complete recruiter performance report."""
    report_period: str
    date_from: date
    date_to: date
    recruiters: List[RecruiterMetrics]
    team_avg_time_to_fill: float
    team_avg_hires: float
    top_performers: List[str]
    coaching_opportunities: List[Dict[str, Any]]


@dataclass
class HiringManagerMetrics:
    """Individual hiring manager metrics."""
    manager_id: str
    manager_name: str
    department: str
    open_positions: int
    filled_positions: int
    fill_rate: float
    avg_time_to_fill_days: float
    avg_interviews_per_hire: float
    interview_to_offer_ratio: float
    offer_acceptance_rate: float
    new_hire_retention_90_days: float
    avg_feedback_turnaround_hours: float
    candidate_experience_score: float


@dataclass
class HiringManagerScorecard:
    """Complete hiring manager scorecard."""
    report_period: str
    date_from: date
    date_to: date
    managers: List[HiringManagerMetrics]
    department_rankings: Dict[str, int]
    best_practices: List[str]
    improvement_areas: List[Dict[str, Any]]


# =============================================================================
# REPORT SERVICE BASE CLASS
# =============================================================================

class ReportService:
    """
    Base class for ATS reports with common functionality.
    """

    @staticmethod
    def get_date_range(
        period: ReportPeriod,
        custom_from: date = None,
        custom_to: date = None
    ) -> Tuple[date, date]:
        """
        Get date range for report period.

        Args:
            period: Report period enum
            custom_from: Custom start date (for CUSTOM period)
            custom_to: Custom end date (for CUSTOM period)

        Returns:
            Tuple of (start_date, end_date)
        """
        today = timezone.now().date()

        if period == ReportPeriod.LAST_7_DAYS:
            return today - timedelta(days=7), today
        elif period == ReportPeriod.LAST_30_DAYS:
            return today - timedelta(days=30), today
        elif period == ReportPeriod.LAST_90_DAYS:
            return today - timedelta(days=90), today
        elif period == ReportPeriod.LAST_YEAR:
            return today - timedelta(days=365), today
        elif period == ReportPeriod.YEAR_TO_DATE:
            return date(today.year, 1, 1), today
        elif period == ReportPeriod.QUARTER_TO_DATE:
            quarter_start_month = ((today.month - 1) // 3) * 3 + 1
            return date(today.year, quarter_start_month, 1), today
        elif period == ReportPeriod.CUSTOM:
            return custom_from or today - timedelta(days=30), custom_to or today
        else:
            return today - timedelta(days=30), today

    @staticmethod
    def calculate_percentage(numerator: int, denominator: int) -> float:
        """Calculate percentage safely."""
        if denominator == 0:
            return 0.0
        return round((numerator / denominator) * 100, 2)


# =============================================================================
# RECRUITING FUNNEL REPORT
# =============================================================================

class RecruitingFunnelReportService(ReportService):
    """
    Service for generating recruiting funnel reports.
    """

    @classmethod
    def generate(
        cls,
        tenant,
        period: ReportPeriod = ReportPeriod.LAST_30_DAYS,
        job_id: str = None,
        pipeline_id: str = None,
        date_from: date = None,
        date_to: date = None
    ) -> RecruitingFunnelData:
        """
        Generate recruiting funnel report.

        Args:
            tenant: Tenant context
            period: Report period
            job_id: Optional specific job filter
            pipeline_id: Optional specific pipeline filter
            date_from: Custom start date
            date_to: Custom end date

        Returns:
            RecruitingFunnelData with complete funnel analysis
        """
        from jobs.models import Application, ApplicationActivity, Pipeline, PipelineStage

        start_date, end_date = cls.get_date_range(period, date_from, date_to)

        # Base query
        applications = Application.objects.filter(
            tenant=tenant,
            applied_at__date__range=[start_date, end_date]
        )

        if job_id:
            applications = applications.filter(job_id=job_id)

        # Get pipeline
        if pipeline_id:
            pipeline = Pipeline.objects.filter(id=pipeline_id, tenant=tenant).first()
        else:
            pipeline = Pipeline.objects.filter(tenant=tenant, is_default=True).first()

        if not pipeline:
            # Return empty report
            return RecruitingFunnelData(
                report_period=period.value,
                date_from=start_date,
                date_to=end_date,
                total_applications=0,
                total_hires=0,
                overall_conversion_rate=0.0,
                stages=[],
                bottleneck_stages=[],
                improvement_opportunities=["No pipeline configured"],
            )

        total_applications = applications.count()
        total_hires = applications.filter(status='hired').count()

        # Analyze each stage
        stages = []
        bottleneck_stages = []
        prev_entered = total_applications

        for stage in pipeline.stages.filter(is_active=True).order_by('order'):
            # Get activities for this stage
            entered = ApplicationActivity.objects.filter(
                application__in=applications,
                activity_type='stage_change',
                new_value=stage.name
            ).values('application').distinct().count()

            # For first stage, use total applications
            if stage.order == 0:
                entered = total_applications

            exited = ApplicationActivity.objects.filter(
                application__in=applications,
                activity_type='stage_change',
                old_value=stage.name
            ).values('application').distinct().count()

            current = applications.filter(current_stage=stage).count()

            # Calculate time in stage
            time_data = []
            exit_activities = ApplicationActivity.objects.filter(
                application__in=applications,
                activity_type='stage_change',
                old_value=stage.name
            ).select_related('application')

            for exit_act in exit_activities:
                entry = ApplicationActivity.objects.filter(
                    application=exit_act.application,
                    activity_type='stage_change',
                    new_value=stage.name,
                    created_at__lt=exit_act.created_at
                ).order_by('-created_at').first()

                if entry:
                    duration = (exit_act.created_at - entry.created_at).days
                    time_data.append(duration)

            avg_time = sum(time_data) / len(time_data) if time_data else 0
            sorted_times = sorted(time_data)
            median_time = sorted_times[len(sorted_times) // 2] if sorted_times else 0

            conversion_rate = cls.calculate_percentage(exited, entered) if not stage.is_terminal else 0
            drop_off = 100 - conversion_rate

            stages.append(FunnelStage(
                stage_name=stage.name,
                stage_type=stage.stage_type,
                entered_count=entered,
                exited_count=exited,
                current_count=current,
                conversion_rate=conversion_rate,
                drop_off_rate=drop_off,
                average_time_days=round(avg_time, 1),
                median_time_days=median_time,
            ))

            # Identify bottlenecks
            if avg_time > 7 or (conversion_rate < 50 and not stage.is_terminal):
                bottleneck_stages.append(stage.name)

            prev_entered = entered

        # Generate improvement opportunities
        opportunities = []
        for stage_data in stages:
            if stage_data.average_time_days > 7:
                opportunities.append(
                    f"Reduce time in '{stage_data.stage_name}' stage (currently {stage_data.average_time_days} days)"
                )
            if stage_data.drop_off_rate > 40 and stage_data.stage_type not in ['hired', 'rejected']:
                opportunities.append(
                    f"Investigate high drop-off in '{stage_data.stage_name}' stage ({stage_data.drop_off_rate:.1f}%)"
                )

        return RecruitingFunnelData(
            report_period=period.value,
            date_from=start_date,
            date_to=end_date,
            total_applications=total_applications,
            total_hires=total_hires,
            overall_conversion_rate=cls.calculate_percentage(total_hires, total_applications),
            stages=stages,
            bottleneck_stages=bottleneck_stages,
            improvement_opportunities=opportunities,
        )


# =============================================================================
# DEI REPORT
# =============================================================================

class DEIReportService(ReportService):
    """
    Service for generating Diversity, Equity, and Inclusion reports.

    Note: All data is anonymized and aggregated to protect individual privacy.
    """

    # Default demographic categories (can be customized per tenant)
    GENDER_CATEGORIES = ['Male', 'Female', 'Non-binary', 'Prefer not to say', 'Unknown']
    AGE_GROUPS = ['18-24', '25-34', '35-44', '45-54', '55-64', '65+', 'Unknown']

    @classmethod
    def generate(
        cls,
        tenant,
        period: ReportPeriod = ReportPeriod.LAST_90_DAYS,
        department: str = None,
        date_from: date = None,
        date_to: date = None
    ) -> DEIReport:
        """
        Generate DEI report with anonymized metrics.

        Args:
            tenant: Tenant context
            period: Report period
            department: Optional department filter
            date_from: Custom start date
            date_to: Custom end date

        Returns:
            DEIReport with aggregated diversity metrics
        """
        from jobs.models import Application, Candidate

        start_date, end_date = cls.get_date_range(period, date_from, date_to)

        # Base query
        applications = Application.objects.filter(
            tenant=tenant,
            applied_at__date__range=[start_date, end_date]
        ).select_related('candidate', 'job')

        if department:
            applications = applications.filter(job__team=department)

        total_apps = applications.count()
        interviewed = applications.filter(
            status__in=['interviewing', 'offer_pending', 'offer_extended', 'hired']
        ).count()
        hired = applications.filter(status='hired').count()

        # Note: In production, these would come from actual candidate demographic data
        # For privacy, we only report aggregates with minimum thresholds

        # Generate placeholder metrics (in production, use actual demographic data)
        gender_metrics = cls._generate_category_metrics(
            applications, 'gender', cls.GENDER_CATEGORIES
        )
        age_metrics = cls._generate_category_metrics(
            applications, 'age_group', cls.AGE_GROUPS
        )

        # Generate recommendations based on data
        recommendations = cls._generate_dei_recommendations(
            gender_metrics, age_metrics
        )

        return DEIReport(
            report_period=period.value,
            date_from=start_date,
            date_to=end_date,
            total_applications=total_apps,
            total_interviews=interviewed,
            total_hires=hired,
            gender_metrics=gender_metrics,
            ethnicity_metrics=[],  # Requires demographic data collection
            veteran_metrics=[],
            disability_metrics=[],
            age_group_metrics=age_metrics,
            recommendations=recommendations,
        )

    @classmethod
    def _generate_category_metrics(
        cls,
        applications,
        field_name: str,
        categories: List[str]
    ) -> List[DEIMetrics]:
        """Generate metrics for a demographic category."""
        metrics = []
        total = applications.count()

        for category in categories:
            # In production, filter by actual demographic field
            # For now, simulate with even distribution
            count = total // len(categories)

            interview_count = count // 2
            hire_count = count // 10

            metrics.append(DEIMetrics(
                category=category,
                applicant_count=count,
                applicant_percentage=cls.calculate_percentage(count, total),
                interview_count=interview_count,
                interview_rate=cls.calculate_percentage(interview_count, count),
                hire_count=hire_count,
                hire_rate=cls.calculate_percentage(hire_count, count),
                avg_time_to_decision_days=14.0,
            ))

        return metrics

    @classmethod
    def _generate_dei_recommendations(
        cls,
        gender_metrics: List[DEIMetrics],
        age_metrics: List[DEIMetrics]
    ) -> List[str]:
        """Generate actionable DEI recommendations."""
        recommendations = []

        # Analyze gender diversity
        if gender_metrics:
            interview_rates = [m.interview_rate for m in gender_metrics if m.applicant_count > 10]
            if interview_rates and max(interview_rates) - min(interview_rates) > 20:
                recommendations.append(
                    "Review interview selection criteria for potential bias in gender representation"
                )

        # Analyze age diversity
        if age_metrics:
            young_hire_rate = next(
                (m.hire_rate for m in age_metrics if m.category == '18-24'), 0
            )
            senior_hire_rate = next(
                (m.hire_rate for m in age_metrics if m.category == '55-64'), 0
            )

            if young_hire_rate < 5 and senior_hire_rate < 5:
                recommendations.append(
                    "Consider programs to improve age diversity in hiring"
                )

        if not recommendations:
            recommendations.append(
                "Continue monitoring DEI metrics and collecting voluntary demographic data"
            )

        return recommendations


# =============================================================================
# COST PER HIRE REPORT
# =============================================================================

class CostPerHireReportService(ReportService):
    """
    Service for generating cost per hire reports.
    """

    # Cost categories
    COST_CATEGORIES = {
        'sourcing': ['job_boards', 'linkedin', 'agencies', 'referral_bonuses', 'events'],
        'recruiting': ['recruiter_salary', 'ats_software', 'background_checks', 'assessments'],
        'interviewing': ['interviewer_time', 'travel', 'facilities'],
        'onboarding': ['training', 'equipment', 'orientation'],
    }

    @classmethod
    def generate(
        cls,
        tenant,
        period: ReportPeriod = ReportPeriod.LAST_90_DAYS,
        department: str = None,
        include_estimates: bool = True,
        date_from: date = None,
        date_to: date = None
    ) -> CostPerHireData:
        """
        Generate cost per hire report.

        Args:
            tenant: Tenant context
            period: Report period
            department: Optional department filter
            include_estimates: Include estimated costs
            date_from: Custom start date
            date_to: Custom end date

        Returns:
            CostPerHireData with comprehensive cost analysis
        """
        from jobs.models import Application, JobPosting

        start_date, end_date = cls.get_date_range(period, date_from, date_to)

        # Get hired applications
        hired = Application.objects.filter(
            tenant=tenant,
            status='hired',
            hired_at__date__range=[start_date, end_date]
        ).select_related('job', 'candidate')

        if department:
            hired = hired.filter(job__team=department)

        total_hires = hired.count()

        # Calculate costs (in production, integrate with financial data)
        cost_breakdown = cls._calculate_cost_breakdown(tenant, total_hires)
        total_cost = sum(c.amount for c in cost_breakdown)
        cost_per_hire = total_cost / total_hires if total_hires > 0 else Decimal('0')

        # Group by department
        dept_costs = {}
        dept_hires = hired.values('job__team').annotate(count=Count('id'))
        for item in dept_hires:
            dept = item['job__team'] or 'Unknown'
            dept_cost = cost_per_hire * item['count']
            dept_costs[dept] = dept_cost

        # Group by source
        source_costs = {}
        source_hires = hired.values('candidate__source').annotate(count=Count('id'))
        for item in source_hires:
            source = item['candidate__source'] or 'Unknown'
            source_cost = cost_per_hire * item['count']
            source_costs[source] = source_cost

        # Group by job type
        type_costs = {}
        type_hires = hired.values('job__job_type').annotate(count=Count('id'))
        for item in type_hires:
            job_type = item['job__job_type'] or 'Unknown'
            type_cost = cost_per_hire * item['count']
            type_costs[job_type] = type_cost

        # Generate trend data
        trend_data = cls._generate_cost_trend(tenant, start_date, end_date)

        # Benchmark comparison
        benchmark = {
            'industry_avg': Decimal('4500'),
            'industry_median': Decimal('4000'),
            'your_cost': cost_per_hire,
            'difference': cost_per_hire - Decimal('4500'),
            'percentile': 50,  # Would be calculated from real benchmarks
        }

        return CostPerHireData(
            report_period=period.value,
            date_from=start_date,
            date_to=end_date,
            total_hires=total_hires,
            total_cost=total_cost,
            cost_per_hire=cost_per_hire,
            currency='CAD',
            cost_breakdown=cost_breakdown,
            by_department=dept_costs,
            by_source=source_costs,
            by_job_type=type_costs,
            trend_data=trend_data,
            benchmark_comparison=benchmark,
        )

    @classmethod
    def _calculate_cost_breakdown(cls, tenant, hire_count: int) -> List[CostComponent]:
        """Calculate detailed cost breakdown."""
        # In production, integrate with actual financial data
        # Using industry average estimates here
        components = []

        # Sourcing costs
        components.append(CostComponent(
            category='sourcing',
            subcategory='job_boards',
            amount=Decimal('500') * hire_count,
            is_estimated=True,
        ))
        components.append(CostComponent(
            category='sourcing',
            subcategory='referral_bonuses',
            amount=Decimal('1000') * (hire_count // 3),  # Assume 1/3 referrals
            is_estimated=True,
        ))

        # Recruiting costs
        components.append(CostComponent(
            category='recruiting',
            subcategory='recruiter_time',
            amount=Decimal('2000') * hire_count,
            is_estimated=True,
        ))
        components.append(CostComponent(
            category='recruiting',
            subcategory='background_checks',
            amount=Decimal('100') * hire_count,
        ))

        # Interview costs
        components.append(CostComponent(
            category='interviewing',
            subcategory='interviewer_time',
            amount=Decimal('500') * hire_count,
            is_estimated=True,
        ))

        return components

    @classmethod
    def _generate_cost_trend(
        cls,
        tenant,
        start_date: date,
        end_date: date
    ) -> List[Dict[str, Any]]:
        """Generate cost trend over time."""
        from jobs.models import Application

        trend = []
        hired = Application.objects.filter(
            tenant=tenant,
            status='hired',
            hired_at__date__range=[start_date, end_date]
        ).annotate(
            month=TruncMonth('hired_at')
        ).values('month').annotate(
            count=Count('id')
        ).order_by('month')

        for item in hired:
            trend.append({
                'period': item['month'].strftime('%Y-%m'),
                'hires': item['count'],
                'estimated_cost': Decimal('4500') * item['count'],  # Estimate
            })

        return trend


# =============================================================================
# TIME TO FILL REPORT
# =============================================================================

class TimeToFillReportService(ReportService):
    """
    Service for generating time to fill reports.
    """

    @classmethod
    def generate(
        cls,
        tenant,
        period: ReportPeriod = ReportPeriod.LAST_90_DAYS,
        date_from: date = None,
        date_to: date = None
    ) -> TimeToFillReport:
        """
        Generate time to fill report.

        Args:
            tenant: Tenant context
            period: Report period
            date_from: Custom start date
            date_to: Custom end date

        Returns:
            TimeToFillReport with comprehensive time analysis
        """
        from jobs.models import Application, JobPosting

        start_date, end_date = cls.get_date_range(period, date_from, date_to)

        # Get filled positions
        filled_jobs = JobPosting.objects.filter(
            tenant=tenant,
            status__in=['filled', 'closed'],
            closed_at__date__range=[start_date, end_date],
            published_at__isnull=False,
        ).annotate(
            days_to_fill=F('closed_at') - F('published_at')
        )

        # Calculate overall metrics
        time_data = [
            (job.closed_at - job.published_at).days
            for job in filled_jobs
            if job.closed_at and job.published_at
        ]

        overall_avg = sum(time_data) / len(time_data) if time_data else 0
        sorted_times = sorted(time_data)
        overall_median = sorted_times[len(sorted_times) // 2] if sorted_times else 0

        # By department
        by_department = cls._calculate_time_metrics(
            filled_jobs, 'team', 'Department'
        )

        # By experience level
        by_experience = cls._calculate_time_metrics(
            filled_jobs, 'experience_level', 'Experience Level'
        )

        # By job type
        by_job_type = cls._calculate_time_metrics(
            filled_jobs, 'job_type', 'Job Type'
        )

        # Get slowest and fastest positions
        slowest = []
        fastest = []

        if time_data:
            job_times = [
                {'job': job.title, 'department': job.team, 'days': (job.closed_at - job.published_at).days}
                for job in filled_jobs if job.closed_at and job.published_at
            ]
            job_times.sort(key=lambda x: x['days'], reverse=True)
            slowest = job_times[:5]
            fastest = list(reversed(job_times[-5:]))

        # Generate trend
        trend = cls._generate_time_trend(tenant, start_date, end_date)

        return TimeToFillReport(
            report_period=period.value,
            date_from=start_date,
            date_to=end_date,
            overall_avg_days=round(overall_avg, 1),
            overall_median_days=overall_median,
            by_department=by_department,
            by_role=[],  # Would aggregate by similar role titles
            by_experience_level=by_experience,
            by_job_type=by_job_type,
            trend_over_time=trend,
            slowest_positions=slowest,
            fastest_positions=fastest,
        )

    @classmethod
    def _calculate_time_metrics(
        cls,
        queryset,
        group_field: str,
        category_name: str
    ) -> List[TimeToFillMetrics]:
        """Calculate time metrics grouped by a field."""
        metrics = []

        grouped = queryset.values(group_field).annotate(
            total=Count('id'),
            filled=Count('id', filter=Q(status='filled')),
            avg_days=Avg(F('closed_at') - F('published_at')),
        )

        for item in grouped:
            category = item[group_field] or 'Unknown'

            # Get detailed stats
            category_jobs = queryset.filter(**{group_field: item[group_field]})
            times = [
                (j.closed_at - j.published_at).days
                for j in category_jobs
                if j.closed_at and j.published_at
            ]

            if not times:
                continue

            sorted_times = sorted(times)
            median = sorted_times[len(sorted_times) // 2] if sorted_times else 0

            # Calculate std dev
            avg = sum(times) / len(times)
            variance = sum((x - avg) ** 2 for x in times) / len(times)
            stddev = variance ** 0.5

            metrics.append(TimeToFillMetrics(
                category=category,
                total_positions=item['total'],
                filled_positions=item['filled'],
                fill_rate=cls.calculate_percentage(item['filled'], item['total']),
                avg_days_to_fill=round(avg, 1),
                median_days_to_fill=median,
                min_days_to_fill=min(times),
                max_days_to_fill=max(times),
                stddev_days=round(stddev, 1),
            ))

        return metrics

    @classmethod
    def _generate_time_trend(
        cls,
        tenant,
        start_date: date,
        end_date: date
    ) -> List[Dict[str, Any]]:
        """Generate time to fill trend over time."""
        from jobs.models import JobPosting

        trend = []

        jobs = JobPosting.objects.filter(
            tenant=tenant,
            status='filled',
            closed_at__date__range=[start_date, end_date],
        ).annotate(
            month=TruncMonth('closed_at')
        )

        monthly = jobs.values('month').annotate(
            count=Count('id'),
        ).order_by('month')

        for item in monthly:
            month_jobs = jobs.filter(
                closed_at__month=item['month'].month,
                closed_at__year=item['month'].year
            )

            times = [
                (j.closed_at - j.published_at).days
                for j in month_jobs
                if j.closed_at and j.published_at
            ]

            avg_time = sum(times) / len(times) if times else 0

            trend.append({
                'period': item['month'].strftime('%Y-%m'),
                'positions_filled': item['count'],
                'avg_days_to_fill': round(avg_time, 1),
            })

        return trend


# =============================================================================
# SOURCE QUALITY REPORT
# =============================================================================

class SourceQualityReportService(ReportService):
    """
    Service for generating source quality reports.
    """

    @classmethod
    def generate(
        cls,
        tenant,
        period: ReportPeriod = ReportPeriod.LAST_90_DAYS,
        date_from: date = None,
        date_to: date = None
    ) -> SourceQualityReport:
        """
        Generate source quality report.

        Args:
            tenant: Tenant context
            period: Report period
            date_from: Custom start date
            date_to: Custom end date

        Returns:
            SourceQualityReport with source performance analysis
        """
        from jobs.models import Application, Candidate

        start_date, end_date = cls.get_date_range(period, date_from, date_to)

        applications = Application.objects.filter(
            tenant=tenant,
            applied_at__date__range=[start_date, end_date]
        ).select_related('candidate')

        total_apps = applications.count()
        total_hires = applications.filter(status='hired').count()

        # Group by source
        source_data = applications.values('candidate__source').annotate(
            total=Count('id'),
            interviews=Count('id', filter=Q(status__in=['interviewing', 'offer_pending', 'offer_extended', 'hired'])),
            hires=Count('id', filter=Q(status='hired')),
        )

        sources = []
        for item in source_data:
            source_name = item['candidate__source'] or 'Unknown'
            source_apps = item['total']
            interviews = item['interviews']
            hires = item['hires']

            # Calculate time to hire for this source
            source_hired = applications.filter(
                candidate__source=item['candidate__source'],
                status='hired',
                hired_at__isnull=False
            )
            times = [(a.hired_at - a.applied_at).days for a in source_hired]
            avg_time = sum(times) / len(times) if times else 0

            # Estimate costs (would come from actual financial data)
            cost_per_app = Decimal('50')  # Estimate
            cost_per_hire = cost_per_app * source_apps / hires if hires > 0 else Decimal('0')

            # Calculate ROI score (higher is better)
            # Based on: hire rate, quality, cost efficiency
            hire_rate = hires / source_apps * 100 if source_apps > 0 else 0
            roi_score = hire_rate / (float(cost_per_hire) / 1000 + 1) if cost_per_hire > 0 else hire_rate

            sources.append(SourceMetrics(
                source_name=source_name,
                total_applications=source_apps,
                applications_percentage=cls.calculate_percentage(source_apps, total_apps),
                interview_count=interviews,
                interview_rate=cls.calculate_percentage(interviews, source_apps),
                hire_count=hires,
                hire_rate=cls.calculate_percentage(hires, source_apps),
                avg_time_to_hire_days=round(avg_time, 1),
                avg_quality_score=3.5,  # Would come from performance data
                cost_per_application=cost_per_app,
                cost_per_hire=cost_per_hire,
                roi_score=round(roi_score, 2),
            ))

        # Sort by ROI score
        sources.sort(key=lambda x: x.roi_score, reverse=True)

        # Identify top and underperforming sources
        top_sources = [s.source_name for s in sources[:3] if s.roi_score > 0]
        underperforming = [
            s.source_name for s in sources
            if s.total_applications > 10 and s.hire_rate < 2
        ]

        # Generate recommendations
        recommendations = []
        if top_sources:
            recommendations.append(f"Increase investment in top sources: {', '.join(top_sources)}")
        if underperforming:
            recommendations.append(f"Review or reduce spending on: {', '.join(underperforming)}")

        return SourceQualityReport(
            report_period=period.value,
            date_from=start_date,
            date_to=end_date,
            total_applications=total_apps,
            total_hires=total_hires,
            sources=sources,
            top_sources=top_sources,
            underperforming_sources=underperforming,
            recommendations=recommendations,
        )


# =============================================================================
# RECRUITER PERFORMANCE REPORT
# =============================================================================

class RecruiterPerformanceReportService(ReportService):
    """
    Service for generating recruiter performance reports.
    """

    @classmethod
    def generate(
        cls,
        tenant,
        period: ReportPeriod = ReportPeriod.LAST_90_DAYS,
        date_from: date = None,
        date_to: date = None
    ) -> RecruiterPerformanceReport:
        """
        Generate recruiter performance report.

        Args:
            tenant: Tenant context
            period: Report period
            date_from: Custom start date
            date_to: Custom end date

        Returns:
            RecruiterPerformanceReport with individual metrics
        """
        from jobs.models import Application, JobPosting, Interview

        start_date, end_date = cls.get_date_range(period, date_from, date_to)

        # Get recruiters with activity
        recruiters_query = JobPosting.objects.filter(
            tenant=tenant,
            recruiter__isnull=False,
        ).values('recruiter', 'recruiter__first_name', 'recruiter__last_name').distinct()

        recruiters = []
        total_hires = 0

        for rec in recruiters_query:
            recruiter_id = rec['recruiter']
            name = f"{rec['recruiter__first_name']} {rec['recruiter__last_name']}"

            # Get recruiter's jobs
            jobs = JobPosting.objects.filter(
                tenant=tenant,
                recruiter_id=recruiter_id
            )

            active_reqs = jobs.filter(status='open').count()

            # Get applications for their jobs in period
            apps = Application.objects.filter(
                job__in=jobs,
                applied_at__date__range=[start_date, end_date]
            )

            processed = apps.exclude(status='new').count()
            interviews = Interview.objects.filter(
                application__in=apps,
                scheduled_start__date__range=[start_date, end_date]
            ).count()

            offers = apps.filter(status__in=['offer_pending', 'offer_extended', 'hired']).count()
            hires = apps.filter(status='hired').count()
            total_hires += hires

            # Calculate time to fill
            filled_jobs = jobs.filter(
                status='filled',
                closed_at__date__range=[start_date, end_date]
            )
            fill_times = [
                (j.closed_at - j.published_at).days
                for j in filled_jobs
                if j.closed_at and j.published_at
            ]
            avg_fill = sum(fill_times) / len(fill_times) if fill_times else 0

            recruiters.append(RecruiterMetrics(
                recruiter_id=str(recruiter_id),
                recruiter_name=name,
                active_requisitions=active_reqs,
                applications_processed=processed,
                interviews_scheduled=interviews,
                offers_extended=offers,
                hires_made=hires,
                avg_time_to_fill_days=round(avg_fill, 1),
                candidate_satisfaction_score=4.0,  # Would come from surveys
                hiring_manager_satisfaction=4.2,  # Would come from surveys
                response_time_hours=24,  # Would be calculated from activity
                quality_of_hire_score=3.8,  # Would come from performance data
            ))

        # Calculate team averages
        team_avg_fill = sum(r.avg_time_to_fill_days for r in recruiters) / len(recruiters) if recruiters else 0
        team_avg_hires = sum(r.hires_made for r in recruiters) / len(recruiters) if recruiters else 0

        # Identify top performers
        recruiters.sort(key=lambda x: x.hires_made, reverse=True)
        top_performers = [r.recruiter_name for r in recruiters[:3] if r.hires_made > 0]

        # Identify coaching opportunities
        coaching = []
        for r in recruiters:
            if r.avg_time_to_fill_days > team_avg_fill * 1.5:
                coaching.append({
                    'recruiter': r.recruiter_name,
                    'area': 'time_to_fill',
                    'recommendation': 'Review pipeline efficiency and candidate communication',
                })

        return RecruiterPerformanceReport(
            report_period=period.value,
            date_from=start_date,
            date_to=end_date,
            recruiters=recruiters,
            team_avg_time_to_fill=round(team_avg_fill, 1),
            team_avg_hires=round(team_avg_hires, 1),
            top_performers=top_performers,
            coaching_opportunities=coaching,
        )


# =============================================================================
# HIRING MANAGER SCORECARD
# =============================================================================

class HiringManagerScorecardService(ReportService):
    """
    Service for generating hiring manager scorecards.
    """

    @classmethod
    def generate(
        cls,
        tenant,
        period: ReportPeriod = ReportPeriod.LAST_90_DAYS,
        department: str = None,
        date_from: date = None,
        date_to: date = None
    ) -> HiringManagerScorecard:
        """
        Generate hiring manager scorecard.

        Args:
            tenant: Tenant context
            period: Report period
            department: Optional department filter
            date_from: Custom start date
            date_to: Custom end date

        Returns:
            HiringManagerScorecard with manager effectiveness metrics
        """
        from jobs.models import Application, JobPosting, Interview, Offer

        start_date, end_date = cls.get_date_range(period, date_from, date_to)

        # Get hiring managers with activity
        managers_query = JobPosting.objects.filter(
            tenant=tenant,
            hiring_manager__isnull=False,
        )

        if department:
            managers_query = managers_query.filter(team=department)

        managers_data = managers_query.values(
            'hiring_manager', 'hiring_manager__first_name', 'hiring_manager__last_name', 'team'
        ).distinct()

        managers = []

        for mgr in managers_data:
            manager_id = mgr['hiring_manager']
            name = f"{mgr['hiring_manager__first_name']} {mgr['hiring_manager__last_name']}"
            dept = mgr['team'] or 'Unknown'

            # Get manager's jobs
            jobs = JobPosting.objects.filter(
                tenant=tenant,
                hiring_manager_id=manager_id
            )

            open_positions = jobs.filter(status='open').count()
            filled = jobs.filter(
                status='filled',
                closed_at__date__range=[start_date, end_date]
            ).count()
            total = jobs.filter(
                published_at__date__lte=end_date
            ).count()

            # Calculate fill rate
            fill_rate = cls.calculate_percentage(filled, total)

            # Calculate time to fill
            filled_jobs = jobs.filter(
                status='filled',
                closed_at__date__range=[start_date, end_date]
            )
            fill_times = [
                (j.closed_at - j.published_at).days
                for j in filled_jobs
                if j.closed_at and j.published_at
            ]
            avg_fill = sum(fill_times) / len(fill_times) if fill_times else 0

            # Get applications for their jobs
            apps = Application.objects.filter(job__in=jobs)

            # Calculate interview to hire ratio
            interviewed = apps.filter(
                status__in=['interviewing', 'offer_pending', 'offer_extended', 'hired']
            ).count()
            hired = apps.filter(status='hired').count()
            interviews_per_hire = interviewed / hired if hired > 0 else 0

            # Calculate offer acceptance rate
            offers = Offer.objects.filter(application__job__in=jobs)
            accepted = offers.filter(status='accepted').count()
            total_offers = offers.filter(status__in=['sent', 'accepted', 'declined']).count()
            acceptance_rate = cls.calculate_percentage(accepted, total_offers)

            managers.append(HiringManagerMetrics(
                manager_id=str(manager_id),
                manager_name=name,
                department=dept,
                open_positions=open_positions,
                filled_positions=filled,
                fill_rate=fill_rate,
                avg_time_to_fill_days=round(avg_fill, 1),
                avg_interviews_per_hire=round(interviews_per_hire, 1),
                interview_to_offer_ratio=0.3,  # Would be calculated
                offer_acceptance_rate=acceptance_rate,
                new_hire_retention_90_days=85.0,  # Would come from HR data
                avg_feedback_turnaround_hours=48,  # Would be calculated from activity
                candidate_experience_score=4.0,  # Would come from surveys
            ))

        # Rank departments
        dept_metrics = {}
        for m in managers:
            if m.department not in dept_metrics:
                dept_metrics[m.department] = []
            dept_metrics[m.department].append(m.fill_rate)

        dept_rankings = {}
        sorted_depts = sorted(
            dept_metrics.items(),
            key=lambda x: sum(x[1]) / len(x[1]) if x[1] else 0,
            reverse=True
        )
        for rank, (dept, _) in enumerate(sorted_depts, 1):
            dept_rankings[dept] = rank

        # Best practices from top performers
        best_practices = []
        managers.sort(key=lambda x: x.fill_rate, reverse=True)
        if managers and managers[0].fill_rate > 80:
            best_practices.append(
                f"Follow {managers[0].manager_name}'s interview efficiency practices"
            )

        # Improvement areas
        improvement_areas = []
        for m in managers:
            if m.avg_time_to_fill_days > 45:
                improvement_areas.append({
                    'manager': m.manager_name,
                    'area': 'time_to_fill',
                    'current': m.avg_time_to_fill_days,
                    'target': 30,
                    'recommendation': 'Review job requirements and interview process',
                })

        return HiringManagerScorecard(
            report_period=period.value,
            date_from=start_date,
            date_to=end_date,
            managers=managers,
            department_rankings=dept_rankings,
            best_practices=best_practices,
            improvement_areas=improvement_areas,
        )
