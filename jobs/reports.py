"""
ATS Reports - HR Reporting and Analytics

This module implements comprehensive HR reporting:
- PipelineReport: Funnel metrics and conversion analysis
- TimeToHireReport: Time-based hiring metrics
- SourceEffectivenessReport: Recruitment source ROI analysis
- DiversityReport: Anonymized diversity analytics

Reports follow HR best practices:
- Data-driven decision making
- Privacy-preserving analytics
- Benchmark comparisons
- Actionable insights
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
from enum import Enum
from collections import defaultdict
from decimal import Decimal
import statistics
import logging

from django.utils import timezone
from django.db.models import Count, Avg, F, Q, Sum, Min, Max, When, Case, Value
from django.db.models.functions import TruncDate, TruncWeek, TruncMonth, ExtractWeekDay

logger = logging.getLogger(__name__)


# ==================== REPORT ENUMS AND DATA CLASSES ====================

class ReportPeriod(Enum):
    """Time period for reports."""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"
    CUSTOM = "custom"


class ExportFormat(Enum):
    """Export format options."""
    JSON = "json"
    CSV = "csv"
    EXCEL = "excel"
    PDF = "pdf"


@dataclass
class ReportMetric:
    """Individual metric in a report."""
    name: str
    value: Any
    previous_value: Optional[Any] = None
    change_percent: Optional[float] = None
    trend: str = "stable"  # up, down, stable
    benchmark: Optional[Any] = None
    unit: str = ""
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'value': self.value,
            'previous_value': self.previous_value,
            'change_percent': self.change_percent,
            'trend': self.trend,
            'benchmark': self.benchmark,
            'unit': self.unit,
            'description': self.description
        }


@dataclass
class ReportSection:
    """Section of a report with related metrics."""
    title: str
    metrics: List[ReportMetric]
    charts: List[Dict[str, Any]] = field(default_factory=list)
    tables: List[Dict[str, Any]] = field(default_factory=list)
    insights: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'title': self.title,
            'metrics': [m.to_dict() for m in self.metrics],
            'charts': self.charts,
            'tables': self.tables,
            'insights': self.insights
        }


@dataclass
class ReportResult:
    """Complete report result."""
    report_type: str
    title: str
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    sections: List[ReportSection]
    summary: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'report_type': self.report_type,
            'title': self.title,
            'generated_at': self.generated_at.isoformat(),
            'period_start': self.period_start.isoformat(),
            'period_end': self.period_end.isoformat(),
            'sections': [s.to_dict() for s in self.sections],
            'summary': self.summary,
            'metadata': self.metadata
        }


# ==================== BASE REPORT CLASS ====================

class BaseReport(ABC):
    """
    Abstract base class for all reports.

    Each report provides:
    - Data collection and aggregation
    - Metric calculation
    - Trend analysis
    - Insight generation
    """

    def __init__(
        self,
        period: ReportPeriod = ReportPeriod.MONTHLY,
        start_date: datetime = None,
        end_date: datetime = None,
        filters: Dict[str, Any] = None
    ):
        self.period = period
        self.end_date = end_date or timezone.now()
        self.start_date = start_date or self._calculate_start_date()
        self.filters = filters or {}

        # For comparison period
        duration = self.end_date - self.start_date
        self.previous_start = self.start_date - duration
        self.previous_end = self.start_date

    def _calculate_start_date(self) -> datetime:
        """Calculate start date based on period."""
        now = self.end_date
        if self.period == ReportPeriod.DAILY:
            return now - timedelta(days=1)
        elif self.period == ReportPeriod.WEEKLY:
            return now - timedelta(weeks=1)
        elif self.period == ReportPeriod.MONTHLY:
            return now - timedelta(days=30)
        elif self.period == ReportPeriod.QUARTERLY:
            return now - timedelta(days=90)
        elif self.period == ReportPeriod.YEARLY:
            return now - timedelta(days=365)
        return now - timedelta(days=30)

    @abstractmethod
    def generate(self) -> ReportResult:
        """Generate the report."""
        pass

    def _calculate_change(
        self,
        current: float,
        previous: float
    ) -> Tuple[float, str]:
        """Calculate percentage change and trend."""
        if previous == 0:
            if current > 0:
                return 100.0, "up"
            return 0.0, "stable"

        change = ((current - previous) / previous) * 100
        if change > 5:
            trend = "up"
        elif change < -5:
            trend = "down"
        else:
            trend = "stable"

        return round(change, 2), trend

    def _get_queryset_for_period(
        self,
        queryset,
        date_field: str,
        current: bool = True
    ):
        """Filter queryset for current or previous period."""
        if current:
            start = self.start_date
            end = self.end_date
        else:
            start = self.previous_start
            end = self.previous_end

        return queryset.filter(**{
            f'{date_field}__gte': start,
            f'{date_field}__lt': end
        })


# ==================== PIPELINE REPORT ====================

class PipelineReport(BaseReport):
    """
    Recruitment funnel metrics and conversion analysis.

    Metrics included:
    - Applications per stage
    - Stage conversion rates
    - Drop-off analysis
    - Bottleneck identification
    - Pipeline velocity
    """

    def __init__(
        self,
        job_id: int = None,
        pipeline_id: int = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.job_id = job_id
        self.pipeline_id = pipeline_id

    def generate(self) -> ReportResult:
        """Generate pipeline report."""
        from .models import Application, Pipeline, PipelineStage, JobPosting

        # Build base queryset
        applications = Application.objects.all()

        if self.job_id:
            applications = applications.filter(job_id=self.job_id)
        if self.pipeline_id:
            applications = applications.filter(job__pipeline_id=self.pipeline_id)

        # Apply date filter
        current_apps = self._get_queryset_for_period(applications, 'applied_at')
        previous_apps = self._get_queryset_for_period(applications, 'applied_at', current=False)

        sections = []

        # Section 1: Funnel Overview
        funnel_section = self._generate_funnel_section(current_apps, previous_apps)
        sections.append(funnel_section)

        # Section 2: Stage Analysis
        stage_section = self._generate_stage_section(current_apps)
        sections.append(stage_section)

        # Section 3: Conversion Rates
        conversion_section = self._generate_conversion_section(current_apps, previous_apps)
        sections.append(conversion_section)

        # Section 4: Bottleneck Analysis
        bottleneck_section = self._generate_bottleneck_section(current_apps)
        sections.append(bottleneck_section)

        # Generate summary
        summary = self._generate_summary(sections)

        return ReportResult(
            report_type="pipeline",
            title="Recruitment Pipeline Report",
            generated_at=timezone.now(),
            period_start=self.start_date,
            period_end=self.end_date,
            sections=sections,
            summary=summary,
            metadata={
                'job_id': self.job_id,
                'pipeline_id': self.pipeline_id,
                'total_applications': current_apps.count()
            }
        )

    def _generate_funnel_section(self, current_apps, previous_apps) -> ReportSection:
        """Generate funnel overview section."""
        metrics = []

        # Total applications
        current_total = current_apps.count()
        previous_total = previous_apps.count()
        change, trend = self._calculate_change(current_total, previous_total)

        metrics.append(ReportMetric(
            name="Total Applications",
            value=current_total,
            previous_value=previous_total,
            change_percent=change,
            trend=trend,
            description="Total applications received"
        ))

        # Applications by status
        status_counts = current_apps.values('status').annotate(
            count=Count('id')
        ).order_by('-count')

        status_data = {item['status']: item['count'] for item in status_counts}

        metrics.append(ReportMetric(
            name="New Applications",
            value=status_data.get('new', 0),
            description="Applications pending review"
        ))

        metrics.append(ReportMetric(
            name="In Progress",
            value=sum(
                status_data.get(s, 0)
                for s in ['in_review', 'shortlisted', 'interviewing', 'offer_pending']
            ),
            description="Active applications in pipeline"
        ))

        metrics.append(ReportMetric(
            name="Hired",
            value=status_data.get('hired', 0),
            description="Successfully hired candidates"
        ))

        # Funnel chart data
        funnel_chart = {
            'type': 'funnel',
            'data': [
                {'stage': 'Applied', 'count': current_total},
                {'stage': 'Screening', 'count': status_data.get('in_review', 0) + sum(
                    status_data.get(s, 0) for s in ['shortlisted', 'interviewing', 'offer_pending', 'offer_extended', 'hired']
                )},
                {'stage': 'Interview', 'count': status_data.get('interviewing', 0) + sum(
                    status_data.get(s, 0) for s in ['offer_pending', 'offer_extended', 'hired']
                )},
                {'stage': 'Offer', 'count': status_data.get('offer_extended', 0) + status_data.get('hired', 0)},
                {'stage': 'Hired', 'count': status_data.get('hired', 0)}
            ]
        }

        return ReportSection(
            title="Funnel Overview",
            metrics=metrics,
            charts=[funnel_chart],
            insights=self._generate_funnel_insights(status_data, current_total)
        )

    def _generate_stage_section(self, current_apps) -> ReportSection:
        """Generate stage analysis section."""
        metrics = []

        # Applications per stage
        stage_counts = current_apps.filter(
            current_stage__isnull=False
        ).values(
            'current_stage__name',
            'current_stage__stage_type'
        ).annotate(
            count=Count('id'),
            avg_rating=Avg('overall_rating')
        ).order_by('current_stage__order')

        stage_table = {
            'columns': ['Stage', 'Count', 'Avg Rating', '% of Total'],
            'rows': []
        }

        total = current_apps.count() or 1
        for stage in stage_counts:
            stage_table['rows'].append([
                stage['current_stage__name'],
                stage['count'],
                round(stage['avg_rating'] or 0, 2),
                f"{round(stage['count'] / total * 100, 1)}%"
            ])

        # Stage distribution chart
        stage_chart = {
            'type': 'bar',
            'title': 'Applications by Stage',
            'data': [
                {'stage': s['current_stage__name'], 'count': s['count']}
                for s in stage_counts
            ]
        }

        return ReportSection(
            title="Stage Analysis",
            metrics=metrics,
            charts=[stage_chart],
            tables=[stage_table]
        )

    def _generate_conversion_section(self, current_apps, previous_apps) -> ReportSection:
        """Generate conversion rates section."""
        metrics = []

        total = current_apps.count() or 1
        previous_total = previous_apps.count() or 1

        # Screen-to-interview rate
        interviewed = current_apps.filter(
            status__in=['interviewing', 'offer_pending', 'offer_extended', 'hired']
        ).count()
        prev_interviewed = previous_apps.filter(
            status__in=['interviewing', 'offer_pending', 'offer_extended', 'hired']
        ).count()

        current_rate = (interviewed / total) * 100
        previous_rate = (prev_interviewed / previous_total) * 100
        change, trend = self._calculate_change(current_rate, previous_rate)

        metrics.append(ReportMetric(
            name="Screen-to-Interview Rate",
            value=round(current_rate, 1),
            previous_value=round(previous_rate, 1),
            change_percent=change,
            trend=trend,
            unit="%",
            benchmark=25,  # Industry benchmark
            description="Percentage of applicants who reach interview stage"
        ))

        # Interview-to-offer rate
        offered = current_apps.filter(
            status__in=['offer_extended', 'hired']
        ).count()
        offer_rate = (offered / max(interviewed, 1)) * 100

        metrics.append(ReportMetric(
            name="Interview-to-Offer Rate",
            value=round(offer_rate, 1),
            unit="%",
            benchmark=30,
            description="Percentage of interviewed candidates receiving offers"
        ))

        # Offer acceptance rate
        hired = current_apps.filter(status='hired').count()
        acceptance_rate = (hired / max(offered, 1)) * 100

        metrics.append(ReportMetric(
            name="Offer Acceptance Rate",
            value=round(acceptance_rate, 1),
            unit="%",
            benchmark=85,
            description="Percentage of offers accepted"
        ))

        # Overall conversion rate
        overall_rate = (hired / total) * 100

        metrics.append(ReportMetric(
            name="Overall Conversion Rate",
            value=round(overall_rate, 1),
            unit="%",
            benchmark=3,
            description="Percentage of applicants hired"
        ))

        return ReportSection(
            title="Conversion Rates",
            metrics=metrics,
            insights=self._generate_conversion_insights(metrics)
        )

    def _generate_bottleneck_section(self, current_apps) -> ReportSection:
        """Generate bottleneck analysis section."""
        metrics = []
        insights = []

        # Find stages with longest average time
        from django.db.models import DurationField, ExpressionWrapper

        # This is a simplified version - in production, track time per stage
        stale_apps = current_apps.filter(
            last_stage_change_at__isnull=False,
            status__in=['new', 'in_review', 'screening']
        ).annotate(
            days_in_stage=ExpressionWrapper(
                timezone.now() - F('last_stage_change_at'),
                output_field=DurationField()
            )
        )

        # Count applications stale for >7 days
        stale_count = sum(
            1 for app in stale_apps
            if app.days_in_stage and app.days_in_stage.days > 7
        )

        metrics.append(ReportMetric(
            name="Stale Applications",
            value=stale_count,
            description="Applications in same stage for >7 days"
        ))

        if stale_count > 0:
            insights.append(
                f"{stale_count} applications need attention - stuck in current stage"
            )

        # Rejection rate by stage
        rejected = current_apps.filter(status='rejected')
        rejection_stages = rejected.values('rejection_reason').annotate(
            count=Count('id')
        ).order_by('-count')[:5]

        rejection_table = {
            'title': 'Top Rejection Reasons',
            'columns': ['Reason', 'Count'],
            'rows': [[r['rejection_reason'] or 'Not specified', r['count']] for r in rejection_stages]
        }

        return ReportSection(
            title="Bottleneck Analysis",
            metrics=metrics,
            tables=[rejection_table],
            insights=insights
        )

    def _generate_funnel_insights(self, status_data: Dict, total: int) -> List[str]:
        """Generate insights from funnel data."""
        insights = []

        if total == 0:
            return ["No applications in this period"]

        # Check rejection rate
        rejected = status_data.get('rejected', 0)
        rejection_rate = (rejected / total) * 100
        if rejection_rate > 70:
            insights.append(
                f"High rejection rate ({rejection_rate:.1f}%) - review job requirements or sourcing"
            )

        # Check hired rate
        hired = status_data.get('hired', 0)
        hire_rate = (hired / total) * 100
        if hire_rate < 1 and total > 50:
            insights.append(
                "Low hire rate - consider improving candidate quality or screening process"
            )

        return insights

    def _generate_conversion_insights(self, metrics: List[ReportMetric]) -> List[str]:
        """Generate insights from conversion metrics."""
        insights = []

        for metric in metrics:
            if metric.benchmark and metric.value < metric.benchmark * 0.7:
                insights.append(
                    f"{metric.name} ({metric.value}%) is below industry benchmark ({metric.benchmark}%)"
                )

        return insights

    def _generate_summary(self, sections: List[ReportSection]) -> str:
        """Generate report summary."""
        # Find key metrics
        total_apps = 0
        hire_rate = 0

        for section in sections:
            for metric in section.metrics:
                if metric.name == "Total Applications":
                    total_apps = metric.value
                elif metric.name == "Overall Conversion Rate":
                    hire_rate = metric.value

        return (
            f"Pipeline processed {total_apps} applications with {hire_rate:.1f}% "
            f"conversion to hire during this period."
        )


# ==================== TIME TO HIRE REPORT ====================

class TimeToHireReport(BaseReport):
    """
    Time-based hiring metrics and analysis.

    Metrics included:
    - Average time to hire
    - Time per stage
    - Time to fill by role
    - Hiring velocity trends
    """

    def __init__(
        self,
        job_id: int = None,
        department: str = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.job_id = job_id
        self.department = department

    def generate(self) -> ReportResult:
        """Generate time to hire report."""
        from .models import Application, JobPosting

        # Get hired applications
        hired_apps = Application.objects.filter(
            status='hired',
            hired_at__isnull=False
        )

        if self.job_id:
            hired_apps = hired_apps.filter(job_id=self.job_id)

        current_hired = self._get_queryset_for_period(hired_apps, 'hired_at')
        previous_hired = self._get_queryset_for_period(hired_apps, 'hired_at', current=False)

        sections = []

        # Section 1: Time to Hire Overview
        overview_section = self._generate_overview_section(current_hired, previous_hired)
        sections.append(overview_section)

        # Section 2: Time by Stage
        stage_section = self._generate_stage_time_section(current_hired)
        sections.append(stage_section)

        # Section 3: Time by Role
        role_section = self._generate_role_time_section(current_hired)
        sections.append(role_section)

        # Section 4: Trends
        trend_section = self._generate_trend_section(hired_apps)
        sections.append(trend_section)

        summary = self._generate_summary(sections)

        return ReportResult(
            report_type="time_to_hire",
            title="Time to Hire Report",
            generated_at=timezone.now(),
            period_start=self.start_date,
            period_end=self.end_date,
            sections=sections,
            summary=summary,
            metadata={
                'job_id': self.job_id,
                'department': self.department,
                'hires_analyzed': current_hired.count()
            }
        )

    def _generate_overview_section(self, current_hired, previous_hired) -> ReportSection:
        """Generate time to hire overview."""
        metrics = []

        # Calculate average time to hire
        current_times = []
        for app in current_hired:
            if app.hired_at and app.applied_at:
                days = (app.hired_at - app.applied_at).days
                current_times.append(days)

        previous_times = []
        for app in previous_hired:
            if app.hired_at and app.applied_at:
                days = (app.hired_at - app.applied_at).days
                previous_times.append(days)

        current_avg = statistics.mean(current_times) if current_times else 0
        previous_avg = statistics.mean(previous_times) if previous_times else 0
        change, trend = self._calculate_change(previous_avg, current_avg)  # Reversed - lower is better

        metrics.append(ReportMetric(
            name="Average Time to Hire",
            value=round(current_avg, 1),
            previous_value=round(previous_avg, 1),
            change_percent=-change,  # Negative because lower is better
            trend="up" if change < 0 else "down" if change > 0 else "stable",
            unit="days",
            benchmark=36,  # Industry average
            description="Average days from application to hire"
        ))

        # Median time to hire
        if current_times:
            median = statistics.median(current_times)
            metrics.append(ReportMetric(
                name="Median Time to Hire",
                value=round(median, 1),
                unit="days",
                description="Median days from application to hire"
            ))

        # Fastest and slowest hires
        if current_times:
            metrics.append(ReportMetric(
                name="Fastest Hire",
                value=min(current_times),
                unit="days"
            ))
            metrics.append(ReportMetric(
                name="Slowest Hire",
                value=max(current_times),
                unit="days"
            ))

        # Distribution chart
        if current_times:
            buckets = {'1-14': 0, '15-30': 0, '31-45': 0, '46-60': 0, '60+': 0}
            for days in current_times:
                if days <= 14:
                    buckets['1-14'] += 1
                elif days <= 30:
                    buckets['15-30'] += 1
                elif days <= 45:
                    buckets['31-45'] += 1
                elif days <= 60:
                    buckets['46-60'] += 1
                else:
                    buckets['60+'] += 1

            distribution_chart = {
                'type': 'bar',
                'title': 'Time to Hire Distribution',
                'data': [{'range': k, 'count': v} for k, v in buckets.items()]
            }
        else:
            distribution_chart = {'type': 'bar', 'title': 'No data', 'data': []}

        return ReportSection(
            title="Time to Hire Overview",
            metrics=metrics,
            charts=[distribution_chart],
            insights=self._generate_time_insights(current_avg, current_times)
        )

    def _generate_stage_time_section(self, hired_apps) -> ReportSection:
        """Generate time by stage analysis."""
        # In a full implementation, this would track time spent in each stage
        # For now, provide simplified analysis

        metrics = []

        # Estimate time in key phases
        # This is simplified - production would use stage change history

        return ReportSection(
            title="Time by Stage",
            metrics=metrics,
            insights=["Detailed stage timing requires activity log analysis"]
        )

    def _generate_role_time_section(self, hired_apps) -> ReportSection:
        """Generate time by role analysis."""
        metrics = []

        # Group by job title/category
        time_by_job = {}

        for app in hired_apps.select_related('job'):
            if app.hired_at and app.applied_at:
                days = (app.hired_at - app.applied_at).days
                job_title = app.job.title
                if job_title not in time_by_job:
                    time_by_job[job_title] = []
                time_by_job[job_title].append(days)

        # Calculate averages
        role_data = []
        for title, times in time_by_job.items():
            role_data.append({
                'role': title,
                'avg_days': round(statistics.mean(times), 1),
                'hires': len(times)
            })

        role_data.sort(key=lambda x: x['avg_days'], reverse=True)

        role_table = {
            'title': 'Time to Hire by Role',
            'columns': ['Role', 'Avg Days', 'Hires'],
            'rows': [[r['role'], r['avg_days'], r['hires']] for r in role_data[:10]]
        }

        return ReportSection(
            title="Time by Role",
            metrics=metrics,
            tables=[role_table]
        )

    def _generate_trend_section(self, hired_apps) -> ReportSection:
        """Generate time to hire trends."""
        # Monthly trend for the past 6 months
        six_months_ago = timezone.now() - timedelta(days=180)
        recent_hires = hired_apps.filter(hired_at__gte=six_months_ago)

        monthly_data = recent_hires.annotate(
            month=TruncMonth('hired_at')
        ).values('month').annotate(
            count=Count('id')
        ).order_by('month')

        trend_chart = {
            'type': 'line',
            'title': 'Hiring Trend (6 months)',
            'data': [
                {
                    'month': item['month'].strftime('%Y-%m') if item['month'] else '',
                    'hires': item['count']
                }
                for item in monthly_data
            ]
        }

        return ReportSection(
            title="Hiring Trends",
            metrics=[],
            charts=[trend_chart]
        )

    def _generate_time_insights(self, avg: float, times: List[int]) -> List[str]:
        """Generate time to hire insights."""
        insights = []

        if avg > 45:
            insights.append(
                f"Time to hire ({avg:.0f} days) exceeds industry benchmark. "
                "Consider streamlining interview process."
            )
        elif avg < 20:
            insights.append(
                f"Excellent time to hire ({avg:.0f} days). "
                "Process is efficient."
            )

        if times and max(times) > avg * 2:
            insights.append(
                "Some positions take significantly longer. "
                "Review outliers for process improvements."
            )

        return insights

    def _generate_summary(self, sections: List[ReportSection]) -> str:
        """Generate report summary."""
        avg_time = 0
        for section in sections:
            for metric in section.metrics:
                if metric.name == "Average Time to Hire":
                    avg_time = metric.value
                    break

        return f"Average time to hire is {avg_time:.0f} days for this period."


# ==================== SOURCE EFFECTIVENESS REPORT ====================

class SourceEffectivenessReport(BaseReport):
    """
    Recruitment source ROI and effectiveness analysis.

    Metrics included:
    - Applications by source
    - Conversion rates by source
    - Quality metrics by source
    - Cost per hire by source
    """

    def __init__(
        self,
        job_id: int = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.job_id = job_id

    def generate(self) -> ReportResult:
        """Generate source effectiveness report."""
        from .models import Application, Candidate

        applications = Application.objects.select_related('candidate')

        if self.job_id:
            applications = applications.filter(job_id=self.job_id)

        current_apps = self._get_queryset_for_period(applications, 'applied_at')

        sections = []

        # Section 1: Source Overview
        overview_section = self._generate_overview_section(current_apps)
        sections.append(overview_section)

        # Section 2: Quality by Source
        quality_section = self._generate_quality_section(current_apps)
        sections.append(quality_section)

        # Section 3: Conversion by Source
        conversion_section = self._generate_conversion_section(current_apps)
        sections.append(conversion_section)

        # Section 4: Source ROI (if cost data available)
        roi_section = self._generate_roi_section(current_apps)
        sections.append(roi_section)

        summary = self._generate_summary(sections)

        return ReportResult(
            report_type="source_effectiveness",
            title="Source Effectiveness Report",
            generated_at=timezone.now(),
            period_start=self.start_date,
            period_end=self.end_date,
            sections=sections,
            summary=summary,
            metadata={
                'job_id': self.job_id,
                'applications_analyzed': current_apps.count()
            }
        )

    def _generate_overview_section(self, current_apps) -> ReportSection:
        """Generate source overview section."""
        metrics = []

        # Applications by source
        source_counts = current_apps.values(
            'candidate__source'
        ).annotate(
            count=Count('id')
        ).order_by('-count')

        total = current_apps.count()

        source_chart = {
            'type': 'pie',
            'title': 'Applications by Source',
            'data': [
                {
                    'source': s['candidate__source'] or 'Unknown',
                    'count': s['count'],
                    'percentage': round(s['count'] / total * 100, 1) if total else 0
                }
                for s in source_counts
            ]
        }

        # Top source
        if source_counts:
            top_source = source_counts[0]
            metrics.append(ReportMetric(
                name="Top Source",
                value=top_source['candidate__source'] or 'Unknown',
                description=f"{top_source['count']} applications ({round(top_source['count']/total*100, 1)}%)"
            ))

        source_table = {
            'title': 'Applications by Source',
            'columns': ['Source', 'Applications', '% of Total'],
            'rows': [
                [
                    s['candidate__source'] or 'Unknown',
                    s['count'],
                    f"{round(s['count']/total*100, 1)}%"
                ]
                for s in source_counts
            ]
        }

        return ReportSection(
            title="Source Overview",
            metrics=metrics,
            charts=[source_chart],
            tables=[source_table]
        )

    def _generate_quality_section(self, current_apps) -> ReportSection:
        """Generate quality by source section."""
        metrics = []

        # Average score by source
        source_quality = current_apps.filter(
            ai_match_score__isnull=False
        ).values(
            'candidate__source'
        ).annotate(
            avg_score=Avg('ai_match_score'),
            count=Count('id')
        ).order_by('-avg_score')

        quality_table = {
            'title': 'Quality by Source',
            'columns': ['Source', 'Avg Score', 'Applications'],
            'rows': [
                [
                    s['candidate__source'] or 'Unknown',
                    round(s['avg_score'], 1),
                    s['count']
                ]
                for s in source_quality
            ]
        }

        if source_quality:
            best_quality = source_quality[0]
            metrics.append(ReportMetric(
                name="Highest Quality Source",
                value=best_quality['candidate__source'] or 'Unknown',
                description=f"Average score: {round(best_quality['avg_score'], 1)}"
            ))

        return ReportSection(
            title="Quality by Source",
            metrics=metrics,
            tables=[quality_table]
        )

    def _generate_conversion_section(self, current_apps) -> ReportSection:
        """Generate conversion by source section."""
        # Calculate conversion rates by source
        source_data = {}

        for source_item in current_apps.values('candidate__source').distinct():
            source = source_item['candidate__source']
            source_apps = current_apps.filter(candidate__source=source)

            total = source_apps.count()
            interviewed = source_apps.filter(
                status__in=['interviewing', 'offer_pending', 'offer_extended', 'hired']
            ).count()
            hired = source_apps.filter(status='hired').count()

            source_data[source or 'Unknown'] = {
                'total': total,
                'interviewed': interviewed,
                'hired': hired,
                'interview_rate': round(interviewed / total * 100, 1) if total else 0,
                'hire_rate': round(hired / total * 100, 1) if total else 0
            }

        conversion_table = {
            'title': 'Conversion by Source',
            'columns': ['Source', 'Applications', 'Interviewed', 'Interview %', 'Hired', 'Hire %'],
            'rows': [
                [
                    source,
                    data['total'],
                    data['interviewed'],
                    f"{data['interview_rate']}%",
                    data['hired'],
                    f"{data['hire_rate']}%"
                ]
                for source, data in sorted(
                    source_data.items(),
                    key=lambda x: x[1]['hire_rate'],
                    reverse=True
                )
            ]
        }

        insights = []
        # Find most effective source for hiring
        if source_data:
            best_hire_source = max(
                source_data.items(),
                key=lambda x: x[1]['hire_rate']
            )
            if best_hire_source[1]['hire_rate'] > 0:
                insights.append(
                    f"{best_hire_source[0]} has highest conversion to hire "
                    f"({best_hire_source[1]['hire_rate']}%)"
                )

        return ReportSection(
            title="Conversion by Source",
            metrics=[],
            tables=[conversion_table],
            insights=insights
        )

    def _generate_roi_section(self, current_apps) -> ReportSection:
        """Generate source ROI section."""
        # This would require cost data integration
        # Placeholder for now
        return ReportSection(
            title="Source ROI",
            metrics=[],
            insights=["Cost data not available for ROI calculation"]
        )

    def _generate_summary(self, sections: List[ReportSection]) -> str:
        """Generate report summary."""
        return "Source effectiveness analysis shows variation in quality and conversion across channels."


# ==================== DIVERSITY REPORT ====================

class DiversityReport(BaseReport):
    """
    Anonymized diversity analytics for hiring.

    Provides:
    - Pipeline diversity metrics
    - Stage progression equity analysis
    - Anonymized demographic insights
    - Bias detection signals

    Note: All data is aggregated and anonymized for privacy.
    """

    def __init__(
        self,
        job_id: int = None,
        minimum_sample_size: int = 5,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.job_id = job_id
        self.minimum_sample_size = minimum_sample_size

    def generate(self) -> ReportResult:
        """Generate diversity report."""
        from .models import Application

        applications = Application.objects.all()

        if self.job_id:
            applications = applications.filter(job_id=self.job_id)

        current_apps = self._get_queryset_for_period(applications, 'applied_at')

        sections = []

        # Section 1: Pipeline Overview
        pipeline_section = self._generate_pipeline_section(current_apps)
        sections.append(pipeline_section)

        # Section 2: Geographic Diversity
        geo_section = self._generate_geographic_section(current_apps)
        sections.append(geo_section)

        # Section 3: Experience Diversity
        experience_section = self._generate_experience_section(current_apps)
        sections.append(experience_section)

        # Section 4: Source Diversity
        source_section = self._generate_source_diversity_section(current_apps)
        sections.append(source_section)

        summary = self._generate_summary(sections)

        return ReportResult(
            report_type="diversity",
            title="Diversity Analytics Report (Anonymized)",
            generated_at=timezone.now(),
            period_start=self.start_date,
            period_end=self.end_date,
            sections=sections,
            summary=summary,
            metadata={
                'job_id': self.job_id,
                'applications_analyzed': current_apps.count(),
                'minimum_sample_size': self.minimum_sample_size,
                'privacy_note': 'All metrics are aggregated to protect individual privacy'
            }
        )

    def _generate_pipeline_section(self, current_apps) -> ReportSection:
        """Generate pipeline diversity overview."""
        metrics = []

        total = current_apps.count()
        if total < self.minimum_sample_size:
            return ReportSection(
                title="Pipeline Overview",
                metrics=[],
                insights=["Insufficient data for diversity analysis"]
            )

        # Calculate diversity of applications vs hires
        # This is anonymized - just looking at distribution patterns

        status_distribution = current_apps.values('status').annotate(
            count=Count('id')
        )

        metrics.append(ReportMetric(
            name="Total Candidates Analyzed",
            value=total,
            description="Anonymized candidate pool"
        ))

        return ReportSection(
            title="Pipeline Overview",
            metrics=metrics,
            insights=[
                "Diversity metrics are calculated on aggregated, anonymized data",
                "Individual candidates cannot be identified from these reports"
            ]
        )

    def _generate_geographic_section(self, current_apps) -> ReportSection:
        """Generate geographic diversity metrics."""
        # Group by country (anonymized)
        geo_data = current_apps.values(
            'candidate__country'
        ).annotate(
            count=Count('id')
        ).filter(
            count__gte=self.minimum_sample_size
        ).order_by('-count')

        total = current_apps.count()

        geo_chart = {
            'type': 'bar',
            'title': 'Geographic Distribution',
            'data': [
                {
                    'region': g['candidate__country'] or 'Not Specified',
                    'count': g['count'],
                    'percentage': round(g['count'] / total * 100, 1) if total else 0
                }
                for g in geo_data
            ]
        }

        # Count unique countries
        unique_countries = geo_data.count()

        metrics = [
            ReportMetric(
                name="Geographic Regions Represented",
                value=unique_countries,
                description="Number of distinct regions in candidate pool"
            )
        ]

        return ReportSection(
            title="Geographic Diversity",
            metrics=metrics,
            charts=[geo_chart]
        )

    def _generate_experience_section(self, current_apps) -> ReportSection:
        """Generate experience level diversity."""
        # Group by years of experience (bucketed)
        apps_with_exp = current_apps.filter(
            candidate__years_experience__isnull=False
        ).select_related('candidate')

        experience_buckets = {
            '0-2 years': 0,
            '3-5 years': 0,
            '6-10 years': 0,
            '10+ years': 0
        }

        for app in apps_with_exp:
            years = app.candidate.years_experience or 0
            if years <= 2:
                experience_buckets['0-2 years'] += 1
            elif years <= 5:
                experience_buckets['3-5 years'] += 1
            elif years <= 10:
                experience_buckets['6-10 years'] += 1
            else:
                experience_buckets['10+ years'] += 1

        total = sum(experience_buckets.values())

        exp_chart = {
            'type': 'pie',
            'title': 'Experience Distribution',
            'data': [
                {
                    'range': k,
                    'count': v,
                    'percentage': round(v / total * 100, 1) if total else 0
                }
                for k, v in experience_buckets.items()
            ]
        }

        return ReportSection(
            title="Experience Diversity",
            metrics=[],
            charts=[exp_chart]
        )

    def _generate_source_diversity_section(self, current_apps) -> ReportSection:
        """Generate source diversity analysis."""
        # Analyze if different sources bring different candidate profiles
        source_data = current_apps.values(
            'candidate__source'
        ).annotate(
            count=Count('id'),
            avg_score=Avg('ai_match_score')
        ).filter(
            count__gte=self.minimum_sample_size
        ).order_by('-count')

        # Check for source concentration
        total = current_apps.count()
        insights = []

        if source_data:
            top_source = source_data[0]
            top_percentage = (top_source['count'] / total * 100) if total else 0

            if top_percentage > 60:
                insights.append(
                    f"Source concentration: {top_percentage:.0f}% from single source. "
                    "Consider diversifying recruitment channels."
                )
            else:
                insights.append(
                    "Healthy distribution across multiple recruitment sources."
                )

        return ReportSection(
            title="Source Diversity",
            metrics=[],
            insights=insights
        )

    def _generate_summary(self, sections: List[ReportSection]) -> str:
        """Generate report summary."""
        return (
            "Diversity metrics calculated from anonymized, aggregated data. "
            "All reports protect individual candidate privacy."
        )


# ==================== REPORT SERVICE ====================

class ReportService:
    """
    Service for generating and managing HR reports.

    Provides:
    - Report generation
    - Report caching
    - Export functionality
    - Scheduled report delivery
    """

    REPORT_TYPES = {
        'pipeline': PipelineReport,
        'time_to_hire': TimeToHireReport,
        'source_effectiveness': SourceEffectivenessReport,
        'diversity': DiversityReport
    }

    def __init__(self):
        self.cache: Dict[str, ReportResult] = {}

    def generate_report(
        self,
        report_type: str,
        period: ReportPeriod = ReportPeriod.MONTHLY,
        start_date: datetime = None,
        end_date: datetime = None,
        filters: Dict[str, Any] = None,
        use_cache: bool = True
    ) -> ReportResult:
        """
        Generate a report of the specified type.

        Args:
            report_type: Type of report (pipeline, time_to_hire, etc.)
            period: Report period
            start_date: Custom start date
            end_date: Custom end date
            filters: Additional filters (job_id, etc.)
            use_cache: Whether to use cached results

        Returns:
            ReportResult with complete report data
        """
        report_class = self.REPORT_TYPES.get(report_type)
        if not report_class:
            raise ValueError(f"Unknown report type: {report_type}")

        # Generate cache key
        cache_key = f"{report_type}:{period.value}:{start_date}:{end_date}:{filters}"

        if use_cache and cache_key in self.cache:
            cached = self.cache[cache_key]
            # Check if cache is fresh (within 1 hour)
            age = timezone.now() - cached.generated_at
            if age.total_seconds() < 3600:
                return cached

        # Generate fresh report
        report = report_class(
            period=period,
            start_date=start_date,
            end_date=end_date,
            filters=filters,
            **(filters or {})
        )

        result = report.generate()
        self.cache[cache_key] = result

        return result

    def export_report(
        self,
        report: ReportResult,
        format: ExportFormat = ExportFormat.JSON
    ) -> Any:
        """Export report to specified format."""
        if format == ExportFormat.JSON:
            return report.to_dict()

        elif format == ExportFormat.CSV:
            # Simplified CSV export
            lines = [f"Report: {report.title}"]
            lines.append(f"Period: {report.period_start} to {report.period_end}")
            lines.append("")

            for section in report.sections:
                lines.append(section.title)
                for metric in section.metrics:
                    lines.append(f"{metric.name},{metric.value},{metric.unit}")
                lines.append("")

            return "\n".join(lines)

        else:
            raise ValueError(f"Unsupported export format: {format}")

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get summary metrics for dashboard display."""
        from .models import Application, JobPosting, Interview, Offer

        now = timezone.now()
        thirty_days_ago = now - timedelta(days=30)

        return {
            'open_jobs': JobPosting.objects.filter(status='open').count(),
            'applications_this_month': Application.objects.filter(
                applied_at__gte=thirty_days_ago
            ).count(),
            'interviews_scheduled': Interview.objects.filter(
                status__in=['scheduled', 'confirmed'],
                scheduled_start__gte=now
            ).count(),
            'pending_offers': Offer.objects.filter(
                status__in=['sent', 'pending_approval']
            ).count(),
            'hires_this_month': Application.objects.filter(
                status='hired',
                hired_at__gte=thirty_days_ago
            ).count()
        }


# Create singleton service instance
report_service = ReportService()
