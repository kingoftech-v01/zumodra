"""
ATS Aggregations - Efficient database aggregations for analytics and reporting.

This module provides optimized aggregation functions for:
- Pipeline stage distribution (Kanban metrics)
- Time-to-hire calculations by department
- Source effectiveness tracking
- Interview and offer analytics
- Recruiting funnel analysis

All aggregations use Django ORM aggregation functions for database-level
computation, minimizing data transfer and Python processing.
"""

from datetime import timedelta
from decimal import Decimal
from typing import Dict, List, Optional, Any

from django.db.models import (
    Count, Avg, Sum, Min, Max, F, Q, Value,
    ExpressionWrapper, DurationField, DecimalField, IntegerField,
    Case, When, Subquery, OuterRef, FloatField
)
from django.db.models.functions import (
    Coalesce, TruncDate, TruncWeek, TruncMonth,
    ExtractDay, ExtractHour, Cast, Now
)
from django.utils import timezone


class PipelineStageAggregation:
    """
    Aggregations for pipeline stage distribution and metrics.

    Provides counts per stage, conversion rates between stages,
    and average time in each stage.
    """

    @staticmethod
    def count_per_stage(application_queryset, job=None):
        """
        Get application count per pipeline stage.

        Args:
            application_queryset: Base Application queryset
            job: Optional JobPosting to filter by

        Returns:
            QuerySet: Stages with application counts
        """
        qs = application_queryset
        if job:
            qs = qs.filter(job=job)

        return qs.exclude(
            current_stage__isnull=True
        ).values(
            stage_id=F('current_stage__id'),
            stage_name=F('current_stage__name'),
            stage_type=F('current_stage__stage_type'),
            stage_color=F('current_stage__color'),
            stage_order=F('current_stage__order'),
        ).annotate(
            count=Count('id'),
            avg_rating=Avg('overall_rating'),
        ).order_by('stage_order')

    @staticmethod
    def count_by_status(application_queryset, job=None):
        """
        Get application count by status.

        Args:
            application_queryset: Base Application queryset
            job: Optional JobPosting to filter by

        Returns:
            QuerySet: Statuses with counts
        """
        qs = application_queryset
        if job:
            qs = qs.filter(job=job)

        return qs.values('status').annotate(
            count=Count('id')
        ).order_by('-count')

    @staticmethod
    def stage_conversion_rates(application_queryset, pipeline):
        """
        Calculate conversion rates between pipeline stages.

        Shows what percentage of applications move from one stage to next.

        Args:
            application_queryset: Base Application queryset
            pipeline: Pipeline instance to analyze

        Returns:
            list: Stage conversion metrics
        """
        from ats.models import PipelineStage

        stages = PipelineStage.objects.filter(
            pipeline=pipeline,
            is_active=True
        ).order_by('order')

        results = []
        prev_count = None

        for stage in stages:
            count = application_queryset.filter(
                current_stage=stage
            ).count()

            # Also count applications that passed through this stage
            passed_through = application_queryset.filter(
                activities__activity_type='stage_change',
                activities__new_value=stage.name
            ).distinct().count()

            conversion_rate = None
            if prev_count and prev_count > 0:
                conversion_rate = round((count / prev_count) * 100, 1)

            results.append({
                'stage_id': stage.id,
                'stage_name': stage.name,
                'stage_type': stage.stage_type,
                'current_count': count,
                'passed_through': passed_through,
                'conversion_rate': conversion_rate,
            })

            prev_count = passed_through or count

        return results

    @staticmethod
    def avg_time_in_stage(application_queryset):
        """
        Calculate average time applications spend in each stage.

        Returns:
            QuerySet: Stages with average duration
        """
        # Applications with stage duration calculated
        return application_queryset.exclude(
            current_stage__isnull=True
        ).annotate(
            stage_duration=ExpressionWrapper(
                Now() - Coalesce(F('last_stage_change_at'), F('applied_at')),
                output_field=DurationField()
            )
        ).values(
            'current_stage__name',
            'current_stage__stage_type'
        ).annotate(
            avg_duration=Avg('stage_duration'),
            min_duration=Min('stage_duration'),
            max_duration=Max('stage_duration'),
            count=Count('id'),
        )

    @staticmethod
    def stage_bottlenecks(application_queryset, threshold_days=14):
        """
        Identify stages where applications get stuck.

        Args:
            application_queryset: Base queryset
            threshold_days: Days to consider as bottleneck

        Returns:
            QuerySet: Stages with stale application counts
        """
        cutoff = timezone.now() - timedelta(days=threshold_days)

        return application_queryset.filter(
            Q(last_stage_change_at__lt=cutoff) |
            Q(last_stage_change_at__isnull=True, applied_at__lt=cutoff)
        ).exclude(
            status__in=['rejected', 'withdrawn', 'hired']
        ).values(
            'current_stage__name',
            'current_stage__stage_type'
        ).annotate(
            stale_count=Count('id')
        ).filter(
            stale_count__gt=0
        ).order_by('-stale_count')


class TimeToHireAggregation:
    """
    Aggregations for time-to-hire metrics.

    Calculates how long it takes to hire candidates,
    broken down by department, job, source, etc.
    """

    @staticmethod
    def average_by_department(application_queryset):
        """
        Calculate average time-to-hire by department/category.

        Args:
            application_queryset: Base Application queryset

        Returns:
            QuerySet: Departments with avg time to hire
        """
        return application_queryset.filter(
            status='hired',
            hired_at__isnull=False
        ).annotate(
            time_to_hire=ExpressionWrapper(
                F('hired_at') - F('applied_at'),
                output_field=DurationField()
            )
        ).values(
            department=F('job__category__name'),
            department_id=F('job__category__id'),
        ).annotate(
            avg_days=Avg(
                ExtractDay(F('time_to_hire'))
            ),
            min_days=Min(
                ExtractDay(F('time_to_hire'))
            ),
            max_days=Max(
                ExtractDay(F('time_to_hire'))
            ),
            hired_count=Count('id'),
        ).order_by('avg_days')

    @staticmethod
    def average_by_job(application_queryset):
        """
        Calculate average time-to-hire by job posting.

        Returns:
            QuerySet: Jobs with time-to-hire metrics
        """
        return application_queryset.filter(
            status='hired',
            hired_at__isnull=False
        ).annotate(
            time_to_hire=ExpressionWrapper(
                F('hired_at') - F('applied_at'),
                output_field=DurationField()
            )
        ).values(
            job_id=F('job__id'),
            job_title=F('job__title'),
            job_ref=F('job__reference_code'),
        ).annotate(
            avg_days=Avg(ExtractDay(F('time_to_hire'))),
            hired_count=Count('id'),
        ).order_by('avg_days')

    @staticmethod
    def average_by_source(application_queryset):
        """
        Calculate average time-to-hire by candidate source.

        Returns:
            QuerySet: Sources with time-to-hire metrics
        """
        return application_queryset.filter(
            status='hired',
            hired_at__isnull=False
        ).annotate(
            time_to_hire=ExpressionWrapper(
                F('hired_at') - F('applied_at'),
                output_field=DurationField()
            )
        ).values(
            source=F('candidate__source'),
        ).annotate(
            avg_days=Avg(ExtractDay(F('time_to_hire'))),
            hired_count=Count('id'),
        ).order_by('avg_days')

    @staticmethod
    def trend_over_time(application_queryset, period='month'):
        """
        Calculate time-to-hire trend over time.

        Args:
            application_queryset: Base queryset
            period: 'week', 'month', or 'date'

        Returns:
            QuerySet: Time periods with avg time-to-hire
        """
        trunc_func = {
            'date': TruncDate,
            'week': TruncWeek,
            'month': TruncMonth,
        }.get(period, TruncMonth)

        return application_queryset.filter(
            status='hired',
            hired_at__isnull=False
        ).annotate(
            time_to_hire=ExpressionWrapper(
                F('hired_at') - F('applied_at'),
                output_field=DurationField()
            ),
            period=trunc_func('hired_at')
        ).values('period').annotate(
            avg_days=Avg(ExtractDay(F('time_to_hire'))),
            hired_count=Count('id'),
        ).order_by('period')

    @staticmethod
    def time_per_stage(application_queryset):
        """
        Calculate average time spent in each stage before hire.

        Uses activity log to track stage transitions.

        Returns:
            dict: Stage -> average days mapping
        """
        from ats.models import ApplicationActivity

        # Get hired applications
        hired_apps = application_queryset.filter(status='hired')

        # Analyze stage change activities
        activities = ApplicationActivity.objects.filter(
            application__in=hired_apps,
            activity_type='stage_change'
        ).values(
            'new_value'  # stage name
        ).annotate(
            avg_duration=Avg(
                # Time until next activity or hire
                ExtractDay(F('application__hired_at') - F('created_at'))
            )
        )

        return {a['new_value']: a['avg_duration'] for a in activities}


class SourceEffectivenessAggregation:
    """
    Aggregations for candidate source effectiveness.

    Tracks which sources produce the best candidates
    (highest hire rates, ratings, fastest hires).
    """

    @staticmethod
    def overall_effectiveness(application_queryset):
        """
        Calculate overall source effectiveness metrics.

        Returns:
            QuerySet: Sources with effectiveness metrics
        """
        return application_queryset.values(
            source=F('candidate__source'),
        ).annotate(
            total_applications=Count('id'),
            hired=Count('id', filter=Q(status='hired')),
            rejected=Count('id', filter=Q(status='rejected')),
            in_progress=Count('id', filter=~Q(
                status__in=['hired', 'rejected', 'withdrawn']
            )),
            avg_rating=Avg('overall_rating'),
            avg_match_score=Avg('ai_match_score'),
        ).annotate(
            hire_rate=Case(
                When(total_applications=0, then=Value(0.0)),
                default=Cast(F('hired'), FloatField()) * 100.0 / Cast(F('total_applications'), FloatField()),
                output_field=FloatField(),
            )
        ).order_by('-hire_rate')

    @staticmethod
    def source_funnel(application_queryset, source):
        """
        Get full funnel metrics for a specific source.

        Args:
            source: Source value to analyze

        Returns:
            dict: Funnel stage counts
        """
        qs = application_queryset.filter(candidate__source=source)

        total = qs.count()
        stages = qs.values('status').annotate(
            count=Count('id')
        )

        funnel = {
            'total': total,
            'new': 0,
            'in_review': 0,
            'interviewing': 0,
            'offer': 0,
            'hired': 0,
            'rejected': 0,
        }

        for stage in stages:
            if stage['status'] in funnel:
                funnel[stage['status']] = stage['count']
            elif stage['status'] in ['offer_pending', 'offer_extended']:
                funnel['offer'] += stage['count']

        # Calculate conversion rates
        if total > 0:
            funnel['review_rate'] = round(
                (funnel['in_review'] + funnel['interviewing'] + funnel['offer'] + funnel['hired']) / total * 100, 1
            )
            funnel['interview_rate'] = round(
                (funnel['interviewing'] + funnel['offer'] + funnel['hired']) / total * 100, 1
            )
            funnel['offer_rate'] = round(
                (funnel['offer'] + funnel['hired']) / total * 100, 1
            )
            funnel['hire_rate'] = round(funnel['hired'] / total * 100, 1)

        return funnel

    @staticmethod
    def cost_per_hire_by_source(application_queryset, source_costs: Dict[str, Decimal] = None):
        """
        Calculate cost per hire by source.

        Args:
            application_queryset: Base queryset
            source_costs: Dict mapping source -> cost per application

        Returns:
            list: Sources with cost metrics
        """
        source_costs = source_costs or {}

        effectiveness = SourceEffectivenessAggregation.overall_effectiveness(
            application_queryset
        )

        results = []
        for source_data in effectiveness:
            source = source_data['source']
            cost_per_app = source_costs.get(source, Decimal('0'))
            total_cost = cost_per_app * source_data['total_applications']

            cost_per_hire = None
            if source_data['hired'] > 0:
                cost_per_hire = total_cost / source_data['hired']

            results.append({
                'source': source,
                'total_applications': source_data['total_applications'],
                'hired': source_data['hired'],
                'hire_rate': source_data['hire_rate'],
                'cost_per_application': cost_per_app,
                'total_cost': total_cost,
                'cost_per_hire': cost_per_hire,
            })

        return sorted(results, key=lambda x: x.get('cost_per_hire') or Decimal('999999'))

    @staticmethod
    def referral_effectiveness(application_queryset):
        """
        Analyze effectiveness of employee referrals specifically.

        Returns:
            dict: Referral program metrics
        """
        referrals = application_queryset.filter(
            candidate__source='referral'
        )
        non_referrals = application_queryset.exclude(
            candidate__source='referral'
        )

        return {
            'referral_applications': referrals.count(),
            'referral_hires': referrals.filter(status='hired').count(),
            'referral_hire_rate': (
                referrals.filter(status='hired').count() / referrals.count() * 100
                if referrals.count() > 0 else 0
            ),
            'referral_avg_rating': referrals.aggregate(
                avg=Avg('overall_rating')
            )['avg'],
            'non_referral_applications': non_referrals.count(),
            'non_referral_hires': non_referrals.filter(status='hired').count(),
            'non_referral_hire_rate': (
                non_referrals.filter(status='hired').count() / non_referrals.count() * 100
                if non_referrals.count() > 0 else 0
            ),
            'non_referral_avg_rating': non_referrals.aggregate(
                avg=Avg('overall_rating')
            )['avg'],
        }


class InterviewAggregation:
    """
    Aggregations for interview metrics and analytics.
    """

    @staticmethod
    def interviews_per_hire(application_queryset):
        """
        Calculate average number of interviews per hire.

        Returns:
            dict: Interview-to-hire metrics
        """
        hired = application_queryset.filter(status='hired')

        return hired.annotate(
            interview_count=Count('interviews')
        ).aggregate(
            avg_interviews=Avg('interview_count'),
            min_interviews=Min('interview_count'),
            max_interviews=Max('interview_count'),
            total_hires=Count('id'),
        )

    @staticmethod
    def interviewer_activity(interview_queryset):
        """
        Get interview count by interviewer.

        Returns:
            QuerySet: Interviewers with counts
        """
        return interview_queryset.values(
            interviewer_id=F('interviewers__id'),
            interviewer_name=F('interviewers__email'),
        ).annotate(
            total_interviews=Count('id'),
            completed=Count('id', filter=Q(status='completed')),
            cancelled=Count('id', filter=Q(status='cancelled')),
            no_shows=Count('id', filter=Q(status='no_show')),
        ).order_by('-total_interviews')

    @staticmethod
    def feedback_completion_rate(interview_queryset):
        """
        Calculate feedback submission rates.

        Returns:
            dict: Feedback completion metrics
        """
        completed = interview_queryset.filter(status='completed')

        return completed.annotate(
            feedback_count=Count('feedback'),
            interviewer_count=Count('interviewers', distinct=True)
        ).aggregate(
            total_interviews=Count('id'),
            with_feedback=Count('id', filter=Q(feedback_count__gt=0)),
            avg_feedback_per_interview=Avg('feedback_count'),
        )

    @staticmethod
    def interview_type_distribution(interview_queryset):
        """
        Get interview distribution by type.

        Returns:
            QuerySet: Interview types with counts
        """
        return interview_queryset.values(
            'interview_type'
        ).annotate(
            count=Count('id'),
            avg_duration=Avg(
                ExtractHour(F('scheduled_end') - F('scheduled_start')) * 60 +
                (ExtractDay(F('scheduled_end') - F('scheduled_start')) * 24 * 60)
            ),
        ).order_by('-count')


class OfferAggregation:
    """
    Aggregations for offer metrics and acceptance rates.
    """

    @staticmethod
    def acceptance_rate(offer_queryset):
        """
        Calculate offer acceptance rate.

        Returns:
            dict: Offer acceptance metrics
        """
        total = offer_queryset.exclude(status='draft').count()
        accepted = offer_queryset.filter(status='accepted').count()
        declined = offer_queryset.filter(status='declined').count()
        pending = offer_queryset.filter(status='sent').count()

        return {
            'total_offers': total,
            'accepted': accepted,
            'declined': declined,
            'pending': pending,
            'acceptance_rate': round(accepted / total * 100, 1) if total > 0 else 0,
            'decline_rate': round(declined / total * 100, 1) if total > 0 else 0,
        }

    @staticmethod
    def salary_stats(offer_queryset):
        """
        Get salary statistics from offers.

        Returns:
            dict: Salary aggregations
        """
        return offer_queryset.filter(
            status__in=['sent', 'accepted', 'declined']
        ).aggregate(
            avg_salary=Avg('base_salary'),
            min_salary=Min('base_salary'),
            max_salary=Max('base_salary'),
            avg_signing_bonus=Avg('signing_bonus'),
        )

    @staticmethod
    def salary_by_department(offer_queryset):
        """
        Get salary statistics by department.

        Returns:
            QuerySet: Departments with salary stats
        """
        return offer_queryset.filter(
            status__in=['sent', 'accepted', 'declined']
        ).values(
            department=F('application__job__category__name'),
        ).annotate(
            offer_count=Count('id'),
            avg_salary=Avg('base_salary'),
            accepted_count=Count('id', filter=Q(status='accepted')),
            acceptance_rate=Cast(
                Count('id', filter=Q(status='accepted')),
                FloatField()
            ) * 100.0 / Cast(Count('id'), FloatField()),
        ).order_by('-offer_count')

    @staticmethod
    def time_to_accept(offer_queryset):
        """
        Calculate average time from offer sent to response.

        Returns:
            dict: Time-to-accept metrics
        """
        responded = offer_queryset.filter(
            sent_at__isnull=False,
            responded_at__isnull=False
        )

        return responded.annotate(
            response_time=ExpressionWrapper(
                F('responded_at') - F('sent_at'),
                output_field=DurationField()
            )
        ).aggregate(
            avg_days=Avg(ExtractDay(F('response_time'))),
            min_days=Min(ExtractDay(F('response_time'))),
            max_days=Max(ExtractDay(F('response_time'))),
        )


class RecruitingFunnelAggregation:
    """
    Full recruiting funnel analysis and metrics.
    """

    @staticmethod
    def full_funnel(application_queryset, job=None):
        """
        Get complete recruiting funnel metrics.

        Args:
            application_queryset: Base queryset
            job: Optional job to filter by

        Returns:
            dict: Complete funnel data
        """
        qs = application_queryset
        if job:
            qs = qs.filter(job=job)

        total = qs.count()

        funnel = {
            'total_applications': total,
            'stages': [],
        }

        if total == 0:
            return funnel

        # Group by status
        status_counts = dict(
            qs.values('status').annotate(
                count=Count('id')
            ).values_list('status', 'count')
        )

        # Define funnel stages
        stages = [
            ('Applied', total, 100.0),
            ('Reviewed', total - status_counts.get('new', 0), None),
            ('Interviewing', (
                status_counts.get('interviewing', 0) +
                status_counts.get('offer_pending', 0) +
                status_counts.get('offer_extended', 0) +
                status_counts.get('hired', 0)
            ), None),
            ('Offer Made', (
                status_counts.get('offer_pending', 0) +
                status_counts.get('offer_extended', 0) +
                status_counts.get('hired', 0)
            ), None),
            ('Hired', status_counts.get('hired', 0), None),
        ]

        for name, count, _ in stages:
            rate = round(count / total * 100, 1) if total > 0 else 0
            funnel['stages'].append({
                'name': name,
                'count': count,
                'rate': rate,
            })

        # Calculate drop-off between stages
        for i in range(1, len(funnel['stages'])):
            prev = funnel['stages'][i - 1]['count']
            curr = funnel['stages'][i]['count']
            funnel['stages'][i]['conversion'] = round(
                curr / prev * 100, 1
            ) if prev > 0 else 0
            funnel['stages'][i]['drop_off'] = prev - curr

        funnel['stages'][0]['conversion'] = 100.0
        funnel['stages'][0]['drop_off'] = 0

        return funnel

    @staticmethod
    def funnel_by_job_type(application_queryset):
        """
        Get funnel metrics grouped by job type.

        Returns:
            dict: Job type -> funnel data mapping
        """
        job_types = application_queryset.values(
            'job__job_type'
        ).distinct()

        return {
            jt['job__job_type']: RecruitingFunnelAggregation.full_funnel(
                application_queryset.filter(job__job_type=jt['job__job_type'])
            )
            for jt in job_types
        }


class DashboardAggregation:
    """
    Pre-computed aggregations for dashboard displays.

    Combines multiple metrics into efficient single-query results
    suitable for dashboard cards and charts.
    """

    @staticmethod
    def recruiter_dashboard(application_queryset, user):
        """
        Get all metrics for a recruiter's dashboard.

        Args:
            user: Recruiter user instance

        Returns:
            dict: Dashboard metrics
        """
        # Filter to recruiter's applications
        qs = application_queryset.filter(
            Q(assigned_to=user) | Q(job__recruiter=user)
        )

        today = timezone.now().date()
        week_ago = today - timedelta(days=7)

        return {
            'total_active': qs.exclude(
                status__in=['hired', 'rejected', 'withdrawn']
            ).count(),
            'new_this_week': qs.filter(
                applied_at__date__gte=week_ago
            ).count(),
            'pending_review': qs.filter(
                status__in=['new', 'in_review']
            ).count(),
            'interviews_this_week': qs.filter(
                interviews__scheduled_start__date__gte=week_ago,
                interviews__scheduled_start__date__lte=today + timedelta(days=7)
            ).distinct().count(),
            'hires_this_month': qs.filter(
                status='hired',
                hired_at__month=today.month,
                hired_at__year=today.year
            ).count(),
            'avg_time_to_hire': qs.filter(
                status='hired',
                hired_at__isnull=False
            ).annotate(
                days=ExtractDay(F('hired_at') - F('applied_at'))
            ).aggregate(avg=Avg('days'))['avg'],
        }

    @staticmethod
    def job_dashboard(application_queryset, job):
        """
        Get all metrics for a job posting dashboard.

        Args:
            job: JobPosting instance

        Returns:
            dict: Job-specific metrics
        """
        qs = application_queryset.filter(job=job)

        return {
            'total_applicants': qs.count(),
            'status_breakdown': dict(
                qs.values('status').annotate(
                    count=Count('id')
                ).values_list('status', 'count')
            ),
            'source_breakdown': dict(
                qs.values('candidate__source').annotate(
                    count=Count('id')
                ).values_list('candidate__source', 'count')
            ),
            'avg_rating': qs.aggregate(avg=Avg('overall_rating'))['avg'],
            'avg_match_score': qs.aggregate(avg=Avg('ai_match_score'))['avg'],
            'hired_count': qs.filter(status='hired').count(),
            'interviews_scheduled': qs.filter(
                interviews__status__in=['scheduled', 'confirmed']
            ).distinct().count(),
        }

    @staticmethod
    def weekly_metrics(application_queryset, weeks=4):
        """
        Get weekly application metrics for trend chart.

        Args:
            weeks: Number of weeks to include

        Returns:
            list: Weekly metric data points
        """
        start_date = timezone.now() - timedelta(weeks=weeks)

        return application_queryset.filter(
            applied_at__gte=start_date
        ).annotate(
            week=TruncWeek('applied_at')
        ).values('week').annotate(
            applications=Count('id'),
            hired=Count('id', filter=Q(status='hired')),
            rejected=Count('id', filter=Q(status='rejected')),
        ).order_by('week')
