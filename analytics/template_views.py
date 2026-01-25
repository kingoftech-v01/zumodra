"""
Analytics Template Views - Frontend views for Analytics and Reporting.

This module implements template-based views for:
- Analytics dashboard
- Recruitment funnel visualization
- Pipeline analytics
- Custom reports
- Data exports

All views are HTMX-aware and return partials when appropriate.
"""

import json
import logging
from datetime import date, timedelta
from decimal import Decimal

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count, Avg, Q, F, Sum
from django.db.models.functions import TruncDate, TruncWeek, TruncMonth
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views import View
from django.views.generic import TemplateView, ListView

from tenants.mixins import TenantViewMixin

logger = logging.getLogger(__name__)


# =============================================================================
# MIXINS
# =============================================================================

class HTMXMixin:
    """Mixin to handle HTMX requests."""
    partial_template_name = None

    def get_template_names(self):
        if self.request.headers.get('HX-Request') and self.partial_template_name:
            return [self.partial_template_name]
        return super().get_template_names()


class AnalyticsPermissionMixin:
    """
    Mixin for analytics-specific permission checks.
    """

    def has_analytics_permission(self, permission_type='view'):
        user = self.request.user

        if user.is_superuser or user.is_staff:
            return True

        if hasattr(user, 'tenantuser'):
            role = user.tenantuser.role.lower() if user.tenantuser.role else ''
            allowed_roles = {
                'view': ['admin', 'pdg', 'hr', 'recruiter', 'hiring_manager', 'supervisor'],
                'export': ['admin', 'pdg', 'hr'],
                'admin': ['admin', 'pdg'],
            }
            return role in allowed_roles.get(permission_type, [])

        return False


# =============================================================================
# MAIN DASHBOARD
# =============================================================================

class AnalyticsDashboardView(LoginRequiredMixin, TenantViewMixin, AnalyticsPermissionMixin, HTMXMixin, TemplateView):
    """
    Main analytics dashboard with key metrics and visualizations.

    Displays:
    - Recruitment funnel
    - Time-to-hire trends
    - Source quality analysis
    - Pipeline bottlenecks
    - Department hiring metrics
    """
    template_name = 'analytics/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.get_tenant()

        if not tenant:
            return context

        # Date range from params or default to last 30 days
        end_date = date.today()
        start_date_str = self.request.GET.get('start_date')
        end_date_str = self.request.GET.get('end_date')
        period = self.request.GET.get('period', '30')  # 7, 30, 90, 365

        if start_date_str and end_date_str:
            from django.utils.dateparse import parse_date
            start_date = parse_date(start_date_str) or (end_date - timedelta(days=int(period)))
            end_date = parse_date(end_date_str) or end_date
        else:
            start_date = end_date - timedelta(days=int(period))

        context['date_range'] = {
            'start': start_date,
            'end': end_date,
            'period': period,
        }

        # Import models
        from jobs.models import JobPosting, Candidate, Application, Interview, Offer

        # ===== KEY METRICS =====

        # Total applications in period
        applications_in_period = Application.objects.filter(
            tenant=tenant,
            created_at__date__gte=start_date,
            created_at__date__lte=end_date
        )

        context['metrics'] = {
            'total_applications': applications_in_period.count(),
            'new_candidates': Candidate.objects.filter(
                tenant=tenant,
                created_at__date__gte=start_date,
                created_at__date__lte=end_date
            ).count(),
            'interviews_scheduled': Interview.objects.filter(
                application__tenant=tenant,
                created_at__date__gte=start_date,
                created_at__date__lte=end_date
            ).count(),
            'offers_sent': Offer.objects.filter(
                application__tenant=tenant,
                created_at__date__gte=start_date,
                created_at__date__lte=end_date
            ).count(),
            'hires': Application.objects.filter(
                tenant=tenant,
                status='hired',
                hired_at__date__gte=start_date,
                hired_at__date__lte=end_date
            ).count(),
        }

        # Calculate conversion rates
        total_apps = context['metrics']['total_applications'] or 1
        context['conversion_rates'] = {
            'application_to_interview': round(
                (context['metrics']['interviews_scheduled'] / total_apps) * 100, 1
            ),
            'interview_to_offer': round(
                (context['metrics']['offers_sent'] / max(context['metrics']['interviews_scheduled'], 1)) * 100, 1
            ),
            'offer_to_hire': round(
                (context['metrics']['hires'] / max(context['metrics']['offers_sent'], 1)) * 100, 1
            ),
            'overall': round(
                (context['metrics']['hires'] / total_apps) * 100, 1
            ),
        }

        # ===== OPEN JOBS =====
        context['open_jobs_count'] = JobPosting.objects.filter(
            tenant=tenant,
            status='open'
        ).count()

        # ===== TIME TO HIRE =====
        hired_apps = Application.objects.filter(
            tenant=tenant,
            status='hired',
            hired_at__date__gte=start_date,
            hired_at__date__lte=end_date,
            hired_at__isnull=False
        )

        time_to_hire_data = []
        for app in hired_apps[:100]:  # Limit for performance
            if app.hired_at and app.applied_at:
                days = (app.hired_at.date() - app.applied_at.date()).days
                time_to_hire_data.append(days)

        context['avg_time_to_hire'] = round(
            sum(time_to_hire_data) / len(time_to_hire_data), 1
        ) if time_to_hire_data else 0

        # ===== APPLICATIONS TREND =====
        applications_trend = Application.objects.filter(
            tenant=tenant,
            created_at__date__gte=start_date,
            created_at__date__lte=end_date
        ).annotate(
            day=TruncDate('created_at')
        ).values('day').annotate(
            count=Count('id')
        ).order_by('day')

        context['applications_trend'] = json.dumps([
            {'date': item['day'].isoformat(), 'count': item['count']}
            for item in applications_trend
        ])

        # ===== JOBS BY STATUS =====
        jobs_by_status = JobPosting.objects.filter(
            tenant=tenant
        ).values('status').annotate(
            count=Count('id')
        )
        context['jobs_by_status'] = json.dumps([
            {'status': item['status'], 'count': item['count']}
            for item in jobs_by_status
        ])

        # ===== TOP SOURCES =====
        from jobs.models import CandidateSource
        top_sources = Candidate.objects.filter(
            tenant=tenant,
            created_at__date__gte=start_date
        ).values(
            'source__name'
        ).annotate(
            count=Count('id')
        ).order_by('-count')[:10]

        context['top_sources'] = list(top_sources)

        return context


# =============================================================================
# FUNNEL VIEWS
# =============================================================================

class FunnelChartView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for recruitment funnel chart data.

    Returns JSON data for funnel visualization.
    """

    def get(self, request):
        tenant = self.get_tenant()
        if not tenant:
            return JsonResponse({'error': 'No tenant'}, status=403)

        # Get date range
        period = int(request.GET.get('period', 30))
        end_date = date.today()
        start_date = end_date - timedelta(days=period)

        # Job filter
        job_id = request.GET.get('job')

        from jobs.models import Application

        base_qs = Application.objects.filter(
            tenant=tenant,
            created_at__date__gte=start_date
        )

        if job_id:
            base_qs = base_qs.filter(job_id=job_id)

        # Get counts by status
        status_counts = base_qs.values('status').annotate(count=Count('id'))
        status_map = {item['status']: item['count'] for item in status_counts}

        # Build funnel data
        funnel_data = [
            {'stage': 'Applied', 'count': base_qs.count(), 'color': '#3B82F6'},
            {'stage': 'Screened', 'count': status_map.get('screened', 0) + status_map.get('in_review', 0) +
                                         status_map.get('interviewing', 0) + status_map.get('offer', 0) +
                                         status_map.get('hired', 0), 'color': '#8B5CF6'},
            {'stage': 'Interviewed', 'count': status_map.get('interviewing', 0) + status_map.get('offer', 0) +
                                              status_map.get('hired', 0), 'color': '#EC4899'},
            {'stage': 'Offered', 'count': status_map.get('offer', 0) + status_map.get('hired', 0), 'color': '#F59E0B'},
            {'stage': 'Hired', 'count': status_map.get('hired', 0), 'color': '#10B981'},
        ]

        if request.headers.get('HX-Request'):
            return render(request, 'analytics/partials/_funnel_chart.html', {
                'funnel_data': funnel_data
            })

        return JsonResponse({'funnel': funnel_data})


class PipelineAnalyticsView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for pipeline stage analytics.
    """

    def get(self, request):
        tenant = self.get_tenant()
        if not tenant:
            return JsonResponse({'error': 'No tenant'}, status=403)

        from jobs.models import Pipeline, Application

        pipeline_id = request.GET.get('pipeline')
        period = int(request.GET.get('period', 30))
        end_date = date.today()
        start_date = end_date - timedelta(days=period)

        # Get pipeline
        if pipeline_id:
            pipeline = Pipeline.objects.filter(tenant=tenant, pk=pipeline_id).first()
        else:
            pipeline = Pipeline.objects.filter(tenant=tenant, is_default=True).first()

        if not pipeline:
            return JsonResponse({'error': 'No pipeline found'}, status=404)

        # Get stages with counts
        stages_data = []
        for stage in pipeline.stages.filter(is_active=True).order_by('order'):
            count = Application.objects.filter(
                current_stage=stage,
                tenant=tenant
            ).count()

            # Calculate average time in stage
            avg_time = 0  # Would need ApplicationActivity to calculate properly

            stages_data.append({
                'id': str(stage.pk),
                'name': stage.name,
                'color': stage.color,
                'count': count,
                'avg_time_days': avg_time,
            })

        if request.headers.get('HX-Request'):
            return render(request, 'analytics/partials/_pipeline_analytics.html', {
                'pipeline': pipeline,
                'stages_data': stages_data,
            })

        return JsonResponse({
            'pipeline': {'id': str(pipeline.pk), 'name': pipeline.name},
            'stages': stages_data,
        })


# =============================================================================
# REPORTS
# =============================================================================

class ReportsView(LoginRequiredMixin, TenantViewMixin, AnalyticsPermissionMixin, HTMXMixin, ListView):
    """
    Reports listing and generation page.

    Shows available reports and allows filtering/export.
    """
    template_name = 'analytics/reports.html'
    context_object_name = 'reports'

    def get_queryset(self):
        # Return list of available report types
        # This could be from a Report model or just a predefined list
        return []

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Available report types
        context['report_types'] = [
            {
                'id': 'recruitment_summary',
                'name': 'Recruitment Summary',
                'description': 'Overview of recruitment activity including applications, interviews, and hires',
                'icon': 'users',
            },
            {
                'id': 'time_to_hire',
                'name': 'Time to Hire Analysis',
                'description': 'Analysis of time taken from application to hire by job, source, and department',
                'icon': 'clock',
            },
            {
                'id': 'source_quality',
                'name': 'Source Quality Report',
                'description': 'Quality metrics for each recruitment source including conversion rates',
                'icon': 'trending-up',
            },
            {
                'id': 'pipeline_performance',
                'name': 'Pipeline Performance',
                'description': 'Stage-by-stage analysis of recruitment pipelines',
                'icon': 'activity',
            },
            {
                'id': 'headcount',
                'name': 'Headcount Report',
                'description': 'Current headcount by department, location, and employment type',
                'icon': 'briefcase',
            },
            {
                'id': 'time_off_summary',
                'name': 'Time-Off Summary',
                'description': 'Summary of time-off requests and balances by department',
                'icon': 'calendar',
            },
            {
                'id': 'turnover',
                'name': 'Turnover Analysis',
                'description': 'Employee turnover metrics and trends',
                'icon': 'user-minus',
            },
            {
                'id': 'dei_metrics',
                'name': 'DEI Metrics',
                'description': 'Diversity, equity, and inclusion metrics for recruitment',
                'icon': 'pie-chart',
            },
        ]

        return context


class ReportGenerateView(LoginRequiredMixin, TenantViewMixin, AnalyticsPermissionMixin, View):
    """
    Generate a specific report.
    """

    def get(self, request, report_type):
        tenant = self.get_tenant()
        if not tenant:
            return JsonResponse({'error': 'No tenant'}, status=403)

        # Parse date range
        end_date = date.today()
        period = int(request.GET.get('period', 30))
        start_date = end_date - timedelta(days=period)

        report_generators = {
            'recruitment_summary': self._generate_recruitment_summary,
            'time_to_hire': self._generate_time_to_hire,
            'source_quality': self._generate_source_quality,
            'pipeline_performance': self._generate_pipeline_performance,
            'headcount': self._generate_headcount,
        }

        generator = report_generators.get(report_type)
        if not generator:
            return JsonResponse({'error': 'Unknown report type'}, status=400)

        data = generator(tenant, start_date, end_date)

        if request.headers.get('HX-Request'):
            return render(request, f'analytics/partials/_report_{report_type}.html', {
                'data': data,
                'start_date': start_date,
                'end_date': end_date,
            })

        return JsonResponse(data)

    def _generate_recruitment_summary(self, tenant, start_date, end_date):
        from jobs.models import JobPosting, Candidate, Application, Interview, Offer

        return {
            'summary': {
                'total_jobs': JobPosting.objects.filter(tenant=tenant, status='open').count(),
                'total_applications': Application.objects.filter(
                    tenant=tenant,
                    created_at__date__gte=start_date
                ).count(),
                'total_interviews': Interview.objects.filter(
                    application__tenant=tenant,
                    created_at__date__gte=start_date
                ).count(),
                'total_offers': Offer.objects.filter(
                    application__tenant=tenant,
                    created_at__date__gte=start_date
                ).count(),
                'total_hires': Application.objects.filter(
                    tenant=tenant,
                    status='hired',
                    hired_at__date__gte=start_date
                ).count(),
            }
        }

    def _generate_time_to_hire(self, tenant, start_date, end_date):
        from jobs.models import Application

        hired_apps = Application.objects.filter(
            tenant=tenant,
            status='hired',
            hired_at__date__gte=start_date,
            hired_at__date__lte=end_date
        ).select_related('job', 'candidate')

        time_data = []
        for app in hired_apps:
            if app.hired_at and app.applied_at:
                days = (app.hired_at.date() - app.applied_at.date()).days
                time_data.append({
                    'job': app.job.title if app.job else 'N/A',
                    'candidate': app.candidate.full_name if app.candidate else 'N/A',
                    'days': days,
                })

        avg_days = sum(t['days'] for t in time_data) / len(time_data) if time_data else 0

        return {
            'average_days': round(avg_days, 1),
            'details': time_data[:50],  # Limit for response size
        }

    def _generate_source_quality(self, tenant, start_date, end_date):
        from jobs.models import Candidate, Application

        # Get candidates by source with application outcomes
        source_data = Candidate.objects.filter(
            tenant=tenant,
            created_at__date__gte=start_date
        ).values('source__name').annotate(
            total=Count('id'),
            hired=Count('applications', filter=Q(applications__status='hired')),
        ).order_by('-total')

        return {
            'sources': list(source_data),
        }

    def _generate_pipeline_performance(self, tenant, start_date, end_date):
        from jobs.models import Pipeline, Application

        pipelines = Pipeline.objects.filter(tenant=tenant)
        pipeline_data = []

        for pipeline in pipelines:
            stages_data = []
            for stage in pipeline.stages.filter(is_active=True).order_by('order'):
                count = Application.objects.filter(
                    current_stage=stage,
                    job__pipeline=pipeline,
                    tenant=tenant
                ).count()
                stages_data.append({
                    'name': stage.name,
                    'count': count,
                })

            pipeline_data.append({
                'name': pipeline.name,
                'stages': stages_data,
            })

        return {'pipelines': pipeline_data}

    def _generate_headcount(self, tenant, start_date, end_date):
        from hr_core.models import Employee

        employees = Employee.objects.filter(
            user__tenantuser__tenant=tenant,
            status='active'
        )

        by_department = employees.values(
            'department__name'
        ).annotate(count=Count('id')).order_by('-count')

        by_type = employees.values(
            'employment_type'
        ).annotate(count=Count('id')).order_by('-count')

        return {
            'total': employees.count(),
            'by_department': list(by_department),
            'by_employment_type': list(by_type),
        }


# =============================================================================
# CHART ENDPOINTS
# =============================================================================

class ApplicationsTrendChartView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for applications trend chart.
    """

    def get(self, request):
        tenant = self.get_tenant()
        if not tenant:
            return JsonResponse({'error': 'No tenant'}, status=403)

        period = int(request.GET.get('period', 30))
        end_date = date.today()
        start_date = end_date - timedelta(days=period)

        from jobs.models import Application

        trend_data = Application.objects.filter(
            tenant=tenant,
            created_at__date__gte=start_date,
            created_at__date__lte=end_date
        ).annotate(
            day=TruncDate('created_at')
        ).values('day').annotate(
            count=Count('id')
        ).order_by('day')

        data = [
            {'date': item['day'].isoformat(), 'count': item['count']}
            for item in trend_data
        ]

        if request.headers.get('HX-Request'):
            return render(request, 'analytics/partials/_applications_trend.html', {
                'trend_data': json.dumps(data)
            })

        return JsonResponse({'trend': data})


class HiresByDepartmentChartView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for hires by department chart.
    """

    def get(self, request):
        tenant = self.get_tenant()
        if not tenant:
            return JsonResponse({'error': 'No tenant'}, status=403)

        period = int(request.GET.get('period', 30))
        end_date = date.today()
        start_date = end_date - timedelta(days=period)

        from jobs.models import Application

        dept_data = Application.objects.filter(
            tenant=tenant,
            status='hired',
            hired_at__date__gte=start_date
        ).values(
            'job__category__name'
        ).annotate(
            count=Count('id')
        ).order_by('-count')

        data = [
            {'department': item['job__category__name'] or 'Uncategorized', 'count': item['count']}
            for item in dept_data
        ]

        if request.headers.get('HX-Request'):
            return render(request, 'analytics/partials/_hires_by_department.html', {
                'dept_data': json.dumps(data)
            })

        return JsonResponse({'departments': data})


class SourcePerformanceChartView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for source performance comparison.
    """

    def get(self, request):
        tenant = self.get_tenant()
        if not tenant:
            return JsonResponse({'error': 'No tenant'}, status=403)

        period = int(request.GET.get('period', 90))
        end_date = date.today()
        start_date = end_date - timedelta(days=period)

        from jobs.models import Candidate, Application

        source_data = Candidate.objects.filter(
            tenant=tenant,
            created_at__date__gte=start_date
        ).values('source__name').annotate(
            candidates=Count('id'),
            applications=Count('applications'),
            hired=Count('applications', filter=Q(applications__status='hired')),
        ).order_by('-candidates')[:10]

        data = []
        for item in source_data:
            conversion = (item['hired'] / item['candidates'] * 100) if item['candidates'] > 0 else 0
            data.append({
                'source': item['source__name'] or 'Unknown',
                'candidates': item['candidates'],
                'applications': item['applications'],
                'hired': item['hired'],
                'conversion': round(conversion, 1),
            })

        if request.headers.get('HX-Request'):
            return render(request, 'analytics/partials/_source_performance.html', {
                'source_data': data
            })

        return JsonResponse({'sources': data})
