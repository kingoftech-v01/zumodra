"""
Analytics Celery Tasks

This module provides Celery tasks for:
- calculate_daily_metrics: Daily metric calculation
- generate_weekly_report: Weekly report generation
- refresh_dashboard_cache: Dashboard cache refresh
- calculate_recruitment_metrics: Recruitment KPIs
- calculate_diversity_metrics: EEOC-compliant diversity metrics
- calculate_hr_metrics: HR analytics (retention, performance, time-off)
"""

import logging
from datetime import date, datetime, timedelta
from typing import Optional, List, Dict, Any

from celery import shared_task, group, chain
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string

from .models import (
    RecruitmentMetric, DiversityMetric, HiringFunnelMetric,
    TimeToHireMetric, SourceEffectivenessMetric, EmployeeRetentionMetric,
    TimeOffAnalytics, PerformanceDistribution, DashboardCache
)
from .services import (
    DateRangeFilter, RecruitmentAnalyticsService, DiversityAnalyticsService,
    HRAnalyticsService, DashboardDataService
)

logger = logging.getLogger(__name__)


# ==================== DAILY METRICS TASKS ====================

@shared_task(bind=True, name='analytics.calculate_daily_metrics')
def calculate_daily_metrics(self, target_date: Optional[str] = None) -> Dict[str, Any]:
    """
    Calculate and store daily metrics for all analytics categories.

    Args:
        target_date: Date string (YYYY-MM-DD) to calculate metrics for.
                    Defaults to yesterday.

    Returns:
        Dict containing status and metrics summary.
    """
    if target_date:
        calc_date = datetime.strptime(target_date, '%Y-%m-%d').date()
    else:
        calc_date = timezone.now().date() - timedelta(days=1)

    logger.info(f"Calculating daily metrics for {calc_date}")

    results = {
        'date': calc_date.isoformat(),
        'metrics_calculated': [],
        'errors': [],
    }

    # Create date filter for the specific day
    date_filter = DateRangeFilter(
        start_date=calc_date,
        end_date=calc_date
    )

    # Calculate recruitment metrics
    try:
        recruitment_service = RecruitmentAnalyticsService(date_filter)
        recruitment_metric = recruitment_service.calculate_recruitment_metric()
        results['metrics_calculated'].append('recruitment')
        logger.info(f"Recruitment metrics calculated: {recruitment_metric.uuid}")
    except Exception as e:
        logger.error(f"Failed to calculate recruitment metrics: {e}")
        results['errors'].append(f'recruitment: {str(e)}')

    # Calculate HR metrics
    try:
        hr_service = HRAnalyticsService(date_filter)
        retention_metric = hr_service.calculate_retention_metric()
        results['metrics_calculated'].append('retention')
        logger.info(f"Retention metrics calculated: {retention_metric.uuid}")
    except Exception as e:
        logger.error(f"Failed to calculate retention metrics: {e}")
        results['errors'].append(f'retention: {str(e)}')

    try:
        time_off_analytics = hr_service.calculate_time_off_analytics()
        results['metrics_calculated'].append('time_off')
        logger.info(f"Time-off analytics calculated: {time_off_analytics.uuid}")
    except Exception as e:
        logger.error(f"Failed to calculate time-off analytics: {e}")
        results['errors'].append(f'time_off: {str(e)}')

    # Refresh dashboard cache
    try:
        dashboard_service = DashboardDataService(date_filter, use_cache=False)
        dashboard_service.refresh_cache('all')
        results['cache_refreshed'] = True
    except Exception as e:
        logger.error(f"Failed to refresh dashboard cache: {e}")
        results['errors'].append(f'cache_refresh: {str(e)}')
        results['cache_refreshed'] = False

    logger.info(f"Daily metrics calculation completed for {calc_date}")
    return results


@shared_task(bind=True, name='analytics.calculate_hourly_metrics')
def calculate_hourly_metrics(self) -> Dict[str, Any]:
    """
    Calculate lightweight hourly metrics for real-time dashboards.

    Returns:
        Dict containing current hour's key metrics.
    """
    now = timezone.now()
    hour_start = now.replace(minute=0, second=0, microsecond=0)
    hour_end = hour_start + timedelta(hours=1)

    logger.info(f"Calculating hourly metrics for {hour_start}")

    date_filter = DateRangeFilter(
        start_date=hour_start.date(),
        end_date=hour_start.date()
    )

    results = {
        'hour': hour_start.isoformat(),
        'metrics': {},
    }

    try:
        # Get current application counts
        from ats.models import Application, Interview

        results['metrics']['new_applications'] = Application.objects.filter(
            applied_at__gte=hour_start,
            applied_at__lt=hour_end
        ).count()

        results['metrics']['interviews_today'] = Interview.objects.filter(
            scheduled_start__date=hour_start.date()
        ).count()

        # Cache the hourly metrics
        cache_key = f"analytics:hourly:{hour_start.strftime('%Y%m%d%H')}"
        cache.set(cache_key, results['metrics'], timeout=3600)  # 1 hour

    except Exception as e:
        logger.error(f"Failed to calculate hourly metrics: {e}")
        results['error'] = str(e)

    return results


# ==================== WEEKLY REPORT TASKS ====================

@shared_task(bind=True, name='analytics.generate_weekly_report')
def generate_weekly_report(
    self,
    week_ending: Optional[str] = None,
    recipients: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Generate and optionally email weekly analytics report.

    Args:
        week_ending: Date string (YYYY-MM-DD) for the week ending date.
                    Defaults to last Sunday.
        recipients: List of email addresses to send report to.

    Returns:
        Dict containing report data and status.
    """
    if week_ending:
        end_date = datetime.strptime(week_ending, '%Y-%m-%d').date()
    else:
        # Default to last Sunday
        today = timezone.now().date()
        days_since_sunday = (today.weekday() + 1) % 7
        end_date = today - timedelta(days=days_since_sunday)

    start_date = end_date - timedelta(days=6)

    logger.info(f"Generating weekly report for {start_date} to {end_date}")

    date_filter = DateRangeFilter(start_date, end_date)

    results = {
        'period': {
            'start': start_date.isoformat(),
            'end': end_date.isoformat(),
        },
        'report_generated': False,
        'email_sent': False,
    }

    try:
        # Get dashboard data
        dashboard_service = DashboardDataService(date_filter)

        recruitment_data = dashboard_service.get_recruitment_dashboard()
        hr_data = dashboard_service.get_hr_dashboard()
        executive_data = dashboard_service.get_executive_summary()

        # Compile report
        report = {
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat(),
            },
            'executive_summary': executive_data['summary'],
            'recruitment': {
                'highlights': {
                    'open_positions': recruitment_data['job_metrics']['open_positions'],
                    'new_applications': recruitment_data['application_metrics']['new_applications'],
                    'hires': recruitment_data['time_to_hire']['total_hires'],
                    'avg_time_to_hire': recruitment_data['time_to_hire']['avg_days'],
                    'offer_acceptance_rate': recruitment_data['offer_metrics']['acceptance_rate'],
                },
                'comparison': recruitment_data.get('comparison', {}),
            },
            'hr': {
                'highlights': {
                    'current_headcount': hr_data['headcount']['current_headcount'],
                    'new_hires': hr_data['headcount']['new_hires'],
                    'departures': hr_data['retention']['total_departures'],
                    'turnover_rate': hr_data['retention']['turnover_rate'],
                },
                'comparison': hr_data.get('comparison', {}),
            },
            'generated_at': timezone.now().isoformat(),
        }

        results['report'] = report
        results['report_generated'] = True

        # Store the weekly metric
        RecruitmentMetric.objects.update_or_create(
            period_type='weekly',
            period_start=start_date,
            defaults={
                'period_end': end_date,
                **{
                    k: v for k, v in recruitment_data['job_metrics'].items()
                    if k in ['open_positions', 'new_positions', 'filled_positions']
                },
                **{
                    k: v for k, v in recruitment_data['application_metrics'].items()
                    if k in ['total_applications', 'new_applications']
                },
                'total_hires': recruitment_data['time_to_hire']['total_hires'],
                'avg_time_to_hire': recruitment_data['time_to_hire']['avg_days'],
                'offer_acceptance_rate': recruitment_data['offer_metrics']['acceptance_rate'],
            }
        )

        # Send email if recipients provided
        if recipients:
            try:
                send_weekly_report_email.delay(report, recipients)
                results['email_queued'] = True
            except Exception as e:
                logger.error(f"Failed to queue email: {e}")
                results['email_error'] = str(e)

        logger.info(f"Weekly report generated successfully for {start_date} to {end_date}")

    except Exception as e:
        logger.error(f"Failed to generate weekly report: {e}")
        results['error'] = str(e)

    return results


@shared_task(bind=True, name='analytics.send_weekly_report_email')
def send_weekly_report_email(self, report: Dict, recipients: List[str]) -> Dict[str, Any]:
    """
    Send the weekly analytics report via email.

    Args:
        report: The compiled report data.
        recipients: List of email addresses.

    Returns:
        Dict containing email send status.
    """
    results = {
        'recipients': recipients,
        'sent': False,
    }

    try:
        # Render email content
        subject = f"Weekly Analytics Report - {report['period']['start']} to {report['period']['end']}"

        # Plain text version
        text_content = f"""
Weekly Analytics Report
Period: {report['period']['start']} to {report['period']['end']}

EXECUTIVE SUMMARY
-----------------
Open Positions: {report['executive_summary'].get('open_positions', 'N/A')}
Total Applications: {report['executive_summary'].get('total_applications', 'N/A')}
Hires This Week: {report['executive_summary'].get('hires', 'N/A')}
Avg Time to Hire: {report['executive_summary'].get('avg_time_to_hire', 'N/A')} days
Offer Acceptance Rate: {report['executive_summary'].get('offer_acceptance_rate', 'N/A')}%

RECRUITMENT HIGHLIGHTS
----------------------
Open Positions: {report['recruitment']['highlights']['open_positions']}
New Applications: {report['recruitment']['highlights']['new_applications']}
Hires: {report['recruitment']['highlights']['hires']}

HR HIGHLIGHTS
-------------
Current Headcount: {report['hr']['highlights']['current_headcount']}
New Hires: {report['hr']['highlights']['new_hires']}
Departures: {report['hr']['highlights']['departures']}
Turnover Rate: {report['hr']['highlights']['turnover_rate']}%

Report generated at: {report['generated_at']}
        """

        # HTML version (optional - requires template)
        try:
            html_content = render_to_string('analytics/email/weekly_report.html', {
                'report': report,
            })
        except Exception:
            html_content = None

        # Send email
        send_mail(
            subject=subject,
            message=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipients,
            html_message=html_content,
            fail_silently=False,
        )

        results['sent'] = True
        logger.info(f"Weekly report email sent to {len(recipients)} recipients")

    except Exception as e:
        logger.error(f"Failed to send weekly report email: {e}")
        results['error'] = str(e)

    return results


# ==================== CACHE REFRESH TASKS ====================

@shared_task(bind=True, name='analytics.refresh_dashboard_cache')
def refresh_dashboard_cache(
    self,
    dashboard_type: str = 'all',
    force: bool = False
) -> Dict[str, Any]:
    """
    Refresh cached dashboard data.

    Args:
        dashboard_type: Type of dashboard to refresh
                       ('recruitment', 'diversity', 'hr', 'executive', 'all')
        force: Force refresh even if cache is not expired.

    Returns:
        Dict containing refresh status.
    """
    logger.info(f"Refreshing dashboard cache: {dashboard_type}")

    results = {
        'dashboard_type': dashboard_type,
        'refreshed': [],
        'errors': [],
    }

    date_filter = DateRangeFilter()  # Default to last 30 days
    dashboard_service = DashboardDataService(date_filter, use_cache=False)

    dashboards_to_refresh = (
        ['recruitment', 'diversity', 'hr', 'executive']
        if dashboard_type == 'all'
        else [dashboard_type]
    )

    for dtype in dashboards_to_refresh:
        try:
            # Check if refresh is needed
            cache_key = f"dashboard:{dtype}:{date_filter.start_date}:{date_filter.end_date}"

            if not force:
                cached = cache.get(cache_key)
                if cached:
                    logger.info(f"Cache still valid for {dtype}, skipping")
                    continue

            # Refresh the dashboard
            if dtype == 'recruitment':
                data = dashboard_service.get_recruitment_dashboard()
            elif dtype == 'diversity':
                data = dashboard_service.get_diversity_dashboard()
            elif dtype == 'hr':
                data = dashboard_service.get_hr_dashboard()
            elif dtype == 'executive':
                data = dashboard_service.get_executive_summary()
            else:
                continue

            # Store in cache
            cache.set(cache_key, data, timeout=300)  # 5 minutes

            # Store in database cache
            dashboard_service.save_to_db_cache(dtype, data)

            results['refreshed'].append(dtype)
            logger.info(f"Dashboard cache refreshed: {dtype}")

        except Exception as e:
            logger.error(f"Failed to refresh {dtype} cache: {e}")
            results['errors'].append(f'{dtype}: {str(e)}')

    return results


# ==================== PERIODIC METRIC CALCULATION TASKS ====================

@shared_task(bind=True, name='analytics.calculate_monthly_metrics')
def calculate_monthly_metrics(
    self,
    year: Optional[int] = None,
    month: Optional[int] = None
) -> Dict[str, Any]:
    """
    Calculate monthly aggregated metrics.

    Args:
        year: Year to calculate for (default: current year)
        month: Month to calculate for (default: previous month)

    Returns:
        Dict containing calculation status.
    """
    now = timezone.now()

    if year is None or month is None:
        # Default to previous month
        if now.month == 1:
            year = now.year - 1
            month = 12
        else:
            year = now.year
            month = now.month - 1

    start_date = date(year, month, 1)
    if month == 12:
        end_date = date(year + 1, 1, 1) - timedelta(days=1)
    else:
        end_date = date(year, month + 1, 1) - timedelta(days=1)

    logger.info(f"Calculating monthly metrics for {year}-{month:02d}")

    date_filter = DateRangeFilter(start_date, end_date)
    results = {
        'year': year,
        'month': month,
        'period': {
            'start': start_date.isoformat(),
            'end': end_date.isoformat(),
        },
        'metrics_calculated': [],
        'errors': [],
    }

    # Calculate recruitment metrics
    try:
        recruitment_service = RecruitmentAnalyticsService(date_filter)
        metric = recruitment_service.calculate_recruitment_metric()
        # Update period type to monthly
        metric.period_type = 'monthly'
        metric.save()
        results['metrics_calculated'].append('recruitment')
    except Exception as e:
        logger.error(f"Failed to calculate monthly recruitment metrics: {e}")
        results['errors'].append(f'recruitment: {str(e)}')

    # Calculate diversity metrics
    try:
        diversity_service = DiversityAnalyticsService(date_filter, scope='employees')
        diversity_metric = diversity_service.calculate_diversity_metric()
        results['metrics_calculated'].append('diversity')
    except Exception as e:
        logger.error(f"Failed to calculate monthly diversity metrics: {e}")
        results['errors'].append(f'diversity: {str(e)}')

    # Calculate HR metrics
    try:
        hr_service = HRAnalyticsService(date_filter)
        retention_metric = hr_service.calculate_retention_metric()
        retention_metric.period_type = 'monthly'
        retention_metric.save()
        results['metrics_calculated'].append('retention')
    except Exception as e:
        logger.error(f"Failed to calculate monthly retention metrics: {e}")
        results['errors'].append(f'retention: {str(e)}')

    logger.info(f"Monthly metrics calculation completed for {year}-{month:02d}")
    return results


@shared_task(bind=True, name='analytics.calculate_quarterly_metrics')
def calculate_quarterly_metrics(
    self,
    year: Optional[int] = None,
    quarter: Optional[int] = None
) -> Dict[str, Any]:
    """
    Calculate quarterly aggregated metrics.

    Args:
        year: Year to calculate for (default: current year)
        quarter: Quarter to calculate for (1-4, default: previous quarter)

    Returns:
        Dict containing calculation status.
    """
    now = timezone.now()

    if year is None or quarter is None:
        # Default to previous quarter
        current_quarter = (now.month - 1) // 3 + 1
        if current_quarter == 1:
            year = now.year - 1
            quarter = 4
        else:
            year = now.year
            quarter = current_quarter - 1

    # Calculate quarter date range
    quarter_start_months = {1: 1, 2: 4, 3: 7, 4: 10}
    start_month = quarter_start_months[quarter]
    start_date = date(year, start_month, 1)

    if quarter == 4:
        end_date = date(year + 1, 1, 1) - timedelta(days=1)
    else:
        end_date = date(year, start_month + 3, 1) - timedelta(days=1)

    logger.info(f"Calculating quarterly metrics for Q{quarter} {year}")

    date_filter = DateRangeFilter(start_date, end_date)
    results = {
        'year': year,
        'quarter': quarter,
        'period': {
            'start': start_date.isoformat(),
            'end': end_date.isoformat(),
        },
        'metrics_calculated': [],
        'errors': [],
    }

    # Calculate diversity metrics (quarterly is standard for EEOC reporting)
    try:
        for scope in ['employees', 'applicants', 'hired']:
            diversity_service = DiversityAnalyticsService(date_filter, scope=scope)
            diversity_metric = diversity_service.calculate_diversity_metric()
            results['metrics_calculated'].append(f'diversity_{scope}')
    except Exception as e:
        logger.error(f"Failed to calculate quarterly diversity metrics: {e}")
        results['errors'].append(f'diversity: {str(e)}')

    # Calculate performance distribution (usually quarterly)
    try:
        hr_service = HRAnalyticsService(date_filter)
        perf_dist = hr_service.calculate_performance_distribution()
        results['metrics_calculated'].append('performance')
    except Exception as e:
        logger.error(f"Failed to calculate quarterly performance metrics: {e}")
        results['errors'].append(f'performance: {str(e)}')

    logger.info(f"Quarterly metrics calculation completed for Q{quarter} {year}")
    return results


# ==================== SOURCE EFFECTIVENESS TASKS ====================

@shared_task(bind=True, name='analytics.calculate_source_effectiveness')
def calculate_source_effectiveness(
    self,
    period_days: int = 90
) -> Dict[str, Any]:
    """
    Calculate source effectiveness metrics for all candidate sources.

    Args:
        period_days: Number of days to include in calculation.

    Returns:
        Dict containing calculation status.
    """
    end_date = timezone.now().date()
    start_date = end_date - timedelta(days=period_days)

    logger.info(f"Calculating source effectiveness for {start_date} to {end_date}")

    results = {
        'period': {
            'start': start_date.isoformat(),
            'end': end_date.isoformat(),
        },
        'sources_calculated': [],
        'errors': [],
    }

    try:
        from ats.models import Candidate, Application

        # Get all sources with applicants in period
        sources = Candidate.objects.filter(
            applications__applied_at__gte=start_date,
            applications__applied_at__lte=end_date,
        ).values_list('source', flat=True).distinct()

        for source in sources:
            try:
                # Get candidates from this source
                candidates = Candidate.objects.filter(
                    source=source,
                    applications__applied_at__gte=start_date,
                    applications__applied_at__lte=end_date,
                ).distinct()

                total_applicants = candidates.count()

                # Get application stats
                apps = Application.objects.filter(
                    candidate__in=candidates,
                    applied_at__gte=start_date,
                    applied_at__lte=end_date,
                )

                interviewed = apps.filter(
                    status__in=['interviewing', 'offer_pending', 'offer_extended', 'hired']
                ).count()

                hires = apps.filter(status='hired').count()

                # Calculate rates
                hire_rate = (hires / total_applicants * 100) if total_applicants > 0 else None

                # Create/update metric
                metric, created = SourceEffectivenessMetric.objects.update_or_create(
                    period_start=start_date,
                    period_end=end_date,
                    source=source,
                    source_detail='',
                    defaults={
                        'total_applicants': total_applicants,
                        'interviewed': interviewed,
                        'hires': hires,
                        'hire_rate': hire_rate,
                    }
                )

                metric.calculate_effectiveness_score()
                metric.save()

                results['sources_calculated'].append(source)

            except Exception as e:
                logger.error(f"Failed to calculate source effectiveness for {source}: {e}")
                results['errors'].append(f'{source}: {str(e)}')

    except Exception as e:
        logger.error(f"Failed to calculate source effectiveness: {e}")
        results['errors'].append(str(e))

    logger.info(f"Source effectiveness calculation completed")
    return results


# ==================== CLEANUP TASKS ====================

@shared_task(bind=True, name='analytics.cleanup_old_metrics')
def cleanup_old_metrics(self, days_to_keep: int = 365) -> Dict[str, Any]:
    """
    Clean up old metric records beyond retention period.

    Args:
        days_to_keep: Number of days of metrics to retain.

    Returns:
        Dict containing cleanup status.
    """
    cutoff_date = timezone.now().date() - timedelta(days=days_to_keep)

    logger.info(f"Cleaning up metrics older than {cutoff_date}")

    results = {
        'cutoff_date': cutoff_date.isoformat(),
        'deleted': {},
        'errors': [],
    }

    models_to_cleanup = [
        ('daily_recruitment', RecruitmentMetric.objects.filter(
            period_type='daily',
            period_start__lt=cutoff_date
        )),
        ('hiring_funnel', HiringFunnelMetric.objects.filter(
            period_start__lt=cutoff_date
        )),
        ('time_to_hire', TimeToHireMetric.objects.filter(
            period_start__lt=cutoff_date
        )),
    ]

    for name, queryset in models_to_cleanup:
        try:
            count, _ = queryset.delete()
            results['deleted'][name] = count
            logger.info(f"Deleted {count} old {name} records")
        except Exception as e:
            logger.error(f"Failed to cleanup {name}: {e}")
            results['errors'].append(f'{name}: {str(e)}')

    logger.info("Metrics cleanup completed")
    return results


@shared_task(bind=True, name='analytics.cleanup_stale_cache')
def cleanup_stale_cache(self) -> Dict[str, Any]:
    """
    Clean up stale dashboard cache entries.

    Returns:
        Dict containing cleanup status.
    """
    logger.info("Cleaning up stale dashboard cache")

    results = {
        'cleaned': [],
        'errors': [],
    }

    try:
        # Clean up database cache
        stale_caches = DashboardCache.objects.filter(
            expires_at__lt=timezone.now()
        )

        for cache_obj in stale_caches:
            cache_obj.is_stale = True
            cache_obj.save()
            results['cleaned'].append(cache_obj.dashboard_type)

        logger.info(f"Marked {len(results['cleaned'])} cache entries as stale")

    except Exception as e:
        logger.error(f"Failed to cleanup stale cache: {e}")
        results['errors'].append(str(e))

    return results


# ==================== NEW TASKS FOR CYCLE 7 ====================

@shared_task(bind=True, name='analytics.update_analytics')
def update_analytics(
    self,
    tenant_id: Optional[int] = None,
    period: str = 'month'
) -> Dict[str, Any]:
    """
    Refresh analytics for a specific tenant and period.

    Args:
        tenant_id: Optional tenant ID for multi-tenant scoping
        period: Period type ('day', 'week', 'month', 'quarter')

    Returns:
        Dict with analytics update results
    """
    from .models import TenantDashboardMetric, HiringAnalytics, RecruitingFunnel

    logger.info(f"Updating analytics for tenant {tenant_id}, period: {period}")

    date_filter = DateRangeFilter(period=period)

    results = {
        'tenant_id': tenant_id,
        'period': period,
        'metrics_updated': [],
        'errors': [],
    }

    try:
        from .services import AnalyticsService, RecruitmentAnalyticsService

        analytics_service = AnalyticsService(tenant_id, date_filter)
        recruitment_service = RecruitmentAnalyticsService(date_filter)

        # Time to hire
        try:
            tth_metrics = analytics_service.compute_time_to_hire()

            TenantDashboardMetric.objects.update_or_create(
                tenant_id=tenant_id,
                metric_type='time_to_hire',
                dimension='none',
                dimension_value='',
                period_start=date_filter.start_date,
                defaults={
                    'period_end': date_filter.end_date,
                    'value': tth_metrics.get('avg_days') or 0,
                    'is_stale': False,
                    'metadata': tth_metrics,
                }
            )
            results['metrics_updated'].append('time_to_hire')
        except Exception as e:
            logger.error(f"Failed to update time_to_hire: {e}")
            results['errors'].append(f'time_to_hire: {str(e)}')

        # Source effectiveness
        try:
            source_metrics = analytics_service.compute_source_effectiveness()

            for source_name, source_data in source_metrics.items():
                TenantDashboardMetric.objects.update_or_create(
                    tenant_id=tenant_id,
                    metric_type='source_quality',
                    dimension='source',
                    dimension_value=source_name,
                    period_start=date_filter.start_date,
                    defaults={
                        'period_end': date_filter.end_date,
                        'value': source_data.get('hire_rate') or 0,
                        'is_stale': False,
                        'metadata': source_data,
                    }
                )
            results['metrics_updated'].append('source_effectiveness')
        except Exception as e:
            logger.error(f"Failed to update source_effectiveness: {e}")
            results['errors'].append(f'source_effectiveness: {str(e)}')

        # Recruiter performance
        try:
            recruiter_metrics = analytics_service.compute_recruiter_performance()

            for recruiter_data in recruiter_metrics:
                TenantDashboardMetric.objects.update_or_create(
                    tenant_id=tenant_id,
                    metric_type='pipeline_velocity',
                    dimension='recruiter',
                    dimension_value=recruiter_data.get('name', ''),
                    period_start=date_filter.start_date,
                    defaults={
                        'period_end': date_filter.end_date,
                        'value': recruiter_data.get('hires', 0),
                        'is_stale': False,
                        'metadata': recruiter_data,
                    }
                )
            results['metrics_updated'].append('recruiter_performance')
        except Exception as e:
            logger.error(f"Failed to update recruiter_performance: {e}")
            results['errors'].append(f'recruiter_performance: {str(e)}')

        logger.info(f"Analytics update completed. Updated: {results['metrics_updated']}")

    except Exception as e:
        logger.error(f"Analytics update failed: {e}")
        results['errors'].append(str(e))

    return results


@shared_task(bind=True, name='analytics.daily_analytics_rollup')
def daily_analytics_rollup(self) -> Dict[str, Any]:
    """
    Daily analytics computation for all tenants.

    Aggregates the previous day's data into analytics records.

    Returns:
        Dict with rollup results
    """
    from .models import HiringAnalytics

    yesterday = timezone.now().date() - timedelta(days=1)
    date_filter = DateRangeFilter(start_date=yesterday, end_date=yesterday)

    logger.info(f"Running daily analytics rollup for {yesterday}")

    results = {
        'date': yesterday.isoformat(),
        'hiring_analytics_created': 0,
        'errors': [],
    }

    try:
        from ats.models import Application, Interview

        # Get yesterday's applications
        apps = Application.objects.filter(
            applied_at__date=yesterday
        )

        apps_received = apps.count()
        apps_qualified = apps.filter(status__in=['in_review', 'shortlisted', 'interviewing', 'hired']).count()

        interviews = Interview.objects.filter(scheduled_start__date=yesterday)
        interviews_scheduled = interviews.count()
        interviews_completed = interviews.filter(status='completed').count()

        # Get offers and hires
        offers_made = apps.filter(status='offer_extended').count()
        offers_accepted = apps.filter(status='hired').count()

        hires = apps.filter(status='hired', hired_at__date=yesterday).count()

        # Create aggregate HiringAnalytics
        analytics, created = HiringAnalytics.objects.update_or_create(
            tenant_id=None,  # Aggregate across all tenants
            department=None,
            period='daily',
            period_date=yesterday,
            defaults={
                'applications_received': apps_received,
                'applications_qualified': apps_qualified,
                'interviews_scheduled': interviews_scheduled,
                'interviews_completed': interviews_completed,
                'offers_made': offers_made,
                'offers_accepted': offers_accepted,
                'hires': hires,
            }
        )

        analytics.calculate_rates()
        analytics.save()

        results['hiring_analytics_created'] = 1 if created else 0
        results['stats'] = {
            'applications': apps_received,
            'interviews': interviews_scheduled,
            'hires': hires,
        }

        logger.info(f"Daily rollup completed for {yesterday}")

    except Exception as e:
        logger.error(f"Daily analytics rollup failed: {e}")
        results['errors'].append(str(e))

    return results


@shared_task(bind=True, name='analytics.compute_hiring_analytics')
def compute_hiring_analytics(
    self,
    department_id: Optional[int] = None,
    period: str = 'monthly',
    period_date: Optional[str] = None
) -> Dict[str, Any]:
    """
    Compute detailed hiring analytics for a department.

    Args:
        department_id: Optional department ID filter
        period: Period type ('daily', 'weekly', 'monthly', 'quarterly')
        period_date: Date string (YYYY-MM-DD) for the period

    Returns:
        Dict with computation results
    """
    from .models import HiringAnalytics

    if period_date:
        target_date = datetime.strptime(period_date, '%Y-%m-%d').date()
    else:
        target_date = timezone.now().date()

    # Determine date range based on period
    if period == 'daily':
        start_date = target_date
        end_date = target_date
    elif period == 'weekly':
        start_date = target_date - timedelta(days=target_date.weekday())
        end_date = start_date + timedelta(days=6)
    elif period == 'monthly':
        start_date = target_date.replace(day=1)
        if target_date.month == 12:
            end_date = date(target_date.year + 1, 1, 1) - timedelta(days=1)
        else:
            end_date = date(target_date.year, target_date.month + 1, 1) - timedelta(days=1)
    else:  # quarterly
        quarter = (target_date.month - 1) // 3 + 1
        start_month = (quarter - 1) * 3 + 1
        start_date = date(target_date.year, start_month, 1)
        if quarter == 4:
            end_date = date(target_date.year + 1, 1, 1) - timedelta(days=1)
        else:
            end_date = date(target_date.year, start_month + 3, 1) - timedelta(days=1)

    logger.info(f"Computing hiring analytics for {start_date} to {end_date}, department: {department_id}")

    results = {
        'period': period,
        'start_date': start_date.isoformat(),
        'end_date': end_date.isoformat(),
        'department_id': department_id,
        'computed': False,
    }

    try:
        from ats.models import Application, Interview, Offer

        # Build base query
        apps_qs = Application.objects.filter(
            applied_at__date__gte=start_date,
            applied_at__date__lte=end_date,
        )

        if department_id:
            apps_qs = apps_qs.filter(job__category_id=department_id)

        # Calculate metrics
        apps_received = apps_qs.count()
        apps_qualified = apps_qs.filter(
            status__in=['in_review', 'shortlisted', 'interviewing', 'offer_pending', 'offer_extended', 'hired']
        ).count()

        interviews_qs = Interview.objects.filter(
            scheduled_start__date__gte=start_date,
            scheduled_start__date__lte=end_date,
        )
        if department_id:
            interviews_qs = interviews_qs.filter(application__job__category_id=department_id)

        interviews_scheduled = interviews_qs.count()
        interviews_completed = interviews_qs.filter(status='completed').count()

        # Offers
        offers_qs = Offer.objects.filter(
            created_at__date__gte=start_date,
            created_at__date__lte=end_date,
        )
        if department_id:
            offers_qs = offers_qs.filter(job__category_id=department_id)

        offers_made = offers_qs.count()
        offers_accepted = offers_qs.filter(status='accepted').count()
        offers_declined = offers_qs.filter(status='declined').count()

        # Hires
        hired_apps = apps_qs.filter(status='hired', hired_at__isnull=False)
        hires = hired_apps.count()

        # Time to hire
        time_to_hire_values = []
        for app in hired_apps:
            if app.hired_at and app.applied_at:
                days = (app.hired_at - app.applied_at).days
                time_to_hire_values.append(days)

        avg_time_to_hire = None
        if time_to_hire_values:
            import statistics
            avg_time_to_hire = statistics.mean(time_to_hire_values)

        # Get department name
        department_name = ''
        if department_id:
            from hr_core.models import Department
            try:
                department_name = Department.objects.get(id=department_id).name
            except Department.DoesNotExist:
                pass

        # Save analytics
        analytics, created = HiringAnalytics.objects.update_or_create(
            tenant_id=None,
            department_id=department_id,
            period=period,
            period_date=start_date,
            defaults={
                'department_name': department_name,
                'applications_received': apps_received,
                'applications_qualified': apps_qualified,
                'interviews_scheduled': interviews_scheduled,
                'interviews_completed': interviews_completed,
                'offers_made': offers_made,
                'offers_accepted': offers_accepted,
                'offers_declined': offers_declined,
                'hires': hires,
                'avg_time_to_hire': avg_time_to_hire,
            }
        )

        analytics.calculate_rates()
        analytics.save()

        results['computed'] = True
        results['metrics'] = {
            'applications': apps_received,
            'interviews': interviews_scheduled,
            'offers': offers_made,
            'hires': hires,
            'avg_time_to_hire': avg_time_to_hire,
        }

        logger.info(f"Hiring analytics computed for {period} ending {end_date}")

    except Exception as e:
        logger.error(f"Failed to compute hiring analytics: {e}")
        results['error'] = str(e)

    return results


@shared_task(bind=True, name='analytics.compute_recruiting_funnel')
def compute_recruiting_funnel(
    self,
    pipeline_id: Optional[int] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
) -> Dict[str, Any]:
    """
    Compute recruiting funnel metrics for a pipeline.

    Args:
        pipeline_id: Optional pipeline ID (None for all pipelines)
        start_date: Start date string (YYYY-MM-DD)
        end_date: End date string (YYYY-MM-DD)

    Returns:
        Dict with funnel computation results
    """
    from .models import RecruitingFunnel

    if start_date:
        start = datetime.strptime(start_date, '%Y-%m-%d').date()
    else:
        start = timezone.now().date() - timedelta(days=30)

    if end_date:
        end = datetime.strptime(end_date, '%Y-%m-%d').date()
    else:
        end = timezone.now().date()

    logger.info(f"Computing recruiting funnel for pipeline {pipeline_id}, {start} to {end}")

    results = {
        'pipeline_id': pipeline_id,
        'start_date': start.isoformat(),
        'end_date': end.isoformat(),
        'computed': False,
    }

    try:
        from ats.models import Application, Pipeline

        # Get applications
        apps_qs = Application.objects.filter(
            applied_at__date__gte=start,
            applied_at__date__lte=end,
        )

        pipeline_name = 'All Pipelines'
        if pipeline_id:
            apps_qs = apps_qs.filter(job__pipeline_id=pipeline_id)
            try:
                pipeline_name = Pipeline.objects.get(id=pipeline_id).name
            except Pipeline.DoesNotExist:
                pass

        # Calculate stage metrics
        total = apps_qs.count()
        stages = {}

        # Define standard funnel stages
        stage_statuses = [
            ('Applied', ['new', 'in_review']),
            ('Screened', ['shortlisted']),
            ('Interviewing', ['interviewing']),
            ('Offered', ['offer_pending', 'offer_extended']),
            ('Hired', ['hired']),
        ]

        prev_count = total
        for stage_name, statuses in stage_statuses:
            count = apps_qs.filter(status__in=statuses).count()

            # For later stages, count also includes progression
            if stage_name != 'Applied':
                count = apps_qs.filter(
                    status__in=[s for _, ss in stage_statuses[stage_statuses.index((stage_name, statuses)):] for s in ss]
                ).count()

            conversion = (count / prev_count * 100) if prev_count > 0 else 0

            stages[stage_name] = {
                'count': count,
                'conversion_rate': round(conversion, 2),
                'avg_time_days': None,  # Would require stage change tracking
            }

            prev_count = count if count > 0 else prev_count

        # Calculate overall conversion
        hired_count = stages.get('Hired', {}).get('count', 0)
        overall_conversion = (hired_count / total * 100) if total > 0 else 0

        # Save funnel
        funnel, created = RecruitingFunnel.objects.update_or_create(
            tenant_id=None,
            pipeline_id=pipeline_id,
            period_start=start,
            period_end=end,
            defaults={
                'pipeline_name': pipeline_name,
                'stages': stages,
                'overall_conversion': round(overall_conversion, 2),
                'total_candidates': total,
                'total_hires': hired_count,
            }
        )

        funnel.identify_bottleneck()
        funnel.save()

        results['computed'] = True
        results['stages'] = stages
        results['overall_conversion'] = overall_conversion

        logger.info(f"Recruiting funnel computed for pipeline {pipeline_id}")

    except Exception as e:
        logger.error(f"Failed to compute recruiting funnel: {e}")
        results['error'] = str(e)

    return results


# ==================== CELERY BEAT SCHEDULE HELPER ====================
# Add these schedules to your CELERY_BEAT_SCHEDULE in settings.py:
#
# CELERY_BEAT_SCHEDULE = {
#     'calculate-daily-metrics': {
#         'task': 'analytics.calculate_daily_metrics',
#         'schedule': crontab(hour=1, minute=0),  # 1:00 AM daily
#     },
#     'calculate-hourly-metrics': {
#         'task': 'analytics.calculate_hourly_metrics',
#         'schedule': crontab(minute=5),  # Every hour at :05
#     },
#     'generate-weekly-report': {
#         'task': 'analytics.generate_weekly_report',
#         'schedule': crontab(hour=6, minute=0, day_of_week=1),  # Monday 6 AM
#     },
#     'refresh-dashboard-cache': {
#         'task': 'analytics.refresh_dashboard_cache',
#         'schedule': timedelta(minutes=5),  # Every 5 minutes
#         'kwargs': {'dashboard_type': 'all', 'force': False},
#     },
#     'calculate-monthly-metrics': {
#         'task': 'analytics.calculate_monthly_metrics',
#         'schedule': crontab(hour=2, minute=0, day_of_month=1),  # 1st of month
#     },
#     'calculate-quarterly-metrics': {
#         'task': 'analytics.calculate_quarterly_metrics',
#         'schedule': crontab(hour=3, minute=0, day_of_month=1, month_of_year='1,4,7,10'),
#     },
#     'calculate-source-effectiveness': {
#         'task': 'analytics.calculate_source_effectiveness',
#         'schedule': crontab(hour=4, minute=0, day_of_week=0),  # Sunday 4 AM
#     },
#     'cleanup-old-metrics': {
#         'task': 'analytics.cleanup_old_metrics',
#         'schedule': crontab(hour=5, minute=0, day_of_month=1),  # 1st of month
#     },
#     'cleanup-stale-cache': {
#         'task': 'analytics.cleanup_stale_cache',
#         'schedule': timedelta(hours=1),  # Every hour
#     },
#     # NEW CYCLE 7 TASKS
#     'daily-analytics-rollup': {
#         'task': 'analytics.daily_analytics_rollup',
#         'schedule': crontab(hour=0, minute=30),  # 12:30 AM daily
#     },
#     'update-analytics-daily': {
#         'task': 'analytics.update_analytics',
#         'schedule': crontab(hour=2, minute=30),  # 2:30 AM daily
#         'kwargs': {'period': 'month'},
#     },
#     'compute-recruiting-funnel-weekly': {
#         'task': 'analytics.compute_recruiting_funnel',
#         'schedule': crontab(hour=3, minute=30, day_of_week=1),  # Monday 3:30 AM
#     },
# }
