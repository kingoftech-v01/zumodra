"""
Dashboard API ViewSets - DRF ViewSets for dashboard data.

Caching:
- Dashboard overview cached for 2 minutes (user-specific)
- Quick stats cached for 5 minutes
- Upcoming interviews cached for 2 minutes
- ATS metrics cached for 5 minutes
- HR metrics cached for 5 minutes

Note: Search and Recent Activity are NOT cached as they are
user-specific or query-dependent and need real-time data.
"""

import logging
from datetime import timedelta

from django.db.models import Count, Q, Avg
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from core.cache import TenantCache
from tenants.mixins import TenantViewMixin

from .serializers import (
    DashboardStatsSerializer,
    QuickStatsSerializer,
    SearchResultsSerializer,
    UpcomingInterviewSerializer,
    RecentActivitySerializer,
    DashboardOverviewSerializer,
    ATSMetricsSerializer,
    HRMetricsSerializer,
)

logger = logging.getLogger(__name__)


class TenantAPIViewMixin(TenantViewMixin):
    """Mixin to provide tenant context to API views."""

    def get_tenant(self):
        """Get tenant from request."""
        if hasattr(self.request, 'tenant'):
            return self.request.tenant
        return None


class DashboardOverviewView(TenantAPIViewMixin, APIView):
    """
    API endpoint for complete dashboard overview.

    Returns all dashboard data in one request.
    Cached for 2 minutes per user.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        tenant = self.get_tenant()
        user = request.user

        if not tenant:
            return Response(
                {'error': 'Tenant context required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check cache first (user-specific)
        tenant_cache = TenantCache(tenant.id)
        cache_key = f"dashboard:overview:user_{user.id}"
        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        # Import models
        from jobs.models import JobPosting, Candidate, Application, Interview
        from hr_core.models import Employee, TimeOffRequest
        from notifications.models import Notification

        now = timezone.now()
        today = now.date()
        week_ago = today - timedelta(days=7)

        # Stats
        try:
            stats = {
                'open_jobs': JobPosting.objects.filter(
                    tenant=tenant, status='open'
                ).count(),
                'total_candidates': Candidate.objects.filter(
                    tenant=tenant
                ).count(),
                'new_candidates_week': Candidate.objects.filter(
                    tenant=tenant, created_at__date__gte=week_ago
                ).count(),
                'active_applications': Application.objects.filter(
                    tenant=tenant,
                    status__in=['in_review', 'interviewing', 'offer']
                ).count(),
                'pending_interviews': Interview.objects.filter(
                    application__tenant=tenant,
                    status__in=['scheduled', 'confirmed'],
                    scheduled_start__gt=now
                ).count(),
                'total_employees': Employee.objects.filter(
                    user__tenantuser__tenant=tenant,
                    status='active'
                ).count(),
                'pending_time_off': TimeOffRequest.objects.filter(
                    employee__user__tenantuser__tenant=tenant,
                    status='pending'
                ).count(),
            }
        except Exception as e:
            logger.error(f"Error fetching dashboard stats: {e}")
            stats = {
                'open_jobs': 0,
                'total_candidates': 0,
                'new_candidates_week': 0,
                'active_applications': 0,
                'pending_interviews': 0,
                'total_employees': 0,
                'pending_time_off': 0,
            }

        # Upcoming interviews
        try:
            week_from_now = now + timedelta(days=7)
            interviews = Interview.objects.filter(
                application__tenant=tenant,
                status__in=['scheduled', 'confirmed'],
                scheduled_start__range=(now, week_from_now)
            ).select_related(
                'application__candidate',
                'application__job'
            ).order_by('scheduled_start')[:5]

            upcoming = [
                {
                    'id': i.id,
                    'candidate_name': i.application.candidate.full_name,
                    'candidate_email': i.application.candidate.email,
                    'job_title': i.application.job.title if i.application.job else 'N/A',
                    'scheduled_start': i.scheduled_start,
                    'scheduled_end': i.scheduled_end,
                    'status': i.status,
                    'interview_type': getattr(i, 'interview_type', None),
                }
                for i in interviews
            ]
        except Exception as e:
            logger.error(f"Error fetching interviews: {e}")
            upcoming = []

        # Recent activity
        try:
            notifications = Notification.objects.filter(
                recipient=user,
                created_at__gte=now - timedelta(days=7)
            ).order_by('-created_at')[:10]

            activity = [
                {
                    'id': n.id,
                    'title': n.title,
                    'message': n.message,
                    'notification_type': n.notification_type,
                    'is_read': n.is_read,
                    'created_at': n.created_at,
                    'action_url': getattr(n, 'action_url', None),
                }
                for n in notifications
            ]

            unread_count = Notification.objects.filter(
                recipient=user, is_read=False
            ).count()
        except Exception as e:
            logger.error(f"Error fetching activity: {e}")
            activity = []
            unread_count = 0

        data = {
            'stats': stats,
            'upcoming_interviews': upcoming,
            'recent_activity': activity,
            'unread_notifications': unread_count,
        }

        serializer = DashboardOverviewSerializer(data)

        # Cache for 2 minutes
        tenant_cache.set(cache_key, serializer.data, timeout=120)

        return Response(serializer.data)


class QuickStatsView(TenantAPIViewMixin, APIView):
    """
    API endpoint for quick stats widget.

    Cached for 5 minutes.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        tenant = self.get_tenant()

        if not tenant:
            return Response(
                {'error': 'Tenant context required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check cache first
        tenant_cache = TenantCache(tenant.id)
        cache_key = "dashboard:quick_stats"
        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        from jobs.models import JobPosting, Candidate, Application, Interview

        now = timezone.now()
        week_ago = now.date() - timedelta(days=7)

        stats = {
            'open_jobs': JobPosting.objects.filter(
                tenant=tenant, status='open'
            ).count(),
            'new_candidates_week': Candidate.objects.filter(
                tenant=tenant, created_at__date__gte=week_ago
            ).count(),
            'active_applications': Application.objects.filter(
                tenant=tenant,
                status__in=['in_review', 'interviewing', 'offer']
            ).count(),
            'pending_interviews': Interview.objects.filter(
                application__tenant=tenant,
                status__in=['scheduled', 'confirmed'],
                scheduled_start__gt=now
            ).count(),
        }

        serializer = QuickStatsSerializer(stats)

        # Cache for 5 minutes
        tenant_cache.set(cache_key, serializer.data, timeout=300)

        return Response(serializer.data)


class SearchView(TenantAPIViewMixin, APIView):
    """
    API endpoint for global search.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        query = request.query_params.get('q', '').strip()
        tenant = self.get_tenant()

        if not query or len(query) < 2 or not tenant:
            return Response({
                'query': query,
                'jobs': [],
                'candidates': [],
                'employees': [],
                'applications': [],
                'total_count': 0,
            })

        from jobs.models import JobPosting, Candidate, Application
        from hr_core.models import Employee

        results = {
            'query': query,
            'jobs': [],
            'candidates': [],
            'employees': [],
            'applications': [],
        }

        # Search jobs
        try:
            jobs = JobPosting.objects.filter(
                tenant=tenant
            ).filter(
                Q(title__icontains=query) |
                Q(description__icontains=query)
            )[:5]
            results['jobs'] = list(jobs.values('id', 'uuid', 'title', 'status', 'location'))
        except Exception as e:
            logger.warning(f"Error searching jobs: {e}")

        # Search candidates
        try:
            candidates = Candidate.objects.filter(
                tenant=tenant
            ).filter(
                Q(first_name__icontains=query) |
                Q(last_name__icontains=query) |
                Q(email__icontains=query)
            )[:5]
            results['candidates'] = list(candidates.values(
                'id', 'uuid', 'first_name', 'last_name', 'email', 'current_title'
            ))
        except Exception as e:
            logger.warning(f"Error searching candidates: {e}")

        # Search employees
        try:
            employees = Employee.objects.filter(
                user__tenantuser__tenant=tenant
            ).filter(
                Q(user__first_name__icontains=query) |
                Q(user__last_name__icontains=query) |
                Q(user__email__icontains=query)
            )[:5]
            results['employees'] = [
                {
                    'id': e.id,
                    'uuid': str(e.uuid),
                    'name': e.full_name,
                    'email': e.user.email,
                    'job_title': e.job_title,
                    'employee_id': e.employee_id,
                }
                for e in employees
            ]
        except Exception as e:
            logger.warning(f"Error searching employees: {e}")

        # Search applications
        try:
            applications = Application.objects.filter(
                tenant=tenant
            ).filter(
                Q(candidate__first_name__icontains=query) |
                Q(candidate__last_name__icontains=query) |
                Q(job__title__icontains=query)
            ).select_related('candidate', 'job')[:5]
            results['applications'] = [
                {
                    'id': a.id,
                    'uuid': str(a.uuid),
                    'candidate_name': a.candidate.full_name,
                    'job_title': a.job.title if a.job else 'N/A',
                    'status': a.status,
                }
                for a in applications
            ]
        except Exception as e:
            logger.warning(f"Error searching applications: {e}")

        results['total_count'] = (
            len(results['jobs']) +
            len(results['candidates']) +
            len(results['employees']) +
            len(results['applications'])
        )

        serializer = SearchResultsSerializer(results)
        return Response(serializer.data)


class UpcomingInterviewsView(TenantAPIViewMixin, APIView):
    """
    API endpoint for upcoming interviews.

    Cached for 2 minutes (short TTL for scheduling accuracy).
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        tenant = self.get_tenant()

        if not tenant:
            return Response({'interviews': []})

        days = int(request.query_params.get('days', 7))
        limit = int(request.query_params.get('limit', 10))

        # Check cache first
        tenant_cache = TenantCache(tenant.id)
        cache_key = f"dashboard:upcoming_interviews:days_{days}:limit_{limit}"
        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        from jobs.models import Interview

        now = timezone.now()
        end_date = now + timedelta(days=days)

        interviews = Interview.objects.filter(
            application__tenant=tenant,
            status__in=['scheduled', 'confirmed'],
            scheduled_start__range=(now, end_date)
        ).select_related(
            'application__candidate',
            'application__job'
        ).order_by('scheduled_start')[:limit]

        data = [
            {
                'id': i.id,
                'candidate_name': i.application.candidate.full_name,
                'candidate_email': i.application.candidate.email,
                'job_title': i.application.job.title if i.application.job else 'N/A',
                'scheduled_start': i.scheduled_start,
                'scheduled_end': i.scheduled_end,
                'status': i.status,
                'interview_type': getattr(i, 'interview_type', None),
            }
            for i in interviews
        ]

        serializer = UpcomingInterviewSerializer(data, many=True)
        response_data = {'interviews': serializer.data}

        # Cache for 2 minutes
        tenant_cache.set(cache_key, response_data, timeout=120)

        return Response(response_data)


class RecentActivityView(TenantAPIViewMixin, APIView):
    """
    API endpoint for recent activity.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from notifications.models import Notification

        days = int(request.query_params.get('days', 7))
        limit = int(request.query_params.get('limit', 20))

        notifications = Notification.objects.filter(
            recipient=request.user,
            created_at__gte=timezone.now() - timedelta(days=days)
        ).order_by('-created_at')[:limit]

        data = [
            {
                'id': n.id,
                'title': n.title,
                'message': n.message,
                'notification_type': n.notification_type,
                'is_read': n.is_read,
                'created_at': n.created_at,
                'action_url': getattr(n, 'action_url', None),
            }
            for n in notifications
        ]

        serializer = RecentActivitySerializer(data, many=True)
        return Response({'activity': serializer.data})


class ATSMetricsView(TenantAPIViewMixin, APIView):
    """
    API endpoint for ATS-specific metrics.

    Cached for 5 minutes.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        tenant = self.get_tenant()

        if not tenant:
            return Response(
                {'error': 'Tenant context required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check cache first
        tenant_cache = TenantCache(tenant.id)
        cache_key = "dashboard:ats_metrics"
        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        from jobs.models import JobPosting, Candidate, Application

        # Job counts
        all_jobs = JobPosting.objects.filter(tenant=tenant)
        total_jobs = all_jobs.count()
        open_jobs = all_jobs.filter(status='open').count()
        closed_jobs = all_jobs.filter(status='closed').count()

        # Candidate and application counts
        total_candidates = Candidate.objects.filter(tenant=tenant).count()
        total_applications = Application.objects.filter(tenant=tenant).count()

        # Applications by status
        by_status = Application.objects.filter(
            tenant=tenant
        ).values('status').annotate(count=Count('id'))

        status_dict = {item['status']: item['count'] for item in by_status}

        metrics = {
            'total_jobs': total_jobs,
            'open_jobs': open_jobs,
            'closed_jobs': closed_jobs,
            'total_candidates': total_candidates,
            'total_applications': total_applications,
            'applications_by_status': status_dict,
            'average_time_to_hire': None,  # Would require date tracking
            'conversion_rate': None,  # Would require more complex calculation
        }

        serializer = ATSMetricsSerializer(metrics)

        # Cache for 5 minutes
        tenant_cache.set(cache_key, serializer.data, timeout=300)

        return Response(serializer.data)


class HRMetricsView(TenantAPIViewMixin, APIView):
    """
    API endpoint for HR-specific metrics.

    Cached for 5 minutes.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        tenant = self.get_tenant()

        if not tenant:
            return Response(
                {'error': 'Tenant context required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check cache first
        tenant_cache = TenantCache(tenant.id)
        cache_key = "dashboard:hr_metrics"
        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        from hr_core.models import Employee, TimeOffRequest

        # Employee counts
        employees = Employee.objects.filter(user__tenantuser__tenant=tenant)
        total = employees.count()
        active = employees.filter(status='active').count()

        # On leave
        today = timezone.now().date()
        on_leave = TimeOffRequest.objects.filter(
            employee__user__tenantuser__tenant=tenant,
            status='approved',
            start_date__lte=today,
            end_date__gte=today
        ).values('employee').distinct().count()

        # Pending requests
        pending = TimeOffRequest.objects.filter(
            employee__user__tenantuser__tenant=tenant,
            status='pending'
        ).count()

        # By department
        by_dept = employees.filter(
            status='active'
        ).values('department__name').annotate(
            count=Count('id')
        ).order_by('-count')

        metrics = {
            'total_employees': total,
            'active_employees': active,
            'employees_on_leave': on_leave,
            'pending_time_off_requests': pending,
            'headcount_by_department': list(by_dept),
        }

        serializer = HRMetricsSerializer(metrics)

        # Cache for 5 minutes
        tenant_cache.set(cache_key, serializer.data, timeout=300)

        return Response(serializer.data)
