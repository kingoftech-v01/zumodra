"""
Dashboard Template Views - Frontend views for the main dashboard.

This module implements template-based views for:
- Main dashboard with widgets
- Global search with HTMX support
- Quick stats and metrics
- Recent activity feed
"""

import logging
from datetime import timedelta

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count, Q, Avg
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from django.views import View
from django.views.generic import TemplateView, ListView

from tenants.mixins import TenantViewMixin

logger = logging.getLogger(__name__)


class DashboardView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """
    Main dashboard view with widgets and metrics.

    Displays:
    - Quick stats (open jobs, candidates, interviews, etc.)
    - Recent activity
    - Upcoming interviews
    - Pipeline overview
    - Performance metrics
    """
    template_name = 'dashboard/index.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.get_tenant()
        user = self.request.user

        # Handle public users (no tenant or public schema)
        if not tenant or (hasattr(tenant, 'schema_name') and tenant.schema_name == 'public'):
            # Use public user dashboard template
            self.template_name = 'dashboard/public_user_dashboard.html'

            # Public user context
            context['is_public_user'] = True
            context['stats'] = {
                'profile_completion': self._calculate_profile_completion(user),
            }
            context['recent_activity'] = []
            context['recommended_jobs'] = self._get_recommended_jobs(user)[:5]
            context['show_tenant_invite'] = True
            context['mfa_enabled'] = self._user_has_mfa(user)
            context['mfa_required_date'] = user.date_joined + timedelta(days=30)
            return context

        # Import models here to avoid circular imports
        from ats.models import JobPosting, Candidate, Application, Interview
        from hr_core.models import Employee, TimeOffRequest
        from notifications.models import Notification

        # Get date ranges
        now = timezone.now()
        today = now.date()
        week_ago = today - timedelta(days=7)
        month_ago = today - timedelta(days=30)

        # Quick stats - ATS
        try:
            open_jobs = JobPosting.objects.filter(
                tenant=tenant,
                status='open'
            ).count()

            total_candidates = Candidate.objects.filter(
                tenant=tenant
            ).count()

            new_candidates_week = Candidate.objects.filter(
                tenant=tenant,
                created_at__date__gte=week_ago
            ).count()

            active_applications = Application.objects.filter(
                tenant=tenant,
                status__in=['in_review', 'interviewing', 'offer']
            ).count()

            pending_interviews = Interview.objects.filter(
                application__tenant=tenant,
                status__in=['scheduled', 'confirmed'],
                scheduled_start__gt=now
            ).count()
        except Exception as e:
            logger.warning(f"Error fetching ATS stats: {e}")
            open_jobs = 0
            total_candidates = 0
            new_candidates_week = 0
            active_applications = 0
            pending_interviews = 0

        # Quick stats - HR
        try:
            total_employees = Employee.objects.filter(
                user__tenantuser__tenant=tenant,
                status='active'
            ).count()

            pending_time_off = TimeOffRequest.objects.filter(
                employee__user__tenantuser__tenant=tenant,
                status='pending'
            ).count()
        except Exception as e:
            logger.warning(f"Error fetching HR stats: {e}")
            total_employees = 0
            pending_time_off = 0

        # Dashboard stats
        context['stats'] = {
            'open_jobs': open_jobs,
            'total_candidates': total_candidates,
            'new_candidates_week': new_candidates_week,
            'active_applications': active_applications,
            'pending_interviews': pending_interviews,
            'total_employees': total_employees,
            'pending_time_off': pending_time_off,
        }

        # Upcoming interviews (next 7 days)
        try:
            week_from_now = now + timedelta(days=7)
            upcoming_interviews = Interview.objects.filter(
                application__tenant=tenant,
                status__in=['scheduled', 'confirmed'],
                scheduled_start__range=(now, week_from_now)
            ).select_related(
                'application__candidate',
                'application__job'
            ).order_by('scheduled_start')[:5]
            context['upcoming_interviews'] = upcoming_interviews
        except Exception as e:
            logger.warning(f"Error fetching upcoming interviews: {e}")
            context['upcoming_interviews'] = []

        # Recent activity (notifications)
        try:
            recent_notifications = Notification.objects.filter(
                recipient=user,
                created_at__gte=timezone.now() - timedelta(days=7)
            ).order_by('-created_at')[:10]
            context['recent_activity'] = recent_notifications
        except Exception as e:
            logger.warning(f"Error fetching recent activity: {e}")
            context['recent_activity'] = []

        # Unread notification count
        try:
            unread_count = Notification.objects.filter(
                recipient=user,
                is_read=False
            ).count()
            context['unread_notifications'] = unread_count
        except Exception:
            context['unread_notifications'] = 0

        return context

    def _calculate_profile_completion(self, user):
        """
        Calculate profile completion percentage for public users.

        Checks key profile fields and returns percentage complete.
        """
        from accounts.models import UserProfile

        try:
            profile = user.userprofile
            fields = ['bio', 'phone', 'location', 'linkedin_url']
            completed = sum(1 for field in fields if getattr(profile, field, None))
            return int((completed / len(fields)) * 100)
        except UserProfile.DoesNotExist:
            return 0
        except Exception as e:
            logger.warning(f"Error calculating profile completion: {e}")
            return 0

    def _get_recommended_jobs(self, user):
        """
        Get recommended jobs from PublicJobCatalog for public users.

        Returns active public job listings ordered by creation date.
        """
        try:
            from tenants.models import PublicJobCatalog
            return PublicJobCatalog.objects.filter(is_active=True).order_by('-created_at')
        except Exception as e:
            logger.warning(f"Error fetching recommended jobs: {e}")
            return PublicJobCatalog.objects.none()

    def _user_has_mfa(self, user):
        """
        Check if user has MFA enabled.

        Supports django-allauth MFA (TOTP and WebAuthn).
        """
        try:
            if hasattr(user, 'mfa_authenticators'):
                return user.mfa_authenticators.filter(is_active=True).exists()
        except Exception as e:
            logger.warning(f"Error checking MFA status: {e}")
        return False


class SearchView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Global search endpoint with HTMX support.

    Searches across:
    - Jobs
    - Candidates
    - Employees
    - Applications

    Returns partial template for HTMX requests.
    """

    def get(self, request):
        query = request.GET.get('q', '').strip()
        tenant = self.get_tenant()

        # Initialize empty results
        results = {
            'jobs': [],
            'candidates': [],
            'employees': [],
            'applications': [],
            'query': query,
        }

        if not query or len(query) < 2 or not tenant:
            if request.headers.get('HX-Request'):
                return render(request, 'dashboard/partials/_search_results.html', results)
            return JsonResponse(results)

        # Import models
        from ats.models import JobPosting, Candidate, Application
        from hr_core.models import Employee

        # Search jobs
        try:
            jobs = JobPosting.objects.filter(
                tenant=tenant
            ).filter(
                Q(title__icontains=query) |
                Q(description__icontains=query) |
                Q(requirements__icontains=query)
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
                Q(email__icontains=query) |
                Q(current_title__icontains=query)
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
                Q(user__email__icontains=query) |
                Q(job_title__icontains=query) |
                Q(employee_id__icontains=query)
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

        # Calculate total results
        results['total_count'] = (
            len(results['jobs']) +
            len(results['candidates']) +
            len(results['employees']) +
            len(results['applications'])
        )

        # Return HTMX partial or JSON
        if request.headers.get('HX-Request'):
            return render(request, 'dashboard/partials/_search_results.html', results)

        return JsonResponse(results)


class QuickStatsView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for refreshing dashboard quick stats.
    """

    def get(self, request):
        tenant = self.get_tenant()

        if not tenant:
            return HttpResponse(status=204)

        from ats.models import JobPosting, Candidate, Application, Interview
        from hr_core.models import Employee, TimeOffRequest

        now = timezone.now()
        week_ago = now.date() - timedelta(days=7)

        stats = {
            'open_jobs': JobPosting.objects.filter(tenant=tenant, status='open').count(),
            'new_candidates_week': Candidate.objects.filter(
                tenant=tenant, created_at__date__gte=week_ago
            ).count(),
            'active_applications': Application.objects.filter(
                tenant=tenant, status__in=['in_review', 'interviewing', 'offer']
            ).count(),
            'pending_interviews': Interview.objects.filter(
                application__tenant=tenant,
                status__in=['scheduled', 'confirmed'],
                scheduled_start__gt=now
            ).count(),
        }

        return render(request, 'dashboard/partials/_quick_stats.html', {'stats': stats})


class RecentActivityView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for recent activity feed.
    """

    def get(self, request):
        from notifications.models import Notification

        notifications = Notification.objects.filter(
            recipient=request.user,
            created_at__gte=timezone.now() - timedelta(days=7)
        ).order_by('-created_at')[:10]

        return render(request, 'dashboard/partials/_recent_activity.html', {
            'recent_activity': notifications
        })


class UpcomingInterviewsView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for upcoming interviews widget.
    """

    def get(self, request):
        tenant = self.get_tenant()

        if not tenant:
            return HttpResponse(status=204)

        from ats.models import Interview

        now = timezone.now()
        week_from_now = now + timedelta(days=7)

        interviews = Interview.objects.filter(
            application__tenant=tenant,
            status__in=['scheduled', 'confirmed'],
            scheduled_start__range=(now, week_from_now)
        ).select_related(
            'application__candidate',
            'application__job'
        ).order_by('scheduled_start')[:5]

        return render(request, 'dashboard/partials/_upcoming_interviews.html', {
            'upcoming_interviews': interviews
        })


class AccountSettingsView(View):
    """Account settings placeholder view."""
    
    def get(self, request, *args, **kwargs):
        from django.shortcuts import redirect
        # Redirect to allauth account settings for now
        return redirect('account_email')


class HelpView(TemplateView):
    """Help and support view."""
    template_name = 'dashboard/help.html'
