"""
Security App Views - Template views for security dashboard.

Provides dashboard views for:
- Audit log monitoring
- Security events
- Failed login tracking
- Session management
"""

from datetime import timedelta

from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Count
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.generic import TemplateView

from .models import (
    AuditLogEntry,
    SecurityEvent,
    FailedLoginAttempt,
    UserSession,
    PasswordResetRequest,
)


@method_decorator(staff_member_required, name='dispatch')
class SecurityDashboardView(TemplateView):
    """
    Security dashboard with monitoring overview.
    """
    template_name = 'security/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        days = int(self.request.GET.get('days', 7))
        since = timezone.now() - timedelta(days=days)
        context['period_days'] = days

        today = timezone.now().date()
        today_start = timezone.make_aware(
            timezone.datetime.combine(today, timezone.datetime.min.time())
        )

        # Summary stats
        context['stats'] = {
            'total_audit_logs': AuditLogEntry.objects.count(),
            'audit_logs_today': AuditLogEntry.objects.filter(timestamp__gte=today_start).count(),
            'security_events_today': SecurityEvent.objects.filter(timestamp__gte=today_start).count(),
            'failed_logins_today': FailedLoginAttempt.objects.filter(attempted_at__gte=today_start).count(),
            'active_sessions': UserSession.objects.filter(is_active=True).count(),
            'pending_password_resets': PasswordResetRequest.objects.filter(used=False).count(),
        }

        # Recent audit logs
        context['recent_audit_logs'] = AuditLogEntry.objects.select_related(
            'actor'
        ).order_by('-timestamp')[:10]

        # Recent security events
        context['recent_security_events'] = SecurityEvent.objects.select_related(
            'user'
        ).order_by('-timestamp')[:10]

        # Recent failed logins
        context['recent_failed_logins'] = FailedLoginAttempt.objects.order_by(
            '-attempted_at'
        )[:10]

        # Audit logs by action
        context['audit_by_action'] = AuditLogEntry.objects.filter(
            timestamp__gte=since
        ).values('action').annotate(
            count=Count('id')
        ).order_by('-count')

        # Audit logs by model
        context['audit_by_model'] = AuditLogEntry.objects.filter(
            timestamp__gte=since
        ).values('model_name').annotate(
            count=Count('id')
        ).order_by('-count')[:10]

        # Security events by type
        context['events_by_type'] = SecurityEvent.objects.filter(
            timestamp__gte=since
        ).values('event_type').annotate(
            count=Count('id')
        ).order_by('-count')

        # Failed logins by IP (suspicious activity)
        context['failed_by_ip'] = FailedLoginAttempt.objects.filter(
            attempted_at__gte=since
        ).values('ip_address').annotate(
            count=Count('id')
        ).filter(count__gte=3).order_by('-count')[:10]

        # Active sessions summary
        context['sessions_by_user'] = UserSession.objects.filter(
            is_active=True
        ).values('user__email').annotate(
            count=Count('id')
        ).order_by('-count')[:10]

        return context


@method_decorator(staff_member_required, name='dispatch')
class AuditLogsListView(TemplateView):
    """Audit logs list view."""
    template_name = 'security/audit_logs_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        logs = AuditLogEntry.objects.select_related('actor').order_by('-timestamp')

        # Apply filters
        action = self.request.GET.get('action')
        if action:
            logs = logs.filter(action=action)

        model = self.request.GET.get('model')
        if model:
            logs = logs.filter(model_name=model)

        search = self.request.GET.get('q')
        if search:
            from django.db.models import Q
            logs = logs.filter(
                Q(object_repr__icontains=search) |
                Q(actor__email__icontains=search) |
                Q(change_message__icontains=search)
            )

        context['logs'] = logs[:100]  # Limit for performance
        context['total_count'] = logs.count()

        # Available actions for filter
        context['actions'] = AuditLogEntry.ACTION_CHOICES

        # Available models for filter
        context['models'] = AuditLogEntry.objects.values_list(
            'model_name', flat=True
        ).distinct()

        context['current_filters'] = {
            'action': action,
            'model': model,
            'q': search or '',
        }

        return context


@method_decorator(staff_member_required, name='dispatch')
class SessionsListView(TemplateView):
    """User sessions list view."""
    template_name = 'security/sessions_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        sessions = UserSession.objects.select_related('user').order_by('-last_activity')

        # Apply filters
        active = self.request.GET.get('active')
        if active == 'true':
            sessions = sessions.filter(is_active=True)
        elif active == 'false':
            sessions = sessions.filter(is_active=False)

        search = self.request.GET.get('q')
        if search:
            from django.db.models import Q
            sessions = sessions.filter(
                Q(user__email__icontains=search) |
                Q(ip_address__icontains=search)
            )

        context['sessions'] = sessions[:100]
        context['total_count'] = sessions.count()

        context['stats'] = {
            'total': UserSession.objects.count(),
            'active': UserSession.objects.filter(is_active=True).count(),
            'inactive': UserSession.objects.filter(is_active=False).count(),
        }

        context['current_filters'] = {
            'active': active,
            'q': search or '',
        }

        return context
