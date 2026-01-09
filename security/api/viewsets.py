"""
Security API ViewSets.

Provides ViewSets for:
- Audit log management
- Security events
- Failed login attempts
- User session management
- Security analytics
"""

from datetime import timedelta

from django.db.models import Count
from django.utils import timezone
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django_filters import rest_framework as filters

from ..models import (
    AuditLogEntry,
    SecurityEvent,
    FailedLoginAttempt,
    UserSession,
    PasswordResetRequest,
)
from ..serializers import (
    AuditLogListSerializer,
    AuditLogDetailSerializer,
    SecurityEventListSerializer,
    SecurityEventDetailSerializer,
    FailedLoginAttemptListSerializer,
    FailedLoginAttemptDetailSerializer,
    UserSessionListSerializer,
    UserSessionDetailSerializer,
    PasswordResetRequestSerializer,
    SecurityAnalyticsSerializer,
)


# =============================================================================
# AUDIT LOG VIEWSET
# =============================================================================

class AuditLogFilter(filters.FilterSet):
    """Filter for audit logs."""
    action = filters.CharFilter()
    model_name = filters.CharFilter()
    actor = filters.NumberFilter()
    date_from = filters.DateFilter(field_name='timestamp', lookup_expr='date__gte')
    date_to = filters.DateFilter(field_name='timestamp', lookup_expr='date__lte')

    class Meta:
        model = AuditLogEntry
        fields = ['action', 'model_name', 'actor', 'date_from', 'date_to']


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for audit logs (read-only, admin only).
    """
    queryset = AuditLogEntry.objects.select_related('actor').all()
    permission_classes = [permissions.IsAdminUser]
    filterset_class = AuditLogFilter
    search_fields = ['object_repr', 'change_message', 'actor__email']
    ordering_fields = ['timestamp', 'action', 'model_name']
    ordering = ['-timestamp']

    def get_serializer_class(self):
        if self.action == 'list':
            return AuditLogListSerializer
        return AuditLogDetailSerializer

    @action(detail=False, methods=['get'])
    def by_action(self, request):
        """Get audit logs grouped by action."""
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)

        stats = AuditLogEntry.objects.filter(
            timestamp__gte=since
        ).values('action').annotate(
            count=Count('id')
        ).order_by('-count')

        return Response([{
            'action': s['action'],
            'count': s['count']
        } for s in stats])

    @action(detail=False, methods=['get'])
    def by_model(self, request):
        """Get audit logs grouped by model."""
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)

        stats = AuditLogEntry.objects.filter(
            timestamp__gte=since
        ).values('model_name').annotate(
            count=Count('id')
        ).order_by('-count')[:10]

        return Response([{
            'model_name': s['model_name'],
            'count': s['count']
        } for s in stats])

    @action(detail=False, methods=['get'])
    def by_user(self, request):
        """Get audit logs grouped by user."""
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)

        stats = AuditLogEntry.objects.filter(
            timestamp__gte=since,
            actor__isnull=False
        ).values('actor__email').annotate(
            count=Count('id')
        ).order_by('-count')[:10]

        return Response([{
            'user': s['actor__email'],
            'count': s['count']
        } for s in stats])


# =============================================================================
# SECURITY EVENT VIEWSET
# =============================================================================

class SecurityEventFilter(filters.FilterSet):
    """Filter for security events."""
    event_type = filters.CharFilter()
    user = filters.NumberFilter()
    date_from = filters.DateFilter(field_name='timestamp', lookup_expr='date__gte')
    date_to = filters.DateFilter(field_name='timestamp', lookup_expr='date__lte')

    class Meta:
        model = SecurityEvent
        fields = ['event_type', 'user', 'date_from', 'date_to']


class SecurityEventViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for security events (read-only, admin only).
    """
    queryset = SecurityEvent.objects.select_related('user').all()
    permission_classes = [permissions.IsAdminUser]
    filterset_class = SecurityEventFilter
    search_fields = ['user__email', 'description']
    ordering_fields = ['timestamp', 'event_type']
    ordering = ['-timestamp']

    def get_serializer_class(self):
        if self.action == 'list':
            return SecurityEventListSerializer
        return SecurityEventDetailSerializer

    @action(detail=False, methods=['get'])
    def by_type(self, request):
        """Get security events grouped by type."""
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)

        stats = SecurityEvent.objects.filter(
            timestamp__gte=since
        ).values('event_type').annotate(
            count=Count('id')
        ).order_by('-count')

        return Response([{
            'event_type': s['event_type'],
            'count': s['count']
        } for s in stats])


# =============================================================================
# FAILED LOGIN VIEWSET
# =============================================================================

class FailedLoginFilter(filters.FilterSet):
    """Filter for failed login attempts."""
    ip_address = filters.CharFilter()
    username_entered = filters.CharFilter(lookup_expr='icontains')
    date_from = filters.DateFilter(field_name='attempted_at', lookup_expr='date__gte')
    date_to = filters.DateFilter(field_name='attempted_at', lookup_expr='date__lte')

    class Meta:
        model = FailedLoginAttempt
        fields = ['ip_address', 'username_entered', 'date_from', 'date_to']


class FailedLoginViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for failed login attempts (read-only, admin only).
    """
    queryset = FailedLoginAttempt.objects.select_related('user').all()
    permission_classes = [permissions.IsAdminUser]
    filterset_class = FailedLoginFilter
    search_fields = ['username_entered', 'ip_address']
    ordering_fields = ['attempted_at', 'ip_address']
    ordering = ['-attempted_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return FailedLoginAttemptListSerializer
        return FailedLoginAttemptDetailSerializer

    @action(detail=False, methods=['get'])
    def by_ip(self, request):
        """Get failed logins grouped by IP address."""
        days = int(request.query_params.get('days', 7))
        since = timezone.now() - timedelta(days=days)

        stats = FailedLoginAttempt.objects.filter(
            attempted_at__gte=since
        ).values('ip_address').annotate(
            count=Count('id')
        ).order_by('-count')[:20]

        return Response([{
            'ip_address': s['ip_address'],
            'count': s['count']
        } for s in stats])

    @action(detail=False, methods=['get'])
    def suspicious(self, request):
        """Get IPs with suspicious activity (5+ failed attempts)."""
        days = int(request.query_params.get('days', 1))
        threshold = int(request.query_params.get('threshold', 5))
        since = timezone.now() - timedelta(days=days)

        stats = FailedLoginAttempt.objects.filter(
            attempted_at__gte=since
        ).values('ip_address').annotate(
            count=Count('id')
        ).filter(count__gte=threshold).order_by('-count')

        return Response([{
            'ip_address': s['ip_address'],
            'count': s['count']
        } for s in stats])


# =============================================================================
# USER SESSION VIEWSET
# =============================================================================

class UserSessionFilter(filters.FilterSet):
    """Filter for user sessions."""
    user = filters.NumberFilter()
    is_active = filters.BooleanFilter()
    ip_address = filters.CharFilter()

    class Meta:
        model = UserSession
        fields = ['user', 'is_active', 'ip_address']


class UserSessionViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing user sessions (admin only).
    """
    queryset = UserSession.objects.select_related('user').all()
    permission_classes = [permissions.IsAdminUser]
    filterset_class = UserSessionFilter
    search_fields = ['user__email', 'ip_address']
    ordering_fields = ['last_activity', 'login_time']
    ordering = ['-last_activity']

    def get_serializer_class(self):
        if self.action == 'list':
            return UserSessionListSerializer
        return UserSessionDetailSerializer

    @action(detail=True, methods=['post'])
    def terminate(self, request, pk=None):
        """Terminate a user session."""
        session = self.get_object()
        session.is_active = False
        session.save(update_fields=['is_active'])
        return Response({'status': 'terminated', 'message': 'Session terminated successfully'})

    @action(detail=False, methods=['post'])
    def terminate_user_sessions(self, request):
        """Terminate all sessions for a user."""
        user_id = request.data.get('user_id')
        if not user_id:
            return Response(
                {'error': 'user_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        count = UserSession.objects.filter(user_id=user_id, is_active=True).update(is_active=False)
        return Response({
            'status': 'terminated',
            'message': f'{count} sessions terminated'
        })

    @action(detail=False, methods=['get'])
    def active_count(self, request):
        """Get count of active sessions."""
        count = UserSession.objects.filter(is_active=True).count()
        unique_users = UserSession.objects.filter(is_active=True).values('user').distinct().count()
        return Response({
            'active_sessions': count,
            'unique_users': unique_users
        })


# =============================================================================
# PASSWORD RESET REQUEST VIEWSET
# =============================================================================

class PasswordResetRequestFilter(filters.FilterSet):
    """Filter for password reset requests."""
    user = filters.NumberFilter()
    used = filters.BooleanFilter()
    date_from = filters.DateFilter(field_name='requested_at', lookup_expr='date__gte')
    date_to = filters.DateFilter(field_name='requested_at', lookup_expr='date__lte')

    class Meta:
        model = PasswordResetRequest
        fields = ['user', 'used', 'date_from', 'date_to']


class PasswordResetRequestViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for password reset requests (read-only, admin only).
    """
    queryset = PasswordResetRequest.objects.select_related('user').all()
    serializer_class = PasswordResetRequestSerializer
    permission_classes = [permissions.IsAdminUser]
    filterset_class = PasswordResetRequestFilter
    search_fields = ['user__email']
    ordering_fields = ['requested_at']
    ordering = ['-requested_at']


# =============================================================================
# SECURITY ANALYTICS VIEW
# =============================================================================

class SecurityAnalyticsView(APIView):
    """
    API view for security analytics dashboard.
    """
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        """Get security analytics summary."""
        today = timezone.now().date()
        today_start = timezone.make_aware(
            timezone.datetime.combine(today, timezone.datetime.min.time())
        )

        data = {
            'total_audit_logs': AuditLogEntry.objects.count(),
            'audit_logs_today': AuditLogEntry.objects.filter(timestamp__gte=today_start).count(),
            'total_security_events': SecurityEvent.objects.count(),
            'security_events_today': SecurityEvent.objects.filter(timestamp__gte=today_start).count(),
            'failed_logins_today': FailedLoginAttempt.objects.filter(attempted_at__gte=today_start).count(),
            'active_sessions': UserSession.objects.filter(is_active=True).count(),
            'pending_password_resets': PasswordResetRequest.objects.filter(used=False).count(),
            'account_lockouts_today': SecurityEvent.objects.filter(
                event_type='account_lockout',
                timestamp__gte=today_start
            ).count(),
        }

        serializer = SecurityAnalyticsSerializer(data)
        return Response(serializer.data)
