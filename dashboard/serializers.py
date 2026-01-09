"""
Dashboard Serializers - DRF serializers for dashboard API.
"""

from rest_framework import serializers


class DashboardStatsSerializer(serializers.Serializer):
    """Serializer for main dashboard statistics."""
    open_jobs = serializers.IntegerField()
    total_candidates = serializers.IntegerField()
    new_candidates_week = serializers.IntegerField()
    active_applications = serializers.IntegerField()
    pending_interviews = serializers.IntegerField()
    total_employees = serializers.IntegerField()
    pending_time_off = serializers.IntegerField()


class QuickStatsSerializer(serializers.Serializer):
    """Serializer for quick stats widget."""
    open_jobs = serializers.IntegerField()
    new_candidates_week = serializers.IntegerField()
    active_applications = serializers.IntegerField()
    pending_interviews = serializers.IntegerField()


class JobSearchResultSerializer(serializers.Serializer):
    """Serializer for job search results."""
    id = serializers.IntegerField()
    uuid = serializers.UUIDField()
    title = serializers.CharField()
    status = serializers.CharField()
    location = serializers.CharField(allow_null=True)


class CandidateSearchResultSerializer(serializers.Serializer):
    """Serializer for candidate search results."""
    id = serializers.IntegerField()
    uuid = serializers.UUIDField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    email = serializers.EmailField()
    current_title = serializers.CharField(allow_null=True)


class EmployeeSearchResultSerializer(serializers.Serializer):
    """Serializer for employee search results."""
    id = serializers.IntegerField()
    uuid = serializers.UUIDField()
    name = serializers.CharField()
    email = serializers.EmailField()
    job_title = serializers.CharField(allow_null=True)
    employee_id = serializers.CharField(allow_null=True)


class ApplicationSearchResultSerializer(serializers.Serializer):
    """Serializer for application search results."""
    id = serializers.IntegerField()
    uuid = serializers.UUIDField()
    candidate_name = serializers.CharField()
    job_title = serializers.CharField()
    status = serializers.CharField()


class SearchResultsSerializer(serializers.Serializer):
    """Serializer for global search results."""
    query = serializers.CharField()
    jobs = JobSearchResultSerializer(many=True)
    candidates = CandidateSearchResultSerializer(many=True)
    employees = EmployeeSearchResultSerializer(many=True)
    applications = ApplicationSearchResultSerializer(many=True)
    total_count = serializers.IntegerField()


class UpcomingInterviewSerializer(serializers.Serializer):
    """Serializer for upcoming interview data."""
    id = serializers.IntegerField()
    candidate_name = serializers.CharField()
    candidate_email = serializers.EmailField(allow_null=True)
    job_title = serializers.CharField()
    scheduled_start = serializers.DateTimeField()
    scheduled_end = serializers.DateTimeField(allow_null=True)
    status = serializers.CharField()
    interview_type = serializers.CharField(allow_null=True)


class RecentActivitySerializer(serializers.Serializer):
    """Serializer for recent activity feed."""
    id = serializers.IntegerField()
    title = serializers.CharField()
    message = serializers.CharField()
    notification_type = serializers.CharField()
    is_read = serializers.BooleanField()
    created_at = serializers.DateTimeField()
    action_url = serializers.CharField(allow_null=True)


class DashboardOverviewSerializer(serializers.Serializer):
    """Complete dashboard overview serializer."""
    stats = DashboardStatsSerializer()
    upcoming_interviews = UpcomingInterviewSerializer(many=True)
    recent_activity = RecentActivitySerializer(many=True)
    unread_notifications = serializers.IntegerField()


class ATSMetricsSerializer(serializers.Serializer):
    """Serializer for ATS-specific metrics."""
    total_jobs = serializers.IntegerField()
    open_jobs = serializers.IntegerField()
    closed_jobs = serializers.IntegerField()
    total_candidates = serializers.IntegerField()
    total_applications = serializers.IntegerField()
    applications_by_status = serializers.DictField()
    average_time_to_hire = serializers.FloatField(allow_null=True)
    conversion_rate = serializers.FloatField(allow_null=True)


class HRMetricsSerializer(serializers.Serializer):
    """Serializer for HR-specific metrics."""
    total_employees = serializers.IntegerField()
    active_employees = serializers.IntegerField()
    employees_on_leave = serializers.IntegerField()
    pending_time_off_requests = serializers.IntegerField()
    headcount_by_department = serializers.ListField()


class WidgetDataSerializer(serializers.Serializer):
    """Generic serializer for widget data."""
    widget_type = serializers.CharField()
    title = serializers.CharField()
    data = serializers.JSONField()
    updated_at = serializers.DateTimeField()
