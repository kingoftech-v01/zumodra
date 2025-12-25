from django.db import models
from custom_account_u.models import User
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType


class PageView(models.Model):
    """Track page views for analytics"""
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='page_views'
    )
    session_key = models.CharField(max_length=40, blank=True)
    path = models.CharField(max_length=500)
    referrer = models.CharField(max_length=500, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['path', '-timestamp']),
            models.Index(fields=['user', '-timestamp']),
        ]

    def __str__(self):
        return f"{self.path} at {self.timestamp}"


class UserAction(models.Model):
    """Track user actions for analytics"""
    ACTION_TYPES = [
        ('service_view', 'Service Viewed'),
        ('service_like', 'Service Liked'),
        ('service_create', 'Service Created'),
        ('proposal_submit', 'Proposal Submitted'),
        ('proposal_accept', 'Proposal Accepted'),
        ('contract_create', 'Contract Created'),
        ('contract_complete', 'Contract Completed'),
        ('review_create', 'Review Created'),
        ('profile_update', 'Profile Updated'),
        ('search', 'Search Performed'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='user_actions'
    )
    action_type = models.CharField(max_length=50, choices=ACTION_TYPES)
    description = models.TextField(blank=True)

    # Generic relation to any object
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    object_id = models.PositiveIntegerField(null=True, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')

    metadata = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'action_type', '-timestamp']),
            models.Index(fields=['action_type', '-timestamp']),
        ]

    def __str__(self):
        user_str = self.user.email if self.user else 'Anonymous'
        return f"{user_str} - {self.get_action_type_display()} at {self.timestamp}"


class SearchQuery(models.Model):
    """Track search queries for analytics and improvement"""
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='search_queries'
    )
    query = models.CharField(max_length=500, db_index=True)
    results_count = models.PositiveIntegerField(default=0)
    filters_used = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name_plural = 'Search Queries'

    def __str__(self):
        return f'"{self.query}" ({self.results_count} results)'


class DashboardMetric(models.Model):
    """Store calculated metrics for dashboard"""
    METRIC_TYPES = [
        ('daily_revenue', 'Daily Revenue'),
        ('monthly_revenue', 'Monthly Revenue'),
        ('active_users', 'Active Users'),
        ('new_users', 'New Users'),
        ('total_services', 'Total Services'),
        ('active_contracts', 'Active Contracts'),
        ('completed_contracts', 'Completed Contracts'),
        ('conversion_rate', 'Conversion Rate'),
    ]

    metric_type = models.CharField(max_length=50, choices=METRIC_TYPES, db_index=True)
    value = models.DecimalField(max_digits=15, decimal_places=2)
    metadata = models.JSONField(default=dict, blank=True)
    date = models.DateField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-date', 'metric_type']
        unique_together = ['metric_type', 'date']

    def __str__(self):
        return f"{self.get_metric_type_display()}: {self.value} on {self.date}"


# Audit logging
from auditlog.registry import auditlog
auditlog.register(PageView)
auditlog.register(UserAction)
auditlog.register(SearchQuery)
auditlog.register(DashboardMetric)
