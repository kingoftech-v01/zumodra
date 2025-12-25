from django.contrib import admin
from .models import PageView, UserAction, SearchQuery, DashboardMetric


@admin.register(PageView)
class PageViewAdmin(admin.ModelAdmin):
    list_display = ['path', 'user', 'ip_address', 'timestamp']
    list_filter = ['timestamp']
    search_fields = ['path', 'user__email', 'ip_address']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'


@admin.register(UserAction)
class UserActionAdmin(admin.ModelAdmin):
    list_display = ['user', 'action_type', 'description', 'timestamp']
    list_filter = ['action_type', 'timestamp']
    search_fields = ['user__email', 'description']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'


@admin.register(SearchQuery)
class SearchQueryAdmin(admin.ModelAdmin):
    list_display = ['query', 'user', 'results_count', 'timestamp']
    list_filter = ['timestamp', 'results_count']
    search_fields = ['query', 'user__email']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'


@admin.register(DashboardMetric)
class DashboardMetricAdmin(admin.ModelAdmin):
    list_display = ['metric_type', 'value', 'date', 'created_at']
    list_filter = ['metric_type', 'date']
    search_fields = ['metric_type']
    readonly_fields = ['created_at']
    date_hierarchy = 'date'
