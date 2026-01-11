"""
HR Core Frontend URL Configuration.

Routes for HR template views and HTMX endpoints.
"""

from django.urls import path

from .template_views import (
    # Employee views
    EmployeeDirectoryView,
    EmployeeDetailView,
    EmployeeEditView,

    # Time-off views
    TimeOffCalendarView,
    TimeOffRequestView,
    TimeOffApprovalView,
    MyTimeOffView,

    # Org chart
    OrgChartView,
    OrgChartDataView,

    # Onboarding
    OnboardingDashboardView,
    OnboardingDetailView,
    OnboardingTaskCompleteView,
)

app_name = 'hr'

urlpatterns = [
    # ===== EMPLOYEE ROUTES =====
    path('employees/', EmployeeDirectoryView.as_view(), name='employee-directory'),
    path('employees/create/', EmployeeEditView.as_view(), name='employee-create'),
    path('employees/<uuid:pk>/', EmployeeDetailView.as_view(), name='employee-detail'),
    path('employees/<uuid:pk>/edit/', EmployeeEditView.as_view(), name='employee-edit'),

    # ===== TIME-OFF ROUTES =====
    path('time-off/calendar/', TimeOffCalendarView.as_view(), name='time-off-calendar'),
    path('time-off/request/', TimeOffRequestView.as_view(), name='time-off-request'),
    path('time-off/my/', MyTimeOffView.as_view(), name='my-time-off'),
    path('time-off/<uuid:pk>/approve/', TimeOffApprovalView.as_view(), name='time-off-approval'),

    # ===== ORG CHART ROUTES =====
    path('org-chart/', OrgChartView.as_view(), name='org-chart'),
    path('org-chart/data/', OrgChartDataView.as_view(), name='org-chart-data'),

    # ===== ONBOARDING ROUTES =====
    path('onboarding/', OnboardingDashboardView.as_view(), name='onboarding-dashboard'),
    path('onboarding/<uuid:pk>/', OnboardingDetailView.as_view(), name='onboarding-detail'),
    path('onboarding/task/<uuid:pk>/complete/', OnboardingTaskCompleteView.as_view(), name='onboarding-task-complete'),
]
