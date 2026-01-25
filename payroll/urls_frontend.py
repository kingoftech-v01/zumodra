"""
Payroll Frontend URLs
"""

from django.urls import path
from .template_views import (
    PayrollDashboardView,
    PayrollRunListView,
    PayrollRunDetailView,
    EmployeePaymentListView,
    EmployeePaymentDetailView,
    DirectDepositListView,
    DirectDepositDetailView,
    PayStubListView,
    PayStubDetailView,
    HTMXPayrollStatsView,
)

app_name = 'payroll'

urlpatterns = [
    # Dashboard
    path('', PayrollDashboardView.as_view(), name='dashboard'),

    # Payroll Runs
    path('runs/', PayrollRunListView.as_view(), name='run-list'),
    path('runs/<int:pk>/', PayrollRunDetailView.as_view(), name='run-detail'),

    # Employee Payments
    path('payments/', EmployeePaymentListView.as_view(), name='payment-list'),
    path('payments/<int:pk>/', EmployeePaymentDetailView.as_view(), name='payment-detail'),

    # Direct Deposits
    path('direct-deposits/', DirectDepositListView.as_view(), name='direct-deposit-list'),
    path('direct-deposits/<int:pk>/', DirectDepositDetailView.as_view(), name='direct-deposit-detail'),

    # Pay Stubs
    path('paystubs/', PayStubListView.as_view(), name='paystub-list'),
    path('paystubs/<int:pk>/', PayStubDetailView.as_view(), name='paystub-detail'),

    # HTMX Partials
    path('htmx/stats/', HTMXPayrollStatsView.as_view(), name='htmx-stats'),
]
