"""
Frontend URL Configuration - Consolidated routing for all frontend template views.

This module provides URL routing for the HTMX-powered frontend views:
- Dashboard (main dashboard, search, widgets)
- ATS (jobs, candidates, pipeline, recruitment interviews)
- HR (employees, time-off, org chart, onboarding)
- Finance (payments, subscriptions, invoices, escrow)
- Analytics (dashboards, charts, reports)
- Notifications (list, actions, preferences)
- Accounts (verification, trust score, profile)
- Messages (real-time messaging, conversations)
- Interview Scheduling (appointment booking, calendar)

All routes are prefixed with 'app/' in the main URL configuration.
"""

from django.urls import path, include

app_name = 'frontend'

urlpatterns = [
    # Dashboard Views
    # URL: /app/dashboard/
    path('dashboard/', include('dashboard.urls_frontend')),

    # Jobs Views (Applicant Tracking System)
    # URL: /app/jobs/
    path('jobs/', include('jobs.urls_frontend')),

    # HR Views (Human Resources)
    # URL: /app/hr/
    path('hr/', include('hr_core.urls_frontend')),

    # Projects Views (Project Missions with Deliverables)
    # URL: /app/projects/
    path('projects/', include('projects.urls_frontend')),

    # Services Views (Freelance Marketplace)
    # URL: /app/services/
    path('services/', include('services.urls_frontend')),

    # Finance Apps - NEW MODULAR STRUCTURE (Phase 11 Refactoring)
    # URL: /app/payments/
    path('payments/', include('payments.urls_frontend')),

    # Escrow Views (Secure Funds Holding)
    # URL: /app/escrow/
    path('escrow/', include('escrow.urls_frontend')),

    # Payroll Views (Employee Payroll Processing)
    # URL: /app/payroll/
    path('payroll/', include('payroll.urls_frontend')),

    # Expenses Views (Business Expense Tracking)
    # URL: /app/expenses/
    path('expenses/', include('expenses.urls_frontend')),

    # Subscriptions Views (Tenant Subscription Products)
    # URL: /app/subscriptions/
    path('subscriptions/', include('subscriptions.urls_frontend')),

    # Stripe Connect Views (Marketplace Payments)
    # URL: /app/stripe-connect/
    path('stripe-connect/', include('stripe_connect.urls_frontend')),

    # Tax Views (Tax Calculation & Compliance)
    # URL: /app/tax/
    path('tax/', include('tax.urls_frontend')),

    # Billing Views (Platform Subscription Management)
    # URL: /app/billing/
    path('billing/', include('billing.urls_frontend')),

    # Accounting Views (Accounting Integration)
    # URL: /app/accounting/
    path('accounting/', include('accounting.urls_frontend')),

    # Finance Webhooks Views (Webhook Monitoring)
    # URL: /app/webhooks/
    path('webhooks/', include('finance_webhooks.urls_frontend')),

    # Analytics Views
    # URL: /app/analytics/
    path('analytics/', include('analytics.urls_frontend')),

    # Notifications Views
    # URL: /app/notifications/
    path('notifications/', include('notifications.urls_frontend')),

    # Accounts Views (Verification, Trust Score, Profile)
    # URL: /app/accounts/
    path('accounts/', include('tenant_profiles.urls_frontend')),

    # Messages Views (Real-time Messaging)
    # URL: /app/messages/
    path('messages/', include('messages_sys.urls_frontend')),

    # Marketing Campaigns Views (Unified Marketing & Newsletter)
    # URL: /app/marketing/
    path('marketing/', include('marketing_campaigns.urls_frontend')),

    # Interview Scheduling Views - Staff/Admin (Scheduling, Booking, Calendar)
    # URL: /app/appointments/ (requires staff access)
    path('appointments/', include('interviews.urls_frontend')),

    # Interview Scheduling Views - Customer (My Appointments)
    # URL: /app/my-appointments/ (requires authentication only)
    path('my-appointments/', include('interviews.urls_customer')),
]
