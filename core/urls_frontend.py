"""
Frontend URL Configuration - Consolidated routing for all frontend template views.

This module provides URL routing for the HTMX-powered frontend views:
- Dashboard (main dashboard, search, widgets)
- ATS (jobs, candidates, pipeline, interviews)
- HR (employees, time-off, org chart, onboarding)
- Finance (payments, subscriptions, invoices, escrow)
- Analytics (dashboards, charts, reports)
- Notifications (list, actions, preferences)
- Accounts (verification, trust score, profile)
- Messages (real-time messaging, conversations)
- Appointments (scheduling, booking, calendar)

All routes are prefixed with 'app/' in the main URL configuration.
"""

from django.urls import path, include

app_name = 'frontend'

urlpatterns = [
    # Dashboard Views
    # URL: /app/dashboard/
    path('dashboard/', include('dashboard.urls_frontend')),

    # ATS Views (Applicant Tracking System)
    # URL: /app/ats/
    path('ats/', include('ats.urls_frontend')),

    # HR Views (Human Resources)
    # URL: /app/hr/
    path('hr/', include('hr_core.urls_frontend')),

    # Finance Views (Payments, Subscriptions, Invoices)
    # URL: /app/finance/
    path('finance/', include('finance.urls_frontend')),

    # Analytics Views
    # URL: /app/analytics/
    path('analytics/', include('analytics.urls_frontend')),

    # Notifications Views
    # URL: /app/notifications/
    path('notifications/', include('notifications.urls_frontend')),

    # Accounts Views (Verification, Trust Score, Profile)
    # URL: /app/accounts/
    path('accounts/', include('accounts.urls_frontend')),

    # Messages Views (Real-time Messaging)
    # URL: /app/messages/
    path('messages/', include('messages_sys.urls_frontend')),

    # Appointments Views (Scheduling, Booking, Calendar)
    # URL: /app/appointments/
    path('appointments/', include('appointment.urls_frontend')),
]
