"""
Interviews API URLs (renamed from appointment).
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .viewsets import (
    ServiceViewSet,
    StaffMemberViewSet,
    WorkingHoursViewSet,
    DayOffViewSet,
    AppointmentRequestViewSet,
    AppointmentViewSet,
    PaymentInfoViewSet,
    ConfigViewSet,
    BookingView,
    AppointmentStatsView,
)

app_name = 'interviews'  # Changed from 'appointment' to match frontend namespace (2026-01-18)

router = DefaultRouter()

# Services
router.register(r'services', ServiceViewSet, basename='service')

# Staff members
router.register(r'staff', StaffMemberViewSet, basename='staff')

# Working hours
router.register(r'working-hours', WorkingHoursViewSet, basename='working-hours')

# Days off
router.register(r'days-off', DayOffViewSet, basename='days-off')

# Appointment requests
router.register(r'requests', AppointmentRequestViewSet, basename='request')

# Appointments
router.register(r'appointments', AppointmentViewSet, basename='appointment')

# Payment info
router.register(r'payments', PaymentInfoViewSet, basename='payment')

# Config
router.register(r'config', ConfigViewSet, basename='config')

urlpatterns = [
    path('', include(router.urls)),
    path('book/', BookingView.as_view(), name='book'),
    path('stats/', AppointmentStatsView.as_view(), name='stats'),
]
