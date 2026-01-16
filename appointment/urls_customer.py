"""
Customer-facing URL patterns for appointments.

These URLs allow authenticated users (non-staff) to access their own appointments.

Author: Claude Code
Since: 1.0.0
"""

from django.urls import path
from . import views_customer

app_name = 'appointment_customer'

urlpatterns = [
    # List user's appointments
    path('', views_customer.my_appointments, name='my_appointments'),
    path('<str:response_type>/', views_customer.my_appointments, name='my_appointments_format'),

    # View specific appointment details
    path('detail/<int:appointment_id>/', views_customer.appointment_detail, name='appointment_detail'),
    path('detail/<int:appointment_id>/<str:response_type>/', views_customer.appointment_detail, name='appointment_detail_format'),

    # Cancel appointment
    path('cancel/<int:appointment_id>/', views_customer.cancel_appointment, name='cancel_appointment'),
    path('cancel/<int:appointment_id>/<str:response_type>/', views_customer.cancel_appointment, name='cancel_appointment_format'),
]
