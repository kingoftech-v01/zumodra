"""
Appointment Frontend URLs - Appointment scheduling and management.

This module provides frontend URL routing for the appointment system:
- Appointment calendar/list view
- Appointment booking
- Appointment management
"""

from django.urls import path, include

from interviews.views import (
    appointment_request,
    appointment_request_submit,
    prepare_reschedule_appointment,
    reschedule_appointment_submit,
    confirm_reschedule,
    appointment_client_information,
    enter_verification_code,
    default_thank_you,
)

from interviews.views_admin import (
    get_user_appointments,
    display_appointment,
    delete_appointment,
)

app_name = 'interviews'

urlpatterns = [
    # Main appointment list/calendar view
    path('', get_user_appointments, name='get_user_appointments'),
    path('<str:response_type>/', get_user_appointments, name='get_user_event_type'),

    # Appointment detail
    path('view/<int:appointment_id>/', display_appointment, name='display_appointment'),

    # Appointment booking
    path('request/<int:service_id>/', appointment_request, name='appointment_request'),
    path('request-submit/', appointment_request_submit, name='appointment_request_submit'),

    # Appointment rescheduling
    path('<str:id_request>/reschedule/', prepare_reschedule_appointment, name='prepare_reschedule_appointment'),
    path('reschedule-submit/', reschedule_appointment_submit, name='reschedule_appointment_submit'),
    path('confirm-reschedule/<str:id_request>/', confirm_reschedule, name='confirm_reschedule'),

    # Client information and verification
    path('client-info/<int:appointment_request_id>/<str:id_request>/', appointment_client_information, name='appointment_client_information'),
    path('verification-code/<int:appointment_request_id>/<str:id_request>/', enter_verification_code, name='enter_verification_code'),

    # Thank you page
    path('thank-you/<int:appointment_id>/', default_thank_you, name='default_thank_you'),

    # Delete appointment
    path('delete/<int:appointment_id>/', delete_appointment, name='delete_appointment'),
]
