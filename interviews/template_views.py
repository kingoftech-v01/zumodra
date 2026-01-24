"""
Interviews Template Views

Frontend HTML views for interview scheduling system (HTMX-enabled).

This module consolidates admin and customer views following v2 convention.
Actual view implementations are in views_admin.py and views_customer.py.
"""

# Admin/Staff views (from views_admin.py)
from .views_admin import (
    get_user_appointments,
    create_appointment,
    reschedule_appointment_view,
    delete_appointment,
    edit_appointment,
    user_profile,
    update_email,
    update_email_verified,
    update_personal_info,
    staff_appointments,
    manage_staff,
    manage_services,
    manage_day_off,
    manage_working_hours,
)

# Customer views (from views_customer.py)
from .views_customer import (
    list_services,
    view_service,
    request_appointment,
    manage_appointment_requests,
    my_appointments,
    appointment_detail,
    reschedule_my_appointment,
    cancel_my_appointment,
)

# Additional views (from views.py if needed)
# Note: views.py may contain API views or utilities
# Check if any template views need to be imported

__all__ = [
    # Admin/Staff views
    'get_user_appointments',
    'create_appointment',
    'reschedule_appointment_view',
    'delete_appointment',
    'edit_appointment',
    'user_profile',
    'update_email',
    'update_email_verified',
    'update_personal_info',
    'staff_appointments',
    'manage_staff',
    'manage_services',
    'manage_day_off',
    'manage_working_hours',
    # Customer views
    'list_services',
    'view_service',
    'request_appointment',
    'manage_appointment_requests',
    'my_appointments',
    'appointment_detail',
    'reschedule_my_appointment',
    'cancel_my_appointment',
]
