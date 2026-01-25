"""
Customer-facing appointment views for regular users.

These views allow authenticated users to view and manage their own appointments
without requiring staff permissions.

Author: Claude Code
Since: 1.0.0
"""

from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.utils.translation import gettext_lazy as _

from .models import Appointment, AppointmentRequest
from .decorators import require_user_authenticated
from .utils.error_codes import ErrorCode
from .utils.json_context import json_response


@require_user_authenticated
def my_appointments(request, response_type='html'):
    """
    View user's own appointments (no staff requirement).

    Shows all appointments where the current user is the client.
    Supports both HTML and JSON responses.
    """
    # Only show appointments where user is the client
    appointments = Appointment.objects.filter(
        client=request.user
    ).select_related(
        'appointment_request',
        'appointment_request__service',
        'appointment_request__staff_member'
    ).order_by('-appointment_request__date', '-appointment_request__start_time')

    if response_type == 'json':
        # Return JSON response with appointment data
        appointments_data = []
        for apt in appointments:
            apt_request = apt.appointment_request
            appointments_data.append({
                'id': apt.id,
                'service': apt_request.service.name if apt_request.service else None,
                'staff_member': str(apt_request.staff_member) if apt_request.staff_member else None,
                'date': apt_request.date.isoformat(),
                'start_time': apt_request.start_time.strftime('%H:%M'),
                'end_time': apt_request.end_time.strftime('%H:%M'),
                'phone': str(apt.phone) if apt.phone else None,
                'address': apt.address or None,
                'paid': apt.paid,
                'amount_to_pay': str(apt.amount_to_pay) if apt.amount_to_pay else None,
                'want_reminder': apt.want_reminder,
                'additional_info': apt.additional_info or None,
            })

        return json_response(
            message=_("Appointments retrieved successfully."),
            success=True,
            data={'appointments': appointments_data, 'count': len(appointments_data)}
        )

    # Return HTML response
    context = {
        'appointments': appointments,
        'page_title': _('My Appointments'),
    }
    return render(request, 'appointment/customer_appointments.html', context)


@require_user_authenticated
def appointment_detail(request, appointment_id, response_type='html'):
    """
    View details of a specific appointment.

    Only allows users to view their own appointments.
    """
    # Get appointment and verify ownership
    appointment = get_object_or_404(
        Appointment.objects.select_related(
            'appointment_request',
            'appointment_request__service',
            'appointment_request__staff_member'
        ),
        id=appointment_id,
        client=request.user
    )

    apt_request = appointment.appointment_request

    if response_type == 'json':
        # Return detailed JSON response
        data = {
            'id': appointment.id,
            'service': {
                'name': apt_request.service.name if apt_request.service else None,
                'description': apt_request.service.description if apt_request.service else None,
                'price': str(apt_request.service.price) if apt_request.service else None,
                'duration': str(apt_request.service.duration) if apt_request.service else None,
            },
            'staff_member': {
                'name': str(apt_request.staff_member) if apt_request.staff_member else None,
            },
            'date': apt_request.date.isoformat(),
            'start_time': apt_request.start_time.strftime('%H:%M'),
            'end_time': apt_request.end_time.strftime('%H:%M'),
            'phone': str(appointment.phone) if appointment.phone else None,
            'address': appointment.address or None,
            'paid': appointment.paid,
            'amount_to_pay': str(appointment.amount_to_pay) if appointment.amount_to_pay else None,
            'want_reminder': appointment.want_reminder,
            'additional_info': appointment.additional_info or None,
            'payment_type': apt_request.payment_type,
            'reschedule_attempts': apt_request.reschedule_attempts,
            'created_at': appointment.created_at.isoformat() if hasattr(appointment, 'created_at') else None,
        }

        return json_response(
            message=_("Appointment details retrieved."),
            success=True,
            data=data
        )

    # Return HTML response
    context = {
        'appointment': appointment,
        'page_title': _('Appointment Details'),
    }
    return render(request, 'appointment/customer_appointment_detail.html', context)


@require_user_authenticated
def cancel_appointment(request, appointment_id, response_type='html'):
    """
    Allow users to cancel their own appointments.

    This is a placeholder for the cancellation logic.
    Actual implementation would handle cancellation policies, refunds, etc.
    """
    if request.method != 'POST':
        return json_response(
            message=_("Only POST method is allowed."),
            status=405,
            success=False,
            error_code=ErrorCode.INVALID_DATA
        )

    try:
        # Get appointment and verify ownership
        appointment = Appointment.objects.select_related(
            'appointment_request__service',
            'appointment_request__staff_member'
        ).get(
            id=appointment_id,
            client=request.user
        )

        # Get optional cancellation reason from request
        cancellation_reason = request.POST.get('reason', '')

        # Check if appointment can be cancelled
        can_cancel, reason = appointment.can_be_cancelled()

        if not can_cancel:
            return json_response(
                message=reason,
                status=400,
                success=False,
                error_code=ErrorCode.INVALID_DATA
            )

        # Calculate refund amount to show user
        refund_amount = appointment.calculate_refund_amount()

        # Queue cancellation task for async processing
        # Imports TODO-APPT-001 implementation from appointment/tasks.py
        from interviews.tasks import process_appointment_cancellation

        task_result = process_appointment_cancellation.apply_async(
            args=[appointment.id, request.user.id, cancellation_reason],
            countdown=2  # 2-second delay to allow transaction to commit
        )

        # Prepare response message
        if refund_amount > 0:
            message = _(
                f"Appointment cancelled successfully. "
                f"A refund of {refund_amount:.2f} {appointment.get_appointment_currency()} "
                f"will be processed within 5-7 business days."
            )
        else:
            hours_until = appointment.get_hours_until_appointment()
            if hours_until < 12:
                message = _(
                    "Appointment cancelled. No refund available due to short notice "
                    "(less than 12 hours before appointment)."
                )
            else:
                message = _("Appointment cancelled successfully.")

        return json_response(
            message=message,
            success=True,
            data={
                'appointment_id': appointment.id,
                'refund_amount': float(refund_amount),
                'task_id': task_result.id,
            }
        )

    except Appointment.DoesNotExist:
        return json_response(
            message=_("Appointment not found or not authorized."),
            status=404,
            success=False,
            error_code=ErrorCode.APPOINTMENT_NOT_FOUND
        )
