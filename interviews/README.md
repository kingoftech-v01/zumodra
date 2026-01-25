# Interviews App (Interview Scheduling)

## Overview

The Interviews app provides comprehensive scheduling and booking functionality for Zumodra's multi-tenant platform. It enables businesses to manage services, staff schedules, business hours, and customer appointments with conflict detection, automated notifications, and flexible rescheduling workflows.

## Key Features

### Completed Features

- **Service Management**: Full CRUD for services with pricing, duration, images, and rescheduling policies
- **Staff Scheduling**: Individual staff member schedules with working hours, time off, and buffer times
- **Business Hours Configuration**: Per-staff or global working hours with weekend work options
- **Slot Generation**: Dynamic available slot calculation based on staff schedules and existing bookings
- **Appointment Booking**: Customer booking interface with date selection and slot availability
- **Conflict Detection**: Real-time validation to prevent double-booking and scheduling conflicts
- **Appointment Management**: View, reschedule, and delete appointments with full history tracking
- **Email Notifications**: Automated appointment confirmations, reminders, and reschedule notifications
- **Payment Integration**: Support for full payment and down payment options with Stripe integration
- **Admin Interface**: Staff member management, service configuration, and appointment calendar
- **Customer Portal**: User-facing appointment list, detail views, and self-service management
- **Reschedule Workflow**: Complete rescheduling flow with staff change options and attempt limits
- **Email Verification**: Verification code system for returning users
- **ICS Calendar Export**: Generate ICS files for calendar imports

### In Development

- **Cancellation Workflow**: Full cancellation logic with refund processing (see TODO-APPT-001)
- **Calendar Integration**: Google Calendar, Outlook, and iCal sync
- **Recurring Appointments**: Support for weekly/monthly recurring bookings
- **SMS Notifications**: Twilio integration for SMS reminders
- **Video Meeting Links**: Auto-generate Zoom/Teams links for virtual appointments
- **Appointment Analytics**: Booking rates, no-show tracking, revenue metrics

## Architecture

### Models

Located in `interviews/models.py`:

| Model | Description | Key Fields |
|-------|-------------|------------|
| **Service** | Appointment services | name, description, duration, price, down_payment, currency, image, reschedule_limit, allow_rescheduling |
| **StaffMember** | Staff scheduling info | user, services_offered, slot_duration, lead_time, finish_time, appointment_buffer_time, work_on_saturday, work_on_sunday |
| **AppointmentRequest** | Booking request | date, start_time, end_time, service, staff_member, payment_type, reschedule_attempts |
| **Appointment** | Confirmed appointment | client, appointment_request, phone, address, want_reminder, additional_info, paid, amount_to_pay |
| **AppointmentRescheduleHistory** | Reschedule audit trail | appointment_request, date, start_time, end_time, staff_member, reason_for_rescheduling, reschedule_status |
| **Config** | Global settings | slot_duration, lead_time, finish_time, appointment_buffer_time, website_name, default_reschedule_limit, allow_staff_change_on_reschedule |
| **WorkingHours** | Staff schedules | staff_member, day_of_week, start_time, end_time |
| **DayOff** | Staff time off | staff_member, start_date, end_date, description |
| **PaymentInfo** | Payment tracking | appointment, created_at |
| **EmailVerificationCode** | Email verification | user, code, created_at |
| **PasswordResetToken** | Password reset | user, token, expires_at, status |

### Views

#### Frontend Views (`interviews/views.py`)

**Customer Booking:**
- `appointment_request` - Select service and staff member
- `appointment_request_submit` - Submit appointment request
- `get_available_slots_ajax` - AJAX fetch available time slots
- `get_next_available_date_ajax` - Find next available booking date
- `appointment_client_information` - Collect client details
- `enter_verification_code` - Email verification for existing users
- `default_thank_you` - Confirmation page after booking

**Rescheduling:**
- `prepare_reschedule_appointment` - Initiate reschedule workflow
- `reschedule_appointment_submit` - Submit reschedule request
- `confirm_reschedule` - Confirm reschedule changes

**Authentication:**
- `set_passwd` - Set password for new users

#### Admin Views (`interviews/views_admin.py`)

**Appointment Management:**
- `get_user_appointments` - Staff appointment calendar view
- `display_appointment` - Appointment details
- `delete_appointment` - Delete appointment
- `delete_appointment_ajax` - AJAX delete
- `update_appt_min_info` - Update appointment basic info
- `update_appt_date_time` - Update appointment timing
- `validate_appointment_date` - Validate appointment dates

**Staff Management:**
- `user_profile` - Staff member profile
- `update_personal_info` - Update staff personal info
- `add_staff_member_info` - Add new staff member
- `create_new_staff_member` - Create staff member account
- `add_or_update_staff_info` - Update staff scheduling info
- `remove_staff_member` - Remove staff member
- `make_superuser_staff_member` - Grant admin access
- `remove_superuser_staff_member` - Revoke admin access

**Service Management:**
- `add_or_update_service` - Create/edit services
- `delete_service` - Delete service
- `get_service_list` - List all services
- `fetch_service_list_for_staff` - AJAX service list for staff

**Schedule Management:**
- `add_working_hours` - Add working hours
- `update_working_hours` - Update working hours
- `delete_working_hours` - Delete working hours
- `add_day_off` - Add time off
- `update_day_off` - Update time off
- `delete_day_off` - Delete time off

#### Customer Views (`interviews/views_customer.py`)

**Self-Service Portal:**
- `my_appointments` - List user's appointments
- `appointment_detail` - View appointment details
- `cancel_appointment` - Cancel appointment (TODO: needs implementation)

#### API Views (`interviews/api/viewsets.py`)

RESTful API endpoints using Django REST Framework:

```
/api/v1/appointments/services/
/api/v1/appointments/staff/
/api/v1/appointments/working-hours/
/api/v1/appointments/days-off/
/api/v1/appointments/requests/
/api/v1/appointments/appointments/
/api/v1/appointments/payments/
/api/v1/appointments/config/
/api/v1/appointments/book/
/api/v1/appointments/stats/
```

**ViewSets:**
- `ServiceViewSet` - Service CRUD with caching
- `StaffMemberViewSet` - Staff member management
- `WorkingHoursViewSet` - Schedule management
- `DayOffViewSet` - Time off management
- `AppointmentRequestViewSet` - Appointment requests
- `AppointmentViewSet` - Confirmed appointments
- `PaymentInfoViewSet` - Payment tracking
- `ConfigViewSet` - System configuration
- `BookingView` - Simplified booking endpoint
- `AppointmentStatsView` - Booking analytics

### URL Structure

#### Frontend URLs (`frontend:interviews:*`)

```python
# Main appointment interface
frontend:interviews:get_user_appointments
frontend:interviews:display_appointment (appointment_id)

# Booking
frontend:interviews:appointment_request (service_id)
frontend:interviews:appointment_request_submit

# Rescheduling
frontend:interviews:prepare_reschedule_appointment (id_request)
frontend:interviews:reschedule_appointment_submit
frontend:interviews:confirm_reschedule (id_request)

# Client flow
frontend:interviews:appointment_client_information (appointment_request_id, id_request)
frontend:interviews:enter_verification_code (appointment_request_id, id_request)
frontend:interviews:default_thank_you (appointment_id)

# Management
frontend:interviews:delete_appointment (appointment_id)
```

#### Customer URLs (`interviews_customer:*`)

```python
# Self-service portal
interviews_customer:my_appointments
interviews_customer:appointment_detail (appointment_id)
interviews_customer:cancel_appointment (appointment_id)
```

#### Legacy URLs (`interviews:*`)

The app includes legacy URL patterns for backward compatibility at `/interviews/`.

### Templates

Located in `templates/interviews/` (if exists) or integrated into admin templates:

**Admin Templates:**
- `administration/staff_index.html` - Staff appointment calendar
- `administration/display_appointment.html` - Appointment detail view
- `administration/user_profile.html` - Staff member profile

**Customer Templates:**
- `interviews/customer_appointments.html` - Customer appointment list
- `interviews/booking_interface.html` - Booking flow interface
- `interviews/reschedule_interface.html` - Rescheduling interface
- `interviews/thank_you.html` - Confirmation page

## Integration Points

### With Other Apps

- **Accounts**: User authentication, staff member accounts
- **Tenants**: Multi-tenant isolation, tenant-specific services and staff
- **ATS**: Integration for interview scheduling
- **HR Core**: Staff member profiles, employee schedules, meeting bookings
- **Services**: Service provider consultations and appointments
- **Notifications**: Email/SMS notifications for reminders and confirmations
- **Finance**: Payment processing, refunds, invoice generation
- **Dashboard**: Appointment statistics and upcoming appointments widget

### External Services

- **Email**: SendGrid/Django email backend for notifications
- **Payment**: Stripe for payment processing
- **Calendar**: Google Calendar, Microsoft 365 (planned)
- **SMS**: Twilio for SMS notifications (planned)
- **Video**: Zoom/Teams API for virtual appointments (planned)
- **Storage**: S3/local storage for service images

## Security & Permissions

### Role-Based Access

| Role | Permissions |
|------|-------------|
| **PDG/CEO** | Full access to all appointments, staff, and configuration |
| **HR Manager** | Manage appointments, staff schedules, services |
| **Staff Member** | View own appointments, manage own schedule |
| **Customer** | Book appointments, view own appointments, reschedule |
| **Viewer** | Read-only access to appointment calendar |

### Tenant Isolation

- All appointments scoped to `request.tenant`
- Staff members cannot be shared across tenants
- Services are tenant-specific
- Appointment requests isolated per tenant
- Payment information tenant-isolated

### Data Protection

- Phone numbers stored securely
- Payment information handled via Stripe (PCI compliant)
- Email verification for user identity
- CSRF protection on all forms
- Rate limiting on API endpoints
- Permission checks on all views

## Database Considerations

### Indexes

Key indexes for performance:

```python
# Service
models.Index(fields=['name'])
models.Index(fields=['price'])

# AppointmentRequest
models.Index(fields=['date', 'start_time'])
models.Index(fields=['staff_member', 'date'])

# Appointment
models.Index(fields=['client', '-created_at'])

# WorkingHours
models.Index(fields=['staff_member', 'day_of_week'])
```

### Constraints

```python
# Appointment - positive amount to pay
models.CheckConstraint(check=models.Q(amount_to_pay__gte=0), name='positive_amount_to_pay')

# WorkingHours - start before end
models.CheckConstraint(check=models.Q(start_time__lt=models.F('end_time')), name='start_time_before_end_time')

# WorkingHours - unique per staff/day
unique_together = ['staff_member', 'day_of_week']
```

### Relationships

```
Service (1) ←→ (N) AppointmentRequest
StaffMember (1) ←→ (N) AppointmentRequest
StaffMember (1) ←→ (N) WorkingHours
StaffMember (1) ←→ (N) DayOff
AppointmentRequest (1) ←→ (1) Appointment
AppointmentRequest (1) ←→ (N) AppointmentRescheduleHistory
Appointment (1) ←→ (1) PaymentInfo
User (1) ←→ (N) Appointment (as client)
User (1) ←→ (1) StaffMember
```

## Future Improvements

### High Priority

1. **[TODO-APPT-001] Complete Cancellation Logic**
   - Implement full customer appointment cancellation workflow
   - Add cancellation policy checks (24-hour notice requirement)
   - Calculate refund amounts based on timing
   - Integrate with finance app for refund processing
   - Send cancellation notifications to customer and staff
   - Add cancellation reason field
   - Track cancellation history
   - Handle edge cases (same-day, no-show policy)

2. **Calendar Integration**
   - Google Calendar sync
   - Microsoft 365/Outlook integration
   - iCal subscription feeds
   - Two-way sync for availability
   - Automatic meeting link generation

3. **Recurring Appointments**
   - Weekly/monthly recurring bookings
   - Series management (edit one vs. all)
   - Recurring payment handling
   - Exception dates for holidays

4. **SMS Notifications**
   - Twilio integration
   - SMS appointment reminders
   - SMS confirmation codes
   - Delivery status tracking

5. **Video Meeting Integration**
   - Auto-generate Zoom links
   - Microsoft Teams integration
   - Google Meet support
   - Virtual waiting room

### Medium Priority

6. **Advanced Analytics**
   - Booking conversion rates
   - Revenue by service/staff
   - No-show tracking and patterns
   - Peak booking times analysis
   - Staff utilization metrics

7. **Automated Reminders**
   - Configurable reminder timing (24h, 1h before)
   - Multiple reminder channels (email + SMS)
   - Reminder preferences per user
   - Confirmation required reminders

8. **Waitlist Management**
   - Allow customers to join waitlist for full slots
   - Auto-notify when slots open up
   - Waitlist priority system
   - Expiring waitlist offers

9. **Group Appointments**
   - Multi-person bookings
   - Class/workshop scheduling
   - Capacity limits per slot
   - Group payment handling

10. **Custom Booking Forms**
    - Configurable intake forms per service
    - Conditional questions
    - File uploads (medical forms, documents)
    - Form response storage and review

### Low Priority

11. **[TODO-APPT-002] Django FORMAT_MODULE_PATH**
    - Evaluate migration from custom DATE_FORMATS dictionary
    - Research Django's official i18n format approach
    - Document pros/cons of each approach
    - Implement if beneficial

12. **[TODO-APPT-TEST-001] Night Shift Support**
    - Support for businesses with night shifts (10 PM - 6 AM)
    - Handle date rollovers (appointments spanning midnight)
    - Update slot generation for cross-midnight ranges
    - Add test coverage for night shift scenarios

13. **Mobile Optimization**
    - Native mobile booking interface
    - Touch-optimized calendar picker
    - Mobile push notifications
    - Offline booking draft save

14. **Multi-Location Support**
    - Locations per service
    - Staff member location assignment
    - Location-based filtering
    - Map integration

15. **Advanced Rescheduling**
    - Reschedule suggestions based on preferences
    - Bulk reschedule for staff time off
    - Auto-reschedule for cancellations
    - Smart slot recommendation

## Testing

### Test Coverage

Target: 80%+ coverage for appointment booking and scheduling logic

### Test Structure

```
interviews/tests/
├── models/
│   ├── test_service.py              # Service model tests
│   ├── test_staff_member.py         # Staff member tests
│   ├── test_appointment_request.py  # Request tests
│   ├── test_appointment.py          # Appointment tests
│   ├── test_config.py               # Config tests
│   └── test_working_hours.py        # Schedule tests
├── views/
│   ├── test_booking_views.py        # Booking flow tests
│   ├── test_admin_views.py          # Admin view tests
│   ├── test_customer_views.py       # Customer portal tests
│   └── test_reschedule_views.py     # Reschedule tests
├── api/
│   ├── test_service_api.py          # Service API tests
│   ├── test_appointment_api.py      # Appointment API tests
│   └── test_booking_api.py          # Booking API tests
└── services/
    ├── test_slot_generation.py      # Slot calculation tests
    └── test_conflict_detection.py   # Conflict detection tests
```

### Key Test Scenarios

- Service creation and configuration
- Staff member scheduling with working hours
- Available slot calculation with conflicts
- Customer booking flow end-to-end
- Double-booking prevention
- Appointment rescheduling with limits
- Email verification for existing users
- Payment processing integration
- Cancellation workflow (when implemented)
- Tenant isolation verification
- Permission enforcement
- ICS calendar export

## Performance Optimization

### Current Optimizations

- Service list cached for 10 minutes (API)
- Staff members list cached for 10 minutes (API)
- Available slots cached for 1 minute (short TTL for accuracy)
- Appointment stats cached for 5 minutes (API)
- `select_related()` for foreign keys in queries
- `prefetch_related()` for appointment lists
- Database indexes on frequent query fields
- Lazy loading of related data

### Planned Optimizations

- Redis caching for slot availability
- Background job for slot pre-calculation
- Denormalized appointment count per staff
- Batch notification sending via Celery
- CDN for service images
- Database query optimization with `annotate()`
- Elasticsearch for appointment search (if needed)

## Migration Notes

When modifying models:

```bash
# Create migrations
python manage.py makemigrations appointment

# Apply to all tenant schemas (appointments are tenant-specific)
python manage.py migrate_schemas --tenant

# If modifying shared models (Config), also run:
python manage.py migrate_schemas --shared

# Verify migration
python manage.py check
```

### Data Migration Considerations

- Appointment history must be preserved
- Service changes should not affect past appointments
- Staff member removal should handle appointment reassignment
- Payment records must remain immutable

## Contributing

When adding features to the Interviews app:

1. Follow existing patterns in `views.py` and `views_admin.py`
2. Add URL patterns to appropriate URL files (`urls_frontend.py`, `urls_customer.py`)
3. Create/update templates in `templates/interviews/`
4. Add API endpoints to `api/viewsets.py` and `api/urls.py`
5. Write comprehensive tests for new functionality
6. Update this README with changes
7. Ensure tenant isolation is maintained
8. Add caching where appropriate
9. Document any new TODOs in `TODO.md`
10. Test email notifications in MailHog

## Configuration

### Environment Variables

```bash
# Appointment settings (optional, has defaults)
APPOINTMENT_PAYMENT_URL=/payments/interviews/
APPOINTMENT_THANK_YOU_URL=/interviews/thank-you/

# Email settings (required for notifications)
EMAIL_HOST=smtp.sendgrid.net
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=apikey
EMAIL_HOST_PASSWORD=your_sendgrid_api_key

# Celery (for background tasks)
CELERY_BROKER_URL=amqp://guest:guest@rabbitmq:5672//
CELERY_RESULT_BACKEND=redis://redis:6379/0
```

### Config Model Settings

The `Config` model (singleton) provides global defaults:

- `slot_duration`: Default appointment slot duration (minutes)
- `lead_time`: Default start of working hours
- `finish_time`: Default end of working hours
- `appointment_buffer_time`: Time buffer before first slot (minutes)
- `website_name`: Display name for the business
- `default_reschedule_limit`: Default reschedule attempts (3)
- `allow_staff_change_on_reschedule`: Allow changing staff on reschedule (True)

Access via: `Config.get_instance()`

## Support

For questions or issues related to the Interviews app:
- Check existing tests for usage examples
- Review `views.py` and `views_admin.py` for view implementations
- Consult `models.py` for model field documentation
- See `TODO.md` for known issues and planned features
- Consult the main [CLAUDE.md](../CLAUDE.md) for project guidelines

---

**Last Updated:** January 2026
**Module Version:** 1.0
**Status:** Production with TODOs
