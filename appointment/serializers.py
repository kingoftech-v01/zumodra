"""
Appointment Serializers - DRF serializers for appointment models.
"""

from rest_framework import serializers
from django.utils import timezone

from .models import (
    Service, StaffMember, AppointmentRequest, AppointmentRescheduleHistory,
    Appointment, Config, PaymentInfo, DayOff, WorkingHours
)


class ServiceListSerializer(serializers.ModelSerializer):
    """List serializer for appointment services."""
    duration_text = serializers.CharField(source='get_duration', read_only=True)
    price_text = serializers.CharField(source='get_price_text', read_only=True)
    down_payment_text = serializers.CharField(source='get_down_payment_text', read_only=True)
    image_url = serializers.CharField(source='get_image_url', read_only=True)

    class Meta:
        model = Service
        fields = [
            'id', 'name', 'description', 'duration', 'duration_text',
            'price', 'price_text', 'down_payment', 'down_payment_text',
            'currency', 'background_color', 'image', 'image_url',
            'reschedule_limit', 'allow_rescheduling',
            'created_at', 'updated_at'
        ]


class ServiceDetailSerializer(ServiceListSerializer):
    """Detail serializer for appointment services."""
    staff_members = serializers.SerializerMethodField()

    class Meta(ServiceListSerializer.Meta):
        fields = ServiceListSerializer.Meta.fields + ['staff_members']

    def get_staff_members(self, obj):
        """Get staff members offering this service."""
        staff = StaffMember.objects.filter(services_offered=obj)
        return StaffMemberListSerializer(staff, many=True).data


class ServiceCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating services."""

    class Meta:
        model = Service
        fields = [
            'name', 'description', 'duration', 'price', 'down_payment',
            'currency', 'background_color', 'image',
            'reschedule_limit', 'allow_rescheduling'
        ]

    def validate_name(self, value):
        """Sanitize name."""
        from core.validators import sanitize_html
        return sanitize_html(value)

    def validate_description(self, value):
        """Sanitize description."""
        if value:
            from core.validators import sanitize_html
            return sanitize_html(value)
        return value


class StaffMemberListSerializer(serializers.ModelSerializer):
    """List serializer for staff members."""
    name = serializers.CharField(source='get_staff_member_name', read_only=True)
    first_name = serializers.CharField(source='get_staff_member_first_name', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    slot_duration_text = serializers.CharField(source='get_slot_duration_text', read_only=True)
    weekend_days_text = serializers.CharField(source='get_weekend_days_worked_text', read_only=True)
    services_text = serializers.CharField(source='get_service_offered_text', read_only=True)

    class Meta:
        model = StaffMember
        fields = [
            'id', 'name', 'first_name', 'email', 'user',
            'slot_duration', 'slot_duration_text',
            'lead_time', 'finish_time', 'appointment_buffer_time',
            'work_on_saturday', 'work_on_sunday', 'weekend_days_text',
            'services_text', 'created_at', 'updated_at'
        ]


class StaffMemberDetailSerializer(StaffMemberListSerializer):
    """Detail serializer for staff members."""
    services_offered = ServiceListSerializer(many=True, read_only=True)
    working_hours = serializers.SerializerMethodField()
    days_off = serializers.SerializerMethodField()

    class Meta(StaffMemberListSerializer.Meta):
        fields = StaffMemberListSerializer.Meta.fields + [
            'services_offered', 'working_hours', 'days_off'
        ]

    def get_working_hours(self, obj):
        """Get working hours."""
        hours = obj.get_working_hours()
        return WorkingHoursSerializer(hours, many=True).data

    def get_days_off(self, obj):
        """Get days off."""
        days = obj.get_days_off()
        return DayOffSerializer(days, many=True).data


class StaffMemberCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating staff members."""
    services_offered = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Service.objects.all(), required=False
    )

    class Meta:
        model = StaffMember
        fields = [
            'user', 'services_offered', 'slot_duration',
            'lead_time', 'finish_time', 'appointment_buffer_time',
            'work_on_saturday', 'work_on_sunday'
        ]


class WorkingHoursSerializer(serializers.ModelSerializer):
    """Serializer for working hours."""
    day_name = serializers.CharField(source='get_day_of_week_display', read_only=True)

    class Meta:
        model = WorkingHours
        fields = [
            'id', 'staff_member', 'day_of_week', 'day_name',
            'start_time', 'end_time', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class DayOffSerializer(serializers.ModelSerializer):
    """Serializer for days off."""
    staff_member_name = serializers.CharField(
        source='staff_member.get_staff_member_name', read_only=True
    )

    class Meta:
        model = DayOff
        fields = [
            'id', 'staff_member', 'staff_member_name',
            'start_date', 'end_date', 'description',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_description(self, value):
        """Sanitize description."""
        if value:
            from core.validators import sanitize_html
            return sanitize_html(value)
        return value


class AppointmentRequestListSerializer(serializers.ModelSerializer):
    """List serializer for appointment requests."""
    service_name = serializers.CharField(source='get_service_name', read_only=True)
    service_price = serializers.DecimalField(
        source='get_service_price', max_digits=10, decimal_places=2, read_only=True
    )
    staff_member_name = serializers.SerializerMethodField()

    class Meta:
        model = AppointmentRequest
        fields = [
            'id', 'date', 'start_time', 'end_time',
            'service', 'service_name', 'service_price',
            'staff_member', 'staff_member_name',
            'payment_type', 'id_request', 'reschedule_attempts',
            'created_at', 'updated_at'
        ]

    def get_staff_member_name(self, obj):
        """Get staff member name."""
        if obj.staff_member:
            return obj.staff_member.get_staff_member_name()
        return None


class AppointmentRequestDetailSerializer(AppointmentRequestListSerializer):
    """Detail serializer for appointment requests."""
    service_detail = ServiceListSerializer(source='service', read_only=True)
    staff_member_detail = StaffMemberListSerializer(source='staff_member', read_only=True)
    reschedule_history = serializers.SerializerMethodField()
    can_reschedule = serializers.BooleanField(source='can_be_rescheduled', read_only=True)

    class Meta(AppointmentRequestListSerializer.Meta):
        fields = AppointmentRequestListSerializer.Meta.fields + [
            'service_detail', 'staff_member_detail',
            'reschedule_history', 'can_reschedule'
        ]

    def get_reschedule_history(self, obj):
        """Get reschedule history."""
        history = obj.get_reschedule_history()
        return AppointmentRescheduleHistorySerializer(history, many=True).data


class AppointmentRequestCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating appointment requests."""

    class Meta:
        model = AppointmentRequest
        fields = [
            'date', 'start_time', 'end_time', 'service',
            'staff_member', 'payment_type'
        ]

    def validate(self, data):
        """Validate appointment request."""
        # Validate date is not in the past
        if data['date'] < timezone.now().date():
            raise serializers.ValidationError({
                'date': 'Date cannot be in the past.'
            })

        # Validate start_time < end_time
        if data['start_time'] >= data['end_time']:
            raise serializers.ValidationError({
                'start_time': 'Start time must be before end time.'
            })

        return data


class AppointmentRescheduleHistorySerializer(serializers.ModelSerializer):
    """Serializer for reschedule history."""
    staff_member_name = serializers.SerializerMethodField()

    class Meta:
        model = AppointmentRescheduleHistory
        fields = [
            'id', 'appointment_request', 'date', 'start_time', 'end_time',
            'staff_member', 'staff_member_name', 'reason_for_rescheduling',
            'reschedule_status', 'id_request', 'created_at', 'updated_at'
        ]

    def get_staff_member_name(self, obj):
        """Get staff member name."""
        if obj.staff_member:
            return obj.staff_member.get_staff_member_name()
        return None


class AppointmentListSerializer(serializers.ModelSerializer):
    """List serializer for appointments."""
    client_name = serializers.CharField(source='get_client_name', read_only=True)
    client_email = serializers.EmailField(source='client.email', read_only=True)
    service_name = serializers.CharField(source='get_service_name', read_only=True)
    staff_member_name = serializers.CharField(source='get_staff_member_name', read_only=True)
    date = serializers.DateField(source='get_date', read_only=True)
    start_time = serializers.DateTimeField(source='get_start_time', read_only=True)
    end_time = serializers.DateTimeField(source='get_end_time', read_only=True)
    is_paid = serializers.BooleanField(read_only=True)
    amount_to_pay_text = serializers.CharField(source='get_appointment_amount_to_pay_text', read_only=True)

    class Meta:
        model = Appointment
        fields = [
            'id', 'client', 'client_name', 'client_email',
            'appointment_request', 'service_name', 'staff_member_name',
            'date', 'start_time', 'end_time',
            'phone', 'address', 'want_reminder', 'additional_info',
            'paid', 'is_paid', 'amount_to_pay', 'amount_to_pay_text',
            'id_request', 'created_at', 'updated_at'
        ]


class AppointmentDetailSerializer(AppointmentListSerializer):
    """Detail serializer for appointments."""
    appointment_request_detail = AppointmentRequestDetailSerializer(
        source='appointment_request', read_only=True
    )
    service_detail = ServiceListSerializer(source='get_service', read_only=True)
    staff_member_detail = serializers.SerializerMethodField()
    payment_info = serializers.SerializerMethodField()

    class Meta(AppointmentListSerializer.Meta):
        fields = AppointmentListSerializer.Meta.fields + [
            'appointment_request_detail', 'service_detail',
            'staff_member_detail', 'payment_info'
        ]

    def get_staff_member_detail(self, obj):
        """Get staff member detail."""
        staff = obj.get_staff_member()
        if staff:
            return StaffMemberListSerializer(staff).data
        return None

    def get_payment_info(self, obj):
        """Get payment info."""
        try:
            payment = PaymentInfo.objects.filter(appointment=obj).first()
            if payment:
                return PaymentInfoSerializer(payment).data
        except PaymentInfo.DoesNotExist:
            pass
        return None


class AppointmentCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating appointments."""

    class Meta:
        model = Appointment
        fields = [
            'client', 'appointment_request', 'phone', 'address',
            'want_reminder', 'additional_info'
        ]

    def validate_additional_info(self, value):
        """Sanitize additional info."""
        if value:
            from core.validators import sanitize_html
            return sanitize_html(value)
        return value


class PaymentInfoSerializer(serializers.ModelSerializer):
    """Serializer for payment info."""
    id_request = serializers.CharField(source='get_id_request', read_only=True)
    amount_to_pay = serializers.DecimalField(
        source='get_amount_to_pay', max_digits=10, decimal_places=2, read_only=True
    )
    currency = serializers.CharField(source='get_currency', read_only=True)
    service_name = serializers.CharField(source='get_name', read_only=True)
    image_url = serializers.CharField(source='get_img_url', read_only=True)

    class Meta:
        model = PaymentInfo
        fields = [
            'id', 'appointment', 'id_request', 'amount_to_pay',
            'currency', 'service_name', 'image_url',
            'created_at', 'updated_at'
        ]


class ConfigSerializer(serializers.ModelSerializer):
    """Serializer for appointment configuration."""

    class Meta:
        model = Config
        fields = [
            'id', 'slot_duration', 'lead_time', 'finish_time',
            'appointment_buffer_time', 'website_name', 'app_offered_by_label',
            'default_reschedule_limit', 'allow_staff_change_on_reschedule',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class AvailableSlotSerializer(serializers.Serializer):
    """Serializer for available time slots."""
    date = serializers.DateField()
    start_time = serializers.TimeField()
    end_time = serializers.TimeField()
    staff_member_id = serializers.IntegerField()
    staff_member_name = serializers.CharField()


class BookingRequestSerializer(serializers.Serializer):
    """Serializer for booking requests."""
    service_id = serializers.IntegerField()
    staff_member_id = serializers.IntegerField(required=False)
    date = serializers.DateField()
    start_time = serializers.TimeField()
    payment_type = serializers.ChoiceField(choices=['full', 'down'], default='full')
    phone = serializers.CharField(required=False, allow_blank=True)
    address = serializers.CharField(required=False, allow_blank=True)
    want_reminder = serializers.BooleanField(default=False)
    additional_info = serializers.CharField(required=False, allow_blank=True)


class AppointmentStatsSerializer(serializers.Serializer):
    """Serializer for appointment statistics."""
    total_appointments = serializers.IntegerField()
    upcoming_appointments = serializers.IntegerField()
    past_appointments = serializers.IntegerField()
    paid_appointments = serializers.IntegerField()
    unpaid_appointments = serializers.IntegerField()
    total_services = serializers.IntegerField()
    total_staff_members = serializers.IntegerField()
    appointments_by_service = serializers.ListField()
    appointments_by_staff = serializers.ListField()
    revenue_total = serializers.DecimalField(max_digits=12, decimal_places=2)
