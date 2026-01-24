"""
Appointment API ViewSets - DRF ViewSets for appointment models.

Caching:
- Services list cached for 10 minutes
- Staff members list cached for 10 minutes
- Available slots cached for 1 minute (short TTL for accuracy)
- Appointment stats cached for 5 minutes
"""

from datetime import datetime, timedelta
from decimal import Decimal

from django.db.models import Count, Sum, Q
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.views import APIView
import django_filters

from core.cache import TenantCache

from ..models import (
    Service, StaffMember, AppointmentRequest, AppointmentRescheduleHistory,
    Appointment, Config, PaymentInfo, DayOff, WorkingHours
)
from .serializers import (
    ServiceListSerializer,
    ServiceDetailSerializer,
    ServiceCreateSerializer,
    StaffMemberListSerializer,
    StaffMemberDetailSerializer,
    StaffMemberCreateSerializer,
    WorkingHoursSerializer,
    DayOffSerializer,
    AppointmentRequestListSerializer,
    AppointmentRequestDetailSerializer,
    AppointmentRequestCreateSerializer,
    AppointmentRescheduleHistorySerializer,
    AppointmentListSerializer,
    AppointmentDetailSerializer,
    AppointmentCreateSerializer,
    PaymentInfoSerializer,
    ConfigSerializer,
    AvailableSlotSerializer,
    BookingRequestSerializer,
    AppointmentStatsSerializer,
)


class ServiceFilter(django_filters.FilterSet):
    """Filter for appointment services."""
    min_price = django_filters.NumberFilter(field_name='price', lookup_expr='gte')
    max_price = django_filters.NumberFilter(field_name='price', lookup_expr='lte')
    currency = django_filters.CharFilter(field_name='currency')
    allow_rescheduling = django_filters.BooleanFilter(field_name='allow_rescheduling')
    search = django_filters.CharFilter(method='filter_search')

    def filter_search(self, queryset, name, value):
        """Search in name and description."""
        return queryset.filter(
            Q(name__icontains=value) | Q(description__icontains=value)
        )

    class Meta:
        model = Service
        fields = ['currency', 'allow_rescheduling', 'min_price', 'max_price', 'search']


class ServiceViewSet(viewsets.ModelViewSet):
    """
    ViewSet for appointment services with caching.

    Public can view services, admin can manage.
    """
    queryset = Service.objects.all()
    filterset_class = ServiceFilter
    ordering_fields = ['name', 'price', 'created_at']
    ordering = ['name']

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == 'retrieve':
            return ServiceDetailSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return ServiceCreateSerializer
        return ServiceListSerializer

    def get_permissions(self):
        """Set permissions based on action."""
        if self.action in ['list', 'retrieve']:
            return [AllowAny()]
        return [IsAdminUser()]

    def list(self, request, *args, **kwargs):
        """List services with caching."""
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        cache_key = "appointment:services:list"

        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        response = super().list(request, *args, **kwargs)

        # Cache for 10 minutes
        tenant_cache.set(cache_key, response.data, timeout=600)

        return response

    @action(detail=True, methods=['get'])
    def staff_members(self, request, pk=None):
        """Get staff members offering this service."""
        service = self.get_object()
        staff = StaffMember.objects.filter(services_offered=service)
        serializer = StaffMemberListSerializer(staff, many=True)
        return Response(serializer.data)


class StaffMemberFilter(django_filters.FilterSet):
    """Filter for staff members."""
    service = django_filters.NumberFilter(field_name='services_offered__id')
    work_on_saturday = django_filters.BooleanFilter(field_name='work_on_saturday')
    work_on_sunday = django_filters.BooleanFilter(field_name='work_on_sunday')
    search = django_filters.CharFilter(method='filter_search')

    def filter_search(self, queryset, name, value):
        """Search in user name and email."""
        return queryset.filter(
            Q(user__first_name__icontains=value) |
            Q(user__last_name__icontains=value) |
            Q(user__email__icontains=value)
        )

    class Meta:
        model = StaffMember
        fields = ['service', 'work_on_saturday', 'work_on_sunday', 'search']


class StaffMemberViewSet(viewsets.ModelViewSet):
    """
    ViewSet for staff members.

    Public can view, admin can manage.
    """
    queryset = StaffMember.objects.all()
    filterset_class = StaffMemberFilter
    ordering = ['user__first_name', 'user__last_name']

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == 'retrieve':
            return StaffMemberDetailSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return StaffMemberCreateSerializer
        return StaffMemberListSerializer

    def get_permissions(self):
        """Set permissions based on action."""
        if self.action in ['list', 'retrieve']:
            return [AllowAny()]
        return [IsAdminUser()]

    @action(detail=True, methods=['get'])
    def available_slots(self, request, pk=None):
        """Get available time slots for this staff member."""
        staff = self.get_object()
        date_str = request.query_params.get('date')
        service_id = request.query_params.get('service')

        if not date_str:
            return Response(
                {'error': 'Date parameter required (YYYY-MM-DD)'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            return Response(
                {'error': 'Invalid date format. Use YYYY-MM-DD'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get working hours for this day
        day_of_week = date.weekday()
        # Convert Python weekday (0=Monday) to model weekday (0=Sunday)
        model_day = (day_of_week + 1) % 7

        try:
            working_hours = WorkingHours.objects.get(
                staff_member=staff, day_of_week=model_day
            )
        except WorkingHours.DoesNotExist:
            return Response({'slots': []})

        # Check if it's a day off
        if DayOff.objects.filter(
            staff_member=staff,
            start_date__lte=date,
            end_date__gte=date
        ).exists():
            return Response({'slots': []})

        # Get service duration
        if service_id:
            try:
                service = Service.objects.get(pk=service_id)
                slot_duration = service.duration
            except Service.DoesNotExist:
                slot_duration = timedelta(minutes=staff.get_slot_duration() or 30)
        else:
            slot_duration = timedelta(minutes=staff.get_slot_duration() or 30)

        # Generate available slots
        slots = []
        current_time = datetime.combine(date, working_hours.start_time)
        end_time = datetime.combine(date, working_hours.end_time)

        # Get existing appointments
        existing_appointments = AppointmentRequest.objects.filter(
            staff_member=staff, date=date
        ).values_list('start_time', 'end_time')

        booked_times = [(start, end) for start, end in existing_appointments]

        while current_time + slot_duration <= end_time:
            slot_end = current_time + slot_duration
            is_available = True

            for booked_start, booked_end in booked_times:
                booked_start_dt = datetime.combine(date, booked_start)
                booked_end_dt = datetime.combine(date, booked_end)

                if (current_time < booked_end_dt and slot_end > booked_start_dt):
                    is_available = False
                    break

            if is_available:
                # Skip past times for today
                if date == timezone.now().date() and current_time.time() <= timezone.now().time():
                    current_time += slot_duration
                    continue

                slots.append({
                    'date': date,
                    'start_time': current_time.time(),
                    'end_time': slot_end.time(),
                    'staff_member_id': staff.id,
                    'staff_member_name': staff.get_staff_member_name()
                })

            current_time += slot_duration

        return Response({'slots': slots})


class WorkingHoursViewSet(viewsets.ModelViewSet):
    """
    ViewSet for working hours.

    Admin-only access.
    """
    queryset = WorkingHours.objects.all()
    serializer_class = WorkingHoursSerializer
    permission_classes = [IsAdminUser]
    ordering = ['staff_member', 'day_of_week']

    def get_queryset(self):
        """Filter by staff member if specified."""
        queryset = WorkingHours.objects.all()
        staff_id = self.request.query_params.get('staff_member')

        if staff_id:
            queryset = queryset.filter(staff_member_id=staff_id)

        return queryset


class DayOffViewSet(viewsets.ModelViewSet):
    """
    ViewSet for days off.

    Admin-only access.
    """
    queryset = DayOff.objects.all()
    serializer_class = DayOffSerializer
    permission_classes = [IsAdminUser]
    ordering = ['-start_date']

    def get_queryset(self):
        """Filter by staff member if specified."""
        queryset = DayOff.objects.all()
        staff_id = self.request.query_params.get('staff_member')

        if staff_id:
            queryset = queryset.filter(staff_member_id=staff_id)

        return queryset


class AppointmentRequestFilter(django_filters.FilterSet):
    """Filter for appointment requests."""
    service = django_filters.NumberFilter(field_name='service_id')
    staff_member = django_filters.NumberFilter(field_name='staff_member_id')
    date = django_filters.DateFilter(field_name='date')
    from_date = django_filters.DateFilter(field_name='date', lookup_expr='gte')
    to_date = django_filters.DateFilter(field_name='date', lookup_expr='lte')

    class Meta:
        model = AppointmentRequest
        fields = ['service', 'staff_member', 'date', 'from_date', 'to_date']


class AppointmentRequestViewSet(viewsets.ModelViewSet):
    """
    ViewSet for appointment requests.

    Admin-only access for management.
    """
    queryset = AppointmentRequest.objects.all()
    permission_classes = [IsAdminUser]
    filterset_class = AppointmentRequestFilter
    ordering = ['-date', 'start_time']

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == 'retrieve':
            return AppointmentRequestDetailSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return AppointmentRequestCreateSerializer
        return AppointmentRequestListSerializer


class AppointmentFilter(django_filters.FilterSet):
    """Filter for appointments."""
    client = django_filters.NumberFilter(field_name='client_id')
    paid = django_filters.BooleanFilter(field_name='paid')
    service = django_filters.NumberFilter(
        field_name='appointment_request__service_id'
    )
    staff_member = django_filters.NumberFilter(
        field_name='appointment_request__staff_member_id'
    )
    from_date = django_filters.DateFilter(
        field_name='appointment_request__date', lookup_expr='gte'
    )
    to_date = django_filters.DateFilter(
        field_name='appointment_request__date', lookup_expr='lte'
    )
    upcoming = django_filters.BooleanFilter(method='filter_upcoming')

    def filter_upcoming(self, queryset, name, value):
        """Filter upcoming appointments."""
        today = timezone.now().date()
        if value:
            return queryset.filter(appointment_request__date__gte=today)
        return queryset.filter(appointment_request__date__lt=today)

    class Meta:
        model = Appointment
        fields = ['client', 'paid', 'service', 'staff_member', 'from_date', 'to_date', 'upcoming']


class AppointmentViewSet(viewsets.ModelViewSet):
    """
    ViewSet for appointments.

    Authenticated users can view their own appointments.
    Admin can view and manage all.
    """
    filterset_class = AppointmentFilter
    ordering = ['-appointment_request__date', 'appointment_request__start_time']

    def get_queryset(self):
        """Filter by user or return all for admin."""
        if self.request.user.is_staff:
            return Appointment.objects.all()
        return Appointment.objects.filter(client=self.request.user)

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == 'retrieve':
            return AppointmentDetailSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return AppointmentCreateSerializer
        return AppointmentListSerializer

    def get_permissions(self):
        """Set permissions based on action."""
        if self.action in ['list', 'retrieve']:
            return [IsAuthenticated()]
        return [IsAuthenticated()]

    @action(detail=True, methods=['post'])
    def mark_paid(self, request, pk=None):
        """Mark appointment as paid."""
        if not request.user.is_staff:
            return Response(
                {'error': 'Admin access required'},
                status=status.HTTP_403_FORBIDDEN
            )

        appointment = self.get_object()
        appointment.set_appointment_paid_status(True)
        serializer = AppointmentDetailSerializer(appointment)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel an appointment."""
        appointment = self.get_object()

        # Check ownership or admin
        if not (request.user.is_staff or appointment.client == request.user):
            return Response(
                {'error': 'Not authorized'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Delete the appointment request (cascades to appointment)
        appointment.appointment_request.delete()

        return Response({'message': 'Appointment cancelled successfully'})

    @action(detail=False, methods=['get'])
    def my_appointments(self, request):
        """Get current user's appointments."""
        appointments = Appointment.objects.filter(client=request.user)

        # Filter upcoming
        upcoming = request.query_params.get('upcoming')
        if upcoming == 'true':
            today = timezone.now().date()
            appointments = appointments.filter(appointment_request__date__gte=today)

        appointments = appointments.order_by('-appointment_request__date')
        serializer = AppointmentListSerializer(appointments, many=True)
        return Response(serializer.data)


class PaymentInfoViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for payment info.

    Admin-only access.
    """
    queryset = PaymentInfo.objects.all()
    serializer_class = PaymentInfoSerializer
    permission_classes = [IsAdminUser]
    ordering = ['-created_at']


class ConfigViewSet(viewsets.ModelViewSet):
    """
    ViewSet for appointment configuration.

    Admin-only access. Only one config object exists.
    """
    queryset = Config.objects.all()
    serializer_class = ConfigSerializer
    permission_classes = [IsAdminUser]

    def list(self, request):
        """Return the single config instance."""
        config = Config.get_instance()
        serializer = self.get_serializer(config)
        return Response(serializer.data)

    def create(self, request):
        """Update or create config (only one exists)."""
        config = Config.get_instance()
        serializer = self.get_serializer(config, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class BookingView(APIView):
    """
    Public booking endpoint for creating appointments.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """Create a new booking."""
        serializer = BookingRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # Get service
        try:
            service = Service.objects.get(pk=data['service_id'])
        except Service.DoesNotExist:
            return Response(
                {'error': 'Service not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Get or auto-select staff member
        staff_member = None
        if data.get('staff_member_id'):
            try:
                staff_member = StaffMember.objects.get(pk=data['staff_member_id'])
            except StaffMember.DoesNotExist:
                return Response(
                    {'error': 'Staff member not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            # Auto-select first available staff member
            staff_member = StaffMember.objects.filter(
                services_offered=service
            ).first()

        if not staff_member:
            return Response(
                {'error': 'No staff member available for this service'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Calculate end time
        end_time = (
            datetime.combine(data['date'], data['start_time']) + service.duration
        ).time()

        # Create appointment request
        appointment_request = AppointmentRequest.objects.create(
            date=data['date'],
            start_time=data['start_time'],
            end_time=end_time,
            service=service,
            staff_member=staff_member,
            payment_type=data.get('payment_type', 'full')
        )

        # Create appointment
        appointment = Appointment.objects.create(
            client=request.user if request.user.is_authenticated else None,
            appointment_request=appointment_request,
            phone=data.get('phone', ''),
            address=data.get('address', ''),
            want_reminder=data.get('want_reminder', False),
            additional_info=data.get('additional_info', '')
        )

        serializer = AppointmentDetailSerializer(appointment)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class AppointmentStatsView(APIView):
    """
    API view for appointment statistics with caching.

    Staff-only access to analytics.
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        """Return appointment statistics with caching."""
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        cache_key = "appointment:stats"
        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        today = timezone.now().date()

        all_appointments = Appointment.objects.all()
        total = all_appointments.count()
        upcoming = all_appointments.filter(appointment_request__date__gte=today).count()
        past = all_appointments.filter(appointment_request__date__lt=today).count()
        paid = all_appointments.filter(paid=True).count()
        unpaid = all_appointments.filter(paid=False).count()

        # Counts
        total_services = Service.objects.count()
        total_staff = StaffMember.objects.count()

        # Appointments by service
        by_service = Service.objects.annotate(
            appointment_count=Count('appointmentrequest__appointment')
        ).values('id', 'name', 'appointment_count')

        # Appointments by staff
        by_staff = StaffMember.objects.annotate(
            appointment_count=Count('appointmentrequest__appointment')
        ).values('id', 'user__email', 'appointment_count')

        # Total revenue
        revenue = all_appointments.filter(paid=True).aggregate(
            total=Sum('amount_to_pay')
        )['total'] or Decimal('0.00')

        stats = {
            'total_appointments': total,
            'upcoming_appointments': upcoming,
            'past_appointments': past,
            'paid_appointments': paid,
            'unpaid_appointments': unpaid,
            'total_services': total_services,
            'total_staff_members': total_staff,
            'appointments_by_service': list(by_service),
            'appointments_by_staff': list(by_staff),
            'revenue_total': revenue,
        }

        serializer = AppointmentStatsSerializer(stats)

        # Cache for 5 minutes
        tenant_cache.set(cache_key, serializer.data, timeout=300)

        return Response(serializer.data)
