"""
HR Core API Filters - Django Filter Classes for HR Models

This module provides django-filter FilterSets for:
- Employee filtering by status, department, manager, etc.
- Time-off request filtering by date range, status, type
- Document filtering by category, status, employee
- Performance review filtering by period, status, type
"""

import django_filters
from django.db.models import Q
from django.utils import timezone

from .models import (
    Employee, TimeOffType, TimeOffRequest,
    OnboardingChecklist, EmployeeOnboarding,
    DocumentTemplate, EmployeeDocument,
    Offboarding, PerformanceReview
)
from configurations.models import Department


class EmployeeFilter(django_filters.FilterSet):
    """
    Filter for Employee model.

    Filters:
    - status: Filter by employment status (exact match)
    - status__in: Filter by multiple statuses
    - employment_type: Filter by employment type
    - department: Filter by department ID
    - department_name: Filter by department name (partial match)
    - manager: Filter by manager ID
    - has_manager: Filter employees with/without manager
    - team: Filter by team name (partial match)
    - work_location: Filter by work location (partial match)
    - hire_date_from/to: Filter by hire date range
    - start_date_from/to: Filter by start date range
    - is_active: Filter by active employment status
    - is_on_probation: Filter employees on probation
    - years_of_service_min/max: Filter by years of service
    """

    status = django_filters.ChoiceFilter(
        choices=Employee.EmploymentStatus.choices
    )
    status__in = django_filters.MultipleChoiceFilter(
        field_name='status',
        choices=Employee.EmploymentStatus.choices,
        conjoined=False  # OR logic
    )
    employment_type = django_filters.ChoiceFilter(
        choices=Employee.EmploymentType.choices
    )
    department = django_filters.NumberFilter(field_name='department__id')
    department_name = django_filters.CharFilter(
        field_name='department__name',
        lookup_expr='icontains'
    )
    manager = django_filters.NumberFilter(field_name='manager__id')
    has_manager = django_filters.BooleanFilter(
        method='filter_has_manager'
    )
    team = django_filters.CharFilter(lookup_expr='icontains')
    work_location = django_filters.CharFilter(lookup_expr='icontains')

    # Date range filters
    hire_date_from = django_filters.DateFilter(
        field_name='hire_date',
        lookup_expr='gte'
    )
    hire_date_to = django_filters.DateFilter(
        field_name='hire_date',
        lookup_expr='lte'
    )
    start_date_from = django_filters.DateFilter(
        field_name='start_date',
        lookup_expr='gte'
    )
    start_date_to = django_filters.DateFilter(
        field_name='start_date',
        lookup_expr='lte'
    )

    # Computed filters
    is_active = django_filters.BooleanFilter(method='filter_is_active')
    is_on_probation = django_filters.BooleanFilter(method='filter_is_on_probation')
    years_of_service_min = django_filters.NumberFilter(
        method='filter_years_of_service_min'
    )
    years_of_service_max = django_filters.NumberFilter(
        method='filter_years_of_service_max'
    )

    # Search by name or email
    search = django_filters.CharFilter(method='filter_search')

    class Meta:
        model = Employee
        fields = [
            'status', 'employment_type', 'department', 'manager',
            'team', 'work_location'
        ]

    def filter_has_manager(self, queryset, name, value):
        if value:
            return queryset.filter(manager__isnull=False)
        return queryset.filter(manager__isnull=True)

    def filter_is_active(self, queryset, name, value):
        active_statuses = ['active', 'probation', 'on_leave']
        if value:
            return queryset.filter(status__in=active_statuses)
        return queryset.exclude(status__in=active_statuses)

    def filter_is_on_probation(self, queryset, name, value):
        if value:
            return queryset.filter(status='probation')
        return queryset.exclude(status='probation')

    def filter_years_of_service_min(self, queryset, name, value):
        cutoff_date = timezone.now().date() - timezone.timedelta(days=int(value * 365.25))
        return queryset.filter(start_date__lte=cutoff_date)

    def filter_years_of_service_max(self, queryset, name, value):
        cutoff_date = timezone.now().date() - timezone.timedelta(days=int(value * 365.25))
        return queryset.filter(start_date__gte=cutoff_date)

    def filter_search(self, queryset, name, value):
        return queryset.filter(
            Q(user__first_name__icontains=value) |
            Q(user__last_name__icontains=value) |
            Q(user__email__icontains=value) |
            Q(employee_id__icontains=value) |
            Q(job_title__icontains=value)
        )


class TimeOffRequestFilter(django_filters.FilterSet):
    """
    Filter for TimeOffRequest model.

    Filters:
    - status: Filter by request status
    - status__in: Filter by multiple statuses
    - employee: Filter by employee ID
    - employee_uuid: Filter by employee UUID
    - time_off_type: Filter by time off type ID
    - time_off_type_code: Filter by time off type code
    - start_date_from/to: Filter by start date range
    - end_date_from/to: Filter by end date range
    - is_half_day: Filter half-day requests
    - approver: Filter by approver user ID
    - is_current: Filter requests that include today
    - is_upcoming: Filter future requests
    - is_past: Filter past requests
    - created_from/to: Filter by creation date
    """

    status = django_filters.ChoiceFilter(
        choices=TimeOffRequest.RequestStatus.choices
    )
    status__in = django_filters.MultipleChoiceFilter(
        field_name='status',
        choices=TimeOffRequest.RequestStatus.choices,
        conjoined=False
    )
    employee = django_filters.NumberFilter(field_name='employee__id')
    employee_uuid = django_filters.UUIDFilter(field_name='employee__uuid')
    time_off_type = django_filters.NumberFilter(field_name='time_off_type__id')
    time_off_type_code = django_filters.CharFilter(
        field_name='time_off_type__code',
        lookup_expr='iexact'
    )

    # Date range filters
    start_date_from = django_filters.DateFilter(
        field_name='start_date',
        lookup_expr='gte'
    )
    start_date_to = django_filters.DateFilter(
        field_name='start_date',
        lookup_expr='lte'
    )
    end_date_from = django_filters.DateFilter(
        field_name='end_date',
        lookup_expr='gte'
    )
    end_date_to = django_filters.DateFilter(
        field_name='end_date',
        lookup_expr='lte'
    )

    is_half_day = django_filters.BooleanFilter()
    approver = django_filters.NumberFilter(field_name='approver__id')

    # Computed date filters
    is_current = django_filters.BooleanFilter(method='filter_is_current')
    is_upcoming = django_filters.BooleanFilter(method='filter_is_upcoming')
    is_past = django_filters.BooleanFilter(method='filter_is_past')

    # Creation date filters
    created_from = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='gte'
    )
    created_to = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='lte'
    )

    class Meta:
        model = TimeOffRequest
        fields = [
            'status', 'employee', 'time_off_type', 'is_half_day', 'approver'
        ]

    def filter_is_current(self, queryset, name, value):
        today = timezone.now().date()
        if value:
            return queryset.filter(
                start_date__lte=today,
                end_date__gte=today
            )
        return queryset.exclude(
            start_date__lte=today,
            end_date__gte=today
        )

    def filter_is_upcoming(self, queryset, name, value):
        today = timezone.now().date()
        if value:
            return queryset.filter(start_date__gt=today)
        return queryset.filter(start_date__lte=today)

    def filter_is_past(self, queryset, name, value):
        today = timezone.now().date()
        if value:
            return queryset.filter(end_date__lt=today)
        return queryset.filter(end_date__gte=today)


class EmployeeDocumentFilter(django_filters.FilterSet):
    """
    Filter for EmployeeDocument model.

    Filters:
    - employee: Filter by employee ID
    - employee_uuid: Filter by employee UUID
    - category: Filter by document category
    - status: Filter by document status
    - status__in: Filter by multiple statuses
    - template: Filter by template ID
    - requires_signature: Filter documents requiring signature
    - is_signed: Filter signed documents
    - is_expired: Filter expired documents
    - expires_before: Filter by expiration date
    - created_from/to: Filter by creation date
    - uploaded_by: Filter by uploader user ID
    """

    employee = django_filters.NumberFilter(field_name='employee__id')
    employee_uuid = django_filters.UUIDFilter(field_name='employee__uuid')
    category = django_filters.ChoiceFilter(
        choices=DocumentTemplate.DocumentCategory.choices
    )
    status = django_filters.ChoiceFilter(
        choices=EmployeeDocument.DocumentStatus.choices
    )
    status__in = django_filters.MultipleChoiceFilter(
        field_name='status',
        choices=EmployeeDocument.DocumentStatus.choices,
        conjoined=False
    )
    template = django_filters.NumberFilter(field_name='template__id')
    requires_signature = django_filters.BooleanFilter()

    # Computed filters
    is_signed = django_filters.BooleanFilter(method='filter_is_signed')
    is_expired = django_filters.BooleanFilter(method='filter_is_expired')
    expires_before = django_filters.DateFilter(
        field_name='expires_at',
        lookup_expr='lte'
    )

    # Creation and upload filters
    created_from = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='gte'
    )
    created_to = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='lte'
    )
    uploaded_by = django_filters.NumberFilter(field_name='uploaded_by__id')

    # Search
    search = django_filters.CharFilter(method='filter_search')

    class Meta:
        model = EmployeeDocument
        fields = [
            'employee', 'category', 'status', 'template',
            'requires_signature', 'uploaded_by'
        ]

    def filter_is_signed(self, queryset, name, value):
        if value:
            return queryset.filter(status='signed')
        return queryset.exclude(status='signed')

    def filter_is_expired(self, queryset, name, value):
        today = timezone.now().date()
        if value:
            return queryset.filter(
                expires_at__isnull=False,
                expires_at__lt=today
            )
        return queryset.filter(
            Q(expires_at__isnull=True) | Q(expires_at__gte=today)
        )

    def filter_search(self, queryset, name, value):
        return queryset.filter(
            Q(title__icontains=value) |
            Q(description__icontains=value)
        )


class PerformanceReviewFilter(django_filters.FilterSet):
    """
    Filter for PerformanceReview model.

    Filters:
    - employee: Filter by employee ID
    - employee_uuid: Filter by employee UUID
    - reviewer: Filter by reviewer user ID
    - review_type: Filter by review type
    - status: Filter by review status
    - status__in: Filter by multiple statuses
    - review_period_start_from/to: Filter by period start
    - review_period_end_from/to: Filter by period end
    - overall_rating: Filter by exact rating
    - overall_rating_min/max: Filter by rating range
    - promotion_recommended: Filter by promotion recommendation
    - pip_recommended: Filter by PIP recommendation
    - is_completed: Filter completed reviews
    - is_pending: Filter pending reviews
    - year: Filter by review period year
    """

    employee = django_filters.NumberFilter(field_name='employee__id')
    employee_uuid = django_filters.UUIDFilter(field_name='employee__uuid')
    reviewer = django_filters.NumberFilter(field_name='reviewer__id')
    review_type = django_filters.ChoiceFilter(
        choices=PerformanceReview.ReviewType.choices
    )
    status = django_filters.ChoiceFilter(
        choices=PerformanceReview.ReviewStatus.choices
    )
    status__in = django_filters.MultipleChoiceFilter(
        field_name='status',
        choices=PerformanceReview.ReviewStatus.choices,
        conjoined=False
    )

    # Date range filters
    review_period_start_from = django_filters.DateFilter(
        field_name='review_period_start',
        lookup_expr='gte'
    )
    review_period_start_to = django_filters.DateFilter(
        field_name='review_period_start',
        lookup_expr='lte'
    )
    review_period_end_from = django_filters.DateFilter(
        field_name='review_period_end',
        lookup_expr='gte'
    )
    review_period_end_to = django_filters.DateFilter(
        field_name='review_period_end',
        lookup_expr='lte'
    )

    # Rating filters
    overall_rating = django_filters.NumberFilter()
    overall_rating_min = django_filters.NumberFilter(
        field_name='overall_rating',
        lookup_expr='gte'
    )
    overall_rating_max = django_filters.NumberFilter(
        field_name='overall_rating',
        lookup_expr='lte'
    )

    # Recommendation filters
    promotion_recommended = django_filters.BooleanFilter()
    salary_increase_recommended = django_filters.BooleanFilter()
    pip_recommended = django_filters.BooleanFilter()

    # Computed filters
    is_completed = django_filters.BooleanFilter(method='filter_is_completed')
    is_pending = django_filters.BooleanFilter(method='filter_is_pending')
    year = django_filters.NumberFilter(method='filter_by_year')

    class Meta:
        model = PerformanceReview
        fields = [
            'employee', 'reviewer', 'review_type', 'status',
            'overall_rating', 'promotion_recommended', 'pip_recommended'
        ]

    def filter_is_completed(self, queryset, name, value):
        if value:
            return queryset.filter(status='completed')
        return queryset.exclude(status='completed')

    def filter_is_pending(self, queryset, name, value):
        pending_statuses = ['pending_self', 'pending_manager', 'pending_approval']
        if value:
            return queryset.filter(status__in=pending_statuses)
        return queryset.exclude(status__in=pending_statuses)

    def filter_by_year(self, queryset, name, value):
        return queryset.filter(review_period_end__year=value)


class OnboardingChecklistFilter(django_filters.FilterSet):
    """
    Filter for OnboardingChecklist model.

    Filters:
    - is_active: Filter active checklists
    - employment_type: Filter by employment type
    - department: Filter by department ID
    - search: Search by name or description
    """

    is_active = django_filters.BooleanFilter()
    employment_type = django_filters.ChoiceFilter(
        choices=Employee.EmploymentType.choices
    )
    department = django_filters.NumberFilter(field_name='department__id')
    search = django_filters.CharFilter(method='filter_search')

    class Meta:
        model = OnboardingChecklist
        fields = ['is_active', 'employment_type', 'department']

    def filter_search(self, queryset, name, value):
        return queryset.filter(
            Q(name__icontains=value) |
            Q(description__icontains=value)
        )


class EmployeeOnboardingFilter(django_filters.FilterSet):
    """
    Filter for EmployeeOnboarding model.

    Filters:
    - employee: Filter by employee ID
    - checklist: Filter by checklist ID
    - start_date_from/to: Filter by start date
    - target_completion_from/to: Filter by target completion
    - is_completed: Filter completed onboardings
    - is_overdue: Filter overdue onboardings
    """

    employee = django_filters.NumberFilter(field_name='employee__id')
    checklist = django_filters.NumberFilter(field_name='checklist__id')

    start_date_from = django_filters.DateFilter(
        field_name='start_date',
        lookup_expr='gte'
    )
    start_date_to = django_filters.DateFilter(
        field_name='start_date',
        lookup_expr='lte'
    )
    target_completion_from = django_filters.DateFilter(
        field_name='target_completion_date',
        lookup_expr='gte'
    )
    target_completion_to = django_filters.DateFilter(
        field_name='target_completion_date',
        lookup_expr='lte'
    )

    is_completed = django_filters.BooleanFilter(method='filter_is_completed')
    is_overdue = django_filters.BooleanFilter(method='filter_is_overdue')

    class Meta:
        model = EmployeeOnboarding
        fields = ['employee', 'checklist']

    def filter_is_completed(self, queryset, name, value):
        if value:
            return queryset.filter(completed_at__isnull=False)
        return queryset.filter(completed_at__isnull=True)

    def filter_is_overdue(self, queryset, name, value):
        today = timezone.now().date()
        if value:
            return queryset.filter(
                completed_at__isnull=True,
                target_completion_date__lt=today
            )
        return queryset.filter(
            Q(completed_at__isnull=False) |
            Q(target_completion_date__isnull=True) |
            Q(target_completion_date__gte=today)
        )


class OffboardingFilter(django_filters.FilterSet):
    """
    Filter for Offboarding model.

    Filters:
    - employee: Filter by employee ID
    - separation_type: Filter by separation type
    - eligible_for_rehire: Filter by rehire eligibility
    - last_working_day_from/to: Filter by last working day
    - is_completed: Filter completed offboardings
    - processed_by: Filter by processor user ID
    """

    employee = django_filters.NumberFilter(field_name='employee__id')
    separation_type = django_filters.ChoiceFilter(
        choices=Offboarding.SeparationType.choices
    )
    eligible_for_rehire = django_filters.BooleanFilter()

    last_working_day_from = django_filters.DateFilter(
        field_name='last_working_day',
        lookup_expr='gte'
    )
    last_working_day_to = django_filters.DateFilter(
        field_name='last_working_day',
        lookup_expr='lte'
    )

    is_completed = django_filters.BooleanFilter(method='filter_is_completed')
    processed_by = django_filters.NumberFilter(field_name='processed_by__id')

    class Meta:
        model = Offboarding
        fields = [
            'employee', 'separation_type', 'eligible_for_rehire', 'processed_by'
        ]

    def filter_is_completed(self, queryset, name, value):
        if value:
            return queryset.filter(completed_at__isnull=False)
        return queryset.filter(completed_at__isnull=True)


class TimeOffTypeFilter(django_filters.FilterSet):
    """
    Filter for TimeOffType model.

    Filters:
    - is_active: Filter active types
    - is_accrued: Filter accrued types
    - requires_approval: Filter types requiring approval
    - is_paid: Filter paid time off types
    - search: Search by name or code
    """

    is_active = django_filters.BooleanFilter()
    is_accrued = django_filters.BooleanFilter()
    requires_approval = django_filters.BooleanFilter()
    is_paid = django_filters.BooleanFilter()
    search = django_filters.CharFilter(method='filter_search')

    class Meta:
        model = TimeOffType
        fields = ['is_active', 'is_accrued', 'requires_approval', 'is_paid']

    def filter_search(self, queryset, name, value):
        return queryset.filter(
            Q(name__icontains=value) |
            Q(code__icontains=value) |
            Q(description__icontains=value)
        )


class DocumentTemplateFilter(django_filters.FilterSet):
    """
    Filter for DocumentTemplate model.

    Filters:
    - category: Filter by document category
    - is_active: Filter active templates
    - requires_signature: Filter templates requiring signature
    - search: Search by name or description
    """

    category = django_filters.ChoiceFilter(
        choices=DocumentTemplate.DocumentCategory.choices
    )
    is_active = django_filters.BooleanFilter()
    requires_signature = django_filters.BooleanFilter()
    search = django_filters.CharFilter(method='filter_search')

    class Meta:
        model = DocumentTemplate
        fields = ['category', 'is_active', 'requires_signature']

    def filter_search(self, queryset, name, value):
        return queryset.filter(
            Q(name__icontains=value) |
            Q(description__icontains=value)
        )
