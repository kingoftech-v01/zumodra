"""
Configurations API ViewSets.

Provides ViewSets for:
- Skill taxonomy
- Company/Organization structure
- Job board
- Website content (FAQ, Testimonials)

Caching:
- Skills list cached for 10 minutes
- FAQs cached for 10 minutes
- Testimonials cached for 10 minutes
"""

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters import rest_framework as filters

from core.cache import TenantCache
from core.viewsets import (
    SecureTenantViewSet,
    SecureReadOnlyViewSet,
    AdminOnlyViewSet,
    RoleBasedViewSet,
)
from api.base import APIResponse

from ..models import (
    Skill,
    Company,
    Site,
    CompanyProfile,
    Department,
    Role,
    Membership,
    CandidateProfile,
    JobPosition,
    Job,
    JobApplication,
    LeaveRequest,
    InternalNotification,
    FAQEntry,
    Partnership,
    Testimonial,
    TrustedCompany,
)
from ..serializers import (
    SkillListSerializer,
    SkillDetailSerializer,
    SkillCreateSerializer,
    CompanyListSerializer,
    CompanyDetailSerializer,
    CompanyCreateSerializer,
    SiteListSerializer,
    SiteDetailSerializer,
    SiteCreateSerializer,
    DepartmentListSerializer,
    DepartmentDetailSerializer,
    DepartmentCreateSerializer,
    RoleListSerializer,
    RoleDetailSerializer,
    RoleCreateSerializer,
    MembershipListSerializer,
    MembershipDetailSerializer,
    JobPositionSerializer,
    JobListSerializer,
    JobDetailSerializer,
    JobCreateSerializer,
    JobApplicationListSerializer,
    JobApplicationDetailSerializer,
    JobApplicationUpdateSerializer,
    LeaveRequestListSerializer,
    LeaveRequestDetailSerializer,
    InternalNotificationSerializer,
    FAQListSerializer,
    FAQDetailSerializer,
    FAQCreateSerializer,
    PartnershipSerializer,
    TestimonialListSerializer,
    TestimonialDetailSerializer,
    TestimonialCreateSerializer,
    TrustedCompanySerializer,
    CandidateProfileSerializer,
)


# =============================================================================
# SKILL VIEWSET
# =============================================================================

class SkillFilter(filters.FilterSet):
    """Filter for skills."""
    category = filters.CharFilter(lookup_expr='iexact')
    name = filters.CharFilter(lookup_expr='icontains')
    is_verified = filters.BooleanFilter()

    class Meta:
        model = Skill
        fields = ['category', 'name', 'is_verified']


class SkillViewSet(SecureTenantViewSet):
    """
    ViewSet for managing skills.

    Provides:
    - List all skills
    - Create new skills
    - Update/delete skills (admin only)
    - Verify skills (admin action)
    """
    queryset = Skill.objects.all()
    filterset_class = SkillFilter
    search_fields = ['name', 'description', 'category']
    ordering_fields = ['name', 'category', 'created_at']
    ordering = ['name']

    action_permissions = {
        'list': [],  # Use default
        'retrieve': [],
        'create': [],
        'update': [],
        'partial_update': [],
        'destroy': [],
        'verify': [],
    }

    def get_serializer_class(self):
        if self.action == 'list':
            return SkillListSerializer
        elif self.action == 'create':
            return SkillCreateSerializer
        return SkillDetailSerializer

    def list(self, request, *args, **kwargs):
        """List skills with caching."""
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        # Build cache key from filters
        filter_params = '|'.join(f"{k}={v}" for k, v in sorted(request.query_params.items()))
        cache_key = f"skills:list:{hash(filter_params)}"

        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        response = super().list(request, *args, **kwargs)

        # Cache for 10 minutes
        tenant_cache.set(cache_key, response.data, timeout=600)

        return response

    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        """Mark a skill as verified (admin only)."""
        skill = self.get_object()
        skill.is_verified = True
        skill.save(update_fields=['is_verified'])

        # Invalidate skills cache
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)
        tenant_cache.delete_pattern("skills:")

        return APIResponse.success(
            data=SkillDetailSerializer(skill).data,
            message="Skill verified successfully"
        )


# =============================================================================
# COMPANY VIEWSET
# =============================================================================

class CompanyFilter(filters.FilterSet):
    """Filter for companies."""
    industry = filters.CharFilter(lookup_expr='icontains')
    name = filters.CharFilter(lookup_expr='icontains')
    is_verified = filters.BooleanFilter()

    class Meta:
        model = Company
        fields = ['industry', 'name', 'is_verified']


class CompanyViewSet(SecureTenantViewSet):
    """
    ViewSet for managing companies.
    """
    queryset = Company.objects.all()
    filterset_class = CompanyFilter
    search_fields = ['name', 'industry', 'description']
    ordering_fields = ['name', 'created_at', 'employee_count']
    ordering = ['name']

    def get_serializer_class(self):
        if self.action == 'list':
            return CompanyListSerializer
        elif self.action == 'create':
            return CompanyCreateSerializer
        return CompanyDetailSerializer

    @action(detail=True, methods=['get'])
    def sites(self, request, pk=None):
        """Get all sites for a company."""
        company = self.get_object()
        sites = company.sites.filter(is_active=True)
        serializer = SiteListSerializer(sites, many=True)
        return Response(serializer.data)


# =============================================================================
# SITE VIEWSET
# =============================================================================

class SiteViewSet(SecureTenantViewSet):
    """
    ViewSet for managing sites.
    """
    queryset = Site.objects.select_related('company').all()
    search_fields = ['name', 'city', 'address']
    ordering_fields = ['name', 'city', 'created_at']
    ordering = ['name']

    def get_serializer_class(self):
        if self.action == 'list':
            return SiteListSerializer
        elif self.action == 'create':
            return SiteCreateSerializer
        return SiteDetailSerializer


# =============================================================================
# DEPARTMENT VIEWSET
# =============================================================================

class DepartmentViewSet(SecureTenantViewSet):
    """
    ViewSet for managing departments.
    """
    queryset = Department.objects.select_related('company__company', 'manager', 'parent').all()
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']

    def get_serializer_class(self):
        if self.action == 'list':
            return DepartmentListSerializer
        elif self.action == 'create':
            return DepartmentCreateSerializer
        return DepartmentDetailSerializer

    @action(detail=True, methods=['get'])
    def members(self, request, pk=None):
        """Get all members in a department."""
        department = self.get_object()
        memberships = department.memberships.filter(is_active=True)
        serializer = MembershipListSerializer(memberships, many=True)
        return Response(serializer.data)


# =============================================================================
# ROLE VIEWSET
# =============================================================================

class RoleViewSet(AdminOnlyViewSet):
    """
    ViewSet for managing roles (admin only).
    """
    queryset = Role.objects.select_related('company__company', 'group').all()
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']

    def get_serializer_class(self):
        if self.action == 'list':
            return RoleListSerializer
        elif self.action == 'create':
            return RoleCreateSerializer
        return RoleDetailSerializer


# =============================================================================
# MEMBERSHIP VIEWSET
# =============================================================================

class MembershipViewSet(RoleBasedViewSet):
    """
    ViewSet for managing company memberships.
    """
    queryset = Membership.objects.select_related(
        'user', 'company__company', 'department', 'role'
    ).all()
    search_fields = ['user__email', 'user__first_name', 'user__last_name', 'job_title']
    ordering_fields = ['joined_at', 'job_title']
    ordering = ['-joined_at']

    role_permissions = {
        'list': ['owner', 'admin', 'hr_manager', 'viewer'],
        'retrieve': ['owner', 'admin', 'hr_manager', 'viewer'],
        'create': ['owner', 'admin', 'hr_manager'],
        'update': ['owner', 'admin', 'hr_manager'],
        'partial_update': ['owner', 'admin', 'hr_manager'],
        'destroy': ['owner', 'admin'],
    }

    def get_serializer_class(self):
        if self.action == 'list':
            return MembershipListSerializer
        return MembershipDetailSerializer


# =============================================================================
# JOB VIEWSET
# =============================================================================

class JobFilter(filters.FilterSet):
    """Filter for jobs."""
    is_active = filters.BooleanFilter()
    company = filters.NumberFilter()
    min_salary = filters.NumberFilter(field_name='salary_from', lookup_expr='gte')
    max_salary = filters.NumberFilter(field_name='salary_to', lookup_expr='lte')

    class Meta:
        model = Job
        fields = ['is_active', 'company', 'min_salary', 'max_salary']


class JobViewSet(SecureTenantViewSet):
    """
    ViewSet for managing job listings.
    """
    queryset = Job.objects.select_related('company', 'position').all()
    filterset_class = JobFilter
    search_fields = ['title', 'description', 'requirements']
    ordering_fields = ['title', 'posted_at', 'salary_from']
    ordering = ['-posted_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return JobListSerializer
        elif self.action == 'create':
            return JobCreateSerializer
        return JobDetailSerializer

    @action(detail=True, methods=['get'])
    def applications(self, request, pk=None):
        """Get all applications for a job."""
        job = self.get_object()
        applications = job.applications.select_related('candidate__user')
        serializer = JobApplicationListSerializer(applications, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def close(self, request, pk=None):
        """Close a job listing."""
        job = self.get_object()
        job.is_active = False
        job.save(update_fields=['is_active'])
        return APIResponse.success(message="Job listing closed successfully")

    @action(detail=True, methods=['post'])
    def reopen(self, request, pk=None):
        """Reopen a job listing."""
        job = self.get_object()
        job.is_active = True
        job.save(update_fields=['is_active'])
        return APIResponse.success(message="Job listing reopened successfully")


# =============================================================================
# JOB APPLICATION VIEWSET
# =============================================================================

class JobApplicationFilter(filters.FilterSet):
    """Filter for job applications."""
    status = filters.CharFilter()
    job = filters.NumberFilter()

    class Meta:
        model = JobApplication
        fields = ['status', 'job']


class JobApplicationViewSet(RoleBasedViewSet):
    """
    ViewSet for managing job applications.
    """
    queryset = JobApplication.objects.select_related('candidate__user', 'job__company').all()
    filterset_class = JobApplicationFilter
    search_fields = ['candidate__user__email', 'candidate__user__first_name', 'candidate__user__last_name']
    ordering_fields = ['applied_at', 'status']
    ordering = ['-applied_at']

    role_permissions = {
        'list': ['owner', 'admin', 'hr_manager', 'recruiter', 'viewer'],
        'retrieve': ['owner', 'admin', 'hr_manager', 'recruiter', 'viewer'],
        'create': ['owner', 'admin', 'hr_manager', 'recruiter'],
        'update': ['owner', 'admin', 'hr_manager', 'recruiter'],
        'partial_update': ['owner', 'admin', 'hr_manager', 'recruiter'],
        'destroy': ['owner', 'admin'],
    }

    def get_serializer_class(self):
        if self.action == 'list':
            return JobApplicationListSerializer
        elif self.action in ['update', 'partial_update']:
            return JobApplicationUpdateSerializer
        return JobApplicationDetailSerializer

    @action(detail=True, methods=['post'])
    def review(self, request, pk=None):
        """Mark application as reviewed."""
        from django.utils import timezone
        application = self.get_object()
        application.status = JobApplication.ApplicationStatus.REVIEWED
        application.reviewed_at = timezone.now()
        application.reviewed_by = request.user
        application.save(update_fields=['status', 'reviewed_at', 'reviewed_by'])
        return APIResponse.success(
            data=JobApplicationDetailSerializer(application).data,
            message="Application marked as reviewed"
        )

    @action(detail=True, methods=['post'])
    def schedule_interview(self, request, pk=None):
        """Schedule an interview for the application."""
        application = self.get_object()
        application.status = JobApplication.ApplicationStatus.INTERVIEW
        application.save(update_fields=['status'])
        return APIResponse.success(
            data=JobApplicationDetailSerializer(application).data,
            message="Interview scheduled"
        )

    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """Reject the application."""
        application = self.get_object()
        application.status = JobApplication.ApplicationStatus.REJECTED
        application.save(update_fields=['status'])
        return APIResponse.success(message="Application rejected")

    @action(detail=True, methods=['post'])
    def offer(self, request, pk=None):
        """Send offer to candidate."""
        application = self.get_object()
        application.status = JobApplication.ApplicationStatus.OFFERED
        application.save(update_fields=['status'])
        return APIResponse.success(message="Offer sent to candidate")


# =============================================================================
# FAQ VIEWSET
# =============================================================================

class FAQViewSet(SecureTenantViewSet):
    """
    ViewSet for managing FAQs with caching.
    """
    queryset = FAQEntry.objects.all()
    search_fields = ['question', 'answer', 'category']
    ordering_fields = ['sort_order', 'category', 'created_at']
    ordering = ['sort_order', 'category']

    def get_serializer_class(self):
        if self.action == 'list':
            return FAQListSerializer
        elif self.action == 'create':
            return FAQCreateSerializer
        return FAQDetailSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        # Non-admin users only see published FAQs
        if not self.request.user.is_staff:
            queryset = queryset.filter(is_published=True)
        return queryset

    def list(self, request, *args, **kwargs):
        """List FAQs with caching."""
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        is_staff = request.user.is_staff
        cache_key = f"faqs:list:staff_{is_staff}"

        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        response = super().list(request, *args, **kwargs)

        # Cache for 10 minutes
        tenant_cache.set(cache_key, response.data, timeout=600)

        return response

    @action(detail=False, methods=['get'])
    def by_category(self, request):
        """Get FAQs grouped by category with caching."""
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        is_staff = request.user.is_staff
        cache_key = f"faqs:by_category:staff_{is_staff}"

        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        queryset = self.get_queryset()
        categories = queryset.values_list('category', flat=True).distinct()
        result = {}
        for category in categories:
            faqs = queryset.filter(category=category)
            result[category or 'General'] = FAQListSerializer(faqs, many=True).data

        # Cache for 10 minutes
        tenant_cache.set(cache_key, result, timeout=600)

        return Response(result)


# =============================================================================
# TESTIMONIAL VIEWSET
# =============================================================================

class TestimonialViewSet(SecureTenantViewSet):
    """
    ViewSet for managing testimonials with caching.
    """
    queryset = Testimonial.objects.all()
    search_fields = ['author_name', 'author_company', 'content']
    ordering_fields = ['created_at', 'rating']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return TestimonialListSerializer
        elif self.action == 'create':
            return TestimonialCreateSerializer
        return TestimonialDetailSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        # Non-admin users only see published testimonials
        if not self.request.user.is_staff:
            queryset = queryset.filter(is_published=True)
        return queryset

    def list(self, request, *args, **kwargs):
        """List testimonials with caching."""
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        is_staff = request.user.is_staff
        cache_key = f"testimonials:list:staff_{is_staff}"

        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        response = super().list(request, *args, **kwargs)

        # Cache for 10 minutes
        tenant_cache.set(cache_key, response.data, timeout=600)

        return response

    @action(detail=False, methods=['get'])
    def featured(self, request):
        """Get featured testimonials with caching."""
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        cache_key = "testimonials:featured"
        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        queryset = self.get_queryset().filter(is_featured=True)
        serializer = TestimonialListSerializer(queryset, many=True)

        # Cache for 10 minutes
        tenant_cache.set(cache_key, serializer.data, timeout=600)

        return Response(serializer.data)


# =============================================================================
# PARTNERSHIP VIEWSET
# =============================================================================

class PartnershipViewSet(SecureTenantViewSet):
    """
    ViewSet for managing partnerships.
    """
    queryset = Partnership.objects.all()
    serializer_class = PartnershipSerializer
    search_fields = ['name', 'description']
    ordering_fields = ['sort_order', 'name']
    ordering = ['sort_order', 'name']

    @action(detail=False, methods=['get'])
    def featured(self, request):
        """Get featured partners."""
        queryset = self.get_queryset().filter(is_featured=True)
        serializer = PartnershipSerializer(queryset, many=True)
        return Response(serializer.data)


# =============================================================================
# TRUSTED COMPANY VIEWSET
# =============================================================================

class TrustedCompanyViewSet(SecureTenantViewSet):
    """
    ViewSet for managing trusted companies.
    """
    queryset = TrustedCompany.objects.all()
    serializer_class = TrustedCompanySerializer
    search_fields = ['name']
    ordering_fields = ['sort_order', 'name']
    ordering = ['sort_order', 'name']


# =============================================================================
# CANDIDATE PROFILE VIEWSET
# =============================================================================

class CandidateProfileViewSet(SecureTenantViewSet):
    """
    ViewSet for managing candidate profiles.
    """
    queryset = CandidateProfile.objects.select_related('user').prefetch_related(
        'skills', 'work_experiences', 'educations', 'certifications'
    ).all()
    serializer_class = CandidateProfileSerializer
    search_fields = ['user__email', 'user__first_name', 'user__last_name', 'bio']
    ordering_fields = ['created_at']
    ordering = ['-created_at']


# =============================================================================
# LEAVE REQUEST VIEWSET
# =============================================================================

class LeaveRequestFilter(filters.FilterSet):
    """Filter for leave requests."""
    status = filters.CharFilter()
    leave_type = filters.CharFilter()
    start_date_after = filters.DateFilter(field_name='start_date', lookup_expr='gte')
    end_date_before = filters.DateFilter(field_name='end_date', lookup_expr='lte')

    class Meta:
        model = LeaveRequest
        fields = ['status', 'leave_type', 'start_date_after', 'end_date_before']


class LeaveRequestViewSet(RoleBasedViewSet):
    """
    ViewSet for managing leave requests.
    """
    queryset = LeaveRequest.objects.select_related(
        'employee_record__membership__user', 'reviewed_by'
    ).all()
    filterset_class = LeaveRequestFilter
    ordering_fields = ['start_date', 'created_at', 'status']
    ordering = ['-created_at']

    role_permissions = {
        'list': ['owner', 'admin', 'hr_manager', 'viewer'],
        'retrieve': ['owner', 'admin', 'hr_manager', 'viewer'],
        'create': ['owner', 'admin', 'hr_manager', 'employee'],
        'update': ['owner', 'admin', 'hr_manager'],
        'partial_update': ['owner', 'admin', 'hr_manager'],
        'destroy': ['owner', 'admin'],
        'approve': ['owner', 'admin', 'hr_manager'],
        'reject': ['owner', 'admin', 'hr_manager'],
    }

    def get_serializer_class(self):
        if self.action == 'list':
            return LeaveRequestListSerializer
        return LeaveRequestDetailSerializer

    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve a leave request."""
        from django.utils import timezone
        leave_request = self.get_object()
        leave_request.status = LeaveRequest.LeaveStatus.APPROVED
        leave_request.reviewed_by = request.user
        leave_request.reviewed_at = timezone.now()
        leave_request.save(update_fields=['status', 'reviewed_by', 'reviewed_at'])
        return APIResponse.success(
            data=LeaveRequestDetailSerializer(leave_request).data,
            message="Leave request approved"
        )

    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """Reject a leave request."""
        from django.utils import timezone
        leave_request = self.get_object()
        leave_request.status = LeaveRequest.LeaveStatus.REJECTED
        leave_request.reviewed_by = request.user
        leave_request.reviewed_at = timezone.now()
        leave_request.review_notes = request.data.get('reason', '')
        leave_request.save(update_fields=['status', 'reviewed_by', 'reviewed_at', 'review_notes'])
        return APIResponse.success(message="Leave request rejected")


# =============================================================================
# INTERNAL NOTIFICATION VIEWSET
# =============================================================================

class InternalNotificationViewSet(SecureTenantViewSet):
    """
    ViewSet for managing internal notifications.
    """
    queryset = InternalNotification.objects.select_related('company', 'created_by').all()
    serializer_class = InternalNotificationSerializer
    search_fields = ['title', 'message']
    ordering_fields = ['created_at', 'is_urgent']
    ordering = ['-created_at']

    def get_queryset(self):
        queryset = super().get_queryset()
        # Filter out expired notifications for non-admin users
        if not self.request.user.is_staff:
            from django.utils import timezone
            queryset = queryset.filter(
                is_published=True
            ).filter(
                models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=timezone.now())
            )
        return queryset
