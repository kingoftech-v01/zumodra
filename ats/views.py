"""
ATS ViewSets - REST API endpoints for Applicant Tracking System

This module provides comprehensive ViewSets for:
- Job Categories and Pipelines
- Job Postings (with publish, close, clone actions)
- Candidates (with merge, bulk import actions)
- Applications (with move_stage, reject, advance actions)
- Interviews (with schedule, reschedule, complete actions)
- Offers (with send, accept, decline actions)
- Saved Searches
- Dashboard Statistics

Security Features:
- Tenant isolation on all querysets via for_current_tenant()
- RBAC permission checking for recruiter/hiring manager roles
- Rate limiting on sensitive endpoints
- File upload validation for resumes
- Audit logging for bulk operations
"""

import logging
import os
import magic  # python-magic for file type detection

from rest_framework import viewsets, permissions, filters, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from django_filters.rest_framework import DjangoFilterBackend
from django.db import transaction, connection
from django.db.models import Count, Avg, Q, F
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.core.exceptions import PermissionDenied
from datetime import timedelta

logger = logging.getLogger(__name__)

from .models import (
    JobCategory, Pipeline, PipelineStage, JobPosting,
    Candidate, Application, ApplicationActivity, ApplicationNote,
    Interview, InterviewFeedback, Offer, SavedSearch,
    InterviewSlot, OfferTemplate, OfferApproval
)
from .serializers import (
    JobCategorySerializer, JobCategoryListSerializer,
    PipelineSerializer, PipelineListSerializer, PipelineCreateSerializer,
    PipelineStageSerializer, PipelineStageCreateSerializer,
    JobPostingListSerializer, JobPostingDetailSerializer, JobPostingCreateSerializer,
    JobPostingCloneSerializer,
    CandidateListSerializer, CandidateDetailSerializer, CandidateCreateSerializer,
    CandidateBulkImportSerializer, CandidateMergeSerializer,
    ApplicationListSerializer, ApplicationDetailSerializer, ApplicationCreateSerializer,
    ApplicationStageChangeSerializer, ApplicationRejectSerializer, ApplicationBulkActionSerializer,
    ApplicationActivitySerializer, ApplicationNoteSerializer,
    InterviewListSerializer, InterviewDetailSerializer, InterviewCreateSerializer,
    InterviewRescheduleSerializer, InterviewFeedbackSerializer, InterviewFeedbackCreateSerializer,
    OfferListSerializer, OfferDetailSerializer, OfferCreateSerializer,
    OfferSendSerializer, OfferResponseSerializer,
    SavedSearchSerializer, SavedSearchCreateSerializer,
    DashboardStatsSerializer, KanbanBoardSerializer, AIMatchScoreSerializer,
    UserMinimalSerializer,
    # New serializers for advanced ATS features
    InterviewSlotSerializer, InterviewSlotCreateSerializer, InterviewSlotBulkCreateSerializer,
    InterviewSlotAvailableSerializer, InterviewSlotFindCommonSerializer,
    OfferTemplateSerializer, OfferTemplateCreateSerializer, OfferTemplateApplySerializer,
    OfferApprovalSerializer, OfferApprovalCreateSerializer, OfferApprovalResponseSerializer,
    OfferGenerateLetterSerializer, OfferSignatureSerializer, OfferCounterSerializer,
    StageConversionRateSerializer, PipelineBottleneckSerializer, SLAStatusSerializer,
    PipelineComparisonSerializer, PipelineAnalyticsSerializer,
    RecruitingFunnelSerializer, DEIMetricsSerializer, CostPerHireSerializer,
    TimeToFillSerializer, SourceQualitySerializer, RecruiterPerformanceSerializer
)
from .filters import (
    JobCategoryFilter, PipelineFilter, PipelineStageFilter,
    JobPostingFilter, CandidateFilter, ApplicationFilter,
    InterviewFilter, OfferFilter, SavedSearchFilter
)


# ==================== RATE LIMITING CLASSES ====================

class ApplicationSubmissionThrottle(UserRateThrottle):
    """Rate limit for application submissions - 10 per hour."""
    rate = '10/hour'
    scope = 'application_submission'


class BulkOperationThrottle(UserRateThrottle):
    """Rate limit for bulk operations - 5 per minute."""
    rate = '5/minute'
    scope = 'bulk_operation'


class CandidateImportThrottle(UserRateThrottle):
    """Rate limit for candidate imports - 3 per minute."""
    rate = '3/minute'
    scope = 'candidate_import'


class SensitiveOperationThrottle(UserRateThrottle):
    """Rate limit for sensitive operations - 30 per minute."""
    rate = '30/minute'
    scope = 'sensitive_operation'


# ==================== FILE VALIDATION ====================

# Maximum file size: 10MB
MAX_RESUME_SIZE = 10 * 1024 * 1024

# Allowed MIME types for resume uploads
ALLOWED_RESUME_MIME_TYPES = {
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/plain',
}

# Allowed file extensions
ALLOWED_RESUME_EXTENSIONS = {'.pdf', '.doc', '.docx', '.txt'}


def validate_resume_file(file):
    """
    Validate uploaded resume file.

    Checks:
    - File size (max 10MB)
    - File extension (pdf, doc, docx, txt)
    - MIME type validation via python-magic

    Args:
        file: The uploaded file object

    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    if not file:
        return True, None

    # Check file size
    if file.size > MAX_RESUME_SIZE:
        return False, f'File size exceeds maximum allowed size of {MAX_RESUME_SIZE // (1024*1024)}MB'

    # Check file extension
    filename = file.name.lower() if file.name else ''
    ext = os.path.splitext(filename)[1]
    if ext not in ALLOWED_RESUME_EXTENSIONS:
        return False, f'Invalid file extension. Allowed: {", ".join(ALLOWED_RESUME_EXTENSIONS)}'

    # Validate MIME type using python-magic (content-based detection)
    try:
        # Read the first 2048 bytes to determine file type
        file_head = file.read(2048)
        file.seek(0)  # Reset file pointer

        mime_type = magic.from_buffer(file_head, mime=True)
        if mime_type not in ALLOWED_RESUME_MIME_TYPES:
            return False, f'Invalid file type detected: {mime_type}. Allowed types: PDF, DOC, DOCX, TXT'
    except Exception as e:
        logger.warning(f'MIME type validation failed: {e}')
        # Fall back to extension-based validation only
        pass

    return True, None


# ==================== HELPER FUNCTIONS ====================

def get_current_tenant():
    """
    Get the current tenant from the database connection.

    Returns:
        Tenant instance or None if no tenant is set.
    """
    return getattr(connection, 'tenant', None)


def log_bulk_operation(user, operation_type, model_name, affected_ids, details=None):
    """
    Log bulk operations for audit trail.

    Args:
        user: The user performing the operation
        operation_type: Type of operation (e.g., 'bulk_move_stage', 'bulk_reject')
        model_name: Name of the affected model
        affected_ids: List of affected record IDs
        details: Optional dictionary with additional details
    """
    logger.info(
        f'BULK_OPERATION: user={user.id if user else "anonymous"}, '
        f'type={operation_type}, model={model_name}, '
        f'affected_count={len(affected_ids)}, affected_ids={affected_ids[:20]}..., '
        f'details={details}'
    )


# ==================== PERMISSION CLASSES ====================

class IsOwnerOrReadOnly(permissions.BasePermission):
    """Only owners can edit."""

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        if hasattr(obj, 'created_by'):
            return obj.created_by == request.user
        if hasattr(obj, 'user'):
            return obj.user == request.user
        return False


class IsRecruiterOrHiringManager(permissions.BasePermission):
    """
    RBAC permission class for recruiter and hiring manager roles.

    Checks:
    - User is authenticated
    - User has recruiter or hiring_manager role (via TenantUser or user groups)
    - For object permissions, user is associated with the job
    """

    def _get_user_roles(self, user):
        """
        Get user roles from TenantUser model or groups.

        Returns:
            set: Set of role names the user has
        """
        roles = set()

        # Check TenantUser role if available
        if hasattr(user, 'tenantuser'):
            tenant_user = user.tenantuser
            if tenant_user.role:
                roles.add(tenant_user.role.lower())

        # Check user groups for role-based groups
        user_groups = user.groups.values_list('name', flat=True)
        for group in user_groups:
            group_lower = group.lower()
            if 'recruiter' in group_lower:
                roles.add('recruiter')
            if 'hiring_manager' in group_lower or 'hiring-manager' in group_lower:
                roles.add('hiring_manager')
            if 'hr' in group_lower:
                roles.add('hr')
            if 'admin' in group_lower or 'pdg' in group_lower:
                roles.add('admin')

        # Staff users have admin role
        if user.is_staff or user.is_superuser:
            roles.add('admin')

        return roles

    def has_permission(self, request, view):
        """Check if user has permission to access the view."""
        if not request.user.is_authenticated:
            return False

        # Admin users always have access
        if request.user.is_staff or request.user.is_superuser:
            return True

        # Get user roles
        roles = self._get_user_roles(request.user)

        # Check for required roles
        required_roles = {'recruiter', 'hiring_manager', 'hr', 'admin', 'pdg', 'supervisor'}
        if roles & required_roles:
            return True

        # For read operations, authenticated users may have limited access
        if request.method in permissions.SAFE_METHODS:
            return True

        return False

    def has_object_permission(self, request, view, obj):
        """Check if user has permission for specific object."""
        if not request.user.is_authenticated:
            return False

        # Admin users always have access
        if request.user.is_staff or request.user.is_superuser:
            return True

        # Check if object has a job relation
        job = None
        if hasattr(obj, 'job'):
            job = obj.job
        elif isinstance(obj, JobPosting):
            job = obj

        if job:
            # Check if user is directly associated with the job
            if job.recruiter == request.user:
                return True
            if job.hiring_manager == request.user:
                return True
            if job.created_by == request.user:
                return True

        # Check user roles
        roles = self._get_user_roles(request.user)

        # HR and admin roles have full access
        if {'hr', 'admin', 'pdg'} & roles:
            return True

        # Supervisors can access within their circusale
        if 'supervisor' in roles and hasattr(request.user, 'tenantuser'):
            user_circusale = request.user.tenantuser.circusale
            if hasattr(obj, 'created_by') and hasattr(obj.created_by, 'tenantuser'):
                obj_circusale = obj.created_by.tenantuser.circusale
                if user_circusale and obj_circusale and user_circusale == obj_circusale:
                    return True

        # For read operations, recruiters and hiring managers have limited access
        if request.method in permissions.SAFE_METHODS:
            if {'recruiter', 'hiring_manager'} & roles:
                return True

        return False


class IsTenantMember(permissions.BasePermission):
    """
    Ensure user belongs to the current tenant.

    This permission class verifies that the authenticated user
    is a member of the tenant associated with the current request.
    """

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        tenant = get_current_tenant()
        if not tenant:
            # No tenant context - allow superusers only
            return request.user.is_superuser

        # Check if user belongs to the tenant
        if hasattr(request.user, 'tenantuser'):
            return request.user.tenantuser.tenant == tenant

        # Superusers can access any tenant
        return request.user.is_superuser


# ==================== JOB CATEGORY VIEWSET ====================

class JobCategoryViewSet(viewsets.ModelViewSet):
    """
    ViewSet for job categories.

    list: Get all categories (filterable)
    retrieve: Get specific category with children
    create: Create new category
    update: Update category
    delete: Delete category

    Security:
    - Tenant isolation via for_current_tenant()
    """
    queryset = JobCategory.objects.all()
    permission_classes = [permissions.IsAuthenticatedOrReadOnly, IsTenantMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = JobCategoryFilter
    search_fields = ['name', 'description']
    ordering_fields = ['sort_order', 'name', 'created_at']
    ordering = ['sort_order', 'name']

    def get_serializer_class(self):
        if self.action == 'list':
            return JobCategoryListSerializer
        return JobCategorySerializer

    def get_queryset(self):
        """Filter queryset by current tenant for data isolation."""
        # SECURITY: Always filter by current tenant
        queryset = JobCategory.objects.for_current_tenant()

        # For list, only show active root categories by default
        if self.action == 'list' and not self.request.query_params.get('all'):
            queryset = queryset.filter(is_active=True)
        return queryset

    @action(detail=True, methods=['get'])
    def jobs(self, request, pk=None):
        """Get all open jobs in this category."""
        category = self.get_object()
        # SECURITY: Filter jobs by current tenant
        jobs = JobPosting.objects.for_current_tenant().filter(
            category=category,
            status=JobPosting.JobStatus.OPEN
        )
        serializer = JobPostingListSerializer(jobs, many=True)
        return Response(serializer.data)


# ==================== PIPELINE VIEWSET ====================

class PipelineViewSet(viewsets.ModelViewSet):
    """
    ViewSet for recruitment pipelines.

    list: Get all pipelines
    retrieve: Get pipeline with nested stages
    create: Create pipeline with stages
    update: Update pipeline
    delete: Delete pipeline

    Security:
    - Tenant isolation via for_current_tenant()
    """
    queryset = Pipeline.objects.select_related('created_by').prefetch_related('stages')
    permission_classes = [permissions.IsAuthenticated, IsTenantMember, IsOwnerOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = PipelineFilter
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'created_at', 'is_default']
    ordering = ['-is_default', 'name']

    def get_serializer_class(self):
        if self.action == 'list':
            return PipelineListSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return PipelineCreateSerializer
        return PipelineSerializer

    def get_queryset(self):
        """Filter queryset by current tenant for data isolation."""
        # SECURITY: Always filter by current tenant
        return Pipeline.objects.for_current_tenant().select_related(
            'created_by'
        ).prefetch_related('stages')

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def add_stage(self, request, pk=None):
        """Add a new stage to the pipeline."""
        pipeline = self.get_object()
        serializer = PipelineStageCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Set order to last if not provided
        if 'order' not in serializer.validated_data:
            max_order = pipeline.stages.aggregate(
                max_order=Count('order')
            )['max_order'] or 0
            serializer.validated_data['order'] = max_order

        stage = PipelineStage.objects.create(
            pipeline=pipeline,
            **serializer.validated_data
        )
        return Response(
            PipelineStageSerializer(stage).data,
            status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=['post'])
    def reorder_stages(self, request, pk=None):
        """Reorder stages in the pipeline."""
        pipeline = self.get_object()
        stage_order = request.data.get('stage_order', [])

        if not stage_order:
            return Response(
                {'error': 'stage_order is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        with transaction.atomic():
            for order, stage_id in enumerate(stage_order):
                # SECURITY: Only update stages that belong to this pipeline
                PipelineStage.objects.filter(
                    id=stage_id,
                    pipeline=pipeline
                ).update(order=order)

        return Response({'status': 'reordered'})

    @action(detail=True, methods=['post'])
    def set_default(self, request, pk=None):
        """Set this pipeline as the default."""
        pipeline = self.get_object()

        # SECURITY: Only update pipelines within the current tenant
        Pipeline.objects.for_current_tenant().filter(
            is_default=True
        ).update(is_default=False)

        # Set this as default
        pipeline.is_default = True
        pipeline.save()

        return Response({'status': 'set as default'})


# ==================== PIPELINE STAGE VIEWSET ====================

class PipelineStageViewSet(viewsets.ModelViewSet):
    """
    ViewSet for pipeline stages.

    Security:
    - Tenant isolation via pipeline's tenant
    """
    queryset = PipelineStage.objects.select_related('pipeline')
    serializer_class = PipelineStageSerializer
    permission_classes = [permissions.IsAuthenticated, IsTenantMember]
    filter_backends = [DjangoFilterBackend]
    filterset_class = PipelineStageFilter

    def get_queryset(self):
        """Filter queryset by current tenant through pipeline relation."""
        # SECURITY: Filter stages through their pipeline's tenant
        tenant = get_current_tenant()
        if not tenant:
            return PipelineStage.objects.none()
        return PipelineStage.objects.filter(
            pipeline__tenant=tenant
        ).select_related('pipeline')

    @action(detail=True, methods=['get'])
    def applications(self, request, pk=None):
        """Get all applications in this stage."""
        stage = self.get_object()
        # SECURITY: Filter applications by current tenant
        applications = Application.objects.for_current_tenant().filter(
            current_stage=stage
        )
        serializer = ApplicationListSerializer(applications, many=True)
        return Response(serializer.data)


# ==================== JOB POSTING VIEWSET ====================

class JobPostingViewSet(viewsets.ModelViewSet):
    """
    ViewSet for job postings.

    list: Get all jobs (with extensive filters)
    retrieve: Get job with full details
    create: Create new job posting
    update: Update job posting
    delete: Delete job posting

    Actions:
    - publish: Publish a draft job
    - close: Close a job posting
    - clone: Clone a job posting
    - applications: Get all applications for a job
    - kanban: Get Kanban board data for a job

    Security:
    - Tenant isolation via for_current_tenant()
    - RBAC for write operations
    """
    queryset = JobPosting.objects.select_related(
        'category', 'pipeline', 'hiring_manager', 'recruiter', 'created_by'
    )
    permission_classes = [permissions.IsAuthenticatedOrReadOnly, IsTenantMember, IsOwnerOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = JobPostingFilter
    search_fields = ['title', 'description', 'reference_code', 'requirements']
    ordering_fields = ['title', 'created_at', 'published_at', 'application_deadline']
    ordering = ['-created_at']
    lookup_field = 'uuid'

    def get_serializer_class(self):
        if self.action == 'list':
            return JobPostingListSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return JobPostingCreateSerializer
        if self.action == 'clone':
            return JobPostingCloneSerializer
        return JobPostingDetailSerializer

    def get_queryset(self):
        """Filter queryset by current tenant for data isolation."""
        # SECURITY: Always filter by current tenant
        queryset = JobPosting.objects.for_current_tenant().select_related(
            'category', 'pipeline', 'hiring_manager', 'recruiter', 'created_by'
        )
        # Annotate with application count for sorting
        queryset = queryset.annotate(applications_count=Count('applications'))
        return queryset

    def perform_create(self, serializer):
        # Auto-generate reference code if not provided
        instance = serializer.save(created_by=self.request.user)
        if not instance.reference_code:
            instance.reference_code = f"JOB-{instance.pk:06d}"
            instance.save(update_fields=['reference_code'])

    @action(detail=True, methods=['post'])
    def publish(self, request, uuid=None):
        """Publish a job posting."""
        job = self.get_object()

        if job.status not in [JobPosting.JobStatus.DRAFT, JobPosting.JobStatus.ON_HOLD]:
            return Response(
                {'error': 'Only draft or on-hold jobs can be published'},
                status=status.HTTP_400_BAD_REQUEST
            )

        job.publish()
        return Response(JobPostingDetailSerializer(job).data)

    @action(detail=True, methods=['post'])
    def close(self, request, uuid=None):
        """Close a job posting."""
        job = self.get_object()
        reason = request.data.get('reason', 'closed')

        if reason not in ['filled', 'cancelled', 'closed']:
            return Response(
                {'error': 'Invalid close reason'},
                status=status.HTTP_400_BAD_REQUEST
            )

        job.close(reason=reason)
        return Response(JobPostingDetailSerializer(job).data)

    @action(detail=True, methods=['post'])
    def clone(self, request, uuid=None):
        """Clone a job posting."""
        job = self.get_object()
        serializer = JobPostingCloneSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Create clone
        new_job = JobPosting.objects.get(pk=job.pk)
        new_job.pk = None
        new_job.uuid = None
        new_job.status = JobPosting.JobStatus.DRAFT
        new_job.title = serializer.validated_data.get('new_title', f"Copy of {job.title}")
        new_job.reference_code = serializer.validated_data['new_reference_code']
        new_job.published_at = None
        new_job.closed_at = None
        new_job.created_by = request.user
        new_job.save()

        return Response(
            JobPostingDetailSerializer(new_job).data,
            status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=['get'])
    def applications(self, request, uuid=None):
        """Get all applications for this job."""
        job = self.get_object()
        applications = job.applications.select_related(
            'candidate', 'current_stage'
        ).order_by('-applied_at')

        # Apply filters
        filterset = ApplicationFilter(request.GET, queryset=applications)
        applications = filterset.qs

        serializer = ApplicationListSerializer(applications, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def kanban(self, request, uuid=None):
        """Get Kanban board data for this job."""
        job = self.get_object()

        if not job.pipeline:
            return Response(
                {'error': 'Job has no pipeline assigned'},
                status=status.HTTP_400_BAD_REQUEST
            )

        stages = job.pipeline.stages.filter(is_active=True).order_by('order')
        columns = []

        for stage in stages:
            applications = job.applications.filter(
                current_stage=stage
            ).select_related('candidate').order_by('-applied_at')

            columns.append({
                'stage_id': stage.id,
                'stage_name': stage.name,
                'stage_color': stage.color,
                'stage_type': stage.stage_type,
                'applications': ApplicationListSerializer(applications, many=True).data
            })

        # Add unassigned applications (no stage)
        unassigned = job.applications.filter(
            current_stage__isnull=True
        ).select_related('candidate')

        if unassigned.exists():
            columns.insert(0, {
                'stage_id': None,
                'stage_name': 'Unassigned',
                'stage_color': '#9CA3AF',
                'stage_type': 'new',
                'applications': ApplicationListSerializer(unassigned, many=True).data
            })

        return Response({
            'job_id': job.id,
            'job_title': job.title,
            'pipeline_id': job.pipeline.id,
            'pipeline_name': job.pipeline.name,
            'columns': columns
        })

    @action(detail=True, methods=['get'])
    def stats(self, request, uuid=None):
        """Get statistics for this job."""
        job = self.get_object()
        applications = job.applications

        stats = {
            'total_applications': applications.count(),
            'new_applications': applications.filter(status='new').count(),
            'in_review': applications.filter(status='in_review').count(),
            'interviewing': applications.filter(status='interviewing').count(),
            'offers_sent': applications.filter(status='offer_extended').count(),
            'hired': applications.filter(status='hired').count(),
            'rejected': applications.filter(status='rejected').count(),
            'withdrawn': applications.filter(status='withdrawn').count(),
            'average_rating': applications.aggregate(
                avg=Avg('overall_rating')
            )['avg'],
            'average_ai_score': applications.aggregate(
                avg=Avg('ai_match_score')
            )['avg'],
            'applications_by_source': list(
                applications.values('candidate__source').annotate(
                    count=Count('id')
                ).order_by('-count')
            ),
        }

        return Response(stats)


# ==================== CANDIDATE VIEWSET ====================

class CandidateViewSet(viewsets.ModelViewSet):
    """
    ViewSet for candidates.

    list: Get all candidates (with extensive filters)
    retrieve: Get candidate with full details and applications
    create: Create new candidate (with resume upload)
    update: Update candidate
    delete: Delete candidate

    Actions:
    - merge: Merge duplicate candidates
    - bulk_import: Bulk import candidates
    - applications: Get candidate's applications

    Security:
    - Tenant isolation via for_current_tenant()
    - File upload validation for resumes
    - Rate limiting on bulk operations
    """
    queryset = Candidate.objects.select_related('user', 'referred_by')
    permission_classes = [permissions.IsAuthenticated, IsTenantMember, IsRecruiterOrHiringManager]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = CandidateFilter
    search_fields = [
        'first_name', 'last_name', 'email', 'headline',
        'current_company', 'current_title'
    ]
    ordering_fields = ['first_name', 'last_name', 'created_at', 'last_activity_at']
    ordering = ['-created_at']
    lookup_field = 'uuid'

    def get_serializer_class(self):
        if self.action == 'list':
            return CandidateListSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return CandidateCreateSerializer
        if self.action == 'bulk_import':
            return CandidateBulkImportSerializer
        if self.action == 'merge':
            return CandidateMergeSerializer
        return CandidateDetailSerializer

    def get_queryset(self):
        """Filter queryset by current tenant for data isolation."""
        # SECURITY: Always filter by current tenant
        return Candidate.objects.for_current_tenant().select_related(
            'user', 'referred_by'
        )

    def perform_create(self, serializer):
        """Create candidate with resume validation."""
        resume = self.request.FILES.get('resume')
        if resume:
            # SECURITY: Validate resume file
            is_valid, error = validate_resume_file(resume)
            if not is_valid:
                from rest_framework.exceptions import ValidationError
                raise ValidationError({'resume': error})

        serializer.save()

    def perform_update(self, serializer):
        """Update candidate with resume validation."""
        resume = self.request.FILES.get('resume')
        if resume:
            # SECURITY: Validate resume file
            is_valid, error = validate_resume_file(resume)
            if not is_valid:
                from rest_framework.exceptions import ValidationError
                raise ValidationError({'resume': error})

        serializer.save()

    @action(detail=True, methods=['get'])
    def applications(self, request, uuid=None):
        """Get all applications for this candidate."""
        candidate = self.get_object()
        # SECURITY: Filter applications by current tenant
        applications = Application.objects.for_current_tenant().filter(
            candidate=candidate
        ).select_related('job', 'current_stage').order_by('-applied_at')
        serializer = ApplicationListSerializer(applications, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def bulk_import(self, request):
        """Bulk import candidates with rate limiting and audit logging."""
        # Apply rate limiting
        throttle = CandidateImportThrottle()
        if not throttle.allow_request(request, self):
            return Response(
                {'error': 'Rate limit exceeded for bulk import operations'},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = CandidateBulkImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        tenant = get_current_tenant()
        with transaction.atomic():
            result = serializer.save()

            # SECURITY: Audit log the bulk import
            log_bulk_operation(
                user=request.user,
                operation_type='bulk_import_candidates',
                model_name='Candidate',
                affected_ids=[c.id for c in result['created']],
                details={
                    'created_count': len(result['created']),
                    'skipped_count': len(result['skipped']),
                    'skipped_emails': result['skipped'][:20],  # Limit logged emails
                    'tenant_id': tenant.id if tenant else None
                }
            )

        return Response({
            'created_count': len(result['created']),
            'skipped_count': len(result['skipped']),
            'skipped_emails': result['skipped'],
            'created': CandidateListSerializer(result['created'], many=True).data
        }, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['post'])
    def merge(self, request):
        """Merge duplicate candidates with tenant isolation."""
        serializer = CandidateMergeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        source_ids = serializer.validated_data['source_candidate_ids']
        target_id = serializer.validated_data['target_candidate_id']
        delete_source = serializer.validated_data.get('delete_source', True)

        # SECURITY: Ensure target candidate belongs to current tenant
        target = get_object_or_404(
            Candidate.objects.for_current_tenant(),
            id=target_id
        )

        # SECURITY: Ensure source candidates belong to current tenant
        source_candidates = Candidate.objects.for_current_tenant().filter(
            id__in=source_ids
        )

        # Verify all requested source IDs were found in current tenant
        found_ids = set(source_candidates.values_list('id', flat=True))
        requested_ids = set(source_ids)
        if found_ids != requested_ids:
            missing = requested_ids - found_ids
            return Response(
                {'error': f'Some candidates not found or not accessible: {list(missing)}'},
                status=status.HTTP_404_NOT_FOUND
            )

        with transaction.atomic():
            # Move applications to target
            for source in source_candidates:
                source.applications.update(candidate=target)

                # Merge skills
                target.skills = list(set(target.skills + source.skills))

                # Merge tags
                target.tags = list(set(target.tags + source.tags))

            target.save()

            if delete_source:
                source_candidates.delete()

            # SECURITY: Audit log the merge operation
            log_bulk_operation(
                user=request.user,
                operation_type='merge_candidates',
                model_name='Candidate',
                affected_ids=list(source_ids) + [target_id],
                details={
                    'target_id': target_id,
                    'source_ids': source_ids,
                    'deleted_source': delete_source
                }
            )

        return Response({
            'status': 'merged',
            'target': CandidateDetailSerializer(target).data,
            'merged_count': len(source_ids)
        })

    @action(detail=True, methods=['post'])
    def add_tag(self, request, uuid=None):
        """Add a tag to the candidate."""
        candidate = self.get_object()
        tag = request.data.get('tag', '').strip().lower()

        if not tag:
            return Response(
                {'error': 'Tag is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if tag not in candidate.tags:
            candidate.tags.append(tag)
            candidate.save()

        return Response({'tags': candidate.tags})

    @action(detail=True, methods=['post'])
    def remove_tag(self, request, uuid=None):
        """Remove a tag from the candidate."""
        candidate = self.get_object()
        tag = request.data.get('tag', '').strip().lower()

        if tag in candidate.tags:
            candidate.tags.remove(tag)
            candidate.save()

        return Response({'tags': candidate.tags})


# ==================== APPLICATION VIEWSET ====================

class ApplicationViewSet(viewsets.ModelViewSet):
    """
    ViewSet for applications.

    list: Get all applications (with extensive filters)
    retrieve: Get application with full details
    create: Create new application
    update: Update application
    delete: Delete application

    Actions:
    - move_stage: Move to a different pipeline stage
    - reject: Reject the application
    - advance: Advance to next stage
    - assign: Assign to a user
    - rate: Rate the application
    - notes: Get/add notes
    - activities: Get activity timeline
    - bulk_action: Perform bulk operations

    Security:
    - Tenant isolation via for_current_tenant()
    - RBAC for write operations
    - Rate limiting on application submission
    - Audit logging for bulk operations
    """
    queryset = Application.objects.select_related(
        'candidate', 'job', 'current_stage', 'assigned_to'
    )
    permission_classes = [permissions.IsAuthenticated, IsTenantMember, IsRecruiterOrHiringManager]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = ApplicationFilter
    search_fields = [
        'candidate__first_name', 'candidate__last_name',
        'candidate__email', 'job__title', 'job__reference_code'
    ]
    ordering_fields = [
        'applied_at', 'last_stage_change_at', 'overall_rating', 'ai_match_score'
    ]
    ordering = ['-applied_at']
    lookup_field = 'uuid'

    def get_throttles(self):
        """Apply rate limiting for application creation."""
        if self.action == 'create':
            return [ApplicationSubmissionThrottle()]
        if self.action == 'bulk_action':
            return [BulkOperationThrottle()]
        return super().get_throttles()

    def get_serializer_class(self):
        if self.action == 'list':
            return ApplicationListSerializer
        if self.action == 'create':
            return ApplicationCreateSerializer
        if self.action == 'move_stage':
            return ApplicationStageChangeSerializer
        if self.action == 'reject':
            return ApplicationRejectSerializer
        if self.action == 'bulk_action':
            return ApplicationBulkActionSerializer
        return ApplicationDetailSerializer

    def get_queryset(self):
        """Filter queryset by current tenant for data isolation."""
        # SECURITY: Always filter by current tenant
        return Application.objects.for_current_tenant().select_related(
            'candidate', 'job', 'current_stage', 'assigned_to'
        )

    def perform_create(self, serializer):
        serializer.save()

    @action(detail=True, methods=['post'])
    def move_stage(self, request, uuid=None):
        """Move application to a different pipeline stage."""
        application = self.get_object()
        serializer = ApplicationStageChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_stage = serializer.validated_data['stage_id']
        notes = serializer.validated_data.get('notes', '')

        # Validate stage belongs to the job's pipeline
        if application.job.pipeline and new_stage.pipeline != application.job.pipeline:
            return Response(
                {'error': 'Stage does not belong to the job\'s pipeline'},
                status=status.HTTP_400_BAD_REQUEST
            )

        application.move_to_stage(new_stage, user=request.user)

        if notes:
            ApplicationActivity.objects.filter(
                application=application,
                activity_type=ApplicationActivity.ActivityType.STAGE_CHANGE
            ).order_by('-created_at').first().update(notes=notes)

        return Response(ApplicationDetailSerializer(application).data)

    @action(detail=True, methods=['post'])
    def reject(self, request, uuid=None):
        """Reject the application."""
        application = self.get_object()
        serializer = ApplicationRejectSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        application.reject(
            reason=serializer.validated_data.get('reason', ''),
            feedback=serializer.validated_data.get('feedback', ''),
            user=request.user
        )
        application.send_rejection_email = serializer.validated_data.get('send_email', True)
        application.save()

        return Response(ApplicationDetailSerializer(application).data)

    @action(detail=True, methods=['post'])
    def advance(self, request, uuid=None):
        """Advance application to the next pipeline stage."""
        application = self.get_object()

        if not application.job.pipeline:
            return Response(
                {'error': 'Job has no pipeline assigned'},
                status=status.HTTP_400_BAD_REQUEST
            )

        current_stage = application.current_stage
        stages = list(application.job.pipeline.stages.filter(
            is_active=True
        ).order_by('order'))

        if current_stage:
            try:
                current_index = stages.index(current_stage)
                if current_index < len(stages) - 1:
                    next_stage = stages[current_index + 1]
                    application.move_to_stage(next_stage, user=request.user)
                else:
                    return Response(
                        {'error': 'Application is already at the final stage'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            except ValueError:
                return Response(
                    {'error': 'Current stage not found in pipeline'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            # No current stage, move to first stage
            if stages:
                application.move_to_stage(stages[0], user=request.user)

        return Response(ApplicationDetailSerializer(application).data)

    @action(detail=True, methods=['post'])
    def assign(self, request, uuid=None):
        """Assign application to a user."""
        application = self.get_object()
        assignee_id = request.data.get('assignee_id')

        if assignee_id:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            assignee = get_object_or_404(User, id=assignee_id)
            application.assigned_to = assignee
        else:
            application.assigned_to = None

        application.save()

        ApplicationActivity.objects.create(
            application=application,
            activity_type=ApplicationActivity.ActivityType.ASSIGNED,
            performed_by=request.user,
            new_value=str(assignee_id) if assignee_id else 'Unassigned'
        )

        return Response(ApplicationDetailSerializer(application).data)

    @action(detail=True, methods=['post'])
    def rate(self, request, uuid=None):
        """Rate the application."""
        application = self.get_object()
        rating = request.data.get('rating')

        if rating is None or not (0 <= float(rating) <= 5):
            return Response(
                {'error': 'Rating must be between 0 and 5'},
                status=status.HTTP_400_BAD_REQUEST
            )

        old_rating = application.overall_rating
        application.overall_rating = rating
        application.save()

        ApplicationActivity.objects.create(
            application=application,
            activity_type=ApplicationActivity.ActivityType.RATING_UPDATED,
            performed_by=request.user,
            old_value=str(old_rating) if old_rating else '',
            new_value=str(rating)
        )

        return Response(ApplicationDetailSerializer(application).data)

    @action(detail=True, methods=['get', 'post'])
    def notes(self, request, uuid=None):
        """Get or add notes for this application."""
        application = self.get_object()

        if request.method == 'GET':
            notes = application.notes.select_related('author').order_by('-created_at')
            serializer = ApplicationNoteSerializer(notes, many=True)
            return Response(serializer.data)

        # POST - add note
        serializer = ApplicationNoteSerializer(data={
            **request.data,
            'application': application.id
        })
        serializer.is_valid(raise_exception=True)
        serializer.save(author=request.user, application=application)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['get'])
    def activities(self, request, uuid=None):
        """Get activity timeline for this application."""
        application = self.get_object()
        activities = application.activities.select_related(
            'performed_by'
        ).order_by('-created_at')
        serializer = ApplicationActivitySerializer(activities, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def bulk_action(self, request):
        """
        Perform bulk action on multiple applications.

        SECURITY:
        - All application_ids are filtered by current tenant to prevent cross-tenant access
        - Rate limiting is applied via get_throttles()
        - Full audit logging of all bulk operations
        """
        serializer = ApplicationBulkActionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        application_ids = serializer.validated_data['application_ids']
        action_type = serializer.validated_data['action']

        # SECURITY CRITICAL: Filter applications by current tenant
        # This prevents users from affecting applications in other tenants
        applications = Application.objects.for_current_tenant().filter(
            id__in=application_ids
        )

        # Verify all requested IDs were found in current tenant
        found_ids = set(applications.values_list('id', flat=True))
        requested_ids = set(application_ids)
        if found_ids != requested_ids:
            missing = requested_ids - found_ids
            logger.warning(
                f'SECURITY: User {request.user.id} attempted bulk action on '
                f'applications not in their tenant: {list(missing)}'
            )
            return Response(
                {'error': f'Some applications not found or not accessible: {list(missing)}'},
                status=status.HTTP_404_NOT_FOUND
            )

        count = applications.count()
        tenant = get_current_tenant()

        with transaction.atomic():
            if action_type == 'move_stage':
                stage_id = serializer.validated_data.get('stage_id')
                if not stage_id:
                    return Response(
                        {'error': 'stage_id required for move_stage action'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                # SECURITY: Ensure stage belongs to current tenant's pipeline
                stage = get_object_or_404(
                    PipelineStage.objects.filter(pipeline__tenant=tenant),
                    id=stage_id
                )
                for app in applications:
                    # Validate stage belongs to the application's job pipeline
                    if app.job.pipeline and stage.pipeline != app.job.pipeline:
                        continue  # Skip invalid pipeline assignments
                    app.move_to_stage(stage, user=request.user)

            elif action_type == 'reject':
                reason = serializer.validated_data.get('rejection_reason', '')
                for app in applications:
                    app.reject(reason=reason, user=request.user)

            elif action_type == 'assign':
                assignee_id = serializer.validated_data.get('assigned_to_id')
                # SECURITY: Verify assignee belongs to current tenant
                if assignee_id:
                    from django.contrib.auth import get_user_model
                    User = get_user_model()
                    assignee = User.objects.filter(id=assignee_id).first()
                    if assignee and hasattr(assignee, 'tenantuser'):
                        if tenant and assignee.tenantuser.tenant != tenant:
                            return Response(
                                {'error': 'Assignee does not belong to this tenant'},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                applications.update(assigned_to_id=assignee_id)

            elif action_type == 'delete':
                applications.delete()

            # SECURITY: Audit log the bulk operation
            log_bulk_operation(
                user=request.user,
                operation_type=f'bulk_{action_type}',
                model_name='Application',
                affected_ids=list(found_ids),
                details={
                    'action': action_type,
                    'count': count,
                    'tenant_id': tenant.id if tenant else None,
                    'stage_id': serializer.validated_data.get('stage_id'),
                    'assigned_to_id': serializer.validated_data.get('assigned_to_id'),
                    'rejection_reason': serializer.validated_data.get('rejection_reason', '')[:100]
                }
            )

        return Response({
            'status': 'success',
            'action': action_type,
            'affected_count': count
        })


# ==================== INTERVIEW VIEWSET ====================

class InterviewViewSet(viewsets.ModelViewSet):
    """
    ViewSet for interviews.

    list: Get all interviews (filterable)
    retrieve: Get interview with full details
    create: Schedule new interview
    update: Update interview
    delete: Delete interview

    Actions:
    - reschedule: Reschedule the interview
    - complete: Mark interview as completed
    - cancel: Cancel the interview
    - feedback: Get/submit feedback

    Security:
    - Tenant isolation via application's tenant
    """
    queryset = Interview.objects.select_related(
        'application__candidate', 'application__job', 'organizer'
    ).prefetch_related('interviewers', 'feedback')
    permission_classes = [permissions.IsAuthenticated, IsTenantMember, IsRecruiterOrHiringManager]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = InterviewFilter
    search_fields = ['title', 'application__candidate__first_name']
    ordering_fields = ['scheduled_start', 'created_at']
    ordering = ['scheduled_start']
    lookup_field = 'uuid'

    def get_queryset(self):
        """Filter queryset by current tenant through application relation."""
        # SECURITY: Filter interviews through their application's tenant
        tenant = get_current_tenant()
        if not tenant:
            return Interview.objects.none()
        return Interview.objects.filter(
            application__tenant=tenant
        ).select_related(
            'application__candidate', 'application__job', 'organizer'
        ).prefetch_related('interviewers', 'feedback')

    def get_serializer_class(self):
        if self.action == 'list':
            return InterviewListSerializer
        if self.action == 'create':
            return InterviewCreateSerializer
        if self.action == 'reschedule':
            return InterviewRescheduleSerializer
        return InterviewDetailSerializer

    def perform_create(self, serializer):
        serializer.save(organizer=self.request.user)

    @action(detail=True, methods=['post'])
    def reschedule(self, request, uuid=None):
        """Reschedule the interview."""
        interview = self.get_object()
        serializer = InterviewRescheduleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        old_start = interview.scheduled_start

        interview.scheduled_start = serializer.validated_data['scheduled_start']
        interview.scheduled_end = serializer.validated_data['scheduled_end']
        interview.status = Interview.InterviewStatus.RESCHEDULED
        interview.save()

        ApplicationActivity.objects.create(
            application=interview.application,
            activity_type=ApplicationActivity.ActivityType.INTERVIEW_SCHEDULED,
            performed_by=request.user,
            old_value=old_start.isoformat(),
            new_value=interview.scheduled_start.isoformat(),
            notes=serializer.validated_data.get('reason', 'Rescheduled')
        )

        return Response(InterviewDetailSerializer(interview).data)

    @action(detail=True, methods=['post'])
    def complete(self, request, uuid=None):
        """Mark interview as completed."""
        interview = self.get_object()
        interview.status = Interview.InterviewStatus.COMPLETED
        interview.actual_end = timezone.now()
        if not interview.actual_start:
            interview.actual_start = interview.scheduled_start
        interview.save()

        return Response(InterviewDetailSerializer(interview).data)

    @action(detail=True, methods=['post'])
    def cancel(self, request, uuid=None):
        """Cancel the interview."""
        interview = self.get_object()
        reason = request.data.get('reason', '')

        interview.status = Interview.InterviewStatus.CANCELLED
        interview.save()

        ApplicationActivity.objects.create(
            application=interview.application,
            activity_type=ApplicationActivity.ActivityType.INTERVIEW_SCHEDULED,
            performed_by=request.user,
            new_value='Cancelled',
            notes=reason
        )

        return Response(InterviewDetailSerializer(interview).data)

    @action(detail=True, methods=['get', 'post'])
    def feedback(self, request, uuid=None):
        """Get or submit feedback for this interview."""
        interview = self.get_object()

        if request.method == 'GET':
            feedback = interview.feedback.select_related('interviewer')
            serializer = InterviewFeedbackSerializer(feedback, many=True)
            return Response(serializer.data)

        # POST - submit feedback
        serializer = InterviewFeedbackCreateSerializer(
            data={**request.data, 'interview_id': interview.id},
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['get'])
    def my_interviews(self, request):
        """Get interviews where current user is an interviewer."""
        # SECURITY: Use get_queryset() which is already tenant-filtered
        interviews = self.get_queryset().filter(
            interviewers=request.user
        ).order_by('scheduled_start')
        serializer = InterviewListSerializer(interviews, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def upcoming(self, request):
        """Get upcoming interviews (next 7 days)."""
        now = timezone.now()
        next_week = now + timedelta(days=7)
        # SECURITY: Use get_queryset() which is already tenant-filtered
        interviews = self.get_queryset().filter(
            scheduled_start__gte=now,
            scheduled_start__lte=next_week,
            status__in=['scheduled', 'confirmed']
        ).order_by('scheduled_start')
        serializer = InterviewListSerializer(interviews, many=True)
        return Response(serializer.data)


# ==================== INTERVIEW FEEDBACK VIEWSET ====================

class InterviewFeedbackViewSet(viewsets.ModelViewSet):
    """
    ViewSet for interview feedback.

    Security:
    - Tenant isolation via interview's application tenant
    - Users can only see their own feedback unless they're staff
    """
    queryset = InterviewFeedback.objects.select_related('interview', 'interviewer')
    permission_classes = [permissions.IsAuthenticated, IsTenantMember]
    filter_backends = [DjangoFilterBackend]

    def get_serializer_class(self):
        if self.action == 'create':
            return InterviewFeedbackCreateSerializer
        return InterviewFeedbackSerializer

    def get_queryset(self):
        """Filter queryset by current tenant through interview relation."""
        # SECURITY: Filter feedback through their interview's application's tenant
        tenant = get_current_tenant()
        if not tenant:
            return InterviewFeedback.objects.none()

        queryset = InterviewFeedback.objects.filter(
            interview__application__tenant=tenant
        ).select_related('interview', 'interviewer')

        # Users can only see their own feedback unless they're staff
        if not self.request.user.is_staff:
            queryset = queryset.filter(interviewer=self.request.user)
        return queryset


# ==================== OFFER VIEWSET ====================

class OfferViewSet(viewsets.ModelViewSet):
    """
    ViewSet for offers.

    list: Get all offers (filterable)
    retrieve: Get offer with full details
    create: Create new offer
    update: Update offer
    delete: Delete offer

    Actions:
    - send: Send offer to candidate
    - accept: Mark offer as accepted
    - decline: Mark offer as declined
    - approve: Approve the offer
    - withdraw: Withdraw the offer

    Security:
    - Tenant isolation via application's tenant
    """
    queryset = Offer.objects.select_related(
        'application__candidate', 'application__job',
        'approved_by', 'created_by'
    )
    permission_classes = [permissions.IsAuthenticated, IsTenantMember, IsRecruiterOrHiringManager]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = OfferFilter
    search_fields = ['job_title', 'application__candidate__first_name']
    ordering_fields = ['created_at', 'base_salary', 'start_date']
    ordering = ['-created_at']
    lookup_field = 'uuid'

    def get_queryset(self):
        """Filter queryset by current tenant through application relation."""
        # SECURITY: Filter offers through their application's tenant
        tenant = get_current_tenant()
        if not tenant:
            return Offer.objects.none()
        return Offer.objects.filter(
            application__tenant=tenant
        ).select_related(
            'application__candidate', 'application__job',
            'approved_by', 'created_by'
        )

    def get_serializer_class(self):
        if self.action == 'list':
            return OfferListSerializer
        if self.action == 'create':
            return OfferCreateSerializer
        if self.action == 'send':
            return OfferSendSerializer
        if self.action in ['accept', 'decline']:
            return OfferResponseSerializer
        return OfferDetailSerializer

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def send(self, request, uuid=None):
        """Send offer to candidate."""
        offer = self.get_object()

        if offer.status not in [Offer.OfferStatus.DRAFT, Offer.OfferStatus.APPROVED]:
            return Response(
                {'error': 'Only draft or approved offers can be sent'},
                status=status.HTTP_400_BAD_REQUEST
            )

        offer.send_to_candidate()

        # Update application status
        offer.application.status = Application.ApplicationStatus.OFFER_EXTENDED
        offer.application.save()

        return Response(OfferDetailSerializer(offer).data)

    @action(detail=True, methods=['post'])
    def accept(self, request, uuid=None):
        """Mark offer as accepted."""
        offer = self.get_object()
        serializer = OfferResponseSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if offer.status != Offer.OfferStatus.SENT:
            return Response(
                {'error': 'Only sent offers can be accepted'},
                status=status.HTTP_400_BAD_REQUEST
            )

        offer.response_notes = serializer.validated_data.get('response_notes', '')
        offer.accept()

        ApplicationActivity.objects.create(
            application=offer.application,
            activity_type=ApplicationActivity.ActivityType.OFFER_ACCEPTED,
            performed_by=request.user,
            new_value=offer.job_title
        )

        return Response(OfferDetailSerializer(offer).data)

    @action(detail=True, methods=['post'])
    def decline(self, request, uuid=None):
        """Mark offer as declined."""
        offer = self.get_object()
        serializer = OfferResponseSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if offer.status != Offer.OfferStatus.SENT:
            return Response(
                {'error': 'Only sent offers can be declined'},
                status=status.HTTP_400_BAD_REQUEST
            )

        offer.response_notes = serializer.validated_data.get('response_notes', '')
        offer.decline(reason=serializer.validated_data.get('decline_reason', ''))

        ApplicationActivity.objects.create(
            application=offer.application,
            activity_type=ApplicationActivity.ActivityType.OFFER_DECLINED,
            performed_by=request.user,
            new_value=offer.job_title,
            notes=offer.decline_reason
        )

        return Response(OfferDetailSerializer(offer).data)

    @action(detail=True, methods=['post'])
    def approve(self, request, uuid=None):
        """Approve the offer."""
        offer = self.get_object()

        if offer.status != Offer.OfferStatus.PENDING_APPROVAL:
            return Response(
                {'error': 'Only pending offers can be approved'},
                status=status.HTTP_400_BAD_REQUEST
            )

        offer.status = Offer.OfferStatus.APPROVED
        offer.approved_by = request.user
        offer.approved_at = timezone.now()
        offer.save()

        return Response(OfferDetailSerializer(offer).data)

    @action(detail=True, methods=['post'])
    def withdraw(self, request, uuid=None):
        """Withdraw the offer."""
        offer = self.get_object()
        reason = request.data.get('reason', '')

        if offer.status in [Offer.OfferStatus.ACCEPTED, Offer.OfferStatus.DECLINED]:
            return Response(
                {'error': 'Cannot withdraw an offer that has been responded to'},
                status=status.HTTP_400_BAD_REQUEST
            )

        offer.status = Offer.OfferStatus.WITHDRAWN
        offer.response_notes = reason
        offer.save()

        return Response(OfferDetailSerializer(offer).data)


# ==================== SAVED SEARCH VIEWSET ====================

class SavedSearchViewSet(viewsets.ModelViewSet):
    """
    ViewSet for saved searches.

    list: Get user's saved searches
    retrieve: Get saved search details
    create: Create new saved search
    update: Update saved search
    delete: Delete saved search

    Actions:
    - run: Execute the saved search

    Security:
    - User can only access their own saved searches
    - Run action filters candidates by current tenant
    """
    queryset = SavedSearch.objects.all()
    permission_classes = [permissions.IsAuthenticated, IsTenantMember]
    filter_backends = [DjangoFilterBackend]
    filterset_class = SavedSearchFilter
    lookup_field = 'uuid'

    def get_serializer_class(self):
        if self.action == 'create':
            return SavedSearchCreateSerializer
        return SavedSearchSerializer

    def get_queryset(self):
        """Filter to only user's own saved searches."""
        # SECURITY: Users can only access their own saved searches
        return SavedSearch.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=True, methods=['get'])
    def run(self, request, uuid=None):
        """Execute the saved search and return matching candidates."""
        saved_search = self.get_object()
        filters = saved_search.filters

        # SECURITY: Apply filters to candidates within current tenant only
        queryset = Candidate.objects.for_current_tenant()
        filterset = CandidateFilter(filters, queryset=queryset)
        candidates = filterset.qs

        # Update last run time
        saved_search.last_run_at = timezone.now()
        saved_search.save()

        serializer = CandidateListSerializer(candidates, many=True)
        return Response({
            'search_name': saved_search.name,
            'filters': filters,
            'results_count': candidates.count(),
            'results': serializer.data
        })


# ==================== DASHBOARD STATS VIEW ====================

class DashboardStatsView(APIView):
    """
    API view for ATS dashboard statistics.

    GET: Returns comprehensive statistics including:
    - Total open jobs
    - Application counts
    - Interview stats
    - Offer stats
    - Pipeline metrics

    Security:
    - All statistics are filtered by current tenant
    - Rate limiting applied for performance protection
    """
    permission_classes = [permissions.IsAuthenticated, IsTenantMember]
    throttle_classes = [SensitiveOperationThrottle]

    def get(self, request):
        now = timezone.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = now - timedelta(days=7)
        month_start = now - timedelta(days=30)

        tenant = get_current_tenant()

        # SECURITY: All queries must be filtered by current tenant
        # Basic counts
        total_open_jobs = JobPosting.objects.for_current_tenant().filter(
            status=JobPosting.JobStatus.OPEN
        ).count()

        total_applications = Application.objects.for_current_tenant().count()
        new_applications_today = Application.objects.for_current_tenant().filter(
            applied_at__gte=today_start
        ).count()
        new_applications_this_week = Application.objects.for_current_tenant().filter(
            applied_at__gte=week_start
        ).count()

        # SECURITY: Filter interviews through application's tenant
        interviews_scheduled = Interview.objects.filter(
            application__tenant=tenant,
            status__in=['scheduled', 'confirmed'],
            scheduled_start__gte=now
        ).count() if tenant else 0

        # SECURITY: Filter offers through application's tenant
        offers_pending = Offer.objects.filter(
            application__tenant=tenant,
            status__in=['sent', 'pending_approval']
        ).count() if tenant else 0

        hires_this_month = Application.objects.for_current_tenant().filter(
            status='hired',
            hired_at__gte=month_start
        ).count()

        # Applications by status - filtered by tenant
        applications_by_status = dict(
            Application.objects.for_current_tenant().values('status').annotate(
                count=Count('id')
            ).values_list('status', 'count')
        )

        # Applications by source - filtered by tenant
        applications_by_source = dict(
            Application.objects.for_current_tenant().values('candidate__source').annotate(
                count=Count('id')
            ).values_list('candidate__source', 'count')
        )

        # Top jobs by applications - filtered by tenant
        top_jobs = list(
            JobPosting.objects.for_current_tenant().filter(
                status=JobPosting.JobStatus.OPEN
            ).annotate(
                app_count=Count('applications')
            ).order_by('-app_count')[:10].values(
                'id', 'title', 'reference_code', 'app_count'
            )
        )

        # Pipeline metrics - SECURITY: filtered by tenant
        pipeline_metrics = []
        for pipeline in Pipeline.objects.for_current_tenant().filter(is_active=True):
            stages_data = []
            total_apps = 0

            for stage in pipeline.stages.filter(is_active=True).order_by('order'):
                # SECURITY: Count applications within current tenant
                count = Application.objects.for_current_tenant().filter(
                    current_stage=stage
                ).count()
                total_apps += count
                stages_data.append({
                    'stage_id': stage.id,
                    'stage_name': stage.name,
                    'count': count
                })

            pipeline_metrics.append({
                'pipeline_id': pipeline.id,
                'pipeline_name': pipeline.name,
                'total_applications': total_apps,
                'stages': stages_data,
                'average_time_to_hire': None,  # Would require more complex calculation
                'conversion_rate': 0.0  # Would require more complex calculation
            })

        data = {
            'total_open_jobs': total_open_jobs,
            'total_applications': total_applications,
            'new_applications_today': new_applications_today,
            'new_applications_this_week': new_applications_this_week,
            'interviews_scheduled': interviews_scheduled,
            'offers_pending': offers_pending,
            'hires_this_month': hires_this_month,
            'applications_by_status': applications_by_status,
            'applications_by_source': applications_by_source,
            'top_jobs_by_applications': top_jobs,
            'pipeline_metrics': pipeline_metrics
        }

        serializer = DashboardStatsSerializer(data)
        return Response(serializer.data)


# ==================== AI MATCH SCORE VIEW ====================

class AIMatchScoreView(APIView):
    """
    API view for calculating AI match scores.

    POST: Calculate match score for a candidate against a job
    GET: Get existing match scores for an application

    Security:
    - All lookups are filtered by current tenant
    """
    permission_classes = [permissions.IsAuthenticated, IsTenantMember]
    throttle_classes = [SensitiveOperationThrottle]

    def post(self, request):
        """Calculate AI match score for candidate-job pair."""
        candidate_id = request.data.get('candidate_id')
        job_id = request.data.get('job_id')
        application_id = request.data.get('application_id')

        # SECURITY: All lookups must be filtered by current tenant
        if application_id:
            application = get_object_or_404(
                Application.objects.for_current_tenant(),
                id=application_id
            )
            candidate = application.candidate
            job = application.job
        elif candidate_id and job_id:
            candidate = get_object_or_404(
                Candidate.objects.for_current_tenant(),
                id=candidate_id
            )
            job = get_object_or_404(
                JobPosting.objects.for_current_tenant(),
                id=job_id
            )
            application = Application.objects.for_current_tenant().filter(
                candidate=candidate, job=job
            ).first()
        else:
            return Response(
                {'error': 'Either application_id or both candidate_id and job_id required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Calculate skill match
        candidate_skills = set(s.lower() for s in candidate.skills)
        required_skills = set(s.lower() for s in job.required_skills)
        preferred_skills = set(s.lower() for s in job.preferred_skills)

        required_match = len(candidate_skills & required_skills)
        required_total = len(required_skills) or 1
        required_score = (required_match / required_total) * 100

        preferred_match = len(candidate_skills & preferred_skills)
        preferred_total = len(preferred_skills) or 1
        preferred_score = (preferred_match / preferred_total) * 100

        skill_score = (required_score * 0.7) + (preferred_score * 0.3)

        # Calculate experience match
        experience_score = 100
        if candidate.years_experience and job.experience_level:
            level_years = {
                'entry': (0, 1),
                'junior': (1, 2),
                'mid': (3, 5),
                'senior': (5, 8),
                'lead': (8, 15),
                'executive': (10, 30)
            }
            min_years, max_years = level_years.get(job.experience_level, (0, 100))
            if candidate.years_experience < min_years:
                experience_score = max(0, 100 - (min_years - candidate.years_experience) * 20)
            elif candidate.years_experience > max_years:
                experience_score = max(60, 100 - (candidate.years_experience - max_years) * 5)

        # Calculate location match
        location_score = 100
        if job.remote_policy == 'on_site':
            if candidate.city and job.location_city:
                if candidate.city.lower() != job.location_city.lower():
                    if candidate.willing_to_relocate:
                        location_score = 70
                    else:
                        location_score = 30
        elif job.remote_policy == 'hybrid':
            if candidate.city and job.location_city:
                if candidate.city.lower() != job.location_city.lower():
                    location_score = 80

        # Calculate overall score
        overall_score = (skill_score * 0.5) + (experience_score * 0.3) + (location_score * 0.2)

        # Generate recommendations
        recommendations = []
        if required_score < 50:
            missing = required_skills - candidate_skills
            recommendations.append(
                f"Missing key skills: {', '.join(list(missing)[:5])}"
            )
        if experience_score < 70:
            recommendations.append(
                "Experience level may not match job requirements"
            )
        if location_score < 70:
            recommendations.append(
                "Location mismatch - consider remote or relocation"
            )
        if overall_score >= 80:
            recommendations.append("Strong candidate match!")

        # Update application if exists
        if application:
            application.ai_match_score = overall_score
            application.save(update_fields=['ai_match_score'])

        result = {
            'application_id': application.id if application else None,
            'candidate_id': candidate.id,
            'job_id': job.id,
            'match_score': round(overall_score, 2),
            'skill_match': {
                'score': round(skill_score, 2),
                'required_matched': required_match,
                'required_total': len(required_skills),
                'preferred_matched': preferred_match,
                'preferred_total': len(preferred_skills)
            },
            'experience_match': {
                'score': round(experience_score, 2),
                'candidate_years': candidate.years_experience,
                'job_level': job.experience_level
            },
            'location_match': {
                'score': round(location_score, 2),
                'candidate_location': f"{candidate.city}, {candidate.country}",
                'job_location': f"{job.location_city}, {job.location_country}",
                'remote_policy': job.remote_policy
            },
            'recommendations': recommendations,
            'calculated_at': timezone.now()
        }

        return Response(AIMatchScoreSerializer(result).data)

    def get(self, request):
        """Get match scores for a job or candidate."""
        job_id = request.query_params.get('job_id')
        candidate_id = request.query_params.get('candidate_id')

        if job_id:
            applications = Application.objects.for_current_tenant().filter(
                job_id=job_id,
                ai_match_score__isnull=False
            ).select_related('candidate').order_by('-ai_match_score')

            return Response({
                'job_id': job_id,
                'scores': [
                    {
                        'application_id': app.id,
                        'candidate_id': app.candidate.id,
                        'candidate_name': app.candidate.full_name,
                        'match_score': app.ai_match_score
                    }
                    for app in applications
                ]
            })

        if candidate_id:
            applications = Application.objects.for_current_tenant().filter(
                candidate_id=candidate_id,
                ai_match_score__isnull=False
            ).select_related('job').order_by('-ai_match_score')

            return Response({
                'candidate_id': candidate_id,
                'scores': [
                    {
                        'application_id': app.id,
                        'job_id': app.job.id,
                        'job_title': app.job.title,
                        'match_score': app.ai_match_score
                    }
                    for app in applications
                ]
            })

        return Response(
            {'error': 'job_id or candidate_id required'},
            status=status.HTTP_400_BAD_REQUEST
        )


# ==================== BULK OPERATIONS VIEW ====================

class BulkOperationsView(APIView):
    """
    API view for bulk operations across ATS.

    POST: Perform bulk operations like:
    - Calculate AI scores for all applications
    - Update stages in bulk
    - Send bulk emails
    """
    permission_classes = [permissions.IsAuthenticated, IsTenantMember]
    throttle_classes = [BulkOperationThrottle]

    def post(self, request):
        operation = request.data.get('operation')
        tenant = get_current_tenant()

        if operation == 'calculate_all_scores':
            job_id = request.data.get('job_id')
            if not job_id:
                return Response(
                    {'error': 'job_id required'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Verify job belongs to current tenant
            job = get_object_or_404(
                JobPosting.objects.for_current_tenant(),
                id=job_id
            )

            applications = Application.objects.for_current_tenant().filter(
                job=job,
                ai_match_score__isnull=True
            ).select_related('candidate', 'job')

            # In production, this should be a Celery task
            calculated = 0
            for app in applications[:100]:  # Limit to 100 for sync operation
                # Simplified score calculation
                score = 50.0  # Placeholder
                app.ai_match_score = score
                app.save(update_fields=['ai_match_score'])
                calculated += 1

            log_bulk_operation(request.user, 'calculate_scores', 'Application', calculated)

            return Response({
                'status': 'completed',
                'calculated': calculated
            })

        elif operation == 'bulk_stage_update':
            stage_id = request.data.get('stage_id')
            application_ids = request.data.get('application_ids', [])

            if not stage_id or not application_ids:
                return Response(
                    {'error': 'stage_id and application_ids required'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Verify stage belongs to current tenant's pipeline
            stage = get_object_or_404(
                PipelineStage.objects.filter(pipeline__tenant=tenant),
                id=stage_id
            )

            # Filter applications by current tenant
            applications = Application.objects.for_current_tenant().filter(
                id__in=application_ids
            )

            # Verify all requested applications were found
            if applications.count() != len(application_ids):
                logger.warning(
                    f"Cross-tenant bulk stage update attempt by user {request.user.id}"
                )
                return Response(
                    {'error': 'Some applications not found'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            updated = applications.update(
                current_stage=stage,
                last_stage_change_at=timezone.now()
            )

            log_bulk_operation(request.user, 'stage_update', 'Application', updated)

            return Response({
                'status': 'completed',
                'updated': updated
            })

        return Response(
            {'error': f'Unknown operation: {operation}'},
            status=status.HTTP_400_BAD_REQUEST
        )


# ==================== INTERVIEW SLOT VIEWSET ====================

class InterviewSlotViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing interviewer availability slots.

    Provides endpoints for:
    - CRUD operations on interview slots
    - Bulk creation of recurring slots
    - Finding available slots for scheduling
    - Finding common slots for panel interviews

    Security:
    - Tenant isolation via for_current_tenant()
    - Users can only manage their own slots unless admin
    """
    queryset = InterviewSlot.objects.select_related('interviewer', 'booked_interview')
    permission_classes = [permissions.IsAuthenticated, IsTenantMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    ordering_fields = ['start_time', 'created_at']
    ordering = ['start_time']
    lookup_field = 'uuid'

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return InterviewSlotCreateSerializer
        if self.action == 'bulk_create':
            return InterviewSlotBulkCreateSerializer
        if self.action == 'available':
            return InterviewSlotAvailableSerializer
        if self.action == 'find_common':
            return InterviewSlotFindCommonSerializer
        return InterviewSlotSerializer

    def get_queryset(self):
        """Filter queryset by current tenant for data isolation."""
        # SECURITY: Always filter by current tenant
        queryset = InterviewSlot.objects.for_current_tenant().select_related(
            'interviewer', 'booked_interview'
        )

        # Non-admin users can only see their own slots by default
        if not self.request.user.is_staff:
            # Allow viewing all slots for scheduling purposes, but restrict editing
            if self.action in ['update', 'partial_update', 'destroy']:
                queryset = queryset.filter(interviewer=self.request.user)

        return queryset

    def perform_create(self, serializer):
        """Create slot with current user as default interviewer."""
        if 'interviewer' not in serializer.validated_data:
            serializer.save(interviewer=self.request.user)
        else:
            serializer.save()

    @action(detail=False, methods=['post'])
    def bulk_create(self, request):
        """
        Create multiple interview slots based on a recurring pattern.

        POST /interview-slots/bulk-create/
        Body: {
            "start_date": "2024-01-15",
            "end_date": "2024-01-31",
            "start_time": "09:00",
            "end_time": "17:00",
            "days_of_week": [0, 1, 2, 3, 4],  # Monday-Friday
            "slot_duration_minutes": 60,
            "slot_type": "video"
        }
        """
        serializer = InterviewSlotBulkCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        interviewer_id = data.get('interviewer_id')
        if interviewer_id and request.user.is_staff:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            interviewer = get_object_or_404(User, id=interviewer_id)
        else:
            interviewer = request.user

        from datetime import datetime, time, date
        import pytz

        tz = pytz.timezone(data.get('timezone', 'America/Toronto'))
        start_date = data['start_date']
        end_date = data['end_date']
        start_time = data['start_time']
        end_time = data['end_time']
        days_of_week = set(data['days_of_week'])
        duration = timedelta(minutes=data['slot_duration_minutes'])

        created_slots = []
        current_date = start_date

        with transaction.atomic():
            while current_date <= end_date:
                # Check if this day is in the selected days of week
                if current_date.weekday() in days_of_week:
                    # Create slots for this day
                    slot_start = datetime.combine(current_date, start_time)
                    day_end = datetime.combine(current_date, end_time)
                    slot_start = tz.localize(slot_start)
                    day_end = tz.localize(day_end)

                    while slot_start + duration <= day_end:
                        slot = InterviewSlot.objects.create(
                            tenant=get_current_tenant(),
                            interviewer=interviewer,
                            start_time=slot_start,
                            end_time=slot_start + duration,
                            timezone=data.get('timezone', 'America/Toronto'),
                            slot_type=data.get('slot_type', 'any'),
                            is_available=True
                        )
                        created_slots.append(slot)
                        slot_start = slot_start + duration

                current_date = current_date + timedelta(days=1)

        return Response({
            'created_count': len(created_slots),
            'slots': InterviewSlotSerializer(created_slots, many=True).data
        }, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['get'])
    def available(self, request):
        """
        Get available slots for a date range.

        GET /interview-slots/available/?start_date=2024-01-15&end_date=2024-01-31
        """
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        slot_type = request.query_params.get('slot_type')
        interviewer_ids = request.query_params.getlist('interviewer_ids')

        if not start_date or not end_date:
            return Response(
                {'error': 'start_date and end_date are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        from datetime import datetime
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()

        # SECURITY: Filter by tenant
        queryset = InterviewSlot.objects.for_current_tenant().filter(
            is_available=True,
            booked_interview__isnull=True,
            start_time__date__gte=start_date,
            start_time__date__lte=end_date,
            start_time__gt=timezone.now()
        )

        if slot_type and slot_type != 'any':
            queryset = queryset.filter(Q(slot_type=slot_type) | Q(slot_type='any'))

        if interviewer_ids:
            queryset = queryset.filter(interviewer_id__in=interviewer_ids)

        queryset = queryset.order_by('start_time')
        serializer = InterviewSlotSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def find_common(self, request):
        """
        Find common available slots for multiple interviewers (panel interviews).

        POST /interview-slots/find-common/
        Body: {
            "interviewer_ids": [1, 2, 3],
            "start_date": "2024-01-15",
            "end_date": "2024-01-31",
            "duration_minutes": 60
        }
        """
        serializer = InterviewSlotFindCommonSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        interviewer_ids = data['interviewer_ids']
        start_date = data['start_date']
        end_date = data['end_date']
        duration = timedelta(minutes=data['duration_minutes'])

        # Get available slots for each interviewer
        from datetime import datetime
        from collections import defaultdict

        # SECURITY: Filter by tenant
        base_queryset = InterviewSlot.objects.for_current_tenant().filter(
            is_available=True,
            booked_interview__isnull=True,
            start_time__date__gte=start_date,
            start_time__date__lte=end_date,
            start_time__gt=timezone.now()
        )

        # Find overlapping time slots
        common_slots = []
        slots_by_interviewer = {}

        for interviewer_id in interviewer_ids:
            slots_by_interviewer[interviewer_id] = list(
                base_queryset.filter(interviewer_id=interviewer_id).order_by('start_time')
            )

        # Find common available times
        if len(interviewer_ids) < 2:
            return Response(
                {'error': 'At least 2 interviewers required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        first_interviewer_slots = slots_by_interviewer[interviewer_ids[0]]

        for slot in first_interviewer_slots:
            slot_start = slot.start_time
            slot_end = slot.end_time

            # Check if all other interviewers have overlapping availability
            all_available = True
            for other_id in interviewer_ids[1:]:
                other_slots = slots_by_interviewer[other_id]
                has_overlap = False

                for other_slot in other_slots:
                    # Check for overlap
                    overlap_start = max(slot_start, other_slot.start_time)
                    overlap_end = min(slot_end, other_slot.end_time)

                    if overlap_end - overlap_start >= duration:
                        has_overlap = True
                        break

                if not has_overlap:
                    all_available = False
                    break

            if all_available:
                common_slots.append({
                    'start_time': slot_start,
                    'end_time': slot_end,
                    'duration_minutes': slot.duration_minutes,
                    'interviewer_ids': interviewer_ids
                })

        return Response({
            'common_slots_count': len(common_slots),
            'common_slots': common_slots
        })


# ==================== INTERVIEW SCHEDULING VIEW ====================

class InterviewSchedulingView(APIView):
    """
    Advanced interview scheduling endpoints.

    Provides:
    - Schedule interview with availability slot
    - Reschedule interview
    - Cancel interview
    - Send manual reminders
    """
    permission_classes = [permissions.IsAuthenticated, IsTenantMember, IsRecruiterOrHiringManager]
    throttle_classes = [SensitiveOperationThrottle]

    def post(self, request, action=None, uuid=None):
        """Handle interview scheduling actions."""
        if action == 'schedule':
            return self._schedule_interview(request)
        elif action == 'reschedule' and uuid:
            return self._reschedule_interview(request, uuid)
        elif action == 'cancel' and uuid:
            return self._cancel_interview(request, uuid)
        elif action == 'send-reminders' and uuid:
            return self._send_reminders(request, uuid)
        else:
            return Response(
                {'error': 'Invalid action'},
                status=status.HTTP_400_BAD_REQUEST
            )

    def _schedule_interview(self, request):
        """
        Schedule a new interview using an availability slot.

        POST /interviews/schedule/
        Body: {
            "application_id": 123,
            "slot_id": 456,
            "interview_type": "video",
            "title": "Technical Interview",
            "interviewer_ids": [1, 2]
        }
        """
        application_id = request.data.get('application_id')
        slot_id = request.data.get('slot_id')

        if not application_id:
            return Response(
                {'error': 'application_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # SECURITY: Verify application belongs to current tenant
        application = get_object_or_404(
            Application.objects.for_current_tenant(),
            id=application_id
        )

        # If slot_id provided, use the slot times
        if slot_id:
            slot = get_object_or_404(
                InterviewSlot.objects.for_current_tenant(),
                id=slot_id
            )

            if not slot.can_book:
                return Response(
                    {'error': 'This slot is not available'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            scheduled_start = slot.start_time
            scheduled_end = slot.end_time
        else:
            # Use provided times
            scheduled_start = request.data.get('scheduled_start')
            scheduled_end = request.data.get('scheduled_end')

            if not scheduled_start or not scheduled_end:
                return Response(
                    {'error': 'Either slot_id or scheduled_start/scheduled_end required'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        with transaction.atomic():
            interview = Interview.objects.create(
                application=application,
                interview_type=request.data.get('interview_type', 'video'),
                title=request.data.get('title', f'Interview - {application.candidate.full_name}'),
                description=request.data.get('description', ''),
                scheduled_start=scheduled_start,
                scheduled_end=scheduled_end,
                timezone=request.data.get('timezone', 'America/Toronto'),
                location=request.data.get('location', ''),
                meeting_url=request.data.get('meeting_url', ''),
                organizer=request.user,
                preparation_notes=request.data.get('preparation_notes', '')
            )

            # Add interviewers
            interviewer_ids = request.data.get('interviewer_ids', [])
            if interviewer_ids:
                from django.contrib.auth import get_user_model
                User = get_user_model()
                interviewers = User.objects.filter(id__in=interviewer_ids)
                interview.interviewers.set(interviewers)

            # If using a slot, mark it as booked
            if slot_id:
                slot.booked_interview = interview
                slot.is_available = False
                slot.save(update_fields=['booked_interview', 'is_available', 'updated_at'])

            # Log activity
            ApplicationActivity.objects.create(
                application=application,
                activity_type=ApplicationActivity.ActivityType.INTERVIEW_SCHEDULED,
                performed_by=request.user,
                new_value=interview.title,
                metadata={
                    'interview_id': interview.id,
                    'scheduled_start': interview.scheduled_start.isoformat()
                }
            )

        return Response(
            InterviewDetailSerializer(interview).data,
            status=status.HTTP_201_CREATED
        )

    def _reschedule_interview(self, request, uuid):
        """Reschedule an existing interview."""
        tenant = get_current_tenant()
        interview = get_object_or_404(
            Interview.objects.filter(application__tenant=tenant),
            uuid=uuid
        )

        new_start = request.data.get('scheduled_start')
        new_end = request.data.get('scheduled_end')
        reason = request.data.get('reason', '')
        new_slot_id = request.data.get('new_slot_id')

        if new_slot_id:
            slot = get_object_or_404(
                InterviewSlot.objects.for_current_tenant(),
                id=new_slot_id
            )
            if not slot.can_book:
                return Response(
                    {'error': 'New slot is not available'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            new_start = slot.start_time
            new_end = slot.end_time

        if not new_start or not new_end:
            return Response(
                {'error': 'scheduled_start and scheduled_end required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        old_start = interview.scheduled_start

        with transaction.atomic():
            # Release old slot if exists
            old_slot = InterviewSlot.objects.filter(booked_interview=interview).first()
            if old_slot:
                old_slot.booked_interview = None
                old_slot.is_available = True
                old_slot.save(update_fields=['booked_interview', 'is_available', 'updated_at'])

            # Update interview
            interview.scheduled_start = new_start
            interview.scheduled_end = new_end
            interview.status = Interview.InterviewStatus.RESCHEDULED
            interview.save()

            # Book new slot if provided
            if new_slot_id:
                slot.booked_interview = interview
                slot.is_available = False
                slot.save(update_fields=['booked_interview', 'is_available', 'updated_at'])

            # Log activity
            ApplicationActivity.objects.create(
                application=interview.application,
                activity_type=ApplicationActivity.ActivityType.INTERVIEW_SCHEDULED,
                performed_by=request.user,
                old_value=old_start.isoformat(),
                new_value=interview.scheduled_start.isoformat(),
                notes=f'Rescheduled: {reason}'
            )

        return Response(InterviewDetailSerializer(interview).data)

    def _cancel_interview(self, request, uuid):
        """Cancel an interview."""
        tenant = get_current_tenant()
        interview = get_object_or_404(
            Interview.objects.filter(application__tenant=tenant),
            uuid=uuid
        )

        reason = request.data.get('reason', '')
        notify_candidate = request.data.get('notify_candidate', True)
        notify_interviewers = request.data.get('notify_interviewers', True)

        with transaction.atomic():
            # Release slot if exists
            slot = InterviewSlot.objects.filter(booked_interview=interview).first()
            if slot:
                slot.booked_interview = None
                slot.is_available = True
                slot.save(update_fields=['booked_interview', 'is_available', 'updated_at'])

            interview.status = Interview.InterviewStatus.CANCELLED
            interview.save(update_fields=['status', 'updated_at'])

            # Log activity
            ApplicationActivity.objects.create(
                application=interview.application,
                activity_type=ApplicationActivity.ActivityType.INTERVIEW_SCHEDULED,
                performed_by=request.user,
                new_value='Cancelled',
                notes=reason
            )

        return Response({
            'status': 'cancelled',
            'interview': InterviewDetailSerializer(interview).data,
            'notifications_queued': {
                'candidate': notify_candidate,
                'interviewers': notify_interviewers
            }
        })

    def _send_reminders(self, request, uuid):
        """Send manual interview reminders."""
        tenant = get_current_tenant()
        interview = get_object_or_404(
            Interview.objects.filter(application__tenant=tenant),
            uuid=uuid
        )

        remind_candidate = request.data.get('remind_candidate', True)
        remind_interviewers = request.data.get('remind_interviewers', True)
        custom_message = request.data.get('custom_message', '')

        # In production, this would queue Celery tasks
        reminders_sent = {
            'candidate': remind_candidate,
            'interviewers': remind_interviewers,
            'interviewers_count': interview.interviewers.count() if remind_interviewers else 0
        }

        return Response({
            'status': 'reminders_queued',
            'reminders': reminders_sent
        })


# ==================== OFFER TEMPLATE VIEWSET ====================

class OfferTemplateViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing offer letter templates.

    Provides:
    - CRUD for offer templates
    - Apply template to an offer

    Security:
    - Tenant isolation via for_current_tenant()
    """
    queryset = OfferTemplate.objects.select_related('created_by')
    permission_classes = [permissions.IsAuthenticated, IsTenantMember, IsRecruiterOrHiringManager]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description', 'department']
    ordering_fields = ['name', 'created_at', 'is_default']
    ordering = ['-is_default', 'name']
    lookup_field = 'uuid'

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return OfferTemplateCreateSerializer
        if self.action == 'apply':
            return OfferTemplateApplySerializer
        return OfferTemplateSerializer

    def get_queryset(self):
        """Filter queryset by current tenant for data isolation."""
        return OfferTemplate.objects.for_current_tenant().select_related('created_by')

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def apply(self, request, uuid=None):
        """
        Apply a template to an offer.

        POST /offer-templates/{uuid}/apply/
        Body: {
            "offer_id": 123,
            "context": {
                "candidate_name": "John Doe",
                "job_title": "Software Engineer"
            }
        }
        """
        template = self.get_object()
        serializer = OfferTemplateApplySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        offer_id = serializer.validated_data['offer_id']
        context = serializer.validated_data.get('context', {})

        # SECURITY: Verify offer belongs to current tenant
        tenant = get_current_tenant()
        offer = get_object_or_404(
            Offer.objects.filter(application__tenant=tenant),
            id=offer_id
        )

        # Build context with offer/candidate data
        full_context = {
            'candidate_name': offer.application.candidate.full_name,
            'candidate_first_name': offer.application.candidate.first_name,
            'job_title': offer.job_title,
            'base_salary': str(offer.base_salary),
            'start_date': str(offer.start_date) if offer.start_date else '',
            **context
        }

        # Apply template
        template.apply_to_offer(offer, full_context)
        offer.save()

        return Response(OfferDetailSerializer(offer).data)


# ==================== OFFER APPROVAL VIEWSET ====================

class OfferApprovalViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing offer approvals.

    Provides:
    - List approvals for an offer
    - Request new approval
    - Approve/reject actions

    Security:
    - Tenant isolation via offer's application tenant
    """
    queryset = OfferApproval.objects.select_related('offer', 'approver', 'requested_by')
    permission_classes = [permissions.IsAuthenticated, IsTenantMember]
    filter_backends = [DjangoFilterBackend]
    lookup_field = 'uuid'

    def get_serializer_class(self):
        if self.action in ['approve', 'reject']:
            return OfferApprovalResponseSerializer
        return OfferApprovalSerializer

    def get_queryset(self):
        """Filter queryset by current tenant through offer relation."""
        tenant = get_current_tenant()
        if not tenant:
            return OfferApproval.objects.none()

        queryset = OfferApproval.objects.filter(
            offer__application__tenant=tenant
        ).select_related('offer', 'approver', 'requested_by')

        # Filter by offer if provided
        offer_id = self.request.query_params.get('offer_id')
        if offer_id:
            queryset = queryset.filter(offer_id=offer_id)

        return queryset

    @action(detail=True, methods=['post'])
    def approve(self, request, uuid=None):
        """
        Approve an offer approval request.

        POST /approvals/{uuid}/approve/
        Body: {"comments": "Approved - good candidate"}
        """
        approval = self.get_object()

        if not approval.is_pending:
            return Response(
                {'error': 'This approval has already been responded to'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Verify current user is the approver
        if approval.approver != request.user and not request.user.is_staff:
            return Response(
                {'error': 'You are not authorized to approve this request'},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = OfferApprovalResponseSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        approval.approve(
            user=request.user,
            comments=serializer.validated_data.get('comments', '')
        )

        return Response(OfferApprovalSerializer(approval).data)

    @action(detail=True, methods=['post'])
    def reject(self, request, uuid=None):
        """
        Reject an offer approval request.

        POST /approvals/{uuid}/reject/
        Body: {"rejection_reason": "Salary too high for this role"}
        """
        approval = self.get_object()

        if not approval.is_pending:
            return Response(
                {'error': 'This approval has already been responded to'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Verify current user is the approver
        if approval.approver != request.user and not request.user.is_staff:
            return Response(
                {'error': 'You are not authorized to reject this request'},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = OfferApprovalResponseSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        approval.reject(
            user=request.user,
            reason=serializer.validated_data.get('rejection_reason', '')
        )

        return Response(OfferApprovalSerializer(approval).data)


# ==================== OFFER WORKFLOW VIEW ====================

class OfferWorkflowView(APIView):
    """
    Offer workflow actions.

    Provides:
    - Generate offer letter from template
    - Send for e-signature
    - Check signature status
    - Create counter-offer
    - Request approval
    """
    permission_classes = [permissions.IsAuthenticated, IsTenantMember, IsRecruiterOrHiringManager]
    throttle_classes = [SensitiveOperationThrottle]

    def post(self, request, uuid, action):
        """Handle offer workflow actions."""
        tenant = get_current_tenant()
        offer = get_object_or_404(
            Offer.objects.filter(application__tenant=tenant),
            uuid=uuid
        )

        if action == 'generate-letter':
            return self._generate_letter(request, offer)
        elif action == 'send-for-signature':
            return self._send_for_signature(request, offer)
        elif action == 'check-signature-status':
            return self._check_signature_status(request, offer)
        elif action == 'counter':
            return self._create_counter_offer(request, offer)
        elif action == 'request-approval':
            return self._request_approval(request, offer)
        else:
            return Response(
                {'error': f'Unknown action: {action}'},
                status=status.HTTP_400_BAD_REQUEST
            )

    def _generate_letter(self, request, offer):
        """Generate offer letter from template."""
        serializer = OfferGenerateLetterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        template_id = serializer.validated_data.get('template_id')
        context = serializer.validated_data.get('context', {})

        if template_id:
            template = get_object_or_404(
                OfferTemplate.objects.for_current_tenant(),
                id=template_id
            )
        else:
            # Try to find default template
            template = OfferTemplate.objects.for_current_tenant().filter(
                is_default=True
            ).first()

        if template:
            full_context = {
                'candidate_name': offer.application.candidate.full_name,
                'candidate_first_name': offer.application.candidate.first_name,
                'job_title': offer.job_title,
                'base_salary': str(offer.base_salary),
                'salary_currency': offer.salary_currency,
                'start_date': str(offer.start_date) if offer.start_date else 'TBD',
                'department': offer.department,
                **context
            }
            template.apply_to_offer(offer, full_context)
            offer.save()

        return Response({
            'status': 'generated',
            'offer': OfferDetailSerializer(offer).data
        })

    def _send_for_signature(self, request, offer):
        """Send offer for e-signature."""
        serializer = OfferSignatureSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if offer.status not in [Offer.OfferStatus.DRAFT, Offer.OfferStatus.APPROVED]:
            return Response(
                {'error': 'Only draft or approved offers can be sent for signature'},
                status=status.HTTP_400_BAD_REQUEST
            )

        provider = serializer.validated_data.get('provider', 'docusign')
        expiration_days = serializer.validated_data.get('expiration_days', 7)

        # In production, this would integrate with e-signature provider
        # For now, simulate the process
        offer.requires_signature = True
        offer.signature_document_id = f'{provider}_{offer.id}_{timezone.now().timestamp()}'
        offer.status = Offer.OfferStatus.SENT
        offer.sent_at = timezone.now()
        offer.expiration_date = timezone.now().date() + timedelta(days=expiration_days)
        offer.save()

        return Response({
            'status': 'sent_for_signature',
            'provider': provider,
            'document_id': offer.signature_document_id,
            'expiration_date': offer.expiration_date,
            'offer': OfferDetailSerializer(offer).data
        })

    def _check_signature_status(self, request, offer):
        """Check e-signature status."""
        if not offer.signature_document_id:
            return Response(
                {'error': 'This offer has not been sent for signature'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # In production, this would query the e-signature provider
        signature_status = {
            'document_id': offer.signature_document_id,
            'status': 'pending' if not offer.signed_at else 'signed',
            'signed_at': offer.signed_at,
            'offer_status': offer.status
        }

        return Response(signature_status)

    def _create_counter_offer(self, request, offer):
        """Create a counter-offer based on candidate negotiation."""
        serializer = OfferCounterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Create new offer as counter
        counter_offer = Offer.objects.create(
            application=offer.application,
            status=Offer.OfferStatus.DRAFT,
            job_title=offer.job_title,
            department=offer.department,
            reports_to=offer.reports_to,
            employment_type=offer.employment_type,
            base_salary=serializer.validated_data['base_salary'],
            salary_currency=offer.salary_currency,
            salary_period=offer.salary_period,
            signing_bonus=serializer.validated_data.get('signing_bonus', offer.signing_bonus),
            start_date=serializer.validated_data.get('start_date', offer.start_date),
            pto_days=serializer.validated_data.get('pto_days', offer.pto_days),
            equity=serializer.validated_data.get('equity', offer.equity),
            benefits_summary=offer.benefits_summary,
            remote_policy=offer.remote_policy,
            offer_letter_content=offer.offer_letter_content,
            terms_and_conditions=offer.terms_and_conditions,
            created_by=request.user,
            response_notes=serializer.validated_data.get('notes', 'Counter-offer')
        )

        # Mark original offer as superseded
        offer.status = Offer.OfferStatus.WITHDRAWN
        offer.response_notes = f'Superseded by counter-offer {counter_offer.id}'
        offer.save()

        return Response({
            'status': 'counter_offer_created',
            'original_offer_id': offer.id,
            'counter_offer': OfferDetailSerializer(counter_offer).data
        }, status=status.HTTP_201_CREATED)

    def _request_approval(self, request, offer):
        """Request approval for an offer."""
        serializer = OfferApprovalCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        approver_ids = serializer.validated_data['approver_ids']
        due_date = serializer.validated_data.get('due_date')

        from django.contrib.auth import get_user_model
        User = get_user_model()

        approvals_created = []
        with transaction.atomic():
            offer.status = Offer.OfferStatus.PENDING_APPROVAL
            offer.save(update_fields=['status', 'updated_at'])

            for order, approver_id in enumerate(approver_ids):
                approver = get_object_or_404(User, id=approver_id)

                approval, created = OfferApproval.objects.get_or_create(
                    offer=offer,
                    approver=approver,
                    defaults={
                        'approval_order': order,
                        'requested_by': request.user,
                        'due_date': due_date
                    }
                )
                if created:
                    approvals_created.append(approval)

        return Response({
            'status': 'approvals_requested',
            'approvals_count': len(approvals_created),
            'approvals': OfferApprovalSerializer(approvals_created, many=True).data
        })


# ==================== PIPELINE ANALYTICS VIEW ====================

class PipelineAnalyticsView(APIView):
    """
    Pipeline analytics and reporting.

    Provides:
    - Full pipeline analytics
    - Stage conversion rates
    - Bottleneck identification
    - SLA compliance status
    - Pipeline comparison (A/B testing)
    """
    permission_classes = [permissions.IsAuthenticated, IsTenantMember, IsRecruiterOrHiringManager]
    throttle_classes = [SensitiveOperationThrottle]

    def get(self, request, pk=None, action=None):
        """Handle pipeline analytics requests."""
        if pk and action == 'analytics':
            return self._get_full_analytics(request, pk)
        elif pk and action == 'conversion-rates':
            return self._get_conversion_rates(request, pk)
        elif pk and action == 'bottlenecks':
            return self._get_bottlenecks(request, pk)
        elif pk and action == 'sla-status':
            return self._get_sla_status(request, pk)
        elif action == 'compare':
            return self._compare_pipelines(request)
        else:
            return Response(
                {'error': 'Invalid action'},
                status=status.HTTP_400_BAD_REQUEST
            )

    def _get_pipeline(self, pk):
        """Get pipeline with tenant isolation."""
        return get_object_or_404(
            Pipeline.objects.for_current_tenant(),
            pk=pk
        )

    def _get_date_range(self, request):
        """Parse date range from request params."""
        days = int(request.query_params.get('days', 30))
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)

        # Allow custom date range
        if request.query_params.get('start_date'):
            from datetime import datetime
            start_date = datetime.strptime(
                request.query_params['start_date'], '%Y-%m-%d'
            )
            start_date = timezone.make_aware(start_date)
        if request.query_params.get('end_date'):
            from datetime import datetime
            end_date = datetime.strptime(
                request.query_params['end_date'], '%Y-%m-%d'
            )
            end_date = timezone.make_aware(end_date)

        return start_date, end_date

    def _get_full_analytics(self, request, pk):
        """Get comprehensive pipeline analytics."""
        pipeline = self._get_pipeline(pk)
        start_date, end_date = self._get_date_range(request)

        # Get applications in this period
        applications = Application.objects.for_current_tenant().filter(
            job__pipeline=pipeline,
            applied_at__gte=start_date,
            applied_at__lte=end_date
        )

        total_apps = applications.count()
        total_hires = applications.filter(status='hired').count()
        total_rejections = applications.filter(status='rejected').count()
        total_withdrawals = applications.filter(status='withdrawn').count()

        # Calculate conversion rate
        conversion_rate = (total_hires / total_apps * 100) if total_apps > 0 else 0

        # Calculate average time to hire
        hired_apps = applications.filter(
            status='hired',
            hired_at__isnull=False
        )
        total_days = 0
        hire_count = 0
        for app in hired_apps:
            if app.hired_at and app.applied_at:
                total_days += (app.hired_at - app.applied_at).days
                hire_count += 1
        avg_time_to_hire = (total_days / hire_count) if hire_count > 0 else None

        # Stage metrics
        stage_metrics = []
        stages = pipeline.stages.filter(is_active=True).order_by('order')

        for stage in stages:
            entered = ApplicationActivity.objects.filter(
                application__job__pipeline=pipeline,
                activity_type='stage_change',
                new_value=stage.name,
                created_at__gte=start_date,
                created_at__lte=end_date
            ).count()

            advanced = ApplicationActivity.objects.filter(
                application__job__pipeline=pipeline,
                activity_type='stage_change',
                old_value=stage.name,
                created_at__gte=start_date,
                created_at__lte=end_date
            ).count()

            conv_rate = (advanced / entered * 100) if entered > 0 else 0

            stage_metrics.append({
                'stage_id': stage.id,
                'stage_name': stage.name,
                'stage_order': stage.order,
                'applications_entered': entered,
                'applications_advanced': advanced,
                'conversion_rate': round(conv_rate, 2),
                'average_time_in_stage_days': None  # Would need more complex calculation
            })

        data = {
            'pipeline_id': pipeline.id,
            'pipeline_name': pipeline.name,
            'period_start': start_date,
            'period_end': end_date,
            'total_applications': total_apps,
            'total_hires': total_hires,
            'total_rejections': total_rejections,
            'total_withdrawals': total_withdrawals,
            'overall_conversion_rate': round(conversion_rate, 2),
            'average_time_to_hire_days': avg_time_to_hire,
            'stage_metrics': stage_metrics
        }

        return Response(PipelineAnalyticsSerializer(data).data)

    def _get_conversion_rates(self, request, pk):
        """Get stage-by-stage conversion rates."""
        pipeline = self._get_pipeline(pk)
        start_date, end_date = self._get_date_range(request)

        stages = pipeline.stages.filter(is_active=True).order_by('order')
        conversion_rates = []

        for stage in stages:
            entered = ApplicationActivity.objects.filter(
                application__job__pipeline=pipeline,
                activity_type='stage_change',
                new_value=stage.name,
                created_at__gte=start_date,
                created_at__lte=end_date
            ).count()

            advanced = ApplicationActivity.objects.filter(
                application__job__pipeline=pipeline,
                activity_type='stage_change',
                old_value=stage.name,
                created_at__gte=start_date,
                created_at__lte=end_date
            ).count()

            conversion_rates.append({
                'stage_id': stage.id,
                'stage_name': stage.name,
                'stage_order': stage.order,
                'applications_entered': entered,
                'applications_advanced': advanced,
                'conversion_rate': round((advanced / entered * 100) if entered > 0 else 0, 2),
                'average_time_in_stage_days': None
            })

        return Response(StageConversionRateSerializer(conversion_rates, many=True).data)

    def _get_bottlenecks(self, request, pk):
        """Identify pipeline bottlenecks."""
        pipeline = self._get_pipeline(pk)
        threshold_days = int(request.query_params.get('threshold_days', 7))

        stages = pipeline.stages.filter(is_active=True).order_by('order')
        bottlenecks = []

        for stage in stages:
            # Find applications stuck in this stage
            stuck_apps = Application.objects.for_current_tenant().filter(
                job__pipeline=pipeline,
                current_stage=stage,
                status__in=['new', 'in_review', 'shortlisted', 'interviewing', 'offer_pending']
            )

            stuck_count = 0
            total_days_stuck = 0

            for app in stuck_apps:
                days_in_stage = app.days_in_current_stage or 0
                if days_in_stage > threshold_days:
                    stuck_count += 1
                    total_days_stuck += days_in_stage

            avg_days_stuck = (total_days_stuck / stuck_count) if stuck_count > 0 else 0

            if stuck_count > 0:
                # Generate recommendation
                if avg_days_stuck > threshold_days * 2:
                    recommendation = "Critical bottleneck - consider adding resources or reviewing process"
                elif avg_days_stuck > threshold_days:
                    recommendation = "Review applications and prioritize decisions"
                else:
                    recommendation = "Monitor closely"

                bottlenecks.append({
                    'stage_id': stage.id,
                    'stage_name': stage.name,
                    'applications_stuck': stuck_count,
                    'average_days_stuck': round(avg_days_stuck, 1),
                    'recommended_action': recommendation
                })

        # Sort by severity
        bottlenecks.sort(key=lambda x: x['applications_stuck'], reverse=True)

        return Response(PipelineBottleneckSerializer(bottlenecks, many=True).data)

    def _get_sla_status(self, request, pk):
        """Get SLA compliance status for each stage."""
        pipeline = self._get_pipeline(pk)
        default_sla_days = int(request.query_params.get('sla_days', 5))

        stages = pipeline.stages.filter(is_active=True).order_by('order')
        sla_status = []

        for stage in stages:
            # Get SLA for this stage (could be stored on stage model)
            sla_days = stage.auto_reject_after_days if stage.auto_reject_after_days > 0 else default_sla_days

            apps_in_stage = Application.objects.for_current_tenant().filter(
                job__pipeline=pipeline,
                current_stage=stage,
                status__in=['new', 'in_review', 'shortlisted', 'interviewing', 'offer_pending']
            )

            within_sla = 0
            breaching_sla = 0

            for app in apps_in_stage:
                days_in_stage = app.days_in_current_stage or 0
                if days_in_stage <= sla_days:
                    within_sla += 1
                else:
                    breaching_sla += 1

            total = within_sla + breaching_sla
            compliance_rate = (within_sla / total * 100) if total > 0 else 100

            sla_status.append({
                'stage_id': stage.id,
                'stage_name': stage.name,
                'sla_days': sla_days,
                'applications_within_sla': within_sla,
                'applications_breaching_sla': breaching_sla,
                'compliance_rate': round(compliance_rate, 2)
            })

        return Response(SLAStatusSerializer(sla_status, many=True).data)

    def _compare_pipelines(self, request):
        """Compare two pipelines for A/B testing."""
        pipeline_a_id = request.query_params.get('pipeline_a_id')
        pipeline_b_id = request.query_params.get('pipeline_b_id')

        if not pipeline_a_id or not pipeline_b_id:
            return Response(
                {'error': 'pipeline_a_id and pipeline_b_id are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        pipeline_a = self._get_pipeline(pipeline_a_id)
        pipeline_b = self._get_pipeline(pipeline_b_id)

        days = int(request.query_params.get('days', 30))
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)

        def get_pipeline_metrics(pipeline):
            apps = Application.objects.for_current_tenant().filter(
                job__pipeline=pipeline,
                applied_at__gte=start_date,
                applied_at__lte=end_date
            )

            total = apps.count()
            hires = apps.filter(status='hired').count()

            hired_apps = apps.filter(status='hired', hired_at__isnull=False)
            avg_time = None
            if hired_apps.exists():
                total_days = sum(
                    (a.hired_at - a.applied_at).days
                    for a in hired_apps if a.hired_at and a.applied_at
                )
                avg_time = total_days / hired_apps.count()

            return {
                'total_applications': total,
                'total_hires': hires,
                'conversion_rate': round((hires / total * 100) if total > 0 else 0, 2),
                'average_time_to_hire_days': avg_time
            }

        metrics_a = get_pipeline_metrics(pipeline_a)
        metrics_b = get_pipeline_metrics(pipeline_b)

        data = {
            'pipeline_a_id': pipeline_a.id,
            'pipeline_a_name': pipeline_a.name,
            'pipeline_b_id': pipeline_b.id,
            'pipeline_b_name': pipeline_b.name,
            'comparison_period_days': days,
            'metrics': {
                'pipeline_a': metrics_a,
                'pipeline_b': metrics_b,
                'conversion_rate_difference': round(
                    metrics_a['conversion_rate'] - metrics_b['conversion_rate'], 2
                ),
                'winner': 'A' if metrics_a['conversion_rate'] > metrics_b['conversion_rate'] else 'B'
            }
        }

        return Response(PipelineComparisonSerializer(data).data)


# ==================== ADVANCED REPORTS VIEW ====================

class AdvancedReportsView(APIView):
    """
    Executive reporting endpoints.

    Provides:
    - Recruiting funnel report
    - DEI metrics
    - Cost per hire analysis
    - Time to fill metrics
    - Source quality analysis
    - Recruiter performance metrics
    """
    permission_classes = [permissions.IsAuthenticated, IsTenantMember, IsRecruiterOrHiringManager]
    throttle_classes = [SensitiveOperationThrottle]

    def get(self, request, report_type):
        """Generate the requested report."""
        if report_type == 'recruiting-funnel':
            return self._recruiting_funnel(request)
        elif report_type == 'dei':
            return self._dei_metrics(request)
        elif report_type == 'cost-per-hire':
            return self._cost_per_hire(request)
        elif report_type == 'time-to-fill':
            return self._time_to_fill(request)
        elif report_type == 'source-quality':
            return self._source_quality(request)
        elif report_type == 'recruiter-performance':
            return self._recruiter_performance(request)
        else:
            return Response(
                {'error': f'Unknown report type: {report_type}'},
                status=status.HTTP_400_BAD_REQUEST
            )

    def _get_date_range(self, request):
        """Parse date range from request."""
        days = int(request.query_params.get('days', 30))
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        return start_date, end_date

    def _recruiting_funnel(self, request):
        """Generate recruiting funnel report."""
        start_date, end_date = self._get_date_range(request)

        applications = Application.objects.for_current_tenant().filter(
            applied_at__gte=start_date,
            applied_at__lte=end_date
        )

        total = applications.count()

        # Define funnel stages
        funnel_stages = [
            {'name': 'Applied', 'count': total},
            {'name': 'Screened', 'count': applications.exclude(status='new').count()},
            {'name': 'Interviewed', 'count': applications.filter(
                status__in=['interviewing', 'offer_pending', 'offer_extended', 'hired']
            ).count()},
            {'name': 'Offer Made', 'count': applications.filter(
                status__in=['offer_extended', 'hired']
            ).count()},
            {'name': 'Hired', 'count': applications.filter(status='hired').count()},
        ]

        # Calculate conversion rates
        conversion_rates = {}
        for i in range(len(funnel_stages) - 1):
            prev_count = funnel_stages[i]['count']
            next_count = funnel_stages[i + 1]['count']
            rate = (next_count / prev_count * 100) if prev_count > 0 else 0
            conversion_rates[f"{funnel_stages[i]['name']}_to_{funnel_stages[i+1]['name']}"] = round(rate, 2)

        # Identify drop-off points
        drop_off_points = []
        for i in range(len(funnel_stages) - 1):
            drop = funnel_stages[i]['count'] - funnel_stages[i + 1]['count']
            drop_rate = (drop / funnel_stages[i]['count'] * 100) if funnel_stages[i]['count'] > 0 else 0
            drop_off_points.append({
                'stage': funnel_stages[i]['name'],
                'drop_count': drop,
                'drop_rate': round(drop_rate, 2)
            })

        data = {
            'period_start': start_date,
            'period_end': end_date,
            'total_applications': total,
            'funnel_stages': funnel_stages,
            'conversion_rates': conversion_rates,
            'drop_off_points': drop_off_points
        }

        return Response(RecruitingFunnelSerializer(data).data)

    def _dei_metrics(self, request):
        """Generate DEI metrics report."""
        start_date, end_date = self._get_date_range(request)

        applications = Application.objects.for_current_tenant().filter(
            applied_at__gte=start_date,
            applied_at__lte=end_date
        ).select_related('candidate')

        total = applications.count()

        # Source diversity
        source_counts = {}
        for app in applications:
            source = app.candidate.source
            source_counts[source] = source_counts.get(source, 0) + 1

        source_diversity = {
            source: {
                'count': count,
                'percentage': round(count / total * 100, 2) if total > 0 else 0
            }
            for source, count in source_counts.items()
        }

        # Hiring rate by source
        hiring_rate_by_source = {}
        for source in source_counts.keys():
            source_apps = applications.filter(candidate__source=source)
            hired = source_apps.filter(status='hired').count()
            total_source = source_apps.count()
            hiring_rate_by_source[source] = round(
                (hired / total_source * 100) if total_source > 0 else 0, 2
            )

        # Stage progression (simplified)
        stage_progression = {}

        # Recommendations
        recommendations = []
        if len(source_counts) < 3:
            recommendations.append("Consider diversifying recruitment sources")

        # Check for imbalanced hiring rates
        rates = list(hiring_rate_by_source.values())
        if rates and max(rates) - min(rates) > 20:
            recommendations.append("Review interview process for potential bias")

        data = {
            'period_start': start_date,
            'period_end': end_date,
            'total_applications': total,
            'source_diversity': source_diversity,
            'stage_progression_equity': stage_progression,
            'hiring_rate_by_source': hiring_rate_by_source,
            'recommendations': recommendations
        }

        return Response(DEIMetricsSerializer(data).data)

    def _cost_per_hire(self, request):
        """Generate cost per hire analysis."""
        start_date, end_date = self._get_date_range(request)

        # Note: Cost data would typically come from finance integration
        # This is a simplified example
        hires = Application.objects.for_current_tenant().filter(
            status='hired',
            hired_at__gte=start_date,
            hired_at__lte=end_date
        ).select_related('job', 'candidate')

        total_hires = hires.count()

        # Simulated cost data (in real implementation, pull from actual cost tracking)
        estimated_cost_per_hire = 5000  # Default estimate
        total_cost = total_hires * estimated_cost_per_hire

        # Cost by source
        cost_by_source = {}
        source_costs = {
            'referral': 1000,
            'career_page': 500,
            'linkedin': 8000,
            'indeed': 3000,
            'agency': 15000,
            'direct': 500,
        }
        for hire in hires:
            source = hire.candidate.source
            cost = source_costs.get(source, 5000)
            if source not in cost_by_source:
                cost_by_source[source] = {'hires': 0, 'cost': 0}
            cost_by_source[source]['hires'] += 1
            cost_by_source[source]['cost'] += cost

        # Cost by department
        cost_by_department = {}
        for hire in hires:
            dept = hire.job.team or 'Unknown'
            if dept not in cost_by_department:
                cost_by_department[dept] = {'hires': 0, 'cost': 0}
            cost_by_department[dept]['hires'] += 1
            cost_by_department[dept]['cost'] += estimated_cost_per_hire

        data = {
            'period_start': start_date,
            'period_end': end_date,
            'total_hires': total_hires,
            'total_cost': total_cost,
            'average_cost_per_hire': estimated_cost_per_hire,
            'cost_breakdown': {
                'recruiting_fees': total_cost * 0.4,
                'job_postings': total_cost * 0.2,
                'tools_software': total_cost * 0.15,
                'interviewing': total_cost * 0.15,
                'onboarding': total_cost * 0.1
            },
            'cost_by_source': cost_by_source,
            'cost_by_department': cost_by_department
        }

        return Response(CostPerHireSerializer(data).data)

    def _time_to_fill(self, request):
        """Generate time to fill metrics."""
        start_date, end_date = self._get_date_range(request)

        hires = Application.objects.for_current_tenant().filter(
            status='hired',
            hired_at__gte=start_date,
            hired_at__lte=end_date
        ).select_related('job')

        times_to_fill = []
        time_by_department = {}
        time_by_job_type = {}
        time_by_level = {}

        for hire in hires:
            if hire.hired_at and hire.applied_at:
                days = (hire.hired_at - hire.applied_at).days
                times_to_fill.append(days)

                # By department
                dept = hire.job.team or 'Unknown'
                if dept not in time_by_department:
                    time_by_department[dept] = []
                time_by_department[dept].append(days)

                # By job type
                job_type = hire.job.job_type
                if job_type not in time_by_job_type:
                    time_by_job_type[job_type] = []
                time_by_job_type[job_type].append(days)

                # By experience level
                level = hire.job.experience_level
                if level not in time_by_level:
                    time_by_level[level] = []
                time_by_level[level].append(days)

        # Calculate averages
        avg_time = sum(times_to_fill) / len(times_to_fill) if times_to_fill else 0
        median_time = sorted(times_to_fill)[len(times_to_fill) // 2] if times_to_fill else 0

        time_by_department = {
            k: round(sum(v) / len(v), 1) if v else 0
            for k, v in time_by_department.items()
        }
        time_by_job_type = {
            k: round(sum(v) / len(v), 1) if v else 0
            for k, v in time_by_job_type.items()
        }
        time_by_level = {
            k: round(sum(v) / len(v), 1) if v else 0
            for k, v in time_by_level.items()
        }

        data = {
            'period_start': start_date,
            'period_end': end_date,
            'average_time_to_fill_days': round(avg_time, 1),
            'median_time_to_fill_days': median_time,
            'time_by_department': time_by_department,
            'time_by_job_type': time_by_job_type,
            'time_by_experience_level': time_by_level,
            'time_trend': []  # Would include historical trend data
        }

        return Response(TimeToFillSerializer(data).data)

    def _source_quality(self, request):
        """Generate source effectiveness analysis."""
        start_date, end_date = self._get_date_range(request)

        applications = Application.objects.for_current_tenant().filter(
            applied_at__gte=start_date,
            applied_at__lte=end_date
        ).select_related('candidate')

        sources_data = {}
        for app in applications:
            source = app.candidate.source
            if source not in sources_data:
                sources_data[source] = {
                    'applications': 0,
                    'interviews': 0,
                    'offers': 0,
                    'hires': 0,
                    'total_rating': 0,
                    'rated_count': 0
                }
            sources_data[source]['applications'] += 1

            if app.status in ['interviewing', 'offer_pending', 'offer_extended', 'hired']:
                sources_data[source]['interviews'] += 1
            if app.status in ['offer_extended', 'hired']:
                sources_data[source]['offers'] += 1
            if app.status == 'hired':
                sources_data[source]['hires'] += 1
            if app.overall_rating:
                sources_data[source]['total_rating'] += float(app.overall_rating)
                sources_data[source]['rated_count'] += 1

        # Format sources
        sources = []
        for source, data in sources_data.items():
            apps = data['applications']
            sources.append({
                'source': source,
                'applications': apps,
                'interview_rate': round(data['interviews'] / apps * 100, 2) if apps else 0,
                'offer_rate': round(data['offers'] / apps * 100, 2) if apps else 0,
                'hire_rate': round(data['hires'] / apps * 100, 2) if apps else 0,
                'average_rating': round(
                    data['total_rating'] / data['rated_count'], 2
                ) if data['rated_count'] > 0 else None,
                'quality_score': round(
                    (data['hires'] / apps * 50 + data['interviews'] / apps * 30 +
                     (data['total_rating'] / data['rated_count'] / 5 * 20 if data['rated_count'] else 0)), 2
                ) if apps else 0
            })

        # Sort by quality score
        sources.sort(key=lambda x: x['quality_score'], reverse=True)
        top_source = sources[0]['source'] if sources else 'N/A'

        # Recommendations
        recommendations = []
        if sources:
            best = sources[0]
            if best['quality_score'] > 50:
                recommendations.append(f"Increase investment in {best['source']} - highest quality source")
            worst = sources[-1]
            if worst['quality_score'] < 20:
                recommendations.append(f"Review ROI of {worst['source']} - low quality conversions")

        data = {
            'period_start': start_date,
            'period_end': end_date,
            'sources': sources,
            'top_performing_source': top_source,
            'recommendations': recommendations
        }

        return Response(SourceQualitySerializer(data).data)

    def _recruiter_performance(self, request):
        """Generate recruiter performance metrics."""
        start_date, end_date = self._get_date_range(request)

        # Get jobs with recruiters
        jobs = JobPosting.objects.for_current_tenant().filter(
            recruiter__isnull=False
        ).select_related('recruiter')

        recruiter_data = {}
        for job in jobs:
            recruiter_id = job.recruiter_id
            if recruiter_id not in recruiter_data:
                recruiter_data[recruiter_id] = {
                    'recruiter_name': f"{job.recruiter.first_name} {job.recruiter.last_name}",
                    'jobs_managed': 0,
                    'applications': 0,
                    'interviews': 0,
                    'offers': 0,
                    'hires': 0,
                    'time_to_fill': []
                }
            recruiter_data[recruiter_id]['jobs_managed'] += 1

            # Get applications for this job in the period
            apps = Application.objects.filter(
                job=job,
                applied_at__gte=start_date,
                applied_at__lte=end_date
            )

            for app in apps:
                recruiter_data[recruiter_id]['applications'] += 1
                if app.status in ['interviewing', 'offer_pending', 'offer_extended', 'hired']:
                    recruiter_data[recruiter_id]['interviews'] += 1
                if app.status in ['offer_extended', 'hired']:
                    recruiter_data[recruiter_id]['offers'] += 1
                if app.status == 'hired':
                    recruiter_data[recruiter_id]['hires'] += 1
                    if app.hired_at and app.applied_at:
                        recruiter_data[recruiter_id]['time_to_fill'].append(
                            (app.hired_at - app.applied_at).days
                        )

        # Format recruiter metrics
        recruiters = []
        for recruiter_id, data in recruiter_data.items():
            ttf = data['time_to_fill']
            avg_ttf = sum(ttf) / len(ttf) if ttf else None
            apps = data['applications']

            recruiters.append({
                'recruiter_id': recruiter_id,
                'recruiter_name': data['recruiter_name'],
                'jobs_managed': data['jobs_managed'],
                'applications_processed': apps,
                'interviews_scheduled': data['interviews'],
                'offers_made': data['offers'],
                'hires': data['hires'],
                'conversion_rate': round(data['hires'] / apps * 100, 2) if apps else 0,
                'average_time_to_fill_days': round(avg_ttf, 1) if avg_ttf else None
            })

        # Calculate team averages
        team_total_apps = sum(r['applications_processed'] for r in recruiters)
        team_total_hires = sum(r['hires'] for r in recruiters)
        team_averages = {
            'applications_per_recruiter': round(
                team_total_apps / len(recruiters), 1
            ) if recruiters else 0,
            'hires_per_recruiter': round(
                team_total_hires / len(recruiters), 1
            ) if recruiters else 0,
            'team_conversion_rate': round(
                team_total_hires / team_total_apps * 100, 2
            ) if team_total_apps else 0
        }

        # Rankings
        rankings = sorted(recruiters, key=lambda x: x['hires'], reverse=True)
        for i, r in enumerate(rankings):
            r['rank'] = i + 1

        data = {
            'period_start': start_date,
            'period_end': end_date,
            'recruiters': recruiters,
            'team_averages': team_averages,
            'rankings': rankings
        }

        return Response(RecruiterPerformanceSerializer(data).data)
