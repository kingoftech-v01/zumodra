"""
Projects API Views - REST API endpoints.

This module provides REST API views using Django Rest Framework:
- ViewSets for CRUD operations
- Custom actions for specific business logic
- Filtering, search, and pagination
- Permission-based access control

All views return JSON responses.
API URL namespace: api:v1:projects:*
"""

from rest_framework import viewsets, status, filters, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from django_filters.rest_framework import DjangoFilterBackend
from django.utils import timezone
from django.db.models import Q, Count

from ..models import (
    ProjectCategory,
    ProjectProvider,
    Project,
    ProjectProposal,
    ProjectContract,
    ProjectMilestone,
    ProjectDeliverable,
    ProjectReview
)
from .serializers import (
    ProjectCategorySerializer,
    ProjectProviderSerializer,
    ProjectListSerializer,
    ProjectSerializer,
    ProjectCreateSerializer,
    ProjectProposalListSerializer,
    ProjectProposalSerializer,
    ProjectProposalCreateSerializer,
    ProjectContractSerializer,
    ProjectMilestoneSerializer,
    ProjectDeliverableSerializer,
    ProjectReviewSerializer
)


# ============================================================================
# PROJECT CATEGORY VIEWSET
# ============================================================================

class ProjectCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for project categories (read-only).

    Provides:
    - list: GET /api/v1/projects/categories/
    - retrieve: GET /api/v1/projects/categories/{id}/
    - tree: GET /api/v1/projects/categories/tree/ (hierarchical structure)

    Filtering:
    - ?parent=<id> - Filter by parent category
    - ?search=keyword - Search category names

    Ordering:
    - ?ordering=display_order
    - ?ordering=name
    """

    queryset = ProjectCategory.objects.all()
    serializer_class = ProjectCategorySerializer
    permission_classes = [permissions.AllowAny]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['parent']
    search_fields = ['name', 'description']
    ordering_fields = ['display_order', 'name', 'project_count']
    ordering = ['display_order', 'name']

    @action(detail=False, methods=['get'])
    def tree(self, request):
        """
        Get hierarchical category tree.

        GET /api/v1/projects/categories/tree/

        Returns:
            200: Hierarchical category structure
        """
        # Get root categories (no parent)
        root_categories = ProjectCategory.objects.filter(
            parent__isnull=True
        ).order_by('display_order', 'name')

        serializer = self.get_serializer(root_categories, many=True)
        return Response(serializer.data)


# ============================================================================
# PROJECT PROVIDER VIEWSET
# ============================================================================

class ProjectProviderViewSet(viewsets.ModelViewSet):
    """
    ViewSet for project providers.

    Provides:
    - list: GET /api/v1/projects/providers/
    - retrieve: GET /api/v1/projects/providers/{uuid}/
    - create: POST /api/v1/projects/providers/
    - update: PUT /api/v1/projects/providers/{uuid}/
    - partial_update: PATCH /api/v1/projects/providers/{uuid}/
    - destroy: DELETE /api/v1/projects/providers/{uuid}/
    - stats: GET /api/v1/projects/providers/{uuid}/stats/

    Filtering:
    - ?is_active=true
    - ?is_accepting_projects=true
    - ?is_verified=true
    - ?country=Canada
    - ?remote_only=true

    Search:
    - ?search=keyword (searches name, description, skills)

    Ordering:
    - ?ordering=-average_rating
    - ?ordering=-completed_projects
    - ?ordering=created_at
    """

    queryset = ProjectProvider.objects.all()
    serializer_class = ProjectProviderSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = [
        'is_active',
        'is_accepting_projects',
        'is_verified',
        'country',
        'remote_only'
    ]
    search_fields = ['name', 'description', 'skills', 'tagline']
    ordering_fields = [
        'created_at',
        'average_rating',
        'completed_projects',
        'total_earnings'
    ]
    ordering = ['-average_rating', '-completed_projects']
    lookup_field = 'uuid'

    def perform_create(self, serializer):
        """Set tenant from request."""
        serializer.save(tenant=self.request.tenant)

    @action(detail=True, methods=['get'])
    def stats(self, request, uuid=None):
        """
        Get detailed statistics for provider.

        GET /api/v1/projects/providers/{uuid}/stats/

        Returns:
            200: Provider statistics
        """
        provider = self.get_object()

        stats = {
            'total_proposals': provider.proposals.count(),
            'accepted_proposals': provider.proposals.filter(status='ACCEPTED').count(),
            'active_projects': provider.assigned_projects.filter(
                status__in=['IN_PROGRESS', 'REVIEW']
            ).count(),
            'completed_projects': provider.completed_projects,
            'total_earnings': float(provider.total_earnings),
            'average_rating': float(provider.average_rating) if provider.average_rating else None,
            'total_reviews': provider.total_reviews,
            'can_accept_new_project': provider.can_accept_new_project,
        }

        return Response(stats)


# ============================================================================
# PROJECT VIEWSET
# ============================================================================

class ProjectViewSet(viewsets.ModelViewSet):
    """
    ViewSet for projects.

    Provides:
    - list: GET /api/v1/projects/projects/
    - retrieve: GET /api/v1/projects/projects/{uuid}/
    - create: POST /api/v1/projects/projects/
    - update: PUT /api/v1/projects/projects/{uuid}/
    - partial_update: PATCH /api/v1/projects/projects/{uuid}/
    - destroy: DELETE /api/v1/projects/projects/{uuid}/

    Custom actions:
    - publish: POST /api/v1/projects/projects/{uuid}/publish/
    - unpublish: POST /api/v1/projects/projects/{uuid}/unpublish/
    - close: POST /api/v1/projects/projects/{uuid}/close/
    - stats: GET /api/v1/projects/projects/stats/

    Filtering:
    - ?status=OPEN
    - ?category=<id>
    - ?budget_type=FIXED
    - ?experience_level=MID
    - ?location_type=REMOTE
    - ?is_published=true

    Search:
    - ?search=keyword (searches title, description, required_skills)

    Ordering:
    - ?ordering=-published_at
    - ?ordering=-created_at
    - ?ordering=deadline
    - ?ordering=-budget_max
    """

    permission_classes = [IsAuthenticatedOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = [
        'status',
        'category',
        'budget_type',
        'experience_level',
        'location_type',
        'is_published'
    ]
    search_fields = ['title', 'description', 'required_skills']
    ordering_fields = [
        'created_at',
        'published_at',
        'deadline',
        'budget_max',
        'budget_min'
    ]
    ordering = ['-created_at']
    lookup_field = 'uuid'

    def get_queryset(self):
        """Return projects for current tenant."""
        return Project.objects.filter(
            tenant=self.request.tenant
        ).select_related('category', 'assigned_provider')

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == 'list':
            return ProjectListSerializer
        elif self.action == 'create':
            return ProjectCreateSerializer
        return ProjectSerializer

    def perform_create(self, serializer):
        """Set tenant from request."""
        serializer.save(tenant=self.request.tenant)

    @action(detail=True, methods=['post'])
    def publish(self, request, uuid=None):
        """
        Publish project to make available for proposals.

        POST /api/v1/projects/projects/{uuid}/publish/

        Returns:
            200: Project published successfully
            400: Project cannot be published
        """
        project = self.get_object()

        # Validate project is complete enough to publish
        if not project.title or not project.description:
            return Response(
                {'error': 'Project must have title and description to publish'},
                status=status.HTTP_400_BAD_REQUEST
            )

        project.publish()
        serializer = self.get_serializer(project)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def unpublish(self, request, uuid=None):
        """
        Unpublish project.

        POST /api/v1/projects/projects/{uuid}/unpublish/

        Returns:
            200: Project unpublished successfully
        """
        project = self.get_object()
        project.unpublish()
        serializer = self.get_serializer(project)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def close(self, request, uuid=None):
        """
        Close project to new proposals.

        POST /api/v1/projects/projects/{uuid}/close/

        Returns:
            200: Project closed successfully
        """
        project = self.get_object()
        project.status = Project.Status.DRAFT
        project.is_published = False
        project.save(update_fields=['status', 'is_published'])

        serializer = self.get_serializer(project)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """
        Get overall statistics for projects.

        GET /api/v1/projects/projects/stats/

        Returns:
            200: Statistics object with counts and aggregates
        """
        queryset = self.get_queryset()

        stats = {
            'total_count': queryset.count(),
            'by_status': dict(
                queryset.values('status')
                .annotate(count=Count('id'))
                .values_list('status', 'count')
            ),
            'published_count': queryset.filter(is_published=True).count(),
            'open_count': queryset.filter(status='OPEN').count(),
            'in_progress_count': queryset.filter(status='IN_PROGRESS').count(),
            'completed_count': queryset.filter(status='COMPLETED').count(),
        }

        return Response(stats)


# ============================================================================
# PROJECT PROPOSAL VIEWSET
# ============================================================================

class ProjectProposalViewSet(viewsets.ModelViewSet):
    """
    ViewSet for project proposals.

    Provides:
    - list: GET /api/v1/projects/proposals/
    - retrieve: GET /api/v1/projects/proposals/{uuid}/
    - create: POST /api/v1/projects/proposals/
    - update: PUT /api/v1/projects/proposals/{uuid}/
    - partial_update: PATCH /api/v1/projects/proposals/{uuid}/
    - destroy: DELETE /api/v1/projects/proposals/{uuid}/

    Custom actions:
    - submit: POST /api/v1/projects/proposals/{uuid}/submit/
    - accept: POST /api/v1/projects/proposals/{uuid}/accept/
    - reject: POST /api/v1/projects/proposals/{uuid}/reject/

    Filtering:
    - ?project=<id>
    - ?provider=<id>
    - ?status=SUBMITTED

    Ordering:
    - ?ordering=-submitted_at
    - ?ordering=proposed_budget
    """

    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['project', 'provider', 'status']
    ordering_fields = ['submitted_at', 'proposed_budget', 'created_at']
    ordering = ['-submitted_at']
    lookup_field = 'uuid'

    def get_queryset(self):
        """Return proposals based on user role."""
        user = self.request.user

        # Tenant members see proposals for their projects
        if hasattr(self.request, 'tenant'):
            return ProjectProposal.objects.filter(
                project__tenant=self.request.tenant
            ).select_related('project', 'provider')

        # Providers see their own proposals
        return ProjectProposal.objects.filter(
            provider__tenant__in=user.tenants.all()
        ).select_related('project', 'provider')

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == 'list':
            return ProjectProposalListSerializer
        elif self.action == 'create':
            return ProjectProposalCreateSerializer
        return ProjectProposalSerializer

    @action(detail=True, methods=['post'])
    def submit(self, request, uuid=None):
        """
        Submit proposal for review.

        POST /api/v1/projects/proposals/{uuid}/submit/

        Returns:
            200: Proposal submitted successfully
            400: Proposal cannot be submitted
        """
        proposal = self.get_object()

        if proposal.status != ProjectProposal.Status.DRAFT:
            return Response(
                {'error': 'Only draft proposals can be submitted'},
                status=status.HTTP_400_BAD_REQUEST
            )

        proposal.submit()
        serializer = self.get_serializer(proposal)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def accept(self, request, uuid=None):
        """
        Accept proposal and assign project to provider.

        POST /api/v1/projects/proposals/{uuid}/accept/

        Returns:
            200: Proposal accepted successfully
            403: No permission
            400: Proposal cannot be accepted
        """
        proposal = self.get_object()

        # Only project owner can accept proposals
        if proposal.project.tenant != self.request.tenant:
            return Response(
                {'error': 'Only project owner can accept proposals'},
                status=status.HTTP_403_FORBIDDEN
            )

        if proposal.status != ProjectProposal.Status.SUBMITTED:
            return Response(
                {'error': 'Only submitted proposals can be accepted'},
                status=status.HTTP_400_BAD_REQUEST
            )

        proposal.accept()
        serializer = self.get_serializer(proposal)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def reject(self, request, uuid=None):
        """
        Reject proposal with reason.

        POST /api/v1/projects/proposals/{uuid}/reject/

        Request body:
            {"reason": "Rejection reason"}

        Returns:
            200: Proposal rejected successfully
            403: No permission
        """
        proposal = self.get_object()

        # Only project owner can reject proposals
        if proposal.project.tenant != self.request.tenant:
            return Response(
                {'error': 'Only project owner can reject proposals'},
                status=status.HTTP_403_FORBIDDEN
            )

        reason = request.data.get('reason', '')
        proposal.reject(reason=reason)

        serializer = self.get_serializer(proposal)
        return Response(serializer.data)


# ============================================================================
# OTHER VIEWSETS
# ============================================================================

class ProjectContractViewSet(viewsets.ModelViewSet):
    """ViewSet for project contracts."""

    queryset = ProjectContract.objects.all()
    serializer_class = ProjectContractSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['project', 'provider', 'status']
    ordering = ['-created_at']
    lookup_field = 'uuid'


class ProjectMilestoneViewSet(viewsets.ModelViewSet):
    """ViewSet for project milestones."""

    queryset = ProjectMilestone.objects.all()
    serializer_class = ProjectMilestoneSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['project', 'contract', 'status']
    ordering = ['project', 'order']
    lookup_field = 'uuid'


class ProjectDeliverableViewSet(viewsets.ModelViewSet):
    """ViewSet for project deliverables."""

    queryset = ProjectDeliverable.objects.all()
    serializer_class = ProjectDeliverableSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['project', 'milestone', 'is_approved']
    ordering = ['-submitted_at']
    lookup_field = 'uuid'


class ProjectReviewViewSet(viewsets.ModelViewSet):
    """ViewSet for project reviews."""

    queryset = ProjectReview.objects.all()
    serializer_class = ProjectReviewSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['project', 'reviewer_type', 'rating', 'is_public']
    ordering = ['-created_at']
    lookup_field = 'uuid'
