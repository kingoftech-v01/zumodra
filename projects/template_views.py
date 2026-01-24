"""
Projects Frontend Views - HTML template views.

This module provides template-based views for human users:
- Project browsing and detail pages
- Project creation and management
- Proposal submission and management
- Milestone tracking
- Deliverable uploads
- Review submission

All views render HTML templates using Django's render().
Uses HTMX for dynamic interactions and Alpine.js for client-side reactivity.

URL Namespace: frontend:projects:*
"""

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

from .models import (
    Project,
    ProjectCategory,
    ProjectProvider,
    ProjectProposal,
    ProjectMilestone,
    ProjectDeliverable,
    ProjectReview
)
from .forms import (
    ProjectForm,
    ProjectFilterForm,
    ProjectProposalForm,
    ProjectMilestoneForm,
    ProjectDeliverableForm,
    ProjectReviewForm
)


# ============================================================================
# PROJECT BROWSING VIEWS
# ============================================================================

@login_required
def project_list(request):
    """
    List all projects for current tenant with filtering and search.

    Features:
    - Search by title/description
    - Filter by status/category/budget/location
    - Sort by created_at, deadline, budget
    - Pagination (20 projects per page)

    Template: projects/project_list.html
    Context:
        - projects: Paginated queryset
        - filter_form: ProjectFilterForm instance
        - total_count: Total projects matching filters
    """
    # Get query parameters
    search = request.GET.get('search', '').strip()
    status_filter = request.GET.get('status')
    category_filter = request.GET.get('category')
    budget_type_filter = request.GET.get('budget_type')
    location_type_filter = request.GET.get('location_type')
    sort_by = request.GET.get('sort', '-created_at')
    page = request.GET.get('page', 1)

    # Base queryset - current tenant only
    projects = Project.objects.filter(
        tenant=request.tenant
    ).select_related('category', 'assigned_provider').annotate(
        proposal_count_annotated=Count('proposals')
    )

    # Apply search
    if search:
        projects = projects.filter(
            Q(title__icontains=search) |
            Q(description__icontains=search) |
            Q(required_skills__icontains=search)
        )

    # Apply filters
    if status_filter:
        projects = projects.filter(status=status_filter)

    if category_filter:
        projects = projects.filter(category_id=category_filter)

    if budget_type_filter:
        projects = projects.filter(budget_type=budget_type_filter)

    if location_type_filter:
        projects = projects.filter(location_type=location_type_filter)

    # Apply sorting
    valid_sorts = [
        'created_at', '-created_at',
        'published_at', '-published_at',
        'deadline', '-deadline',
        'budget_max', '-budget_max',
        'title', '-title'
    ]
    if sort_by in valid_sorts:
        projects = projects.order_by(sort_by)
    else:
        projects = projects.order_by('-created_at')

    # Pagination
    paginator = Paginator(projects, 20)
    projects_page = paginator.get_page(page)

    # Filter form
    filter_form = ProjectFilterForm(request.GET)

    # Stats
    stats = {
        'total': Project.objects.filter(tenant=request.tenant).count(),
        'open': Project.objects.filter(tenant=request.tenant, status='OPEN').count(),
        'in_progress': Project.objects.filter(tenant=request.tenant, status='IN_PROGRESS').count(),
        'completed': Project.objects.filter(tenant=request.tenant, status='COMPLETED').count(),
    }

    context = {
        'projects': projects_page,
        'filter_form': filter_form,
        'total_count': paginator.count,
        'search': search,
        'stats': stats,
        'page_title': _('Projects'),
        'meta_description': _('Manage your project missions'),
    }

    return render(request, 'projects/project_list.html', context)


@login_required
def project_detail(request, uuid):
    """
    Display detailed information for a single project.

    Shows:
    - All project details
    - Proposals (if project owner)
    - Milestones
    - Deliverables
    - Reviews
    - Action buttons (edit, publish, close, etc.)

    Template: projects/project_detail.html
    Context:
        - project: Project instance
        - proposals: Related proposals (if owner)
        - milestones: Project milestones
        - can_edit: Permission check
        - can_manage: Permission check
    """
    project = get_object_or_404(
        Project.objects.select_related('category', 'assigned_provider', 'tenant'),
        uuid=uuid,
        tenant=request.tenant
    )

    # Permission checks
    can_edit = request.user.is_staff or request.user.has_perm('projects.change_project')
    can_manage = can_edit

    # Get related data
    proposals = None
    if can_manage:
        proposals = project.proposals.select_related('provider').order_by('-submitted_at')

    milestones = project.milestones.order_by('order')
    deliverables = project.deliverables.select_related('milestone', 'submitted_by').order_by('-submitted_at')[:10]
    reviews = project.reviews.filter(is_public=True).order_by('-created_at')[:5]

    context = {
        'project': project,
        'proposals': proposals,
        'milestones': milestones,
        'deliverables': deliverables,
        'reviews': reviews,
        'can_edit': can_edit,
        'can_manage': can_manage,
        'page_title': project.title,
        'meta_description': project.short_description or project.description[:160],
    }

    return render(request, 'projects/project_detail.html', context)


# ============================================================================
# PROJECT MANAGEMENT VIEWS
# ============================================================================

@login_required
def project_create(request):
    """
    Create a new project.

    GET: Display empty form
    POST: Validate and save new project

    Template: projects/project_form.html
    Context:
        - form: ProjectForm instance
        - form_title: "Create Project"
        - submit_text: "Create Project"
    """
    if request.method == 'POST':
        form = ProjectForm(request.POST)
        if form.is_valid():
            project = form.save(commit=False)
            project.tenant = request.tenant
            project.save()
            form.save_m2m()

            messages.success(request, _('Project created successfully'))
            return redirect('projects:frontend:project_detail', uuid=project.uuid)
    else:
        form = ProjectForm()

    context = {
        'form': form,
        'form_title': _('Create New Project'),
        'submit_text': _('Create Project'),
        'cancel_url': 'projects:frontend:project_list',
        'page_title': _('Create Project'),
    }

    return render(request, 'projects/project_form.html', context)


@login_required
def project_update(request, uuid):
    """
    Update an existing project.

    GET: Display pre-filled form
    POST: Validate and save changes

    Template: projects/project_form.html
    Context:
        - form: ProjectForm with current data
        - project: Project being edited
        - form_title: "Edit Project"
    """
    project = get_object_or_404(Project, uuid=uuid, tenant=request.tenant)

    # Permission check
    if not (request.user.is_staff or request.user.has_perm('projects.change_project')):
        messages.error(request, _('You do not have permission to edit this project'))
        return redirect('projects:frontend:project_detail', uuid=uuid)

    if request.method == 'POST':
        form = ProjectForm(request.POST, instance=project)
        if form.is_valid():
            form.save()
            messages.success(request, _('Project updated successfully'))
            return redirect('projects:frontend:project_detail', uuid=project.uuid)
    else:
        form = ProjectForm(instance=project)

    context = {
        'form': form,
        'project': project,
        'form_title': _('Edit Project'),
        'submit_text': _('Save Changes'),
        'cancel_url': 'projects:frontend:project_detail',
        'page_title': _('Edit Project'),
    }

    return render(request, 'projects/project_form.html', context)


@login_required
def project_delete(request, uuid):
    """
    Delete a project (with confirmation).

    GET: Display confirmation page
    POST: Delete project and redirect

    Template: projects/project_confirm_delete.html
    Context:
        - project: Project to be deleted
        - proposal_count: Count of proposals
        - milestone_count: Count of milestones
    """
    project = get_object_or_404(Project, uuid=uuid, tenant=request.tenant)

    # Permission check
    if not (request.user.is_staff or request.user.has_perm('projects.delete_project')):
        messages.error(request, _('You do not have permission to delete this project'))
        return redirect('projects:frontend:project_detail', uuid=uuid)

    if request.method == 'POST':
        project_title = project.title
        project.delete()
        messages.success(request, _('Project "%(title)s" deleted successfully') % {'title': project_title})
        return redirect('projects:frontend:project_list')

    # Get related counts
    proposal_count = project.proposals.count()
    milestone_count = project.milestones.count()

    context = {
        'project': project,
        'proposal_count': proposal_count,
        'milestone_count': milestone_count,
        'page_title': _('Delete Project'),
    }

    return render(request, 'projects/project_confirm_delete.html', context)


# ============================================================================
# PROJECT ACTION VIEWS
# ============================================================================

@login_required
def project_publish(request, uuid):
    """
    Publish project to make available for proposals.

    POST only: Publishes project

    Redirects to: project_detail
    """
    project = get_object_or_404(Project, uuid=uuid, tenant=request.tenant)

    # Permission check
    if not (request.user.is_staff or request.user.has_perm('projects.change_project')):
        messages.error(request, _('You do not have permission to publish this project'))
        return redirect('projects:frontend:project_detail', uuid=uuid)

    if request.method == 'POST':
        # Validate project is complete
        if not project.title or not project.description:
            messages.error(request, _('Project must have title and description to publish'))
        else:
            project.publish()
            messages.success(request, _('Project published successfully'))

    return redirect('projects:frontend:project_detail', uuid=project.uuid)


@login_required
def project_unpublish(request, uuid):
    """
    Unpublish project.

    POST only: Unpublishes project

    Redirects to: project_detail
    """
    project = get_object_or_404(Project, uuid=uuid, tenant=request.tenant)

    # Permission check
    if not (request.user.is_staff or request.user.has_perm('projects.change_project')):
        messages.error(request, _('You do not have permission to unpublish this project'))
        return redirect('projects:frontend:project_detail', uuid=uuid)

    if request.method == 'POST':
        project.unpublish()
        messages.success(request, _('Project unpublished successfully'))

    return redirect('projects:frontend:project_detail', uuid=project.uuid)


# ============================================================================
# PROPOSAL VIEWS
# ============================================================================

@login_required
def proposal_list(request):
    """
    List all proposals for current user/tenant.

    Template: projects/proposal_list.html
    Context:
        - proposals: Paginated queryset
        - filter_status: Status filter
    """
    status_filter = request.GET.get('status')
    page = request.GET.get('page', 1)

    # Base queryset - proposals for tenant's projects
    proposals = ProjectProposal.objects.filter(
        project__tenant=request.tenant
    ).select_related('project', 'provider').order_by('-submitted_at')

    # Apply status filter
    if status_filter:
        proposals = proposals.filter(status=status_filter)

    # Pagination
    paginator = Paginator(proposals, 20)
    proposals_page = paginator.get_page(page)

    # Stats
    stats = {
        'total': ProjectProposal.objects.filter(project__tenant=request.tenant).count(),
        'submitted': ProjectProposal.objects.filter(project__tenant=request.tenant, status='SUBMITTED').count(),
        'accepted': ProjectProposal.objects.filter(project__tenant=request.tenant, status='ACCEPTED').count(),
    }

    context = {
        'proposals': proposals_page,
        'total_count': paginator.count,
        'status_filter': status_filter,
        'stats': stats,
        'page_title': _('Proposals'),
    }

    return render(request, 'projects/proposal_list.html', context)


@login_required
def proposal_detail(request, uuid):
    """
    Display detailed proposal information.

    Template: projects/proposal_detail.html
    Context:
        - proposal: ProjectProposal instance
        - can_accept: Permission to accept
        - can_reject: Permission to reject
    """
    proposal = get_object_or_404(
        ProjectProposal.objects.select_related('project', 'provider', 'freelancer_profile'),
        uuid=uuid
    )

    # Permission check - must be project owner or proposal owner
    is_project_owner = proposal.project.tenant == request.tenant
    is_proposal_owner = proposal.provider.tenant == request.tenant

    if not (is_project_owner or is_proposal_owner):
        messages.error(request, _('You do not have permission to view this proposal'))
        return redirect('projects:frontend:project_list')

    # Permission for actions
    can_accept = is_project_owner and proposal.status == 'SUBMITTED'
    can_reject = is_project_owner and proposal.status == 'SUBMITTED'

    context = {
        'proposal': proposal,
        'can_accept': can_accept,
        'can_reject': can_reject,
        'is_project_owner': is_project_owner,
        'is_proposal_owner': is_proposal_owner,
        'page_title': f"Proposal for {proposal.project.title}",
    }

    return render(request, 'projects/proposal_detail.html', context)


@login_required
def proposal_accept(request, uuid):
    """
    Accept a proposal.

    POST only: Accepts proposal and assigns project

    Redirects to: proposal_detail
    """
    proposal = get_object_or_404(ProjectProposal, uuid=uuid)

    # Permission check
    if proposal.project.tenant != request.tenant:
        messages.error(request, _('Only project owner can accept proposals'))
        return redirect('projects:frontend:proposal_detail', uuid=uuid)

    if request.method == 'POST':
        if proposal.status != 'SUBMITTED':
            messages.error(request, _('Only submitted proposals can be accepted'))
        else:
            proposal.accept()
            messages.success(request, _('Proposal accepted successfully'))

    return redirect('projects:frontend:proposal_detail', uuid=proposal.uuid)


@login_required
def proposal_reject(request, uuid):
    """
    Reject a proposal.

    POST only: Rejects proposal with reason

    Redirects to: proposal_detail
    """
    proposal = get_object_or_404(ProjectProposal, uuid=uuid)

    # Permission check
    if proposal.project.tenant != request.tenant:
        messages.error(request, _('Only project owner can reject proposals'))
        return redirect('projects:frontend:proposal_detail', uuid=uuid)

    if request.method == 'POST':
        reason = request.POST.get('reason', '')
        proposal.reject(reason=reason)
        messages.success(request, _('Proposal rejected'))

    return redirect('projects:frontend:proposal_detail', uuid=proposal.uuid)


# ============================================================================
# MILESTONE VIEWS
# ============================================================================

@login_required
def milestone_list(request, project_uuid):
    """
    List all milestones for a project.

    Template: projects/milestone_list.html
    Context:
        - project: Project instance
        - milestones: Milestone queryset
    """
    project = get_object_or_404(Project, uuid=project_uuid, tenant=request.tenant)
    milestones = project.milestones.order_by('order')

    context = {
        'project': project,
        'milestones': milestones,
        'page_title': f"Milestones - {project.title}",
    }

    return render(request, 'projects/milestone_list.html', context)


@login_required
def milestone_detail(request, uuid):
    """
    Display milestone details.

    Template: projects/milestone_detail.html
    Context:
        - milestone: ProjectMilestone instance
        - deliverables: Related deliverables
    """
    milestone = get_object_or_404(
        ProjectMilestone.objects.select_related('project'),
        uuid=uuid
    )

    # Permission check
    if milestone.project.tenant != request.tenant:
        messages.error(request, _('You do not have permission to view this milestone'))
        return redirect('projects:frontend:project_list')

    deliverables = milestone.deliverables.order_by('-submitted_at')

    context = {
        'milestone': milestone,
        'deliverables': deliverables,
        'page_title': milestone.title,
    }

    return render(request, 'projects/milestone_detail.html', context)


# ============================================================================
# DASHBOARD VIEWS
# ============================================================================

@login_required
def project_dashboard(request):
    """
    Project management dashboard with stats and recent activity.

    Template: projects/dashboard.html
    Context:
        - stats: Aggregate statistics
        - recent_projects: Recent projects
        - pending_proposals: Proposals needing review
        - active_milestones: Upcoming milestones
    """
    tenant = request.tenant

    # Statistics
    stats = {
        'total_projects': Project.objects.filter(tenant=tenant).count(),
        'open_projects': Project.objects.filter(tenant=tenant, status='OPEN').count(),
        'in_progress': Project.objects.filter(tenant=tenant, status='IN_PROGRESS').count(),
        'completed': Project.objects.filter(tenant=tenant, status='COMPLETED').count(),
        'pending_proposals': ProjectProposal.objects.filter(
            project__tenant=tenant,
            status='SUBMITTED'
        ).count(),
    }

    # Recent projects
    recent_projects = Project.objects.filter(
        tenant=tenant
    ).select_related('category').order_by('-created_at')[:5]

    # Pending proposals
    pending_proposals = ProjectProposal.objects.filter(
        project__tenant=tenant,
        status='SUBMITTED'
    ).select_related('project', 'provider').order_by('-submitted_at')[:10]

    # Active milestones (upcoming due dates)
    active_milestones = ProjectMilestone.objects.filter(
        project__tenant=tenant,
        status__in=['PENDING', 'IN_PROGRESS'],
        due_date__gte=timezone.now().date()
    ).select_related('project').order_by('due_date')[:10]

    context = {
        'stats': stats,
        'recent_projects': recent_projects,
        'pending_proposals': pending_proposals,
        'active_milestones': active_milestones,
        'page_title': _('Project Dashboard'),
    }

    return render(request, 'projects/dashboard.html', context)
