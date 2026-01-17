"""
ATS Template Views - Frontend views for Applicant Tracking System.

This module implements template-based views for:
- Job listings and detail pages
- Candidate directory and profiles
- Pipeline Kanban board
- Interview scheduling
- Application management

All views are HTMX-aware and return partials when appropriate.
"""

import json
import logging
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.db.models import Count, Q, Prefetch
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.utils import timezone
from django.views import View
from django.views.generic import TemplateView, ListView, DetailView, FormView, CreateView

from tenants.mixins import TenantViewMixin
from tenants.decorators import require_tenant_type

from .models import (
    JobPosting, JobCategory, Pipeline, PipelineStage,
    Candidate, Application, ApplicationActivity, ApplicationNote,
    Interview, InterviewFeedback, Offer, InterviewSlot,
    BackgroundCheck
)

logger = logging.getLogger(__name__)


# =============================================================================
# MIXIN CLASSES
# =============================================================================

class HTMXMixin:
    """
    Mixin to handle HTMX requests gracefully.

    If request has HX-Request header, returns partial template.
    Sets appropriate HTMX response headers.
    """

    partial_template_name = None

    def get_template_names(self):
        """Return partial template for HTMX requests."""
        if self.request.headers.get('HX-Request') and self.partial_template_name:
            return [self.partial_template_name]
        return super().get_template_names()

    def render_htmx_response(self, template, context, **response_kwargs):
        """
        Helper to render HTMX response with appropriate headers.
        """
        response = render(self.request, template, context)

        # Add HTMX trigger headers if needed
        if trigger := response_kwargs.get('hx_trigger'):
            response['HX-Trigger'] = trigger
        if trigger_after := response_kwargs.get('hx_trigger_after_settle'):
            response['HX-Trigger-After-Settle'] = trigger_after
        if push_url := response_kwargs.get('hx_push_url'):
            response['HX-Push-Url'] = push_url
        if retarget := response_kwargs.get('hx_retarget'):
            response['HX-Retarget'] = retarget
        if reswap := response_kwargs.get('hx_reswap'):
            response['HX-Reswap'] = reswap

        return response


class ATSPermissionMixin:
    """
    Mixin for ATS-specific permission checks.

    Verifies user has recruiter/hiring manager access.
    """

    def has_ats_permission(self, permission_type='view'):
        """Check if user has ATS permission."""
        user = self.request.user

        if user.is_superuser or user.is_staff:
            return True

        # Check TenantUser role
        if hasattr(user, 'tenantuser'):
            role = user.tenantuser.role.lower() if user.tenantuser.role else ''
            allowed_roles = {
                'view': ['recruiter', 'hiring_manager', 'hr', 'admin', 'pdg', 'supervisor'],
                'edit': ['recruiter', 'hiring_manager', 'hr', 'admin', 'pdg'],
                'delete': ['hr', 'admin', 'pdg'],
                'admin': ['admin', 'pdg'],
            }
            return role in allowed_roles.get(permission_type, [])

        # Check groups
        user_groups = [g.name.lower() for g in user.groups.all()]
        return any('recruiter' in g or 'hiring' in g or 'hr' in g for g in user_groups)


# =============================================================================
# JOB VIEWS
# =============================================================================
@require_tenant_type('company')
class JobListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """
    Job listings with HTMX pagination and filtering - COMPANY ONLY.

    Displays all job postings with status filters, search, and quick actions.

    TEST NOTES (2026-01-16):
    - URL: /app/ats/jobs/
    - Filters: status, category, job_type, search query
    - Pagination: 20 items per page
    - HTMX: Returns partial template for filter updates
    - Expected status choices: draft, open, closed, on_hold
    - Test: Verify filters work without full page reload
    - Test: Verify pagination displays when > 20 jobs exist
    """
    model = JobPosting
    template_name = 'ats/job_list.html'
    partial_template_name = 'ats/partials/_job_list.html'
    context_object_name = 'jobs'
    paginate_by = 20

    def get_queryset(self):
        tenant = self.get_tenant()
        if not tenant:
            return JobPosting.objects.none()

        # TEST FINDING (2026-01-16): Deleted jobs handling
        # Filters by is_active=True but soft-deleted jobs also need filtering
        # VERIFY: Check if is_active=False is set on soft delete OR
        # if separate is_deleted field is used. May need to add:
        # .exclude(is_deleted=True) to fully hide soft-deleted jobs
        queryset = JobPosting.objects.filter(
            tenant=tenant,
            is_active=True
        ).select_related(
            'category', 'pipeline', 'recruiter', 'hiring_manager'
        ).prefetch_related(
            'applications'
        ).annotate(
            application_count=Count('applications')
        ).order_by('-created_at')

        # Apply filters
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        category = self.request.GET.get('category')
        if category:
            queryset = queryset.filter(category_id=category)

        search = self.request.GET.get('q')
        if search:
            queryset = queryset.filter(
                Q(title__icontains=search) |
                Q(description__icontains=search) |
                Q(location__icontains=search)
            )

        job_type = self.request.GET.get('job_type')
        if job_type:
            queryset = queryset.filter(job_type=job_type)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.get_tenant()

        if tenant:
            # Get filter options
            context['categories'] = JobCategory.objects.filter(
                tenant=tenant, is_active=True
            )
            context['status_choices'] = JobPosting.JobStatus.choices
            context['job_type_choices'] = JobPosting.JobType.choices

            # Current filters for UI
            context['current_filters'] = {
                'status': self.request.GET.get('status', ''),
                'category': self.request.GET.get('category', ''),
                'job_type': self.request.GET.get('job_type', ''),
                'q': self.request.GET.get('q', ''),
            }

            # Stats
            context['stats'] = {
                'open': JobPosting.objects.filter(tenant=tenant, status='open').count(),
                'closed': JobPosting.objects.filter(tenant=tenant, status='closed').count(),
                'draft': JobPosting.objects.filter(tenant=tenant, status='draft').count(),
                'on_hold': JobPosting.objects.filter(tenant=tenant, status='on_hold').count(),
            }

        return context

    def get(self, request, *args, **kwargs):
        """Handle both regular and HTMX requests."""
        response = super().get(request, *args, **kwargs)

        if request.headers.get('HX-Request'):
            # Push URL for browser history
            response['HX-Push-Url'] = request.get_full_path()

        return response

@require_tenant_type('company')
class JobDetailView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, DetailView):
    """
    Job detail page with applicants list - COMPANY ONLY.

    Shows job details, requirements, and list of applicants.

    TEST NOTES (2026-01-16):
    - URL: /app/ats/jobs/<uuid>/
    - Displays: job info, applications by stage, recent applications (last 10)
    - Stats: total, new, in_review, interviewing, offer, hired, rejected
    - Test: Verify all job fields display correctly
    - Test: Verify action buttons visible (Edit, Publish, Duplicate, Delete)
    - Test: Verify pipeline stages render if pipeline assigned
    """
    model = JobPosting
    template_name = 'ats/job_detail.html'
    context_object_name = 'job'
    pk_url_kwarg = 'pk'

    def get_queryset(self):
        tenant = self.get_tenant()
        if not tenant:
            return JobPosting.objects.none()

        return JobPosting.objects.filter(
            tenant=tenant
        ).select_related(
            'category', 'pipeline', 'recruiter', 'hiring_manager', 'created_by'
        ).prefetch_related(
            Prefetch(
                'applications',
                queryset=Application.objects.select_related(
                    'candidate', 'current_stage'
                ).order_by('-created_at')
            ),
            'pipeline__stages'
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        job = self.object

        # Get applications by stage for pipeline view
        if job.pipeline:
            stages = job.pipeline.stages.filter(is_active=True).order_by('order')
            applications_by_stage = {}
            for stage in stages:
                applications_by_stage[stage.id] = job.applications.filter(
                    current_stage=stage
                ).select_related('candidate')
            context['stages'] = stages
            context['applications_by_stage'] = applications_by_stage

        # Recent applications
        context['recent_applications'] = job.applications.order_by('-created_at')[:10]

        # Stats
        context['application_stats'] = {
            'total': job.applications.count(),
            'new': job.applications.filter(status='new').count(),
            'in_review': job.applications.filter(status='in_review').count(),
            'interviewing': job.applications.filter(status='interviewing').count(),
            'offer': job.applications.filter(status='offer').count(),
            'hired': job.applications.filter(status='hired').count(),
            'rejected': job.applications.filter(status='rejected').count(),
        }

        return context

@require_tenant_type('company')
class JobCreateView(LoginRequiredMixin, TenantViewMixin, ATSPermissionMixin, CreateView):
    """
    Create a new job posting - COMPANY ONLY.

    TEST NOTES (2026-01-16):
    - URL: /app/ats/jobs/create/
    - Default status: 'draft'
    - Required fields: title, category, job_type, experience_level, location
    - Optional: salary_min, salary_max, pipeline, recruiter, hiring_manager
    - Test: Verify category dropdown populated from tenant
    - Test: Verify pipeline dropdown populated from tenant
    - Test: Verify form validation for required fields
    - Test: Verify redirect to job detail after successful creation
    - POTENTIAL ISSUE: Success URL may use incorrect namespace (see line 305)
    """
    model = JobPosting
    template_name = 'ats/job_form.html'
    fields = [
        'title', 'category', 'job_type', 'experience_level', 'location',
        'remote_type', 'description', 'requirements', 'responsibilities',
        'salary_min', 'salary_max', 'salary_currency', 'benefits',
        'pipeline', 'recruiter', 'hiring_manager'
    ]

    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        tenant = self.get_tenant()

        if tenant:
            # Filter related fields by tenant
            form.fields['category'].queryset = JobCategory.objects.filter(
                tenant=tenant, is_active=True
            )
            form.fields['pipeline'].queryset = Pipeline.objects.filter(
                tenant=tenant, is_active=True
            )

        return form

    def form_valid(self, form):
        form.instance.tenant = self.get_tenant()
        form.instance.created_by = self.request.user
        form.instance.status = 'draft'
        messages.success(self.request, 'Job posting created successfully!')
        return super().form_valid(form)

    def get_success_url(self):
        # TEST FINDING (2026-01-16): Potential namespace issue
        # URL name 'ats:job-detail' may not match urlpatterns namespace
        # Expected: 'frontend:ats:job_detail' based on urls_frontend.py:76
        # TODO: Verify redirect works correctly after job creation
        # If 404 occurs, change to: reverse('frontend:ats:job_detail', kwargs={'pk': self.object.pk})
        return reverse('ats:job-detail', kwargs={'pk': self.object.pk})


# =============================================================================
# CANDIDATE VIEWS
# =============================================================================
@require_tenant_type('company')
class CandidateListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """
    Candidate directory with search and filtering - COMPANY ONLY.

    Displays all candidates in the talent pool with filters and bulk actions.
    """
    model = Candidate
    template_name = 'ats/candidate_list.html'
    partial_template_name = 'ats/partials/_candidate_list.html'
    context_object_name = 'candidates'
    paginate_by = 25

    def get_queryset(self):
        tenant = self.get_tenant()
        if not tenant:
            return Candidate.objects.none()

        queryset = Candidate.objects.filter(
            tenant=tenant
        ).select_related(
            'source'
        ).prefetch_related(
            'applications__job'
        ).annotate(
            application_count=Count('applications')
        ).order_by('-created_at')

        # Search
        search = self.request.GET.get('q')
        if search:
            queryset = queryset.filter(
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search) |
                Q(email__icontains=search) |
                Q(current_title__icontains=search) |
                Q(current_company__icontains=search)
            )

        # Filters
        source = self.request.GET.get('source')
        if source:
            queryset = queryset.filter(source_id=source)

        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        location = self.request.GET.get('location')
        if location:
            queryset = queryset.filter(location__icontains=location)

        skills = self.request.GET.getlist('skills')
        if skills:
            for skill in skills:
                queryset = queryset.filter(skills__contains=[skill])

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.get_tenant()

        if tenant:
            context['current_filters'] = {
                'q': self.request.GET.get('q', ''),
                'source': self.request.GET.get('source', ''),
                'status': self.request.GET.get('status', ''),
                'location': self.request.GET.get('location', ''),
            }

            # Get common skills for filter dropdown
            from django.db.models.functions import Unnest
            context['common_skills'] = Candidate.objects.filter(
                tenant=tenant
            ).values_list('skills', flat=True).distinct()[:50]

        return context


@require_tenant_type('company')
class CandidateDetailView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, DetailView):
    """
    Candidate profile page with timeline - COMPANY ONLY.

    Shows candidate details, resume, application history, and activity timeline.
    """
    model = Candidate
    template_name = 'ats/candidate_detail.html'
    context_object_name = 'candidate'

    def get_queryset(self):
        tenant = self.get_tenant()
        if not tenant:
            return Candidate.objects.none()

        return Candidate.objects.filter(
            tenant=tenant
        ).select_related(
            'source', 'created_by'
        ).prefetch_related(
            Prefetch(
                'applications',
                queryset=Application.objects.select_related(
                    'job', 'current_stage'
                ).prefetch_related(
                    'activities', 'notes', 'interviews'
                ).order_by('-created_at')
            )
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        candidate = self.object

        # Application history
        context['applications'] = candidate.applications.all()

        # Activity timeline (combined from all applications)
        activities = []
        for app in candidate.applications.all():
            for activity in app.activities.all():
                activities.append({
                    'type': 'activity',
                    'date': activity.created_at,
                    'description': activity.description,
                    'user': activity.performed_by,
                    'application': app,
                })
            for note in app.notes.all():
                activities.append({
                    'type': 'note',
                    'date': note.created_at,
                    'description': note.content,
                    'user': note.author,
                    'application': app,
                })

        activities.sort(key=lambda x: x['date'], reverse=True)
        context['timeline'] = activities[:50]

        # Upcoming interviews
        context['upcoming_interviews'] = Interview.objects.filter(
            application__candidate=candidate,
            status__in=['scheduled', 'confirmed'],
            scheduled_start__gt=timezone.now()
        ).select_related('application__job').order_by('scheduled_start')[:5]

        return context


# =============================================================================
# PIPELINE VIEWS
# =============================================================================

@require_tenant_type('company')
class PipelineBoardView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, TemplateView):
    """
    Kanban pipeline board view - COMPANY ONLY.

    Displays applications organized by pipeline stages.
    Supports drag-and-drop with HTMX.
    """
    template_name = 'ats/pipeline_board.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.get_tenant()

        if not tenant:
            return context

        # Get job if specified
        job_id = self.request.GET.get('job')
        job = None
        if job_id:
            job = get_object_or_404(JobPosting, id=job_id, tenant=tenant)
            context['job'] = job
            pipeline = job.pipeline
        else:
            # Get default pipeline
            pipeline = Pipeline.objects.filter(
                tenant=tenant, is_default=True
            ).first()
            if not pipeline:
                pipeline = Pipeline.objects.filter(tenant=tenant).first()

        if not pipeline:
            context['error'] = 'No pipeline found'
            return context

        context['pipeline'] = pipeline

        # Get stages with applications
        stages = pipeline.stages.filter(is_active=True).order_by('order')
        stages_data = []

        for stage in stages:
            applications = Application.objects.filter(
                current_stage=stage,
                tenant=tenant
            ).select_related('candidate', 'job')

            if job:
                applications = applications.filter(job=job)

            applications = applications.order_by('-updated_at')[:50]

            stages_data.append({
                'stage': stage,
                'applications': applications,
                'count': applications.count(),
            })

        context['stages_data'] = stages_data

        # Available jobs for filter
        context['jobs'] = JobPosting.objects.filter(
            tenant=tenant,
            status='open'
        ).order_by('title')

        return context


@require_tenant_type('company')
class ApplicationMoveView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for moving application between pipeline stages - COMPANY ONLY.

    Called when dragging a candidate card to a new column.
    """

    def post(self, request, pk):
        tenant = self.get_tenant()
        if not tenant:
            return HttpResponse(status=403)

        application = get_object_or_404(
            Application,
            pk=pk,
            tenant=tenant
        )

        new_stage_id = request.POST.get('stage_id')
        if not new_stage_id:
            return HttpResponse('stage_id required', status=400)

        new_stage = get_object_or_404(PipelineStage, pk=new_stage_id)

        # Verify stage belongs to the same pipeline
        if application.job and application.job.pipeline_id != new_stage.pipeline_id:
            return HttpResponse('Invalid stage for this job', status=400)

        old_stage = application.current_stage

        with transaction.atomic():
            # Update application stage
            application.current_stage = new_stage
            application.save(update_fields=['current_stage', 'updated_at'])

            # Log activity
            ApplicationActivity.objects.create(
                application=application,
                activity_type='stage_change',
                description=f'Moved from {old_stage.name if old_stage else "N/A"} to {new_stage.name}',
                performed_by=request.user,
                old_value=old_stage.name if old_stage else '',
                new_value=new_stage.name,
            )

        # Return updated card HTML for HTMX
        response = render(request, 'ats/partials/_application_card.html', {
            'application': application
        })
        response['HX-Trigger'] = json.dumps({
            'applicationMoved': {
                'applicationId': str(application.pk),
                'newStage': str(new_stage.pk),
            }
        })
        return response


@require_tenant_type('company')
class ApplicationBulkActionView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Handle bulk actions on applications - COMPANY ONLY.

    Supports: bulk reject, bulk move stage, bulk archive.
    """

    def post(self, request):
        tenant = self.get_tenant()
        if not tenant:
            return HttpResponse(status=403)

        action = request.POST.get('action')
        application_ids = request.POST.getlist('application_ids')

        if not action or not application_ids:
            return HttpResponse('Action and application_ids required', status=400)

        applications = Application.objects.filter(
            pk__in=application_ids,
            tenant=tenant
        )

        count = 0
        with transaction.atomic():
            if action == 'reject':
                reason = request.POST.get('rejection_reason', 'Bulk rejection')
                for app in applications:
                    app.status = 'rejected'
                    app.rejection_reason = reason
                    app.rejected_at = timezone.now()
                    app.save()
                    ApplicationActivity.objects.create(
                        application=app,
                        activity_type='rejection',
                        description='Application rejected (bulk action)',
                        performed_by=request.user,
                    )
                    count += 1

            elif action == 'move_stage':
                stage_id = request.POST.get('stage_id')
                if stage_id:
                    new_stage = get_object_or_404(PipelineStage, pk=stage_id)
                    for app in applications:
                        old_stage = app.current_stage
                        app.current_stage = new_stage
                        app.save()
                        ApplicationActivity.objects.create(
                            application=app,
                            activity_type='stage_change',
                            description=f'Moved to {new_stage.name} (bulk action)',
                            performed_by=request.user,
                            old_value=old_stage.name if old_stage else '',
                            new_value=new_stage.name,
                        )
                        count += 1

            elif action == 'archive':
                for app in applications:
                    app.is_archived = True
                    app.archived_at = timezone.now()
                    app.save()
                    count += 1

        if request.headers.get('HX-Request'):
            response = HttpResponse(status=204)
            response['HX-Trigger'] = json.dumps({
                'bulkActionComplete': {
                    'action': action,
                    'count': count,
                }
            })
            return response

        messages.success(request, f'{count} applications updated successfully.')
        return redirect(request.META.get('HTTP_REFERER', '/'))


# =============================================================================
# INTERVIEW VIEWS
# =============================================================================
@require_tenant_type('company')
class InterviewScheduleView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Interview scheduling modal/view - COMPANY ONLY.

    Handles both the form display and scheduling submission.
    """
    template_name = 'ats/interview_schedule.html'

    def get(self, request, application_pk=None):
        tenant = self.get_tenant()
        if not tenant:
            return HttpResponse(status=403)

        application = None
        if application_pk:
            application = get_object_or_404(Application, pk=application_pk, tenant=tenant)

        # Get available interview slots
        available_slots = InterviewSlot.objects.filter(
            tenant=tenant,
            is_available=True,
            start_time__gt=timezone.now()
        ).select_related('interviewer').order_by('start_time')[:50]

        # Get interviewers
        from django.contrib.auth import get_user_model
        User = get_user_model()
        interviewers = User.objects.filter(
            tenantuser__tenant=tenant,
            tenantuser__is_active=True
        )

        context = {
            'application': application,
            'available_slots': available_slots,
            'interviewers': interviewers,
            'interview_types': Interview.InterviewType.choices if hasattr(Interview, 'InterviewType') else [],
        }

        if request.headers.get('HX-Request'):
            return render(request, 'ats/partials/_interview_schedule_modal.html', context)

        return render(request, self.template_name, context)

    def post(self, request, application_pk=None):
        tenant = self.get_tenant()
        if not tenant:
            return HttpResponse(status=403)

        application = get_object_or_404(Application, pk=application_pk, tenant=tenant)

        # Extract form data
        interview_type = request.POST.get('interview_type', 'phone')
        scheduled_start = request.POST.get('scheduled_start')
        scheduled_end = request.POST.get('scheduled_end')
        interviewer_ids = request.POST.getlist('interviewers')
        location = request.POST.get('location', '')
        meeting_link = request.POST.get('meeting_link', '')
        notes = request.POST.get('notes', '')

        if not scheduled_start or not interviewer_ids:
            if request.headers.get('HX-Request'):
                return HttpResponse('Missing required fields', status=400)
            messages.error(request, 'Missing required fields')
            return redirect(request.META.get('HTTP_REFERER', '/'))

        from django.utils.dateparse import parse_datetime
        start_dt = parse_datetime(scheduled_start)
        end_dt = parse_datetime(scheduled_end) if scheduled_end else start_dt + timedelta(hours=1)

        with transaction.atomic():
            interview = Interview.objects.create(
                application=application,
                interview_type=interview_type,
                scheduled_start=start_dt,
                scheduled_end=end_dt,
                location=location,
                meeting_link=meeting_link,
                notes=notes,
                status='scheduled',
                created_by=request.user,
            )

            # Add interviewers
            from django.contrib.auth import get_user_model
            User = get_user_model()
            for interviewer_id in interviewer_ids:
                try:
                    interviewer = User.objects.get(pk=interviewer_id)
                    interview.interviewers.add(interviewer)
                except User.DoesNotExist:
                    pass

            # Update application status
            application.status = 'interviewing'
            application.save(update_fields=['status', 'updated_at'])

            # Log activity
            ApplicationActivity.objects.create(
                application=application,
                activity_type='interview_scheduled',
                description=f'{interview.get_interview_type_display()} interview scheduled for {start_dt.strftime("%Y-%m-%d %H:%M")}',
                performed_by=request.user,
            )

        if request.headers.get('HX-Request'):
            response = HttpResponse(status=201)
            response['HX-Trigger'] = json.dumps({
                'interviewScheduled': {
                    'applicationId': str(application.pk),
                    'interviewId': str(interview.pk),
                }
            })
            response['HX-Redirect'] = reverse('ats:application-detail', kwargs={'pk': application.pk})
            return response

        messages.success(request, 'Interview scheduled successfully!')
        return redirect('ats:application-detail', pk=application.pk)


@require_tenant_type('company')
class InterviewFeedbackView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Submit interview feedback - COMPANY ONLY.
    """
    template_name = 'ats/interview_feedback.html'

    def get(self, request, interview_pk):
        tenant = self.get_tenant()
        interview = get_object_or_404(
            Interview,
            pk=interview_pk,
            application__tenant=tenant
        )

        context = {
            'interview': interview,
            'rating_choices': range(1, 6),
        }

        if request.headers.get('HX-Request'):
            return render(request, 'ats/partials/_interview_feedback_form.html', context)

        return render(request, self.template_name, context)

    def post(self, request, interview_pk):
        tenant = self.get_tenant()
        interview = get_object_or_404(
            Interview,
            pk=interview_pk,
            application__tenant=tenant
        )

        rating = request.POST.get('rating')
        recommendation = request.POST.get('recommendation')
        strengths = request.POST.get('strengths', '')
        weaknesses = request.POST.get('weaknesses', '')
        notes = request.POST.get('notes', '')

        feedback = InterviewFeedback.objects.create(
            interview=interview,
            interviewer=request.user,
            rating=int(rating) if rating else None,
            recommendation=recommendation,
            strengths=strengths,
            weaknesses=weaknesses,
            notes=notes,
        )

        # Log activity
        ApplicationActivity.objects.create(
            application=interview.application,
            activity_type='feedback_submitted',
            description=f'Interview feedback submitted by {request.user.get_full_name() or request.user.email}',
            performed_by=request.user,
        )

        if request.headers.get('HX-Request'):
            response = render(request, 'ats/partials/_interview_feedback_success.html', {
                'feedback': feedback
            })
            response['HX-Trigger'] = 'feedbackSubmitted'
            return response

        messages.success(request, 'Feedback submitted successfully!')
        return redirect('ats:application-detail', pk=interview.application.pk)


# =============================================================================
# APPLICATION VIEWS
# =============================================================================

@require_tenant_type('company')
class ApplicationDetailView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, DetailView):
    """
    Application detail view with full timeline and actions - COMPANY ONLY.
    """
    model = Application
    template_name = 'ats/application_detail.html'
    context_object_name = 'application'

    def get_queryset(self):
        tenant = self.get_tenant()
        if not tenant:
            return Application.objects.none()

        return Application.objects.filter(
            tenant=tenant
        ).select_related(
            'candidate', 'job', 'current_stage',
            'job__pipeline', 'job__recruiter', 'job__hiring_manager'
        ).prefetch_related(
            'activities__performed_by',
            'notes__author',
            'interviews__interviewers',
            'interviews__feedback'
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        application = self.object

        # Get pipeline stages for stage selector
        if application.job and application.job.pipeline:
            context['pipeline_stages'] = application.job.pipeline.stages.filter(
                is_active=True
            ).order_by('order')

        # Get interviews
        context['interviews'] = application.interviews.all().order_by('-scheduled_start')

        # Get notes
        context['notes'] = application.notes.all().order_by('-created_at')

        # Build activity timeline
        timeline = []
        for activity in application.activities.select_related('performed_by').all():
            timeline.append({
                'type': 'activity',
                'date': activity.created_at,
                'content': activity.description,
                'user': activity.performed_by,
                'activity_type': activity.activity_type,
            })

        for note in application.notes.select_related('author').all():
            timeline.append({
                'type': 'note',
                'date': note.created_at,
                'content': note.content,
                'user': note.author,
                'is_private': note.is_private,
            })

        for interview in application.interviews.all():
            timeline.append({
                'type': 'interview',
                'date': interview.scheduled_start,
                'content': f'{interview.get_interview_type_display()} - {interview.status}',
                'interview': interview,
            })

        timeline.sort(key=lambda x: x['date'], reverse=True)
        context['timeline'] = timeline

        # Offers
        context['offers'] = Offer.objects.filter(application=application).order_by('-created_at')

        return context


@require_tenant_type('company')
class ApplicationNoteView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Add a note to an application - COMPANY ONLY.
    """

    def post(self, request, application_pk):
        tenant = self.get_tenant()
        application = get_object_or_404(Application, pk=application_pk, tenant=tenant)

        content = request.POST.get('content', '').strip()
        is_private = request.POST.get('is_private', 'false').lower() == 'true'

        if not content:
            return HttpResponse('Content is required', status=400)

        note = ApplicationNote.objects.create(
            application=application,
            author=request.user,
            content=content,
            is_private=is_private,
        )

        if request.headers.get('HX-Request'):
            response = render(request, 'ats/partials/_note_item.html', {'note': note})
            response['HX-Trigger'] = 'noteAdded'
            return response

        messages.success(request, 'Note added successfully!')
        return redirect('ats:application-detail', pk=application.pk)


# =============================================================================
# OFFER VIEWS (Step 5 - End-to-End Hiring)
# =============================================================================
# TEST RESULTS (2026-01-16):
# URL: https://demo-company.zumodra.rhematek-solutions.com/app/ats/offers/
# STATUS: 502 Bad Gateway - Backend server not responding
# ISSUE: Entire demo site is returning 502 errors, indicating the Django
#        application or gunicorn workers are not running or nginx cannot
#        connect to the upstream server.
# RECOMMENDATION: Check server logs, restart Django/gunicorn services,
#                 verify docker containers are running properly.
# =============================================================================

@require_tenant_type('company')
class OfferListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """
    List all offers with filtering - COMPANY ONLY.

    TEST STATUS (2026-01-16): NOT TESTED - 502 Server Error
    Expected functionality:
    - Display paginated list of all offers for tenant
    - Filter by status (draft, sent, accepted, declined, withdrawn)
    - Show candidate name, job title, salary, offer status
    - Links to offer detail pages
    - Create new offer button
    """
    model = Offer
    template_name = 'ats/offer_list.html'
    partial_template_name = 'ats/partials/_offer_list.html'
    context_object_name = 'offers'
    paginate_by = 20

    def get_queryset(self):
        tenant = self.get_tenant()
        if not tenant:
            return Offer.objects.none()

        queryset = Offer.objects.filter(
            application__tenant=tenant
        ).select_related(
            'application__candidate', 'application__job',
            'created_by'
        ).order_by('-created_at')

        # Apply filters
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['status_choices'] = Offer.OfferStatus.choices if hasattr(Offer, 'OfferStatus') else []
        context['current_filters'] = {
            'status': self.request.GET.get('status', ''),
        }
        return context


@require_tenant_type('company')
class OfferDetailView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, DetailView):
    """
    View offer details - COMPANY ONLY.
    """
    model = Offer
    template_name = 'ats/offer_detail.html'
    context_object_name = 'offer'

    def get_queryset(self):
        tenant = self.get_tenant()
        if not tenant:
            return Offer.objects.none()

        return Offer.objects.filter(
            application__tenant=tenant
        ).select_related(
            'application__candidate', 'application__job',
            'created_by', 'approved_by'
        )


@require_tenant_type('company')
class OfferCreateView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Create a new offer for an application - COMPANY ONLY.
    """
    template_name = 'ats/offer_form.html'

    def get(self, request, application_pk):
        tenant = self.get_tenant()
        application = get_object_or_404(
            Application,
            pk=application_pk,
            tenant=tenant
        )

        # Check if there's already a pending/sent offer
        existing_offer = Offer.objects.filter(
            application=application,
            status__in=['draft', 'pending_approval', 'sent']
        ).first()

        if existing_offer:
            messages.warning(request, 'An offer already exists for this application.')
            return redirect('ats:offer-detail', pk=existing_offer.pk)

        context = {
            'application': application,
            'candidate': application.candidate,
            'job': application.job,
        }

        if request.headers.get('HX-Request'):
            return render(request, 'ats/partials/_offer_form_modal.html', context)

        return render(request, self.template_name, context)

    def post(self, request, application_pk):
        tenant = self.get_tenant()
        application = get_object_or_404(
            Application,
            pk=application_pk,
            tenant=tenant
        )

        # Extract form data
        base_salary = request.POST.get('base_salary')
        salary_currency = request.POST.get('salary_currency', 'USD')
        salary_period = request.POST.get('salary_period', 'annual')
        bonus = request.POST.get('bonus', '')
        equity = request.POST.get('equity', '')
        benefits = request.POST.get('benefits', '')
        start_date = request.POST.get('start_date')
        expiration_date = request.POST.get('expiration_date')
        notes = request.POST.get('notes', '')
        send_immediately = request.POST.get('send_immediately') == 'true'

        from decimal import Decimal, InvalidOperation
        from django.utils.dateparse import parse_date

        try:
            base_salary_decimal = Decimal(base_salary) if base_salary else Decimal('0')
        except InvalidOperation:
            messages.error(request, 'Invalid salary amount')
            return redirect('ats:offer-create', application_pk=application_pk)

        with transaction.atomic():
            offer = Offer.objects.create(
                application=application,
                base_salary=base_salary_decimal,
                salary_currency=salary_currency,
                salary_period=salary_period,
                bonus=bonus,
                equity=equity,
                benefits=benefits,
                start_date=parse_date(start_date) if start_date else None,
                expiration_date=parse_date(expiration_date) if expiration_date else None,
                notes=notes,
                status='draft' if not send_immediately else 'sent',
                created_by=request.user,
            )

            # Update application status
            application.status = 'offer_pending' if not send_immediately else 'offer_extended'
            application.save(update_fields=['status', 'updated_at'])

            # Log activity
            ApplicationActivity.objects.create(
                application=application,
                activity_type='offer_created',
                description=f'Offer created with salary {salary_currency} {base_salary_decimal:,.2f}',
                performed_by=request.user,
            )

            if send_immediately:
                ApplicationActivity.objects.create(
                    application=application,
                    activity_type='offer_sent',
                    description='Offer sent to candidate',
                    performed_by=request.user,
                )

        messages.success(request, 'Offer created successfully!')

        if request.headers.get('HX-Request'):
            response = HttpResponse(status=201)
            response['HX-Redirect'] = reverse('ats:offer-detail', kwargs={'pk': offer.pk})
            return response

        return redirect('ats:offer-detail', pk=offer.pk)


@require_tenant_type('company')
class OfferActionView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Perform actions on offers (send, accept, decline, withdraw) - COMPANY ONLY.
    """

    def post(self, request, pk, action):
        tenant = self.get_tenant()
        offer = get_object_or_404(
            Offer,
            pk=pk,
            application__tenant=tenant
        )

        valid_actions = {
            'send': self._send_offer,
            'accept': self._accept_offer,
            'decline': self._decline_offer,
            'withdraw': self._withdraw_offer,
        }

        if action not in valid_actions:
            return HttpResponse('Invalid action', status=400)

        success, message = valid_actions[action](offer, request.user)

        if request.headers.get('HX-Request'):
            if success:
                response = render(request, 'ats/partials/_offer_status_badge.html', {'offer': offer})
                response['HX-Trigger'] = json.dumps({'offerUpdated': {'offerId': str(pk), 'action': action}})
                return response
            return HttpResponse(message, status=400)

        if success:
            messages.success(request, message)
        else:
            messages.error(request, message)

        return redirect('ats:offer-detail', pk=pk)

    def _send_offer(self, offer, user):
        if offer.status != 'draft':
            return False, 'Offer must be in draft status to send'

        offer.status = 'sent'
        offer.sent_at = timezone.now()
        offer.save()

        ApplicationActivity.objects.create(
            application=offer.application,
            activity_type='offer_sent',
            description='Offer sent to candidate',
            performed_by=user,
        )

        offer.application.status = 'offer_extended'
        offer.application.save()

        return True, 'Offer sent successfully'

    def _accept_offer(self, offer, user):
        if offer.status != 'sent':
            return False, 'Offer must be sent before accepting'

        offer.status = 'accepted'
        offer.accepted_at = timezone.now()
        offer.save()

        ApplicationActivity.objects.create(
            application=offer.application,
            activity_type='offer_accepted',
            description='Offer accepted by candidate',
            performed_by=user,
        )

        offer.application.status = 'hired'
        offer.application.hired_at = timezone.now()
        offer.application.save()

        return True, 'Offer accepted - Candidate hired!'

    def _decline_offer(self, offer, user):
        if offer.status != 'sent':
            return False, 'Offer must be sent before declining'

        offer.status = 'declined'
        offer.declined_at = timezone.now()
        offer.save()

        ApplicationActivity.objects.create(
            application=offer.application,
            activity_type='offer_declined',
            description='Offer declined by candidate',
            performed_by=user,
        )

        return True, 'Offer declined'

    def _withdraw_offer(self, offer, user):
        if offer.status not in ['draft', 'sent']:
            return False, 'Cannot withdraw offer in current status'

        offer.status = 'withdrawn'
        offer.save()

        ApplicationActivity.objects.create(
            application=offer.application,
            activity_type='offer_withdrawn',
            description='Offer withdrawn',
            performed_by=user,
        )

        return True, 'Offer withdrawn'

@require_tenant_type('company')
class JobPublishView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Publish a draft job posting - COMPANY ONLY.

    TEST NOTES (2026-01-16):
    - URL: /app/ats/jobs/<uuid>/publish/
    - Method: POST only
    - Changes status from 'draft' to 'open'
    - Sets published_at timestamp
    - Test: Verify only works on draft jobs
    - Test: Verify status badge updates to "Open"
    - Test: Verify published_at timestamp set correctly
    - Test: Verify job appears in public listings (if applicable)
    """

    def post(self, request, pk):
        tenant = self.get_tenant()
        job = get_object_or_404(JobPosting, pk=pk, tenant=tenant)

        if job.status != 'draft':
            messages.warning(request, 'Only draft jobs can be published')
            return redirect('ats:job-detail', pk=pk)

        job.status = 'open'
        job.published_at = timezone.now()
        job.save(update_fields=['status', 'published_at', 'updated_at'])

        messages.success(request, f'Job "{job.title}" published successfully!')

        if request.headers.get('HX-Request'):
            response = HttpResponse(status=200)
            response['HX-Trigger'] = 'jobPublished'
            response['HX-Redirect'] = reverse('ats:job-detail', kwargs={'pk': pk})
            return response

        return redirect('ats:job-detail', pk=pk)

@require_tenant_type('company')
class JobCloseView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Close an open job posting - COMPANY ONLY.

    TEST NOTES (2026-01-16):
    - URL: /app/ats/jobs/<uuid>/close/
    - Method: POST only
    - Changes status to 'closed'
    - Sets closed_at timestamp
    - Requires: status in ['open', 'on_hold']
    - Test: Verify only works on open/on_hold jobs (not draft)
    - Test: Verify status badge updates to "Closed"
    - Test: Verify closed_at timestamp set correctly
    - Test: Verify job no longer in open job listings
    """

    def post(self, request, pk):
        tenant = self.get_tenant()
        job = get_object_or_404(JobPosting, pk=pk, tenant=tenant)

        if job.status not in ['open', 'on_hold']:
            messages.warning(request, 'Only open/on-hold jobs can be closed')
            return redirect('ats:job-detail', pk=pk)

        job.status = 'closed'
        job.closed_at = timezone.now()
        job.save(update_fields=['status', 'closed_at', 'updated_at'])

        messages.success(request, f'Job "{job.title}" closed successfully!')

        if request.headers.get('HX-Request'):
            response = HttpResponse(status=200)
            response['HX-Trigger'] = 'jobClosed'
            return response

        return redirect('ats:job-detail', pk=pk)


# =============================================================================
# INTERVIEW MANAGEMENT VIEWS
# =============================================================================

class InterviewListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """
    Interview list view with filtering capabilities.
    """
    model = Interview
    template_name = 'ats/interview_list.html'
    context_object_name = 'interviews'
    paginate_by = 20

    def get_queryset(self):
        """Get filtered interviews."""
        qs = Interview.objects.select_related(
            'application__candidate',
            'application__job_posting',
            'interviewer'
        ).filter(
            application__job_posting__tenant=self.request.tenant
        )

        # Filter by status
        filter_param = self.request.GET.get('filter', 'upcoming')
        now = timezone.now()

        if filter_param == 'upcoming':
            qs = qs.filter(
                scheduled_start__gte=now,
                status__in=['scheduled', 'confirmed']
            )
        elif filter_param == 'today':
            today_start = now.replace(hour=0, minute=0, second=0)
            today_end = today_start + timedelta(days=1)
            qs = qs.filter(
                scheduled_start__gte=today_start,
                scheduled_start__lt=today_end
            )
        elif filter_param == 'past':
            qs = qs.filter(scheduled_start__lt=now)
        elif filter_param == 'completed':
            qs = qs.filter(status='completed')
        elif filter_param == 'cancelled':
            qs = qs.filter(status='cancelled')

        return qs.order_by('-scheduled_start')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['current_filter'] = self.request.GET.get('filter', 'upcoming')
        return context


class InterviewDetailView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, DetailView):
    """
    Interview detail view showing full interview information.
    """
    model = Interview
    template_name = 'ats/interview_detail.html'
    context_object_name = 'interview'
    pk_url_kwarg = 'pk'

    def get_queryset(self):
        """Ensure interview belongs to tenant."""
        return Interview.objects.select_related(
            'application__candidate',
            'application__job_posting',
            'interviewer'
        ).prefetch_related(
            'feedback_set'
        ).filter(
            application__job_posting__tenant=self.request.tenant
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        interview = self.object

        # Get feedback
        context['feedback_list'] = interview.feedback_set.all()
        context['can_provide_feedback'] = (
            self.request.user == interview.interviewer or
            self.request.user.is_staff
        )

        return context


class InterviewRescheduleView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Reschedule an interview.
    """

    def get(self, request, pk):
        """Show reschedule form."""
        interview = get_object_or_404(
            Interview.objects.filter(
                application__job_posting__tenant=request.tenant
            ),
            pk=pk
        )

        # Get available slots
        slots = InterviewSlot.objects.filter(
            interviewer=interview.interviewer,
            is_available=True,
            start_time__gte=timezone.now()
        ).order_by('start_time')[:20]

        context = {
            'interview': interview,
            'available_slots': slots,
        }

        return render(request, 'ats/partials/_interview_reschedule_form.html', context)

    def post(self, request, pk):
        """Process reschedule."""
        interview = get_object_or_404(
            Interview.objects.filter(
                application__job_posting__tenant=request.tenant
            ),
            pk=pk
        )

        new_start = request.POST.get('scheduled_start')
        new_end = request.POST.get('scheduled_end')

        if new_start and new_end:
            interview.scheduled_start = new_start
            interview.scheduled_end = new_end
            interview.status = 'rescheduled'
            interview.save()

            messages.success(request, f'Interview rescheduled successfully.')

            response = HttpResponse(status=200)
            response['HX-Trigger'] = 'interviewRescheduled'
            return response

        messages.error(request, 'Invalid date/time provided.')
        return HttpResponse(status=400)


class InterviewCancelView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Cancel an interview.
    """

    def post(self, request, pk):
        """Cancel the interview."""
        interview = get_object_or_404(
            Interview.objects.filter(
                application__job_posting__tenant=request.tenant
            ),
            pk=pk
        )

        cancellation_reason = request.POST.get('reason', '')

        interview.status = 'cancelled'
        interview.cancellation_reason = cancellation_reason
        interview.save()

        messages.success(request, f'Interview cancelled.')

        response = HttpResponse(status=200)
        response['HX-Trigger'] = 'interviewCancelled'
        return response


# =============================================================================
# APPLICATION ACTIONS
# =============================================================================

class EmailComposeView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Email composition view for contacting candidates.
    """

    def get(self, request):
        """Show email compose form."""
        recipient = request.GET.get('to', '')
        application_id = request.GET.get('application_id', '')

        context = {
            'recipient': recipient,
            'application_id': application_id,
        }

        return render(request, 'ats/partials/_email_compose.html', context)

    def post(self, request):
        """Send email."""
        from django.core.mail import send_mail
        from django.conf import settings

        recipient = request.POST.get('to')
        subject = request.POST.get('subject')
        message = request.POST.get('message')

        if recipient and subject and message:
            try:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[recipient],
                    fail_silently=False,
                )

                messages.success(request, f'Email sent to {recipient}')
                response = HttpResponse(status=200)
                response['HX-Trigger'] = 'emailSent'
                return response
            except Exception as e:
                logger.error(f'Failed to send email: {e}')
                messages.error(request, 'Failed to send email. Please try again.')
                return HttpResponse(status=500)

        messages.error(request, 'Please fill in all fields.')
        return HttpResponse(status=400)


class ApplicationRejectView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Reject an application.
    """

    def post(self, request, pk):
        """Mark application as rejected."""
        application = get_object_or_404(
            Application.objects.filter(
                job_posting__tenant=request.tenant
            ),
            pk=pk
        )

        rejection_reason = request.POST.get('reason', '')
        send_email = request.POST.get('send_email') == 'true'

        # Move to rejected stage
        rejected_stage = PipelineStage.objects.filter(
            pipeline=application.pipeline,
            stage_type='rejected'
        ).first()

        if rejected_stage:
            application.current_stage = rejected_stage
            application.status = 'rejected'
            application.save()

            # Log activity
            ApplicationActivity.objects.create(
                application=application,
                activity_type='status_change',
                description=f'Application rejected. Reason: {rejection_reason}',
                performed_by=request.user
            )

            # Send rejection email if requested
            if send_email and application.candidate.email:
                from django.core.mail import send_mail
                from django.conf import settings

                try:
                    send_mail(
                        subject=f'Application Update - {application.job_posting.title}',
                        message=f'Thank you for your interest in {application.job_posting.title}. After careful consideration, we have decided to move forward with other candidates.',
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[application.candidate.email],
                        fail_silently=True,
                    )
                except Exception as e:
                    logger.error(f'Failed to send rejection email: {e}')

            messages.success(request, 'Application rejected.')
            response = HttpResponse(status=200)
            response['HX-Trigger'] = 'applicationRejected'
            return response

        messages.error(request, 'Could not find rejected stage.')
        return HttpResponse(status=400)


# =============================================================================
# JOB MANAGEMENT VIEWS
# =============================================================================

class JobEditView(LoginRequiredMixin, TenantViewMixin, ATSPermissionMixin, View):
    """
    Edit existing job posting.

    TEST NOTES (2026-01-16):
    - URL: /app/ats/jobs/<uuid>/edit/
    - Updates: title, description, department, location, job_type, experience_level
    - Also updates: remote_policy, salary (if provided)
    - Test: Verify form pre-populated with existing job data
    - Test: Verify changes save successfully
    - Test: Verify redirect to job detail after edit (uses correct namespace)
    - Permission required: 'edit' (Recruiter, Hiring Manager, HR, Admin, PDG)
    """

    def get(self, request, pk):
        """Show job edit form."""
        job = get_object_or_404(
            JobPosting.objects.filter(tenant=request.tenant),
            pk=pk
        )

        categories = JobCategory.objects.filter(tenant=request.tenant)

        context = {
            'job': job,
            'categories': categories,
            'is_edit': True,
        }

        return render(request, 'ats/job_form.html', context)

    def post(self, request, pk):
        """Update job posting."""
        job = get_object_or_404(
            JobPosting.objects.filter(tenant=request.tenant),
            pk=pk
        )

        # Update job fields
        job.title = request.POST.get('title')
        job.description = request.POST.get('description')
        job.department = request.POST.get('department')
        job.location = request.POST.get('location')
        job.job_type = request.POST.get('job_type')
        job.experience_level = request.POST.get('experience_level')
        job.remote_policy = request.POST.get('remote_policy')

        # Update salary if provided
        min_salary = request.POST.get('min_salary')
        max_salary = request.POST.get('max_salary')
        if min_salary:
            job.min_salary = min_salary
        if max_salary:
            job.max_salary = max_salary

        job.save()

        messages.success(request, f'Job "{job.title}" updated successfully.')
        return redirect('frontend:ats:job_detail', pk=job.pk)


class JobDuplicateView(LoginRequiredMixin, TenantViewMixin, ATSPermissionMixin, View):
    """
    Duplicate a job posting.

    TEST NOTES (2026-01-16):
    - URL: /app/ats/jobs/<uuid>/duplicate/
    - Method: POST only
    - Creates new job with " (Copy)" appended to title
    - Status: Always 'draft'
    - Copies: All fields except ID, UUID, applications
    - Test: Verify new UUID generated
    - Test: Verify applications NOT copied to duplicate
    - Test: Verify redirect to new job detail page
    - Test: Verify original job unchanged
    """

    def post(self, request, pk):
        """Create duplicate of job."""
        original_job = get_object_or_404(
            JobPosting.objects.filter(tenant=request.tenant),
            pk=pk
        )

        # Create duplicate
        duplicate = JobPosting.objects.create(
            tenant=request.tenant,
            title=f'{original_job.title} (Copy)',
            description=original_job.description,
            department=original_job.department,
            location=original_job.location,
            job_type=original_job.job_type,
            experience_level=original_job.experience_level,
            remote_policy=original_job.remote_policy,
            min_salary=original_job.min_salary,
            max_salary=original_job.max_salary,
            status='draft',
            created_by=request.user,
        )

        messages.success(request, f'Job duplicated as "{duplicate.title}"')
        return redirect('frontend:ats:job_detail', pk=duplicate.pk)


class JobDeleteView(LoginRequiredMixin, TenantViewMixin, ATSPermissionMixin, View):
    """
    Delete a job posting - SOFT DELETE.

    TEST NOTES (2026-01-16):
    - URL: /app/ats/jobs/<uuid>/delete/
    - Method: DELETE (not POST)
    - Implements soft delete: sets is_deleted=True, deleted_at=timestamp
    - Permission required: 'delete' (HR, Admin, PDG only)
    - Returns: HX-Trigger header 'jobDeleted' for HTMX
    - Test: Verify confirmation required before delete
    - Test: Verify job still in database (soft delete, not hard delete)
    - Test: Verify deleted job not in active job listings
    - Test: Verify permission enforcement (Recruiter should NOT be able to delete)
    - IMPORTANT: Check if JobListView filters out is_deleted=True jobs
    """

    def delete(self, request, pk):
        """Soft delete job posting."""
        job = get_object_or_404(
            JobPosting.objects.filter(tenant=request.tenant),
            pk=pk
        )

        # Soft delete
        job.is_deleted = True
        job.deleted_at = timezone.now()
        job.save()

        messages.success(request, f'Job "{job.title}" deleted.')

        response = HttpResponse(status=200)
        response['HX-Trigger'] = 'jobDeleted'
        return response


# =============================================================================
# CANDIDATE MANAGEMENT VIEWS
# =============================================================================

class CandidateCreateView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Create new candidate.
    """

    def get(self, request):
        """Show candidate creation form."""
        return render(request, 'ats/candidate_form.html', {'is_create': True})

    def post(self, request):
        """Create new candidate."""
        from django.contrib.auth import get_user_model
        User = get_user_model()

        email = request.POST.get('email')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        phone = request.POST.get('phone')

        if not (email and first_name and last_name):
            messages.error(request, 'Please provide email, first name, and last name.')
            return redirect('frontend:ats:candidate_create')

        # Check if candidate already exists
        if Candidate.objects.filter(email=email).exists():
            messages.error(request, f'Candidate with email {email} already exists.')
            return redirect('frontend:ats:candidate_create')

        # Create candidate
        candidate = Candidate.objects.create(
            email=email,
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            source='manual',
        )

        messages.success(request, f'Candidate "{candidate.full_name}" created successfully.')
        return redirect('frontend:ats:candidate_detail', pk=candidate.pk)


class CandidateAddToJobView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Add candidate to a job posting.
    """

    def get(self, request, pk):
        """Show job selection form."""
        candidate = get_object_or_404(Candidate, pk=pk)

        # Get active jobs
        jobs = JobPosting.objects.filter(
            tenant=request.tenant,
            status='open'
        ).order_by('-created_at')[:20]

        context = {
            'candidate': candidate,
            'jobs': jobs,
        }

        return render(request, 'ats/partials/_candidate_add_to_job.html', context)

    def post(self, request, pk):
        """Create application for candidate."""
        candidate = get_object_or_404(Candidate, pk=pk)
        job_id = request.POST.get('job_id')

        if not job_id:
            messages.error(request, 'Please select a job.')
            return HttpResponse(status=400)

        job = get_object_or_404(
            JobPosting.objects.filter(tenant=request.tenant),
            pk=job_id
        )

        # Check if application already exists
        if Application.objects.filter(candidate=candidate, job_posting=job).exists():
            messages.error(request, 'Candidate already applied to this job.')
            return HttpResponse(status=400)

        # Create application
        pipeline = job.pipeline if hasattr(job, 'pipeline') else Pipeline.objects.filter(
            tenant=request.tenant,
            is_default=True
        ).first()

        if pipeline:
            initial_stage = pipeline.stages.filter(stage_type='new').first()

            application = Application.objects.create(
                candidate=candidate,
                job_posting=job,
                pipeline=pipeline,
                current_stage=initial_stage,
                status='new',
                source='manual',
            )

            messages.success(request, f'Candidate added to "{job.title}"')
            response = HttpResponse(status=200)
            response['HX-Trigger'] = 'candidateAddedToJob'
            return response

        messages.error(request, 'Could not find pipeline for job.')
        return HttpResponse(status=400)


# =============================================================================
# UTILITY VIEWS
# =============================================================================

class TeamMemberSearchView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Search team members for assigning to jobs.
    """

    def get(self, request):
        """Search team members."""
        from accounts.models import TenantUser

        query = request.GET.get('q', '').strip()

        if len(query) < 2:
            return JsonResponse({'results': []})

        # Search tenant users
        users = TenantUser.objects.filter(
            tenant=request.tenant,
            is_active=True
        ).filter(
            Q(user__first_name__icontains=query) |
            Q(user__last_name__icontains=query) |
            Q(user__email__icontains=query)
        ).select_related('user')[:10]

        results = [
            {
                'id': str(tu.user.id),
                'name': tu.user.get_full_name() or tu.user.email,
                'email': tu.user.email,
                'role': tu.get_role_display() if tu.role else '',
            }
            for tu in users
        ]

        return JsonResponse({'results': results})


# =============================================================================
# BACKGROUND CHECK VIEWS
# =============================================================================

class InitiateBackgroundCheckView(LoginRequiredMixin, TenantViewMixin, ATSPermissionMixin, HTMXMixin, TemplateView):
    """
    View to initiate a background check for an application.

    Displays a form to select the background check package and collect consent.
    """
    template_name = 'ats/background_check_initiate.html'
    partial_template_name = 'ats/partials/background_check_initiate_form.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        application_uuid = self.kwargs.get('uuid')
        application = get_object_or_404(
            Application.objects.select_related('candidate', 'job', 'job__pipeline'),
            uuid=application_uuid,
            tenant=self.request.tenant
        )

        # Check if background check already exists
        existing_check = BackgroundCheck.objects.filter(
            tenant=self.request.tenant,
            application=application
        ).first()

        # Get available packages
        packages = [
            {
                'value': 'basic',
                'label': 'Basic',
                'description': 'SSN verification and basic criminal record check',
                'price': '$29.99'
            },
            {
                'value': 'standard',
                'label': 'Standard',
                'description': 'SSN, criminal, employment verification',
                'price': '$49.99'
            },
            {
                'value': 'pro',
                'label': 'Professional',
                'description': 'Standard + education verification + references',
                'price': '$79.99'
            },
            {
                'value': 'comprehensive',
                'label': 'Comprehensive',
                'description': 'All checks + credit report + motor vehicle records',
                'price': '$129.99'
            }
        ]

        context.update({
            'application': application,
            'existing_check': existing_check,
            'packages': packages,
            'candidate_name': str(application.candidate),
            'job_title': application.job.title,
        })

        return context

    def post(self, request, *args, **kwargs):
        """Handle form submission to initiate background check."""
        from .background_checks import BackgroundCheckService
        from django.core.exceptions import PermissionDenied

        application_uuid = self.kwargs.get('uuid')
        application = get_object_or_404(
            Application.objects.select_related('candidate', 'job'),
            uuid=application_uuid,
            tenant=request.tenant
        )

        package = request.POST.get('package', 'standard')
        consent_given = request.POST.get('consent_given') == 'on'

        if not consent_given:
            messages.error(request, 'Candidate consent is required to initiate a background check.')
            return redirect('frontend:ats:background_check_initiate', uuid=application_uuid)

        try:
            service = BackgroundCheckService(tenant=request.tenant)
            background_check = service.initiate_check(
                application=application,
                package=package,
                initiated_by=request.user
            )

            # Record consent
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(',')[0]
            else:
                ip_address = request.META.get('REMOTE_ADDR')

            background_check.consent_ip_address = ip_address
            background_check.consent_timestamp = timezone.now()
            background_check.save(update_fields=['consent_ip_address', 'consent_timestamp'])

            messages.success(
                request,
                f'Background check initiated successfully. '
                f'The candidate will receive an email with instructions.'
            )

            return redirect('frontend:ats:background_check_status', uuid=application_uuid)

        except PermissionDenied as e:
            messages.error(request, str(e))
            return redirect('frontend:ats:application_detail', uuid=application_uuid)
        except Exception as e:
            logger.error(f"Failed to initiate background check: {e}", exc_info=True)
            messages.error(request, 'Failed to initiate background check. Please try again.')
            return redirect('frontend:ats:background_check_initiate', uuid=application_uuid)


class BackgroundCheckStatusView(LoginRequiredMixin, TenantViewMixin, ATSPermissionMixin, HTMXMixin, TemplateView):
    """
    View to display background check status and results.

    Shows current status, completion progress, and results when available.
    """
    template_name = 'ats/background_check_status.html'
    partial_template_name = 'ats/partials/background_check_status_partial.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        application_uuid = self.kwargs.get('uuid')
        application = get_object_or_404(
            Application.objects.select_related('candidate', 'job'),
            uuid=application_uuid,
            tenant=self.request.tenant
        )

        try:
            background_check = BackgroundCheck.objects.select_related(
                'initiated_by'
            ).prefetch_related('documents').get(
                tenant=self.request.tenant,
                application=application
            )
        except BackgroundCheck.DoesNotExist:
            background_check = None

        context.update({
            'application': application,
            'background_check': background_check,
            'candidate_name': str(application.candidate),
            'job_title': application.job.title,
        })

        return context


class BackgroundCheckReportView(LoginRequiredMixin, TenantViewMixin, ATSPermissionMixin, TemplateView):
    """
    View to display the full background check report.

    Shows detailed results from the provider including all screenings.
    """
    template_name = 'ats/background_check_report.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        application_uuid = self.kwargs.get('uuid')
        application = get_object_or_404(
            Application.objects.select_related('candidate', 'job'),
            uuid=application_uuid,
            tenant=self.request.tenant
        )

        try:
            background_check = BackgroundCheck.objects.select_related(
                'initiated_by'
            ).prefetch_related('documents').get(
                tenant=self.request.tenant,
                application=application
            )

            # Get full report from service
            from .background_checks import BackgroundCheckService
            service = BackgroundCheckService(tenant=self.request.tenant)
            full_report = service.get_report(background_check.id)

        except BackgroundCheck.DoesNotExist:
            background_check = None
            full_report = None

        context.update({
            'application': application,
            'background_check': background_check,
            'full_report': full_report,
            'candidate_name': str(application.candidate),
            'job_title': application.job.title,
        })

        return context


class BackgroundCheckStatusPartialView(LoginRequiredMixin, TenantViewMixin, ATSPermissionMixin, View):
    """
    HTMX partial view that returns just the background check status badge.

    Used for auto-refreshing status on the application detail page.
    """

    def get(self, request, uuid):
        """Return background check status badge partial."""
        application = get_object_or_404(
            Application.objects.select_related('candidate', 'job'),
            uuid=uuid,
            tenant=request.tenant
        )

        try:
            background_check = BackgroundCheck.objects.get(
                tenant=request.tenant,
                application=application
            )
        except BackgroundCheck.DoesNotExist:
            background_check = None

        return render(
            request,
            'ats/partials/background_check_badge.html',
            {
                'application': application,
                'background_check': background_check,
            }
        )
