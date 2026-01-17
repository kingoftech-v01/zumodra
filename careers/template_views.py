"""
Careers Template Views - Server-rendered views for SEO-optimized career pages.

This module provides Django template views for:
- Career site home (job listings)
- Job detail pages
- Application form and submission
- Application success/confirmation
- Job alert subscription management

All views are SEO-optimized with proper meta tags and structured data.
"""

import json
import logging
from decimal import Decimal
from django.views.generic import TemplateView, FormView, View
from django.views.generic.edit import CreateView
from django.shortcuts import get_object_or_404, redirect
from django.http import Http404, JsonResponse, HttpResponse
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.views.decorators.vary import vary_on_cookie
from django.db import models
from django.db.models import F, Count
from django.contrib import messages
from django import forms
from django.core.validators import FileExtensionValidator
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.core.cache import cache

from .models import CareerPage, CareerSite, JobListing, PublicApplication, JobAlert
from .serializers import (
    PublicCareerSiteSerializer,
    PublicJobListSerializer,
    PublicJobDetailSerializer
)

logger = logging.getLogger(__name__)


# ==================== FORMS ====================

class PublicApplicationForm(forms.Form):
    """
    Public application form with validation.
    Server-side validation for application submissions.
    """
    first_name = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('First Name'),
            'required': True,
            'autocomplete': 'given-name'
        })
    )
    last_name = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Last Name'),
            'required': True,
            'autocomplete': 'family-name'
        })
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': _('Email Address'),
            'required': True,
            'autocomplete': 'email'
        })
    )
    phone = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Phone Number (optional)'),
            'autocomplete': 'tel'
        })
    )
    resume = forms.FileField(
        validators=[FileExtensionValidator(allowed_extensions=['pdf', 'doc', 'docx'])],
        widget=forms.FileInput(attrs={
            'class': 'form-file',
            'accept': '.pdf,.doc,.docx',
            'required': True
        })
    )
    cover_letter = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'placeholder': _('Cover Letter (optional)'),
            'rows': 5
        })
    )
    linkedin_url = forms.URLField(
        required=False,
        widget=forms.URLInput(attrs={
            'class': 'form-input',
            'placeholder': _('LinkedIn Profile URL (optional)')
        })
    )
    portfolio_url = forms.URLField(
        required=False,
        widget=forms.URLInput(attrs={
            'class': 'form-input',
            'placeholder': _('Portfolio URL (optional)')
        })
    )
    consent_to_store = forms.BooleanField(
        required=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox'
        })
    )
    consent_to_process = forms.BooleanField(
        required=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox'
        })
    )
    marketing_consent = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox'
        })
    )
    # Honeypot field - should be hidden and empty
    website = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'tabindex': '-1',
            'autocomplete': 'off',
            'style': 'position: absolute; left: -9999px;'
        })
    )

    def __init__(self, *args, job_listing=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.job_listing = job_listing

        # Make cover letter required if job requires it
        if job_listing and job_listing.job.require_cover_letter:
            self.fields['cover_letter'].required = True

    def clean_website(self):
        """Honeypot validation - field should be empty."""
        value = self.cleaned_data.get('website')
        if value:
            raise forms.ValidationError(_("Invalid submission detected."))
        return value

    def clean_resume(self):
        """Validate resume file size."""
        resume = self.cleaned_data.get('resume')
        if resume:
            if resume.size > 10 * 1024 * 1024:  # 10MB
                raise forms.ValidationError(_("Resume file size must be under 10MB."))
        return resume


class JobAlertForm(forms.Form):
    """Job alert subscription form."""
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': _('Your email address'),
            'required': True
        })
    )
    departments = forms.MultipleChoiceField(
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={
            'class': 'form-checkbox-group'
        })
    )
    job_types = forms.MultipleChoiceField(
        required=False,
        choices=[
            ('full_time', _('Full-time')),
            ('part_time', _('Part-time')),
            ('contract', _('Contract')),
            ('internship', _('Internship')),
        ],
        widget=forms.CheckboxSelectMultiple(attrs={
            'class': 'form-checkbox-group'
        })
    )
    remote_only = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox'
        })
    )
    frequency = forms.ChoiceField(
        choices=[
            ('daily', _('Daily')),
            ('weekly', _('Weekly')),
            ('monthly', _('Monthly')),
        ],
        initial='weekly',
        widget=forms.Select(attrs={
            'class': 'form-select'
        })
    )


# ==================== MIXINS ====================

class CareerSiteContextMixin:
    """Mixin to add career site configuration to context."""

    def dispatch(self, request, *args, **kwargs):
        """Validate tenant type before processing request."""
        # TENANT TYPE VALIDATION: Only COMPANY tenants can have career pages
        if hasattr(request, 'tenant') and request.tenant:
            if request.tenant.tenant_type != 'company':
                raise Http404(
                    _("Career pages are only available for company tenants. "
                      "Freelancer tenants can showcase services at /services/")
                )

        return super().dispatch(request, *args, **kwargs)

    def get_career_site(self):
        """Get the active career page configuration."""
        try:
            return CareerPage.objects.filter(is_active=True).first()
        except CareerPage.DoesNotExist:
            return None

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        site = self.get_career_site()

        if site:
            context['site'] = site
            context['site_serialized'] = PublicCareerSiteSerializer(
                site, context={'request': self.request}
            ).data

            # CSS variables for branding
            context['css_variables'] = {
                '--primary-color': site.primary_color,
                '--secondary-color': site.secondary_color,
                '--accent-color': site.accent_color,
                '--text-color': site.text_color,
                '--background-color': site.background_color,
            }

            # SEO meta
            context['meta_title'] = site.meta_title or site.title
            context['meta_description'] = site.meta_description or site.tagline
            context['meta_keywords'] = site.meta_keywords

        return context


# ==================== CAREER PAGE VIEWS ====================

class CareerSiteHomeView(CareerSiteContextMixin, TemplateView):
    """
    Career site home page with job listings.
    SEO-optimized server-rendered job listing page with FreelanceHub-style grid.
    """
    template_name = 'careers/browse_jobs.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        site = self.get_career_site()

        if not site:
            raise Http404(_("Career site not found"))

        # Get filter parameters
        category = self.request.GET.get('category')
        location = self.request.GET.get('location')
        job_type = self.request.GET.get('job_type')
        remote = self.request.GET.get('remote')
        search = self.request.GET.get('search', '').strip()
        page = self.request.GET.get('page', 1)

        # Base queryset
        now = timezone.now()
        jobs = JobListing.objects.filter(
            job__status='open',
            job__published_on_career_page=True,
            published_at__isnull=False,
        ).exclude(
            expires_at__lt=now
        ).select_related(
            'job', 'job__category'
        ).order_by('-is_featured', '-feature_priority', '-published_at')

        # Apply filters
        if category:
            jobs = jobs.filter(job__category__slug=category)

        if location:
            jobs = jobs.filter(
                models.Q(job__location_city__icontains=location) |
                models.Q(job__location_country__icontains=location)
            )

        if job_type:
            jobs = jobs.filter(job__job_type=job_type)

        if remote == 'true':
            jobs = jobs.filter(job__remote_policy__in=['remote', 'hybrid', 'flexible'])

        if search:
            jobs = jobs.filter(
                models.Q(job__title__icontains=search) |
                models.Q(job__description__icontains=search) |
                models.Q(job__location_city__icontains=search)
            )

        # Additional filters from new jobs filter component
        industry = self.request.GET.get('industry', '').strip()
        if industry:
            jobs = jobs.filter(job__industry__icontains=industry)

        career_level = self.request.GET.get('career_level', '').strip()
        if career_level:
            jobs = jobs.filter(job__career_level__icontains=career_level)

        # Experience level (checkbox array)
        selected_experience = self.request.GET.getlist('experience')
        if selected_experience:
            jobs = jobs.filter(job__experience_level__in=selected_experience)

        # Salary range filter
        salary_min = self.request.GET.get('salary_min', '').strip()
        salary_max = self.request.GET.get('salary_max', '').strip()
        if salary_min:
            try:
                jobs = jobs.filter(job__salary_min__gte=Decimal(salary_min))
            except (ValueError, Decimal.InvalidOperation):
                pass
        if salary_max:
            try:
                jobs = jobs.filter(job__salary_max__lte=Decimal(salary_max))
            except (ValueError, Decimal.InvalidOperation):
                pass

        # Hourly rate filter
        hourly_min = self.request.GET.get('hourly_min', '').strip()
        hourly_max = self.request.GET.get('hourly_max', '').strip()
        if hourly_min:
            try:
                jobs = jobs.filter(job__hourly_rate_min__gte=Decimal(hourly_min))
            except (ValueError, Decimal.InvalidOperation):
                pass
        if hourly_max:
            try:
                jobs = jobs.filter(job__hourly_rate_max__lte=Decimal(hourly_max))
            except (ValueError, Decimal.InvalidOperation):
                pass

        # Pagination
        paginator = Paginator(jobs, 12)  # 12 jobs per page
        try:
            jobs_page = paginator.page(page)
        except PageNotAnInteger:
            jobs_page = paginator.page(1)
        except EmptyPage:
            jobs_page = paginator.page(paginator.num_pages)

        # Serialize jobs for JSON-LD
        jobs_serialized = PublicJobListSerializer(
            jobs_page.object_list, many=True, context={'request': self.request}
        ).data

        # Get filter options
        from ats.models import JobCategory
        categories = JobCategory.objects.filter(
            is_active=True
        ).annotate(
            job_count=Count('jobs', filter=models.Q(jobs__status='open'))
        ).filter(job_count__gt=0).order_by('name')

        locations = JobListing.objects.filter(
            job__status='open',
            published_at__isnull=False
        ).exclude(
            job__location_city=''
        ).values_list('job__location_city', flat=True).distinct()

        # Additional filter parameters for new jobs filter
        industry = self.request.GET.get('industry', '').strip()
        career_level = self.request.GET.get('career_level', '').strip()
        selected_experience = self.request.GET.getlist('experience')
        salary_min = self.request.GET.get('salary_min', '0')
        salary_max = self.request.GET.get('salary_max', '300000')
        hourly_min = self.request.GET.get('hourly_min', '').strip()
        hourly_max = self.request.GET.get('hourly_max', '').strip()
        radius = self.request.GET.get('radius', '100')

        # Get unique industries for filter dropdown
        from ats.models import Job
        industries = Job.objects.filter(
            status='open'
        ).exclude(
            industry=''
        ).values_list('industry', flat=True).distinct()

        context.update({
            'jobs': jobs_page,
            'jobs_serialized': jobs_serialized,
            'total_jobs': paginator.count,
            'categories': categories,
            'locations': list(set(locations)),
            'industries': list(set(industries)) if industries else [],
            'job_types': [
                ('full_time', _('Full-time')),
                ('part_time', _('Part-time')),
                ('contract', _('Contract')),
                ('internship', _('Internship')),
                ('temporary', _('Temporary')),
                ('freelance', _('Freelance')),
            ],
            # Current filters (match template variable names)
            'selected_category': category,
            'selected_location': location,
            'selected_job_type': job_type,
            'selected_industry': industry,
            'selected_career_level': career_level,
            'selected_experience': selected_experience,
            'selected_remote': remote,
            'salary_min': salary_min,
            'salary_max': salary_max,
            'hourly_min': hourly_min,
            'hourly_max': hourly_max,
            'radius': radius,
            'search': search,
            # Featured jobs
            'featured_jobs': jobs.filter(is_featured=True)[:3],
        })

        return context


@method_decorator(cache_page(60 * 5), name='dispatch')  # 5 minute cache
@method_decorator(vary_on_cookie, name='dispatch')
class BrowseJobsMapView(CareerSiteContextMixin, TemplateView):
    """
    Career site job listings with map view.
    FreelanceHub-style half-map layout with job locations.
    """
    template_name = 'careers/browse_jobs_map.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        site = self.get_career_site()

        if not site:
            raise Http404(_("Career site not found"))

        # Get filter parameters
        category = self.request.GET.get('category')
        location = self.request.GET.get('location')
        job_type = self.request.GET.get('job_type')
        remote = self.request.GET.get('remote')
        search = self.request.GET.get('search', '').strip()
        page = self.request.GET.get('page', 1)

        # Base queryset
        now = timezone.now()
        jobs = JobListing.objects.filter(
            job__status='open',
            job__published_on_career_page=True,
            published_at__isnull=False,
        ).exclude(
            expires_at__lt=now
        ).select_related(
            'job', 'job__category'
        ).order_by('-is_featured', '-feature_priority', '-published_at')

        # Apply filters
        if category:
            jobs = jobs.filter(job__category__slug=category)

        if location:
            jobs = jobs.filter(
                models.Q(job__location_city__icontains=location) |
                models.Q(job__location_country__icontains=location)
            )

        if job_type:
            jobs = jobs.filter(job__job_type=job_type)

        if remote == 'true':
            jobs = jobs.filter(job__remote_policy__in=['remote', 'hybrid', 'flexible'])

        if search:
            jobs = jobs.filter(
                models.Q(job__title__icontains=search) |
                models.Q(job__description__icontains=search) |
                models.Q(job__location_city__icontains=search)
            )

        # Additional filters from new jobs filter component
        industry = self.request.GET.get('industry', '').strip()
        if industry:
            jobs = jobs.filter(job__industry__icontains=industry)

        career_level = self.request.GET.get('career_level', '').strip()
        if career_level:
            jobs = jobs.filter(job__career_level__icontains=career_level)

        # Experience level (checkbox array)
        selected_experience = self.request.GET.getlist('experience')
        if selected_experience:
            jobs = jobs.filter(job__experience_level__in=selected_experience)

        # Salary range filter
        salary_min = self.request.GET.get('salary_min', '').strip()
        salary_max = self.request.GET.get('salary_max', '').strip()
        if salary_min:
            try:
                jobs = jobs.filter(job__salary_min__gte=Decimal(salary_min))
            except (ValueError, Decimal.InvalidOperation):
                pass
        if salary_max:
            try:
                jobs = jobs.filter(job__salary_max__lte=Decimal(salary_max))
            except (ValueError, Decimal.InvalidOperation):
                pass

        # Hourly rate filter
        hourly_min = self.request.GET.get('hourly_min', '').strip()
        hourly_max = self.request.GET.get('hourly_max', '').strip()
        if hourly_min:
            try:
                jobs = jobs.filter(job__hourly_rate_min__gte=Decimal(hourly_min))
            except (ValueError, Decimal.InvalidOperation):
                pass
        if hourly_max:
            try:
                jobs = jobs.filter(job__hourly_rate_max__lte=Decimal(hourly_max))
            except (ValueError, Decimal.InvalidOperation):
                pass

        # Pagination
        paginator = Paginator(jobs, 12)  # 12 jobs per page
        try:
            jobs_page = paginator.page(page)
        except PageNotAnInteger:
            jobs_page = paginator.page(1)
        except EmptyPage:
            jobs_page = paginator.page(paginator.num_pages)

        # Serialize jobs for JSON-LD
        jobs_serialized = PublicJobListSerializer(
            jobs_page.object_list, many=True, context={'request': self.request}
        ).data

        # Get filter options
        from ats.models import JobCategory
        categories = JobCategory.objects.filter(
            is_active=True
        ).annotate(
            job_count=Count('jobs', filter=models.Q(jobs__status='open'))
        ).filter(job_count__gt=0).order_by('name')

        locations = JobListing.objects.filter(
            job__status='open',
            published_at__isnull=False
        ).exclude(
            job__location_city=''
        ).values_list('job__location_city', flat=True).distinct()

        # Additional filter parameters for new jobs filter
        industry = self.request.GET.get('industry', '').strip()
        career_level = self.request.GET.get('career_level', '').strip()
        selected_experience = self.request.GET.getlist('experience')
        salary_min = self.request.GET.get('salary_min', '0')
        salary_max = self.request.GET.get('salary_max', '300000')
        hourly_min = self.request.GET.get('hourly_min', '').strip()
        hourly_max = self.request.GET.get('hourly_max', '').strip()
        radius = self.request.GET.get('radius', '100')

        # Get unique industries for filter dropdown
        from ats.models import Job
        industries = Job.objects.filter(
            status='open'
        ).exclude(
            industry=''
        ).values_list('industry', flat=True).distinct()

        context.update({
            'jobs': jobs_page,
            'jobs_serialized': jobs_serialized,
            'total_jobs': paginator.count,
            'categories': categories,
            'locations': list(set(locations)),
            'industries': list(set(industries)) if industries else [],
            'job_types': [
                ('full_time', _('Full-time')),
                ('part_time', _('Part-time')),
                ('contract', _('Contract')),
                ('internship', _('Internship')),
                ('temporary', _('Temporary')),
                ('freelance', _('Freelance')),
            ],
            # Current filters
            'selected_category': category,
            'selected_location': location,
            'selected_job_type': job_type,
            'selected_industry': industry,
            'selected_career_level': career_level,
            'selected_experience': selected_experience,
            'selected_remote': remote,
            'salary_min': salary_min,
            'salary_max': salary_max,
            'hourly_min': hourly_min,
            'hourly_max': hourly_max,
            'radius': radius,
            'search': search,
            # Featured jobs
            'featured_jobs': jobs.filter(is_featured=True)[:3],
        })

        return context


class JobDetailPageView(CareerSiteContextMixin, TemplateView):
    """
    Job detail page.
    SEO-optimized with structured data for Google Jobs.
    """
    template_name = 'careers/job_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get job listing by ID or slug
        job_id = kwargs.get('pk')
        job_slug = kwargs.get('slug')

        now = timezone.now()

        if job_id:
            job_listing = get_object_or_404(
                JobListing.objects.select_related('job', 'job__category'),
                pk=job_id,
                job__status='open',
                published_at__isnull=False
            )
        elif job_slug:
            job_listing = get_object_or_404(
                JobListing.objects.select_related('job', 'job__category'),
                custom_slug=job_slug,
                job__status='open',
                published_at__isnull=False
            )
        else:
            raise Http404(_("Job not found"))

        # Check expiration
        if job_listing.expires_at and job_listing.expires_at < now:
            raise Http404(_("This job posting has expired"))

        # Increment view count
        JobListing.objects.filter(pk=job_listing.pk).update(
            view_count=F('view_count') + 1
        )
        job_listing.refresh_from_db()

        # Serialize for JSON-LD and template
        job_serialized = PublicJobDetailSerializer(
            job_listing, context={'request': self.request}
        ).data

        # Get related jobs
        related_jobs = []
        if job_listing.job.category:
            related = JobListing.objects.filter(
                job__category=job_listing.job.category,
                job__status='open',
                published_at__isnull=False
            ).exclude(
                pk=job_listing.pk
            ).exclude(
                expires_at__lt=now
            ).select_related('job', 'job__category')[:3]
            related_jobs = PublicJobListSerializer(
                related, many=True, context={'request': self.request}
            ).data

        # Update meta for this specific job
        context['meta_title'] = f"{job_listing.job.title} - {context.get('meta_title', 'Careers')}"
        context['meta_description'] = job_listing.job.meta_description or job_listing.job.description[:160]

        context.update({
            'job': job_listing,
            'job_serialized': job_serialized,
            'structured_data': job_serialized.get('structured_data', {}),
            'related_jobs': related_jobs,
            'application_form': PublicApplicationForm(job_listing=job_listing),
        })

        return context


class ApplicationPageView(CareerSiteContextMixin, FormView):
    """
    Application form page.
    Handles job application submissions with validation.
    """
    template_name = 'careers/application_form.html'
    form_class = PublicApplicationForm

    def get_job_listing(self):
        """Get the job listing for this application."""
        job_id = self.kwargs.get('pk')
        job_slug = self.kwargs.get('slug')

        if job_id:
            return get_object_or_404(JobListing, pk=job_id, job__status='open')
        elif job_slug:
            return get_object_or_404(JobListing, custom_slug=job_slug, job__status='open')
        return None

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['job_listing'] = self.get_job_listing()
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        job_listing = self.get_job_listing()

        if job_listing:
            context['job'] = job_listing
            context['job_serialized'] = PublicJobDetailSerializer(
                job_listing, context={'request': self.request}
            ).data
            context['meta_title'] = f"Apply for {job_listing.job.title}"

        site = self.get_career_site()
        if site:
            context['gdpr_consent_text'] = site.gdpr_consent_text

        return context

    def form_valid(self, form):
        """Handle valid form submission."""
        job_listing = self.get_job_listing()

        # Get client IP
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip_address = x_forwarded_for.split(',')[0].strip()
        else:
            ip_address = self.request.META.get('REMOTE_ADDR')

        # Create application
        try:
            application = PublicApplication.objects.create(
                job_listing=job_listing,
                first_name=form.cleaned_data['first_name'],
                last_name=form.cleaned_data['last_name'],
                email=form.cleaned_data['email'],
                phone=form.cleaned_data.get('phone', ''),
                resume=form.cleaned_data['resume'],
                cover_letter=form.cleaned_data.get('cover_letter', ''),
                linkedin_url=form.cleaned_data.get('linkedin_url', ''),
                portfolio_url=form.cleaned_data.get('portfolio_url', ''),
                privacy_consent=form.cleaned_data['consent_to_store'],
                marketing_consent=form.cleaned_data.get('marketing_consent', False),
                consent_timestamp=timezone.now(),
                consent_ip=ip_address,
                ip_address=ip_address,
                user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
                referrer=self.request.META.get('HTTP_REFERER', ''),
                utm_source=self.request.GET.get('utm_source', ''),
                utm_medium=self.request.GET.get('utm_medium', ''),
                utm_campaign=self.request.GET.get('utm_campaign', ''),
            )

            # Update apply click count
            if job_listing:
                job_listing.apply_click_count = F('apply_click_count') + 1
                job_listing.save(update_fields=['apply_click_count'])

            # Redirect to success page
            return redirect('careers:template:application-success', uuid=application.uuid)

        except Exception as e:
            logger.error(f"Application submission error: {e}")
            form.add_error(None, _("An error occurred. Please try again."))
            return self.form_invalid(form)

    def get_success_url(self):
        return reverse('careers:template:application-success')


class ApplicationSuccessView(CareerSiteContextMixin, TemplateView):
    """Application success confirmation page."""
    template_name = 'careers/application_success.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get application if UUID provided
        app_uuid = kwargs.get('uuid')
        if app_uuid:
            try:
                application = PublicApplication.objects.select_related(
                    'job_listing', 'job_listing__job'
                ).get(uuid=app_uuid)
                context['application'] = application
                if application.job_listing:
                    context['job'] = application.job_listing
            except PublicApplication.DoesNotExist:
                pass

        context['meta_title'] = _('Application Submitted')

        return context


class JobAlertSubscribeView(CareerSiteContextMixin, FormView):
    """Job alert subscription page."""
    template_name = 'careers/alert_subscribe.html'
    form_class = JobAlertForm

    def get_form(self, form_class=None):
        form = super().get_form(form_class)

        # Populate department choices from categories
        from ats.models import JobCategory
        categories = JobCategory.objects.filter(is_active=True).values_list('slug', 'name')
        form.fields['departments'].choices = list(categories)

        return form

    def form_valid(self, form):
        """Handle job alert subscription."""
        # Get or create the career site for this tenant
        career_site = CareerSite.objects.first()
        if not career_site:
            # Create a default career site if none exists
            career_site = CareerSite.objects.create(
                subdomain='default',
                company_name='Company',
            )

        email = form.cleaned_data['email']

        # Check if subscription already exists
        existing = JobAlert.objects.filter(
            career_site=career_site,
            email=email
        ).first()

        if existing:
            if existing.status == JobAlert.AlertStatus.UNSUBSCRIBED:
                # Reactivate the subscription
                existing.status = JobAlert.AlertStatus.PENDING
                existing.departments = form.cleaned_data.get('departments', [])
                existing.job_types = form.cleaned_data.get('job_types', [])
                existing.remote_only = form.cleaned_data.get('remote_only', False)
                existing.frequency = form.cleaned_data.get('frequency', 'weekly')
                existing.save()
                messages.success(
                    self.request,
                    _("Your subscription has been reactivated. Please check your email to confirm.")
                )
            else:
                messages.info(
                    self.request,
                    _("You are already subscribed to job alerts.")
                )
            return redirect('careers:template:alert-confirmed')

        # Create new job alert subscription
        job_alert = JobAlert.objects.create(
            career_site=career_site,
            email=email,
            departments=form.cleaned_data.get('departments', []),
            job_types=form.cleaned_data.get('job_types', []),
            remote_only=form.cleaned_data.get('remote_only', False),
            frequency=form.cleaned_data.get('frequency', 'weekly'),
            ip_address=self.get_client_ip(),
            status=JobAlert.AlertStatus.PENDING,
        )

        # Send confirmation email
        self.send_confirmation_email(job_alert)

        messages.success(
            self.request,
            _("You have been subscribed to job alerts. Please check your email to confirm.")
        )
        return redirect('careers:template:alert-confirmed')

    def get_client_ip(self):
        """Get client IP address from request."""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip

    def send_confirmation_email(self, job_alert):
        """Send confirmation email to subscriber."""
        try:
            from django.core.mail import send_mail
            from django.template.loader import render_to_string
            from django.conf import settings

            # Build confirmation URL
            confirm_url = self.request.build_absolute_uri(
                reverse('careers:template:alert-confirm', kwargs={
                    'token': str(job_alert.confirmation_token)
                })
            )

            subject = _("Confirm your job alert subscription")
            message = render_to_string('careers/emails/confirm_subscription.txt', {
                'job_alert': job_alert,
                'confirm_url': confirm_url,
            })
            html_message = render_to_string('careers/emails/confirm_subscription.html', {
                'job_alert': job_alert,
                'confirm_url': confirm_url,
            })

            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[job_alert.email],
                html_message=html_message,
                fail_silently=True,
            )
        except Exception as e:
            logger.error(f"Failed to send confirmation email: {e}")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['meta_title'] = _('Subscribe to Job Alerts')
        return context


class JobAlertConfirmedView(CareerSiteContextMixin, TemplateView):
    """Job alert subscription confirmed page."""
    template_name = 'careers/alert_confirmed.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['meta_title'] = _('Subscription Confirmed')
        return context


class JobAlertConfirmTokenView(View):
    """Handle email confirmation token for job alerts."""

    def dispatch(self, request, *args, **kwargs):
        """Validate tenant type before processing request."""
        # TENANT TYPE VALIDATION: Only COMPANY tenants can have career pages
        if hasattr(request, 'tenant') and request.tenant:
            if request.tenant.tenant_type != 'company':
                raise Http404(
                    _("Career pages are only available for company tenants.")
                )
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, token):
        """Confirm the subscription using the token."""
        try:
            job_alert = JobAlert.objects.get(confirmation_token=token)

            if job_alert.status == JobAlert.AlertStatus.PENDING:
                job_alert.confirm()
                messages.success(
                    request,
                    _("Your job alert subscription has been confirmed! You will now receive alerts for new jobs.")
                )
            elif job_alert.status == JobAlert.AlertStatus.ACTIVE:
                messages.info(
                    request,
                    _("Your subscription was already confirmed.")
                )
            else:
                messages.warning(
                    request,
                    _("This subscription is no longer active.")
                )

            return redirect('careers:template:alert-confirmed')

        except JobAlert.DoesNotExist:
            messages.error(
                request,
                _("Invalid confirmation link. Please try subscribing again.")
            )
            return redirect('careers:template:subscribe')


class JobAlertUnsubscribeTokenView(View):
    """Handle unsubscribe token for job alerts."""

    def dispatch(self, request, *args, **kwargs):
        """Validate tenant type before processing request."""
        # TENANT TYPE VALIDATION: Only COMPANY tenants can have career pages
        if hasattr(request, 'tenant') and request.tenant:
            if request.tenant.tenant_type != 'company':
                raise Http404(
                    _("Career pages are only available for company tenants.")
                )
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, token):
        """Unsubscribe using the token."""
        try:
            job_alert = JobAlert.objects.get(unsubscribe_token=token)

            if job_alert.status != JobAlert.AlertStatus.UNSUBSCRIBED:
                job_alert.unsubscribe()
                messages.success(
                    request,
                    _("You have been unsubscribed from job alerts.")
                )
            else:
                messages.info(
                    request,
                    _("You were already unsubscribed.")
                )

            return redirect('careers:template:alert-unsubscribed')

        except JobAlert.DoesNotExist:
            messages.error(
                request,
                _("Invalid unsubscribe link.")
            )
            return redirect('careers:template:home')


class JobAlertUnsubscribedView(CareerSiteContextMixin, TemplateView):
    """Job alert unsubscribed confirmation page."""
    template_name = 'careers/alert_unsubscribed.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['meta_title'] = _('Unsubscribed from Job Alerts')
        return context


# ==================== UTILITY VIEWS ====================

class RobotsTxtView(View):
    """Generate robots.txt for career pages."""

    def dispatch(self, request, *args, **kwargs):
        """Validate tenant type before processing request."""
        # TENANT TYPE VALIDATION: Only COMPANY tenants can have career pages
        if hasattr(request, 'tenant') and request.tenant:
            if request.tenant.tenant_type != 'company':
                raise Http404(
                    _("Career pages are only available for company tenants.")
                )
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        from django.http import HttpResponse
        lines = [
            "User-agent: *",
            "Allow: /careers/",
            "Allow: /careers/jobs/",
            f"Sitemap: {request.build_absolute_uri('/careers/sitemap.xml')}",
        ]
        return HttpResponse("\n".join(lines), content_type="text/plain")


class CareersSitemapView(View):
    """Generate sitemap for career pages."""

    def dispatch(self, request, *args, **kwargs):
        """Validate tenant type before processing request."""
        # TENANT TYPE VALIDATION: Only COMPANY tenants can have career pages
        if hasattr(request, 'tenant') and request.tenant:
            if request.tenant.tenant_type != 'company':
                raise Http404(
                    _("Career pages are only available for company tenants.")
                )
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        from django.http import HttpResponse
        from django.utils import timezone

        now = timezone.now()
        base_url = request.build_absolute_uri('/careers/')

        urls = []

        # Add career home
        urls.append({
            'loc': base_url,
            'changefreq': 'daily',
            'priority': '1.0'
        })

        # Add job listings
        jobs = JobListing.objects.filter(
            job__status='open',
            published_at__isnull=False
        ).exclude(expires_at__lt=now)

        for job in jobs:
            if job.custom_slug:
                url = f"{base_url}jobs/{job.custom_slug}/"
            else:
                url = f"{base_url}jobs/{job.pk}/"

            urls.append({
                'loc': url,
                'lastmod': job.published_at.strftime('%Y-%m-%d') if job.published_at else now.strftime('%Y-%m-%d'),
                'changefreq': 'weekly',
                'priority': '0.8'
            })

        # Build XML
        xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml_content += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'

        for url_info in urls:
            xml_content += '  <url>\n'
            for key, value in url_info.items():
                xml_content += f'    <{key}>{value}</{key}>\n'
            xml_content += '  </url>\n'

        xml_content += '</urlset>'

        return HttpResponse(xml_content, content_type='application/xml')


# ==================== COMPANY BROWSING VIEWS ====================

@method_decorator(cache_page(60 * 5), name='dispatch')  # 5 minute cache
@method_decorator(vary_on_cookie, name='dispatch')
class BrowseCompaniesView(TemplateView):
    """
    Public company browsing page with grid layout.
    FreelanceHub-style grid view for browsing all active companies on the platform.
    """
    template_name = 'careers/browse_companies.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get filter parameters
        location = self.request.GET.get('location', '').strip()
        industry = self.request.GET.get('industry', '').strip()
        search = self.request.GET.get('search', '').strip()
        page = self.request.GET.get('page', 1)

        # Import Tenant model
        from tenants.models import Tenant

        # Base queryset - only active companies
        companies = Tenant.objects.filter(
            status=Tenant.TenantStatus.ACTIVE,
            tenant_type=Tenant.TenantType.COMPANY
        ).select_related('plan')

        # Annotate with open jobs count
        from ats.models import Job
        companies = companies.annotate(
            open_jobs_count=Count(
                'jobs',
                filter=models.Q(jobs__status='open')
            )
        )

        # Apply filters
        if location:
            companies = companies.filter(
                models.Q(city__icontains=location) |
                models.Q(state__icontains=location) |
                models.Q(country__icontains=location)
            )

        if industry:
            companies = companies.filter(industry__icontains=industry)

        if search:
            companies = companies.filter(
                models.Q(name__icontains=search) |
                models.Q(industry__icontains=search) |
                models.Q(city__icontains=search) |
                models.Q(country__icontains=search)
            )

        # Company size filter
        company_size = self.request.GET.get('company_size', '').strip()
        if company_size:
            # Parse company size range (e.g., "1-5 employees" -> filter by employee_count)
            import re
            size_match = re.match(r'(\d+)-(\d+)', company_size)
            if size_match:
                min_size = int(size_match.group(1))
                max_size = int(size_match.group(2))
                # Assuming Tenant model has an employee_count field
                # If not, this filter will be ignored
                if hasattr(Tenant, 'employee_count'):
                    companies = companies.filter(
                        employee_count__gte=min_size,
                        employee_count__lte=max_size
                    )

        # Order by: companies with most open jobs first
        companies = companies.order_by('-open_jobs_count', '-created_at')

        # Pagination
        paginator = Paginator(companies, 16)  # 16 companies per page (4x4 grid)
        try:
            companies_page = paginator.page(page)
        except PageNotAnInteger:
            companies_page = paginator.page(1)
        except EmptyPage:
            companies_page = paginator.page(paginator.num_pages)

        # Get unique industries for filter dropdown
        industries = Tenant.objects.filter(
            status=Tenant.TenantStatus.ACTIVE,
            tenant_type=Tenant.TenantType.COMPANY
        ).exclude(industry='').values_list('industry', flat=True).distinct()

        # Add company_logo property to each company for template compatibility
        for company in companies_page.object_list:
            company.company_logo = company.logo
            company.location_city = company.city
            company.location_country = company.country

        # Get filter parameters for new companies filter
        company_size = self.request.GET.get('company_size', '').strip()
        radius = self.request.GET.get('radius', '100')

        # Get unique locations for filter dropdown
        locations = Tenant.objects.filter(
            status=Tenant.TenantStatus.ACTIVE,
            tenant_type=Tenant.TenantType.COMPANY
        ).exclude(city='').values_list('city', flat=True).distinct()

        context.update({
            'companies': companies_page,
            'total_companies': paginator.count,
            'industries': list(set(industries)),
            'locations': list(set(locations)),
            'view_mode': 'grid',
            # Current filters
            'selected_location': location,
            'selected_industry': industry,
            'selected_size': company_size,
            'radius': radius,
            'search': search,
            # Meta tags
            'meta_description': _('Browse and discover companies hiring on Zumodra. Find your next opportunity at top companies.'),
        })

        return context


@method_decorator(cache_page(60 * 5), name='dispatch')  # 5 minute cache
@method_decorator(vary_on_cookie, name='dispatch')
class BrowseCompaniesMapView(TemplateView):
    """
    Public company browsing page with map layout.
    FreelanceHub-style half-map view showing companies on an interactive map.
    """
    template_name = 'careers/browse_companies_map.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get filter parameters
        location = self.request.GET.get('location', '').strip()
        industry = self.request.GET.get('industry', '').strip()
        search = self.request.GET.get('search', '').strip()
        page = self.request.GET.get('page', 1)

        # Import Tenant model
        from tenants.models import Tenant

        # Base queryset - only active companies
        companies = Tenant.objects.filter(
            status=Tenant.TenantStatus.ACTIVE,
            tenant_type=Tenant.TenantType.COMPANY
        ).select_related('plan')

        # Annotate with open jobs count
        from ats.models import Job
        companies = companies.annotate(
            open_jobs_count=Count(
                'jobs',
                filter=models.Q(jobs__status='open')
            )
        )

        # Apply filters
        if location:
            companies = companies.filter(
                models.Q(city__icontains=location) |
                models.Q(state__icontains=location) |
                models.Q(country__icontains=location)
            )

        if industry:
            companies = companies.filter(industry__icontains=industry)

        if search:
            companies = companies.filter(
                models.Q(name__icontains=search) |
                models.Q(industry__icontains=search) |
                models.Q(city__icontains=search) |
                models.Q(country__icontains=search)
            )

        # Company size filter
        company_size = self.request.GET.get('company_size', '').strip()
        if company_size:
            # Parse company size range (e.g., "1-5 employees" -> filter by employee_count)
            import re
            size_match = re.match(r'(\d+)-(\d+)', company_size)
            if size_match:
                min_size = int(size_match.group(1))
                max_size = int(size_match.group(2))
                # Assuming Tenant model has an employee_count field
                # If not, this filter will be ignored
                if hasattr(Tenant, 'employee_count'):
                    companies = companies.filter(
                        employee_count__gte=min_size,
                        employee_count__lte=max_size
                    )

        # Order by: companies with most open jobs first
        companies = companies.order_by('-open_jobs_count', '-created_at')

        # Pagination
        paginator = Paginator(companies, 12)  # 12 companies per page for map view
        try:
            companies_page = paginator.page(page)
        except PageNotAnInteger:
            companies_page = paginator.page(1)
        except EmptyPage:
            companies_page = paginator.page(paginator.num_pages)

        # Get unique industries for filter dropdown
        industries = Tenant.objects.filter(
            status=Tenant.TenantStatus.ACTIVE,
            tenant_type=Tenant.TenantType.COMPANY
        ).exclude(industry='').values_list('industry', flat=True).distinct()

        # Add company_logo and location properties for template compatibility
        for company in companies_page.object_list:
            company.company_logo = company.logo
            company.location_city = company.city
            company.location_country = company.country
            # For map markers, we'll need coordinates
            # See TODO-CAREERS-001 in careers/TODO.md for geocoding implementation
            company.location_coordinates = None

        # Get filter parameters for new companies filter
        company_size = self.request.GET.get('company_size', '').strip()
        radius = self.request.GET.get('radius', '100')

        # Get unique locations for filter dropdown
        locations = Tenant.objects.filter(
            status=Tenant.TenantStatus.ACTIVE,
            tenant_type=Tenant.TenantType.COMPANY
        ).exclude(city='').values_list('city', flat=True).distinct()

        context.update({
            'companies': companies_page,
            'total_companies': paginator.count,
            'industries': list(set(industries)),
            'locations': list(set(locations)),
            'view_mode': 'map',
            # Current filters
            'selected_location': location,
            'selected_industry': industry,
            'selected_size': company_size,
            'radius': radius,
            'search': search,
            # Meta tags
            'meta_description': _('Browse companies on a map. Find companies hiring in your area.'),
        })

        return context


# ==================== PROJECT/SERVICE BROWSING VIEWS ====================

@method_decorator(cache_page(60 * 5), name='dispatch')  # 5 minute cache
@method_decorator(vary_on_cookie, name='dispatch')
class BrowseProjectsView(TemplateView):
    """
    Public projects/services browsing page with grid layout.
    FreelanceHub-style grid view for browsing freelance projects and services.
    """
    template_name = 'careers/browse_projects.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get filter parameters
        category = self.request.GET.get('category', '').strip()
        location = self.request.GET.get('location', '').strip()
        search = self.request.GET.get('search', '').strip()
        budget_min = self.request.GET.get('budget_min', '').strip()
        budget_max = self.request.GET.get('budget_max', '').strip()
        page = self.request.GET.get('page', 1)

        # Import Service model
        from services.models import Service

        # Base queryset - only active services
        projects = Service.objects.filter(
            is_active=True
        ).select_related('provider', 'category')

        # Apply filters
        if category:
            projects = projects.filter(
                models.Q(category__slug__icontains=category) |
                models.Q(category__name__icontains=category)
            )

        if location:
            projects = projects.filter(
                models.Q(provider__city__icontains=location) |
                models.Q(provider__state__icontains=location) |
                models.Q(provider__country__icontains=location)
            )

        if search:
            projects = projects.filter(
                models.Q(name__icontains=search) |
                models.Q(description__icontains=search) |
                models.Q(short_description__icontains=search) |
                models.Q(provider__city__icontains=search)
            )

        if budget_min:
            try:
                projects = projects.filter(price__gte=Decimal(budget_min))
            except (ValueError, Decimal.InvalidOperation):
                pass

        if budget_max:
            try:
                projects = projects.filter(price__lte=Decimal(budget_max))
            except (ValueError, Decimal.InvalidOperation):
                pass

        # Additional filters from new projects filter component
        timezone_param = self.request.GET.get('timezone', '').strip()
        if timezone_param:
            # Assuming Service model has a timezone field
            if hasattr(projects.model, 'timezone'):
                projects = projects.filter(timezone__icontains=timezone_param)

        english_level = self.request.GET.get('english_level', '').strip()
        if english_level:
            # Assuming Service model has an english_level field
            if hasattr(projects.model, 'english_level'):
                projects = projects.filter(english_level__icontains=english_level)

        # Experience level (checkbox array)
        selected_experience = self.request.GET.getlist('experience')
        if selected_experience:
            # Assuming Service model has an experience_level field
            if hasattr(projects.model, 'experience_level'):
                projects = projects.filter(experience_level__in=selected_experience)

        # Fixed-price range filter (use price_min/price_max from new filter)
        price_min = self.request.GET.get('price_min', '').strip()
        price_max = self.request.GET.get('price_max', '').strip()
        if price_min:
            try:
                projects = projects.filter(price__gte=Decimal(price_min))
            except (ValueError, Decimal.InvalidOperation):
                pass
        if price_max:
            try:
                projects = projects.filter(price__lte=Decimal(price_max))
            except (ValueError, Decimal.InvalidOperation):
                pass

        # Hourly rate filter
        hourly_min = self.request.GET.get('hourly_min', '').strip()
        hourly_max = self.request.GET.get('hourly_max', '').strip()
        if hourly_min:
            try:
                # Assuming Service model has an hourly_rate field
                if hasattr(projects.model, 'hourly_rate'):
                    projects = projects.filter(hourly_rate__gte=Decimal(hourly_min))
            except (ValueError, Decimal.InvalidOperation):
                pass
        if hourly_max:
            try:
                if hasattr(projects.model, 'hourly_rate'):
                    projects = projects.filter(hourly_rate__lte=Decimal(hourly_max))
            except (ValueError, Decimal.InvalidOperation):
                pass

        # Order by: newest first
        projects = projects.order_by('-created_at')

        # Pagination
        paginator = Paginator(projects, 12)  # 12 projects per page
        try:
            projects_page = paginator.page(page)
        except PageNotAnInteger:
            projects_page = paginator.page(1)
        except EmptyPage:
            projects_page = paginator.page(paginator.num_pages)

        # Get unique categories for filter dropdown
        from services.models import ServiceCategory
        categories = ServiceCategory.objects.filter(
            services__is_active=True
        ).distinct()

        # Add computed properties for template compatibility
        for project in projects_page.object_list:
            project.title = project.name
            project.location = f"{project.provider.city}, {project.provider.country}" if project.provider.city else "Remote"
            project.budget = project.price or 0
            project.budget_type = 'fixed-price' if project.service_type == 'fixed' else 'hourly'
            # Use order_count as proxy for proposal/interest count
            # Note: CrossTenantServiceRequests live in requester schemas, making direct counting expensive
            project.proposal_count = project.order_count or 0
            # Calculate client spending: sum of completed contracts where provider's user is the client
            # This shows the financial reliability of the service provider as a client
            from services.models import ServiceContract
            from django.db.models import Sum
            provider_spending = ServiceContract.objects.filter(
                client=project.provider.user,
                status=ServiceContract.ContractStatus.COMPLETED
            ).aggregate(total=Sum('agreed_rate'))['total'] or Decimal('0.00')
            project.client_spent = float(provider_spending)

        # Additional filter parameters for new projects filter
        timezone_param = self.request.GET.get('timezone', '').strip()
        english_level = self.request.GET.get('english_level', '').strip()
        selected_experience = self.request.GET.getlist('experience')
        price_min = self.request.GET.get('price_min', '0')
        price_max = self.request.GET.get('price_max', '3000')
        hourly_min = self.request.GET.get('hourly_min', '').strip()
        hourly_max = self.request.GET.get('hourly_max', '').strip()

        # Static filter options for projects
        locations_list = ['Africa', 'Americas', 'Antarctica', 'Asia', 'Europe', 'Oceania', 'Australia and New Zealand']
        timezones_list = [
            '(UTC-11:00) Midway Island',
            '(UTC-10:00) Hawaii',
            '(UTC-08:00) Alaska',
            '(UTC-07:00) Pacific Time',
            '(UTC-07:00) Arizona',
            '(UTC-06:00) Mountain Time',
            '(UTC-05:00) Eastern Time',
        ]
        english_levels_list = ['Basic', 'Conversational', 'Fluent', 'Native Or Bilingual', 'Professional']

        context.update({
            'projects': projects_page,
            'total_projects': paginator.count,
            'categories': categories,
            'locations': locations_list,
            'timezones': timezones_list,
            'english_levels': english_levels_list,
            # Current filters
            'selected_category': category,
            'selected_location': location,
            'selected_timezone': timezone_param,
            'selected_english_level': english_level,
            'selected_experience': selected_experience,
            'price_min': price_min,
            'price_max': price_max,
            'hourly_min': hourly_min,
            'hourly_max': hourly_max,
            'search': search,
            # Legacy budget params (keep for backward compatibility)
            'budget_min': budget_min,
            'budget_max': budget_max,
            # Meta tags
            'meta_description': _('Browse freelance projects and services on Zumodra. Find your next freelance opportunity.'),
        })

        return context


@method_decorator(cache_page(60 * 5), name='dispatch')  # 5 minute cache
@method_decorator(vary_on_cookie, name='dispatch')
class BrowseProjectsMapView(TemplateView):
    """
    Public projects/services browsing page with map layout.
    FreelanceHub-style half-map view showing projects on an interactive map.
    """
    template_name = 'careers/browse_projects_map.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get filter parameters
        category = self.request.GET.get('category', '').strip()
        location = self.request.GET.get('location', '').strip()
        search = self.request.GET.get('search', '').strip()
        budget_min = self.request.GET.get('budget_min', '').strip()
        budget_max = self.request.GET.get('budget_max', '').strip()
        page = self.request.GET.get('page', 1)

        # Import Service model
        from services.models import Service

        # Base queryset - only active services
        projects = Service.objects.filter(
            is_active=True
        ).select_related('provider', 'category')

        # Apply filters
        if category:
            projects = projects.filter(
                models.Q(category__slug__icontains=category) |
                models.Q(category__name__icontains=category)
            )

        if location:
            projects = projects.filter(
                models.Q(provider__city__icontains=location) |
                models.Q(provider__state__icontains=location) |
                models.Q(provider__country__icontains=location)
            )

        if search:
            projects = projects.filter(
                models.Q(name__icontains=search) |
                models.Q(description__icontains=search) |
                models.Q(short_description__icontains=search) |
                models.Q(provider__city__icontains=search)
            )

        if budget_min:
            try:
                projects = projects.filter(price__gte=Decimal(budget_min))
            except (ValueError, Decimal.InvalidOperation):
                pass

        if budget_max:
            try:
                projects = projects.filter(price__lte=Decimal(budget_max))
            except (ValueError, Decimal.InvalidOperation):
                pass

        # Additional filters from new projects filter component
        timezone_param = self.request.GET.get('timezone', '').strip()
        if timezone_param:
            # Assuming Service model has a timezone field
            if hasattr(projects.model, 'timezone'):
                projects = projects.filter(timezone__icontains=timezone_param)

        english_level = self.request.GET.get('english_level', '').strip()
        if english_level:
            # Assuming Service model has an english_level field
            if hasattr(projects.model, 'english_level'):
                projects = projects.filter(english_level__icontains=english_level)

        # Experience level (checkbox array)
        selected_experience = self.request.GET.getlist('experience')
        if selected_experience:
            # Assuming Service model has an experience_level field
            if hasattr(projects.model, 'experience_level'):
                projects = projects.filter(experience_level__in=selected_experience)

        # Fixed-price range filter (use price_min/price_max from new filter)
        price_min = self.request.GET.get('price_min', '').strip()
        price_max = self.request.GET.get('price_max', '').strip()
        if price_min:
            try:
                projects = projects.filter(price__gte=Decimal(price_min))
            except (ValueError, Decimal.InvalidOperation):
                pass
        if price_max:
            try:
                projects = projects.filter(price__lte=Decimal(price_max))
            except (ValueError, Decimal.InvalidOperation):
                pass

        # Hourly rate filter
        hourly_min = self.request.GET.get('hourly_min', '').strip()
        hourly_max = self.request.GET.get('hourly_max', '').strip()
        if hourly_min:
            try:
                # Assuming Service model has an hourly_rate field
                if hasattr(projects.model, 'hourly_rate'):
                    projects = projects.filter(hourly_rate__gte=Decimal(hourly_min))
            except (ValueError, Decimal.InvalidOperation):
                pass
        if hourly_max:
            try:
                if hasattr(projects.model, 'hourly_rate'):
                    projects = projects.filter(hourly_rate__lte=Decimal(hourly_max))
            except (ValueError, Decimal.InvalidOperation):
                pass

        # Order by: newest first
        projects = projects.order_by('-created_at')

        # Pagination
        paginator = Paginator(projects, 12)  # 12 projects per page for map view
        try:
            projects_page = paginator.page(page)
        except PageNotAnInteger:
            projects_page = paginator.page(1)
        except EmptyPage:
            projects_page = paginator.page(paginator.num_pages)

        # Get unique categories for filter dropdown
        from services.models import ServiceCategory
        categories = ServiceCategory.objects.filter(
            services__is_active=True
        ).distinct()

        # Add computed properties and coordinates for template/map compatibility
        for project in projects_page.object_list:
            project.title = project.name
            project.location = f"{project.provider.city}, {project.provider.country}" if project.provider.city else "Remote"
            project.budget = project.price or 0
            project.budget_type = 'fixed-price' if project.service_type == 'fixed' else 'hourly'
            # Use order_count as proxy for proposal/interest count
            # Note: CrossTenantServiceRequests live in requester schemas, making direct counting expensive
            project.proposal_count = project.order_count or 0
            # Calculate client spending: sum of completed contracts where provider's user is the client
            # This shows the financial reliability of the service provider as a client
            from services.models import ServiceContract
            from django.db.models import Sum
            provider_spending = ServiceContract.objects.filter(
                client=project.provider.user,
                status=ServiceContract.ContractStatus.COMPLETED
            ).aggregate(total=Sum('agreed_rate'))['total'] or Decimal('0.00')
            project.client_spent = float(provider_spending)
            # For map markers, use provider's location if available
            project.location_coordinates = project.provider.location if hasattr(project.provider, 'location') else None

        # Additional filter parameters for new projects filter
        timezone_param = self.request.GET.get('timezone', '').strip()
        english_level = self.request.GET.get('english_level', '').strip()
        selected_experience = self.request.GET.getlist('experience')
        price_min = self.request.GET.get('price_min', '0')
        price_max = self.request.GET.get('price_max', '3000')
        hourly_min = self.request.GET.get('hourly_min', '').strip()
        hourly_max = self.request.GET.get('hourly_max', '').strip()

        # Static filter options for projects
        locations_list = ['Africa', 'Americas', 'Antarctica', 'Asia', 'Europe', 'Oceania', 'Australia and New Zealand']
        timezones_list = [
            '(UTC-11:00) Midway Island',
            '(UTC-10:00) Hawaii',
            '(UTC-08:00) Alaska',
            '(UTC-07:00) Pacific Time',
            '(UTC-07:00) Arizona',
            '(UTC-06:00) Mountain Time',
            '(UTC-05:00) Eastern Time',
        ]
        english_levels_list = ['Basic', 'Conversational', 'Fluent', 'Native Or Bilingual', 'Professional']

        context.update({
            'projects': projects_page,
            'total_projects': paginator.count,
            'categories': categories,
            'locations': locations_list,
            'timezones': timezones_list,
            'english_levels': english_levels_list,
            'view_mode': 'map',
            # Current filters
            'selected_category': category,
            'selected_location': location,
            'selected_timezone': timezone_param,
            'selected_english_level': english_level,
            'selected_experience': selected_experience,
            'price_min': price_min,
            'price_max': price_max,
            'hourly_min': hourly_min,
            'hourly_max': hourly_max,
            'search': search,
            # Legacy budget params (keep for backward compatibility)
            'budget_min': budget_min,
            'budget_max': budget_max,
            # Meta tags
            'meta_description': _('Browse freelance projects on a map. Find projects in your area.'),
        })

        return context
