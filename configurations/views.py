"""
Configurations App Views - Template views for organization management.

Provides dashboard views for:
- Skills management
- Company/Organization structure
- Website content management (FAQ, Testimonials)
"""

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count
from django.views.generic import TemplateView

from tenants.mixins import TenantViewMixin

from .models import (
    Skill,
    Company,
    Site,
    Department,
    Role,
    Membership,
    Job,
    JobApplication,
    FAQEntry,
    Testimonial,
    Partnership,
    TrustedCompany,
)


class ConfigurationsDashboardView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """
    Dashboard for configurations management.

    Shows overview of:
    - Skills taxonomy
    - Company structure
    - Website content status
    """
    template_name = 'configurations/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.get_tenant()

        if not tenant:
            return context

        # Skills stats
        skills_qs = Skill.objects.filter(tenant=tenant)
        context['skills_stats'] = {
            'total': skills_qs.count(),
            'verified': skills_qs.filter(is_verified=True).count(),
            'categories': skills_qs.values('category').distinct().count(),
        }

        # Company stats
        companies_qs = Company.objects.filter(tenant=tenant)
        context['company_stats'] = {
            'total': companies_qs.count(),
            'verified': companies_qs.filter(is_verified=True).count(),
            'sites': Site.objects.filter(tenant=tenant, is_active=True).count(),
            'departments': Department.objects.filter(tenant=tenant).count(),
            'roles': Role.objects.filter(tenant=tenant).count(),
            'active_memberships': Membership.objects.filter(tenant=tenant, is_active=True).count(),
        }

        # Job board stats
        jobs_qs = Job.objects.filter(tenant=tenant)
        context['job_stats'] = {
            'total': jobs_qs.count(),
            'active': jobs_qs.filter(is_active=True).count(),
            'applications': JobApplication.objects.filter(tenant=tenant).count(),
            'pending_applications': JobApplication.objects.filter(
                tenant=tenant,
                status='pending'
            ).count(),
        }

        # Website content stats
        context['content_stats'] = {
            'faqs_total': FAQEntry.objects.filter(tenant=tenant).count(),
            'faqs_published': FAQEntry.objects.filter(tenant=tenant, is_published=True).count(),
            'testimonials_total': Testimonial.objects.filter(tenant=tenant).count(),
            'testimonials_published': Testimonial.objects.filter(tenant=tenant, is_published=True).count(),
            'partnerships': Partnership.objects.filter(tenant=tenant).count(),
            'trusted_companies': TrustedCompany.objects.filter(tenant=tenant).count(),
        }

        # Recent skills
        context['recent_skills'] = skills_qs.order_by('-created_at')[:5]

        # Recent companies
        context['recent_companies'] = companies_qs.order_by('-created_at')[:5]

        # Skills by category
        context['skills_by_category'] = skills_qs.values('category').annotate(
            count=Count('id')
        ).order_by('-count')[:10]

        return context


class SkillsListView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """Skills management list view."""
    template_name = 'configurations/skills_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.get_tenant()

        if tenant:
            skills = Skill.objects.filter(tenant=tenant).order_by('name')

            # Apply filters
            category = self.request.GET.get('category')
            if category:
                skills = skills.filter(category=category)

            verified = self.request.GET.get('verified')
            if verified == 'true':
                skills = skills.filter(is_verified=True)
            elif verified == 'false':
                skills = skills.filter(is_verified=False)

            search = self.request.GET.get('q')
            if search:
                skills = skills.filter(name__icontains=search)

            context['skills'] = skills
            context['categories'] = Skill.objects.filter(tenant=tenant).values_list(
                'category', flat=True
            ).distinct()
            context['current_filters'] = {
                'category': category,
                'verified': verified,
                'q': search or '',
            }

        return context


class CompanyListView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """Company management list view."""
    template_name = 'configurations/company_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.get_tenant()

        if tenant:
            companies = Company.objects.filter(tenant=tenant).annotate(
                sites_count=Count('sites')
            ).order_by('name')

            # Apply filters
            industry = self.request.GET.get('industry')
            if industry:
                companies = companies.filter(industry__icontains=industry)

            search = self.request.GET.get('q')
            if search:
                companies = companies.filter(name__icontains=search)

            context['companies'] = companies
            context['industries'] = Company.objects.filter(tenant=tenant).values_list(
                'industry', flat=True
            ).distinct()
            context['current_filters'] = {
                'industry': industry,
                'q': search or '',
            }

        return context


class FAQListView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """FAQ management list view."""
    template_name = 'configurations/faq_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.get_tenant()

        if tenant:
            faqs = FAQEntry.objects.filter(tenant=tenant).order_by('sort_order', 'category')

            # Apply filters
            category = self.request.GET.get('category')
            if category:
                faqs = faqs.filter(category=category)

            published = self.request.GET.get('published')
            if published == 'true':
                faqs = faqs.filter(is_published=True)
            elif published == 'false':
                faqs = faqs.filter(is_published=False)

            context['faqs'] = faqs
            context['categories'] = FAQEntry.objects.filter(tenant=tenant).values_list(
                'category', flat=True
            ).distinct()
            context['current_filters'] = {
                'category': category,
                'published': published,
            }

        return context


class TestimonialsListView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """Testimonials management list view."""
    template_name = 'configurations/testimonials_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.get_tenant()

        if tenant:
            testimonials = Testimonial.objects.filter(tenant=tenant).order_by('-created_at')

            # Apply filters
            published = self.request.GET.get('published')
            if published == 'true':
                testimonials = testimonials.filter(is_published=True)
            elif published == 'false':
                testimonials = testimonials.filter(is_published=False)

            featured = self.request.GET.get('featured')
            if featured == 'true':
                testimonials = testimonials.filter(is_featured=True)

            context['testimonials'] = testimonials
            context['current_filters'] = {
                'published': published,
                'featured': featured,
            }

        return context
