"""
Marketing Campaigns Frontend Views

HTMX-powered template views for marketing campaigns management.
"""

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView, ListView, DetailView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from django.db.models import Count, Q
from django.utils import timezone

from tenants.mixins import TenantViewMixin
from core.mixins import HTMXMixin
from .models import Contact, MarketingCampaign, CampaignTracking, VisitEvent


class MarketingCampaignsDashboardView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """Marketing campaigns dashboard"""
    template_name = 'marketing_campaigns/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Quick stats
        context['total_contacts'] = Contact.objects.count()
        context['total_campaigns'] = MarketingCampaign.objects.count()
        context['active_campaigns'] = MarketingCampaign.objects.filter(
            status='active'
        ).count()
        context['total_visits'] = VisitEvent.objects.count()

        # Recent campaigns
        context['recent_campaigns'] = MarketingCampaign.objects.select_related(
            'created_by'
        ).order_by('-created_at')[:5]

        # Recent contacts
        context['recent_contacts'] = Contact.objects.order_by('-created_at')[:10]

        return context


class ContactListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """Contact list view"""
    model = Contact
    template_name = 'marketing_campaigns/contact_list.html'
    partial_template_name = 'marketing_campaigns/partials/_contact_list.html'
    context_object_name = 'contacts'
    paginate_by = 20

    def get_queryset(self):
        queryset = super().get_queryset()

        # Search
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                Q(email__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search) |
                Q(company__icontains=search)
            )

        # Status filter
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        return queryset.order_by('-created_at')


class ContactDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Contact detail view"""
    model = Contact
    template_name = 'marketing_campaigns/contact_detail.html'
    context_object_name = 'contact'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Campaign tracking
        context['campaign_tracking'] = CampaignTracking.objects.filter(
            contact=self.object
        ).select_related('campaign').order_by('-created_at')

        # Visit events
        if self.object.user:
            context['visit_events'] = VisitEvent.objects.filter(
                user=self.object.user
            ).order_by('-timestamp')[:20]

        return context


class CampaignListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """Marketing campaign list view"""
    model = MarketingCampaign
    template_name = 'marketing_campaigns/campaign_list.html'
    partial_template_name = 'marketing_campaigns/partials/_campaign_list.html'
    context_object_name = 'campaigns'
    paginate_by = 20

    def get_queryset(self):
        queryset = super().get_queryset()

        # Search
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                Q(title__icontains=search) |
                Q(subject__icontains=search)
            )

        # Status filter
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        # Type filter
        campaign_type = self.request.GET.get('type')
        if campaign_type:
            queryset = queryset.filter(campaign_type=campaign_type)

        return queryset.annotate(
            recipients_count=Count('tracking')
        ).order_by('-created_at')


class CampaignDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Campaign detail view"""
    model = MarketingCampaign
    template_name = 'marketing_campaigns/campaign_detail.html'
    context_object_name = 'campaign'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Campaign stats
        tracking = CampaignTracking.objects.filter(campaign=self.object)
        context['total_sent'] = tracking.count()
        context['total_opened'] = tracking.filter(opened_at__isnull=False).count()
        context['total_clicked'] = tracking.filter(clicked_at__isnull=False).count()

        # Calculate rates
        if context['total_sent'] > 0:
            context['open_rate'] = (context['total_opened'] / context['total_sent']) * 100
            context['click_rate'] = (context['total_clicked'] / context['total_sent']) * 100
        else:
            context['open_rate'] = 0
            context['click_rate'] = 0

        # Recent tracking events
        context['recent_tracking'] = tracking.select_related('contact').order_by('-created_at')[:20]

        return context


class VisitEventsListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """Visit events list view"""
    model = VisitEvent
    template_name = 'marketing_campaigns/visit_events.html'
    partial_template_name = 'marketing_campaigns/partials/_visit_events.html'
    context_object_name = 'visits'
    paginate_by = 50

    def get_queryset(self):
        queryset = super().get_queryset()

        # Date filter
        date_from = self.request.GET.get('date_from')
        if date_from:
            queryset = queryset.filter(timestamp__gte=date_from)

        date_to = self.request.GET.get('date_to')
        if date_to:
            queryset = queryset.filter(timestamp__lte=date_to)

        return queryset.select_related('user').order_by('-timestamp')


class HTMXCampaignStatsView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """HTMX partial view for campaign stats"""
    template_name = 'marketing_campaigns/partials/_campaign_stats.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Overall stats
        total_campaigns = MarketingCampaign.objects.count()
        active_campaigns = MarketingCampaign.objects.filter(status='active').count()

        context['total_campaigns'] = total_campaigns
        context['active_campaigns'] = active_campaigns
        context['total_contacts'] = Contact.objects.count()
        context['total_visits'] = VisitEvent.objects.count()

        return context
