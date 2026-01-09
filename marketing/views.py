"""
Marketing App Views - Template views for marketing dashboard.

Provides dashboard views for:
- Traffic analytics
- Prospects/Leads management
- Newsletter campaigns
- Conversion tracking
"""

from datetime import timedelta
from decimal import Decimal

from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Count, Sum
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.generic import TemplateView

from .models import (
    VisitEvent,
    Prospect,
    NewsletterCampaign,
    NewsletterSubscriber,
    NewsletterTracking,
    ConversionEvent,
)


@method_decorator(staff_member_required, name='dispatch')
class MarketingDashboardView(TemplateView):
    """
    Marketing dashboard with analytics overview.
    """
    template_name = 'marketing/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        days = int(self.request.GET.get('days', 30))
        since = timezone.now() - timedelta(days=days)
        context['period_days'] = days

        # Traffic stats
        visits = VisitEvent.objects.filter(timestamp__gte=since)
        context['traffic_stats'] = {
            'total_visits': visits.count(),
            'unique_visitors': visits.values('marketing_id').distinct().count(),
        }

        # Traffic by source
        context['traffic_by_source'] = visits.values('utm_source').annotate(
            count=Count('id')
        ).order_by('-count')[:5]

        # Traffic by country
        context['traffic_by_country'] = visits.values('country').annotate(
            count=Count('id')
        ).order_by('-count')[:5]

        # Traffic by device
        context['traffic_by_device'] = visits.values('device_type').annotate(
            count=Count('id')
        ).order_by('-count')

        # Prospect stats
        prospects = Prospect.objects.all()
        context['prospect_stats'] = {
            'total': prospects.count(),
            'new': prospects.filter(added_on__gte=since).count(),
            'qualified': prospects.filter(status='qualified').count(),
            'converted': prospects.filter(status='converted').count(),
        }

        # Prospects by status
        context['prospects_by_status'] = prospects.values('status').annotate(
            count=Count('id')
        ).order_by('-count')

        # Recent prospects
        context['recent_prospects'] = prospects.order_by('-added_on')[:5]

        # Newsletter stats
        subscribers = NewsletterSubscriber.objects.all()
        campaigns = NewsletterCampaign.objects.all()

        context['newsletter_stats'] = {
            'total_subscribers': subscribers.count(),
            'active_subscribers': subscribers.filter(active=True).count(),
            'total_campaigns': campaigns.count(),
            'campaigns_sent': campaigns.filter(sent=True).count(),
        }

        # Campaign performance
        sent_campaigns = campaigns.filter(sent=True).order_by('-sent_on')[:5]
        campaign_data = []
        for campaign in sent_campaigns:
            tracking = NewsletterTracking.objects.filter(campaign=campaign)
            total = tracking.count()
            if total > 0:
                opened = tracking.filter(opened=True).count()
                clicked = tracking.filter(clicked=True).count()
                campaign_data.append({
                    'campaign': campaign,
                    'sent': total,
                    'opened': opened,
                    'clicked': clicked,
                    'open_rate': round(opened / total * 100, 1),
                    'click_rate': round(clicked / total * 100, 1),
                })
        context['recent_campaigns'] = campaign_data

        # Conversion stats
        conversions = ConversionEvent.objects.filter(timestamp__gte=since)
        purchase_conversions = conversions.filter(event_name='purchase')

        context['conversion_stats'] = {
            'total_conversions': conversions.count(),
            'total_purchases': purchase_conversions.count(),
            'total_revenue': purchase_conversions.aggregate(
                total=Sum('value')
            )['total'] or Decimal('0'),
        }

        # Conversions by type
        context['conversions_by_type'] = conversions.values('event_name').annotate(
            count=Count('id'),
            value=Sum('value')
        ).order_by('-count')[:5]

        # Calculate conversion rate
        unique_visitors = context['traffic_stats']['unique_visitors']
        if unique_visitors > 0:
            context['conversion_rate'] = round(
                context['conversion_stats']['total_purchases'] / unique_visitors * 100, 2
            )
        else:
            context['conversion_rate'] = 0

        return context


@method_decorator(staff_member_required, name='dispatch')
class ProspectsListView(TemplateView):
    """Prospects management list view."""
    template_name = 'marketing/prospects_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        prospects = Prospect.objects.all().order_by('-added_on')

        # Apply filters
        status_filter = self.request.GET.get('status')
        if status_filter:
            prospects = prospects.filter(status=status_filter)

        source_filter = self.request.GET.get('source')
        if source_filter:
            prospects = prospects.filter(source__icontains=source_filter)

        search = self.request.GET.get('q')
        if search:
            from django.db.models import Q
            prospects = prospects.filter(
                Q(email__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search) |
                Q(company__icontains=search)
            )

        context['prospects'] = prospects[:50]  # Limit for performance
        context['total_count'] = prospects.count()

        # Stats for sidebar
        context['stats'] = {
            'total': Prospect.objects.count(),
            'new': Prospect.objects.filter(status='new').count(),
            'contacted': Prospect.objects.filter(status='contacted').count(),
            'qualified': Prospect.objects.filter(status='qualified').count(),
            'converted': Prospect.objects.filter(status='converted').count(),
            'disqualified': Prospect.objects.filter(status='disqualified').count(),
        }

        context['current_filters'] = {
            'status': status_filter,
            'source': source_filter,
            'q': search or '',
        }

        return context


@method_decorator(staff_member_required, name='dispatch')
class CampaignsListView(TemplateView):
    """Newsletter campaigns list view."""
    template_name = 'marketing/campaigns_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        campaigns = NewsletterCampaign.objects.all().order_by('-created_on')

        # Apply filters
        sent_filter = self.request.GET.get('sent')
        if sent_filter == 'true':
            campaigns = campaigns.filter(sent=True)
        elif sent_filter == 'false':
            campaigns = campaigns.filter(sent=False)

        context['campaigns'] = campaigns

        # Calculate stats for each campaign
        campaign_data = []
        for campaign in campaigns[:20]:
            tracking = NewsletterTracking.objects.filter(campaign=campaign)
            total = tracking.count()
            if total > 0:
                opened = tracking.filter(opened=True).count()
                clicked = tracking.filter(clicked=True).count()
                campaign_data.append({
                    'campaign': campaign,
                    'sent': total,
                    'open_rate': round(opened / total * 100, 1),
                    'click_rate': round(clicked / total * 100, 1),
                })
            else:
                campaign_data.append({
                    'campaign': campaign,
                    'sent': 0,
                    'open_rate': 0,
                    'click_rate': 0,
                })

        context['campaign_data'] = campaign_data

        context['current_filters'] = {
            'sent': sent_filter,
        }

        return context
