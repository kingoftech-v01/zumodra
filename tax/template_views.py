"""
Tax App Frontend Views - Tax Calculation and Compliance Management
"""

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView, ListView, DetailView
from django.db.models import Sum, Count, Q
from django.utils import timezone
from datetime import timedelta

from tenants.mixins import TenantViewMixin
from core.mixins import HTMXMixin
from .models import (
    AvalaraConfig,
    TaxRate,
    TaxCalculation,
    TaxExemption,
    TaxRemittance,
    TaxReport,
)


class TaxDashboardView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """Main tax dashboard with overview stats (admin only)"""
    template_name = 'tax/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        today = timezone.now().date()
        thirty_days_ago = today - timedelta(days=30)

        # Avalara configuration status
        try:
            context['avalara_config'] = AvalaraConfig.objects.first()
        except AvalaraConfig.DoesNotExist:
            context['avalara_config'] = None

        # Tax collected (last 30 days)
        recent_calculations = TaxCalculation.objects.filter(
            calculated_at__date__gte=thirty_days_ago
        )
        context['tax_collected_30d'] = recent_calculations.aggregate(
            total=Sum('tax_amount')
        )['total'] or 0

        # Tax calculations count
        context['calculations_count_30d'] = recent_calculations.count()

        # Pending remittances
        pending_remittances = TaxRemittance.objects.filter(
            status__in=['scheduled', 'overdue']
        )
        context['pending_remittances_count'] = pending_remittances.count()
        context['pending_remittances_amount'] = pending_remittances.aggregate(
            total=Sum('tax_owed')
        )['total'] or 0

        # Active tax exemptions
        context['active_exemptions'] = TaxExemption.objects.filter(
            status='active'
        ).count()

        # Recent activity
        context['recent_calculations'] = TaxCalculation.objects.order_by(
            '-calculated_at'
        )[:10]

        context['recent_remittances'] = TaxRemittance.objects.order_by(
            '-created_at'
        )[:10]

        return context


class AvalaraConfigDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Avalara configuration view (admin only)"""
    model = AvalaraConfig
    template_name = 'tax/avalara_config.html'
    context_object_name = 'config'

    def get_object(self, queryset=None):
        # Get the first (and should be only) config
        return AvalaraConfig.objects.first()


class TaxRateListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List tax rates"""
    model = TaxRate
    template_name = 'tax/rate_list.html'
    partial_template_name = 'tax/partials/_rate_list.html'
    context_object_name = 'rates'
    paginate_by = 50

    def get_queryset(self):
        queryset = TaxRate.objects.order_by('country', 'state_province', 'city')

        # Filter by active
        if self.request.GET.get('active') == 'true':
            queryset = queryset.filter(is_active=True)
        elif self.request.GET.get('active') == 'false':
            queryset = queryset.filter(is_active=False)

        # Filter by type
        tax_type = self.request.GET.get('type')
        if tax_type:
            queryset = queryset.filter(tax_type=tax_type)

        # Filter by jurisdiction
        country = self.request.GET.get('country')
        state = self.request.GET.get('state')
        if country:
            queryset = queryset.filter(country=country)
        if state:
            queryset = queryset.filter(state_province=state)

        return queryset


class TaxCalculationListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List tax calculations"""
    model = TaxCalculation
    template_name = 'tax/calculation_list.html'
    partial_template_name = 'tax/partials/_calculation_list.html'
    context_object_name = 'calculations'
    paginate_by = 50

    def get_queryset(self):
        queryset = TaxCalculation.objects.select_related(
            'payment_transaction', 'subscription_invoice'
        ).order_by('-calculated_at')

        # Filter by source
        source = self.request.GET.get('source')
        if source:
            queryset = queryset.filter(source=source)

        # Date range
        start_date = self.request.GET.get('start_date')
        end_date = self.request.GET.get('end_date')
        if start_date:
            queryset = queryset.filter(calculated_at__date__gte=start_date)
        if end_date:
            queryset = queryset.filter(calculated_at__date__lte=end_date)

        return queryset


class TaxCalculationDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Tax calculation detail"""
    model = TaxCalculation
    template_name = 'tax/calculation_detail.html'
    context_object_name = 'calculation'


class TaxExemptionListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List tax exemptions (admin only)"""
    model = TaxExemption
    template_name = 'tax/exemption_list.html'
    partial_template_name = 'tax/partials/_exemption_list.html'
    context_object_name = 'exemptions'
    paginate_by = 20

    def get_queryset(self):
        queryset = TaxExemption.objects.select_related('customer').order_by('-issue_date')

        # Filter by status
        status_filter = self.request.GET.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        # Filter by type
        exemption_type = self.request.GET.get('type')
        if exemption_type:
            queryset = queryset.filter(exemption_type=exemption_type)

        # Search
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                Q(customer__email__icontains=search) |
                Q(customer__first_name__icontains=search) |
                Q(customer__last_name__icontains=search) |
                Q(exemption_number__icontains=search)
            )

        return queryset


class TaxExemptionDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Tax exemption detail (admin only)"""
    model = TaxExemption
    template_name = 'tax/exemption_detail.html'
    context_object_name = 'exemption'

    def get_queryset(self):
        return TaxExemption.objects.select_related('customer')


class TaxRemittanceListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List tax remittances (admin only)"""
    model = TaxRemittance
    template_name = 'tax/remittance_list.html'
    partial_template_name = 'tax/partials/_remittance_list.html'
    context_object_name = 'remittances'
    paginate_by = 20

    def get_queryset(self):
        queryset = TaxRemittance.objects.order_by('-due_date')

        # Filter by status
        status_filter = self.request.GET.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        # Filter by jurisdiction
        country = self.request.GET.get('country')
        state = self.request.GET.get('state')
        if country:
            queryset = queryset.filter(country=country)
        if state:
            queryset = queryset.filter(state_province=state)

        return queryset


class TaxRemittanceDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Tax remittance detail (admin only)"""
    model = TaxRemittance
    template_name = 'tax/remittance_detail.html'
    context_object_name = 'remittance'

    def get_queryset(self):
        return TaxRemittance.objects.select_related('payment_transaction')


class TaxReportListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List tax reports (admin only)"""
    model = TaxReport
    template_name = 'tax/report_list.html'
    partial_template_name = 'tax/partials/_report_list.html'
    context_object_name = 'reports'
    paginate_by = 20

    def get_queryset(self):
        queryset = TaxReport.objects.select_related('generated_by').order_by('-period_end')

        # Filter by type
        report_type = self.request.GET.get('type')
        if report_type:
            queryset = queryset.filter(report_type=report_type)

        return queryset


class TaxReportDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Tax report detail (admin only)"""
    model = TaxReport
    template_name = 'tax/report_detail.html'
    context_object_name = 'report'

    def get_queryset(self):
        return TaxReport.objects.select_related('generated_by')


class HTMXTaxStatsView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """HTMX partial for real-time tax stats"""
    template_name = 'tax/partials/_stats.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        today = timezone.now().date()
        thirty_days_ago = today - timedelta(days=30)

        # Quick stats
        context['tax_collected_30d'] = TaxCalculation.objects.filter(
            calculated_at__date__gte=thirty_days_ago
        ).aggregate(total=Sum('tax_amount'))['total'] or 0

        pending = TaxRemittance.objects.filter(status__in=['scheduled', 'overdue'])
        context['pending_remittances'] = pending.count()
        context['pending_amount'] = pending.aggregate(total=Sum('tax_owed'))['total'] or 0

        context['active_exemptions'] = TaxExemption.objects.filter(status='active').count()

        return context
