"""
Dashboard Forms - Widget Configuration and Dashboard Settings

This module provides forms for:
- Dashboard widget configuration
- Layout preferences
- Dashboard settings
- Quick actions

Note: dashboard/models.py is empty, so these forms are standalone
configuration forms without direct model backing.
"""

from django import forms
from django.utils.translation import gettext_lazy as _


class DashboardWidgetForm(forms.Form):
    """
    Form for configuring individual dashboard widgets.
    """

    WIDGET_TYPE_CHOICES = [
        ('stats', _('Statistics Card')),
        ('chart', _('Chart')),
        ('table', _('Data Table')),
        ('list', _('List View')),
        ('calendar', _('Calendar')),
        ('activity', _('Activity Feed')),
        ('tasks', _('Task List')),
        ('notifications', _('Notifications')),
    ]

    SIZE_CHOICES = [
        ('small', _('Small (1x1)')),
        ('medium', _('Medium (2x1)')),
        ('large', _('Large (2x2)')),
        ('wide', _('Wide (4x1)')),
        ('full', _('Full Width')),
    ]

    widget_type = forms.ChoiceField(
        choices=WIDGET_TYPE_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Widget Type'),
    )
    title = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Widget Title'),
        }),
        label=_('Title'),
    )
    size = forms.ChoiceField(
        choices=SIZE_CHOICES,
        initial='medium',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Size'),
    )
    position = forms.IntegerField(
        initial=0,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'min': '0',
        }),
        label=_('Position'),
        help_text=_('Order in dashboard (lower numbers appear first)'),
    )
    is_visible = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Visible'),
    )
    refresh_interval = forms.IntegerField(
        required=False,
        initial=0,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'min': '0',
            'max': '3600',
        }),
        label=_('Auto-refresh (seconds)'),
        help_text=_('0 = no auto-refresh'),
    )


class ChartWidgetConfigForm(forms.Form):
    """
    Configuration form for chart widgets.
    """

    CHART_TYPE_CHOICES = [
        ('line', _('Line Chart')),
        ('bar', _('Bar Chart')),
        ('pie', _('Pie Chart')),
        ('doughnut', _('Doughnut Chart')),
        ('area', _('Area Chart')),
        ('radar', _('Radar Chart')),
    ]

    DATA_SOURCE_CHOICES = [
        ('applications', _('Applications')),
        ('candidates', _('Candidates')),
        ('jobs', _('Job Postings')),
        ('interviews', _('Interviews')),
        ('hires', _('Hires')),
        ('time_to_hire', _('Time to Hire')),
        ('source_effectiveness', _('Source Effectiveness')),
    ]

    DATE_RANGE_CHOICES = [
        ('7d', _('Last 7 days')),
        ('30d', _('Last 30 days')),
        ('90d', _('Last 90 days')),
        ('365d', _('Last 12 months')),
        ('ytd', _('Year to date')),
    ]

    chart_type = forms.ChoiceField(
        choices=CHART_TYPE_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Chart Type'),
    )
    data_source = forms.ChoiceField(
        choices=DATA_SOURCE_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Data Source'),
    )
    date_range = forms.ChoiceField(
        choices=DATE_RANGE_CHOICES,
        initial='30d',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Date Range'),
    )
    show_legend = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show Legend'),
    )
    show_data_labels = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show Data Labels'),
    )


class TableWidgetConfigForm(forms.Form):
    """
    Configuration form for data table widgets.
    """

    DATA_TYPE_CHOICES = [
        ('recent_applications', _('Recent Applications')),
        ('upcoming_interviews', _('Upcoming Interviews')),
        ('pending_approvals', _('Pending Approvals')),
        ('active_jobs', _('Active Job Postings')),
        ('top_candidates', _('Top Candidates')),
        ('recent_hires', _('Recent Hires')),
        ('expiring_offers', _('Expiring Offers')),
    ]

    data_type = forms.ChoiceField(
        choices=DATA_TYPE_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Data Type'),
    )
    rows_per_page = forms.IntegerField(
        initial=10,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'min': '5',
            'max': '50',
        }),
        label=_('Rows per Page'),
    )
    show_pagination = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show Pagination'),
    )
    enable_sorting = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Enable Sorting'),
    )


class DashboardLayoutForm(forms.Form):
    """
    Form for configuring overall dashboard layout.
    """

    LAYOUT_CHOICES = [
        ('grid', _('Grid Layout')),
        ('masonry', _('Masonry Layout')),
        ('columns', _('Column Layout')),
    ]

    THEME_CHOICES = [
        ('light', _('Light')),
        ('dark', _('Dark')),
        ('system', _('System Default')),
    ]

    layout = forms.ChoiceField(
        choices=LAYOUT_CHOICES,
        initial='grid',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Layout Style'),
    )
    columns = forms.IntegerField(
        initial=3,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'min': '1',
            'max': '6',
        }),
        label=_('Number of Columns'),
    )
    theme = forms.ChoiceField(
        choices=THEME_CHOICES,
        initial='system',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Theme'),
    )
    compact_mode = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Compact Mode'),
        help_text=_('Reduce spacing between widgets'),
    )
    show_welcome_message = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show Welcome Message'),
    )


class DashboardSettingsForm(forms.Form):
    """
    Form for user's dashboard preferences and settings.
    """

    default_view = forms.ChoiceField(
        choices=[
            ('overview', _('Overview')),
            ('recruiting', _('Recruiting')),
            ('hr', _('HR Management')),
            ('analytics', _('Analytics')),
        ],
        initial='overview',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Default View'),
    )
    auto_refresh_enabled = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Enable Auto-refresh'),
    )
    refresh_interval_minutes = forms.IntegerField(
        initial=5,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'min': '1',
            'max': '60',
        }),
        label=_('Refresh Interval (minutes)'),
    )
    show_notifications_widget = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show Notifications Widget'),
    )
    show_calendar_widget = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show Calendar Widget'),
    )
    show_tasks_widget = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show Tasks Widget'),
    )


class QuickActionForm(forms.Form):
    """
    Form for quick action configuration on dashboard.
    """

    ACTION_CHOICES = [
        ('post_job', _('Post New Job')),
        ('add_candidate', _('Add Candidate')),
        ('schedule_interview', _('Schedule Interview')),
        ('create_offer', _('Create Offer')),
        ('request_time_off', _('Request Time Off')),
        ('approve_request', _('Approve Request')),
        ('send_message', _('Send Message')),
        ('generate_report', _('Generate Report')),
    ]

    enabled_actions = forms.MultipleChoiceField(
        choices=ACTION_CHOICES,
        widget=forms.CheckboxSelectMultiple(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Enabled Quick Actions'),
        help_text=_('Select actions to show in the quick actions panel'),
    )
    show_quick_actions = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show Quick Actions Panel'),
    )


class DateRangeFilterForm(forms.Form):
    """
    Form for filtering dashboard data by date range.
    """

    PRESET_CHOICES = [
        ('today', _('Today')),
        ('yesterday', _('Yesterday')),
        ('7d', _('Last 7 Days')),
        ('30d', _('Last 30 Days')),
        ('90d', _('Last 90 Days')),
        ('this_month', _('This Month')),
        ('last_month', _('Last Month')),
        ('this_quarter', _('This Quarter')),
        ('this_year', _('This Year')),
        ('custom', _('Custom Range')),
    ]

    preset = forms.ChoiceField(
        choices=PRESET_CHOICES,
        initial='30d',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Date Range'),
    )
    start_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('Start Date'),
    )
    end_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('End Date'),
    )

    def clean(self):
        """Validate date range when custom is selected."""
        cleaned_data = super().clean()
        preset = cleaned_data.get('preset')
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')

        if preset == 'custom':
            if not start_date:
                self.add_error('start_date', _('Start date is required for custom range.'))
            if not end_date:
                self.add_error('end_date', _('End date is required for custom range.'))
            if start_date and end_date and start_date > end_date:
                self.add_error('end_date', _('End date must be after start date.'))

        return cleaned_data


class DashboardExportForm(forms.Form):
    """
    Form for exporting dashboard data.
    """

    FORMAT_CHOICES = [
        ('pdf', _('PDF Report')),
        ('excel', _('Excel Spreadsheet')),
        ('csv', _('CSV File')),
    ]

    CONTENT_CHOICES = [
        ('summary', _('Summary Statistics')),
        ('applications', _('Applications Data')),
        ('interviews', _('Interviews Data')),
        ('hires', _('Hires Data')),
        ('all', _('All Dashboard Data')),
    ]

    format = forms.ChoiceField(
        choices=FORMAT_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Export Format'),
    )
    content = forms.ChoiceField(
        choices=CONTENT_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Content to Export'),
    )
    include_charts = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Include Charts'),
    )
    date_range = forms.ChoiceField(
        choices=[
            ('7d', _('Last 7 Days')),
            ('30d', _('Last 30 Days')),
            ('90d', _('Last 90 Days')),
            ('ytd', _('Year to Date')),
        ],
        initial='30d',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Date Range'),
    )


class SaveDashboardViewForm(forms.Form):
    """
    Form for saving custom dashboard views.
    """

    name = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('View Name'),
        }),
        label=_('View Name'),
    )
    description = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 2,
            'placeholder': _('Optional description'),
        }),
        label=_('Description'),
    )
    is_default = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Set as Default View'),
    )
    is_shared = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Share with Team'),
        help_text=_('Allow other team members to use this view'),
    )
