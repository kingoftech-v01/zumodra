"""
Analytics Forms - Report Filters and Analytics Configuration

This module provides forms for:
- Report filtering and date ranges
- Dashboard configuration
- Metric exports
- Analytics preferences
"""

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta


class AnalyticsDateRangeForm(forms.Form):
    """
    Common form for date range selection in analytics views.
    """

    DATE_RANGE_CHOICES = [
        ('today', _('Today')),
        ('yesterday', _('Yesterday')),
        ('7d', _('Last 7 Days')),
        ('30d', _('Last 30 Days')),
        ('90d', _('Last 90 Days')),
        ('mtd', _('Month to Date')),
        ('qtd', _('Quarter to Date')),
        ('ytd', _('Year to Date')),
        ('last_month', _('Last Month')),
        ('last_quarter', _('Last Quarter')),
        ('last_year', _('Last Year')),
        ('custom', _('Custom Range')),
    ]

    date_range = forms.ChoiceField(
        choices=DATE_RANGE_CHOICES,
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
        """Validate date range."""
        cleaned_data = super().clean()
        date_range = cleaned_data.get('date_range')
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')

        if date_range == 'custom':
            if not start_date or not end_date:
                raise ValidationError(_('Start and end dates are required for custom range.'))
            if end_date < start_date:
                raise ValidationError({
                    'end_date': _('End date cannot be before start date.')
                })
            if (end_date - start_date).days > 365:
                raise ValidationError(_('Date range cannot exceed 365 days.'))

        return cleaned_data


class RecruitmentMetricsFilterForm(forms.Form):
    """
    Form for filtering recruitment metrics reports.
    """

    PERIOD_TYPE_CHOICES = [
        ('daily', _('Daily')),
        ('weekly', _('Weekly')),
        ('monthly', _('Monthly')),
        ('quarterly', _('Quarterly')),
    ]

    period_type = forms.ChoiceField(
        choices=PERIOD_TYPE_CHOICES,
        initial='monthly',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Period Type'),
    )
    start_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('Start Date'),
    )
    end_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('End Date'),
    )
    department = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Department'),
    )
    job_type = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Job Type'),
    )
    location = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Location filter'),
        }),
        label=_('Location'),
    )
    compare_previous = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Compare with previous period'),
    )


class DiversityReportFilterForm(forms.Form):
    """
    Form for filtering diversity reports.
    """

    SCOPE_CHOICES = [
        ('employees', _('Current Employees')),
        ('applicants', _('Applicants')),
        ('interviewed', _('Interviewed Candidates')),
        ('hired', _('New Hires')),
        ('leadership', _('Leadership')),
        ('departed', _('Departed Employees')),
    ]

    scope = forms.ChoiceField(
        choices=SCOPE_CHOICES,
        initial='employees',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Population Scope'),
    )
    period_start = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('Period Start'),
    )
    period_end = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('Period End'),
    )
    department = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Department'),
    )
    show_benchmarks = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show industry benchmarks'),
    )
    anonymization_threshold = forms.IntegerField(
        initial=5,
        min_value=3,
        max_value=10,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'min': '3',
            'max': '10',
        }),
        label=_('Anonymization threshold'),
        help_text=_('Minimum count to display category data'),
    )


class HiringFunnelFilterForm(forms.Form):
    """
    Form for filtering hiring funnel reports.
    """

    start_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('Start Date'),
    )
    end_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('End Date'),
    )
    job_posting = forms.IntegerField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Job Posting'),
    )
    department = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Department'),
    )
    job_type = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Job Type'),
    )
    show_time_in_stage = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show time in stage'),
    )
    show_drop_off = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show drop-off analysis'),
    )


class TimeToHireFilterForm(forms.Form):
    """
    Form for filtering time-to-hire reports.
    """

    start_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('Start Date'),
    )
    end_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('End Date'),
    )
    department = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Department'),
    )
    job_type = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Job Type'),
    )
    experience_level = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Experience Level'),
    )
    location = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
        }),
        label=_('Location'),
    )
    target_days = forms.IntegerField(
        required=False,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'min': '1',
        }),
        label=_('Target Days'),
        help_text=_('Target time-to-fill for comparison'),
    )
    group_by = forms.ChoiceField(
        choices=[
            ('none', _('No Grouping')),
            ('department', _('Department')),
            ('job_type', _('Job Type')),
            ('source', _('Source')),
            ('location', _('Location')),
        ],
        initial='none',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Group By'),
    )


class SourceEffectivenessFilterForm(forms.Form):
    """
    Form for filtering source effectiveness reports.
    """

    SOURCE_CHOICES = [
        ('', _('All Sources')),
        ('career_page', _('Career Page')),
        ('linkedin', _('LinkedIn')),
        ('indeed', _('Indeed')),
        ('glassdoor', _('Glassdoor')),
        ('referral', _('Employee Referral')),
        ('agency', _('Recruitment Agency')),
        ('university', _('University/Campus')),
        ('social_media', _('Social Media')),
        ('direct', _('Direct Application')),
    ]

    start_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('Start Date'),
    )
    end_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('End Date'),
    )
    source = forms.ChoiceField(
        choices=SOURCE_CHOICES,
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Source'),
    )
    department = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Department'),
    )
    include_costs = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Include cost metrics'),
    )
    include_quality = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Include quality metrics'),
    )


class RetentionReportFilterForm(forms.Form):
    """
    Form for filtering employee retention reports.
    """

    PERIOD_TYPE_CHOICES = [
        ('monthly', _('Monthly')),
        ('quarterly', _('Quarterly')),
        ('yearly', _('Yearly')),
    ]

    period_type = forms.ChoiceField(
        choices=PERIOD_TYPE_CHOICES,
        initial='quarterly',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Period Type'),
    )
    start_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('Start Date'),
    )
    end_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('End Date'),
    )
    department = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Department'),
    )
    location = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
        }),
        label=_('Location'),
    )
    job_level = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Job Level'),
    )
    show_departure_reasons = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show departure reasons'),
    )
    show_tenure_breakdown = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show tenure breakdown'),
    )


class PerformanceDistributionFilterForm(forms.Form):
    """
    Form for filtering performance distribution reports.
    """

    REVIEW_CYCLE_CHOICES = [
        ('', _('All Cycles')),
        ('q1', _('Q1 Review')),
        ('q2', _('Q2 Review')),
        ('q3', _('Q3 Review')),
        ('q4', _('Q4 Review')),
        ('mid_year', _('Mid-Year Review')),
        ('annual', _('Annual Review')),
    ]

    year = forms.IntegerField(
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'min': '2020',
            'max': '2030',
        }),
        label=_('Year'),
    )
    review_cycle = forms.ChoiceField(
        choices=REVIEW_CYCLE_CHOICES,
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Review Cycle'),
    )
    department = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Department'),
    )
    job_level = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Job Level'),
    )
    show_goals = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show goal metrics'),
    )
    show_recommendations = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show recommendations'),
    )


class ExportReportForm(forms.Form):
    """
    Form for exporting analytics reports.
    """

    FORMAT_CHOICES = [
        ('pdf', _('PDF')),
        ('csv', _('CSV')),
        ('xlsx', _('Excel')),
        ('json', _('JSON')),
    ]

    format = forms.ChoiceField(
        choices=FORMAT_CHOICES,
        initial='pdf',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Export Format'),
    )
    include_charts = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Include charts (PDF only)'),
    )
    include_raw_data = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Include raw data'),
    )
    email_report = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Email report to me'),
    )
    schedule_report = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Schedule recurring report'),
    )
    schedule_frequency = forms.ChoiceField(
        choices=[
            ('daily', _('Daily')),
            ('weekly', _('Weekly')),
            ('monthly', _('Monthly')),
        ],
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Schedule Frequency'),
    )


class DashboardWidgetForm(forms.Form):
    """
    Form for configuring dashboard widgets.
    """

    WIDGET_TYPE_CHOICES = [
        ('metric_card', _('Metric Card')),
        ('line_chart', _('Line Chart')),
        ('bar_chart', _('Bar Chart')),
        ('pie_chart', _('Pie Chart')),
        ('funnel_chart', _('Funnel Chart')),
        ('table', _('Data Table')),
        ('heatmap', _('Heatmap')),
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
    metric_type = forms.CharField(
        max_length=50,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Metric'),
    )
    size = forms.ChoiceField(
        choices=[
            ('small', _('Small (1x1)')),
            ('medium', _('Medium (2x1)')),
            ('large', _('Large (2x2)')),
            ('wide', _('Wide (3x1)')),
        ],
        initial='medium',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Size'),
    )
    show_trend = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show trend indicator'),
    )
    show_comparison = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show period comparison'),
    )


class RecruiterPerformanceFilterForm(forms.Form):
    """
    Form for filtering recruiter performance reports.
    """

    start_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('Start Date'),
    )
    end_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('End Date'),
    )
    recruiter = forms.IntegerField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Recruiter'),
    )
    team = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Team'),
    )
    metric_focus = forms.ChoiceField(
        choices=[
            ('all', _('All Metrics')),
            ('volume', _('Volume (Hires, Screens)')),
            ('efficiency', _('Efficiency (Time metrics)')),
            ('quality', _('Quality (Performance, Retention)')),
        ],
        initial='all',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Metric Focus'),
    )
    show_ranking = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show ranking'),
    )


class TimeOffAnalyticsFilterForm(forms.Form):
    """
    Form for filtering time-off analytics reports.
    """

    PERIOD_TYPE_CHOICES = [
        ('monthly', _('Monthly')),
        ('quarterly', _('Quarterly')),
        ('yearly', _('Yearly')),
    ]

    period_type = forms.ChoiceField(
        choices=PERIOD_TYPE_CHOICES,
        initial='monthly',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Period Type'),
    )
    start_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('Start Date'),
    )
    end_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('End Date'),
    )
    department = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Department'),
    )
    location = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
        }),
        label=_('Location'),
    )
    leave_type = forms.ChoiceField(
        choices=[
            ('', _('All Types')),
            ('pto', _('PTO/Vacation')),
            ('sick', _('Sick Leave')),
            ('unpaid', _('Unpaid Leave')),
            ('other', _('Other')),
        ],
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Leave Type'),
    )
    show_patterns = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Show usage patterns'),
    )
