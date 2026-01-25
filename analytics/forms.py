"""
Analytics App Forms

Forms for analytics dashboards and report generation.
"""

from django import forms


class AnalyticsReportForm(forms.Form):
    """Form for generating analytics reports."""

    report_type = forms.ChoiceField(
        choices=[
            ('recruitment', 'Recruitment Analytics'),
            ('financial', 'Financial Analytics'),
            ('services', 'Services Analytics'),
            ('hr', 'HR Analytics'),
        ],
        widget=forms.Select(attrs={'class': 'form-select'}),
    )
    period_start = forms.DateField(
        widget=forms.DateInput(attrs={'class': 'form-input', 'type': 'date'}),
    )
    period_end = forms.DateField(
        widget=forms.DateInput(attrs={'class': 'form-input', 'type': 'date'}),
    )
    format = forms.ChoiceField(
        choices=[
            ('pdf', 'PDF'),
            ('csv', 'CSV'),
            ('xlsx', 'Excel'),
        ],
        widget=forms.Select(attrs={'class': 'form-select'}),
    )
