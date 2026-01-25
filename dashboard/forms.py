"""
Dashboard App Forms

Forms for dashboard widgets and preferences.
"""

from django import forms


class DashboardDateRangeForm(forms.Form):
    """Form for filtering dashboard data by date range."""

    start_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-input', 'type': 'date'}),
    )
    end_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-input', 'type': 'date'}),
    )


class GlobalSearchForm(forms.Form):
    """Form for global search across tenant."""

    query = forms.CharField(
        max_length=200,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': 'Search jobs, candidates, services...',
        }),
    )
    search_type = forms.ChoiceField(
        required=False,
        choices=[
            ('all', 'All'),
            ('jobs', 'Jobs'),
            ('candidates', 'Candidates'),
            ('services', 'Services'),
            ('employees', 'Employees'),
        ],
        widget=forms.Select(attrs={'class': 'form-select'}),
    )
