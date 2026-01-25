"""
Forms for jobs_public app.

Provides Django forms for job filtering and search in the public catalog.
"""

from django import forms


class JobSearchForm(forms.Form):
    """
    Search and filter form for public job listings.

    Used for job board filtering and search functionality.
    """

    q = forms.CharField(
        required=False,
        label='Search',
        widget=forms.TextInput(attrs={
            'placeholder': 'Job title, company, or keywords...',
            'class': 'form-control'
        })
    )

    location = forms.CharField(
        required=False,
        label='Location',
        widget=forms.TextInput(attrs={
            'placeholder': 'City, state, or country',
            'class': 'form-control'
        })
    )

    employment_type = forms.ChoiceField(
        required=False,
        label='Employment Type',
        choices=[('', 'Any')] + [
            ('full-time', 'Full-time'),
            ('part-time', 'Part-time'),
            ('contract', 'Contract'),
            ('temporary', 'Temporary'),
            ('internship', 'Internship'),
        ],
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    is_remote = forms.BooleanField(
        required=False,
        label='Remote Only',
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )

    sort = forms.ChoiceField(
        required=False,
        label='Sort By',
        choices=[
            ('', 'Default'),
            ('newest', 'Newest First'),
            ('oldest', 'Oldest First'),
            ('salary_high', 'Highest Salary'),
            ('salary_low', 'Lowest Salary'),
        ],
        widget=forms.Select(attrs={'class': 'form-control'})
    )
