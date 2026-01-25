"""
Finance Webhooks App Forms

Forms for webhook event monitoring and retry management.
"""

from django import forms
from .models import WebhookEvent


class WebhookEventFilterForm(forms.Form):
    """Form for filtering webhook events."""

    event_type = forms.ChoiceField(
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'}),
    )
    status = forms.ChoiceField(
        required=False,
        choices=[
            ('', 'All Statuses'),
            ('pending', 'Pending'),
            ('processing', 'Processing'),
            ('success', 'Success'),
            ('failed', 'Failed'),
        ],
        widget=forms.Select(attrs={'class': 'form-select'}),
    )
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-input', 'type': 'date'}),
    )
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-input', 'type': 'date'}),
    )
