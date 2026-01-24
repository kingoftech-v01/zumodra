"""
Integrations App Forms

Forms for third-party integration configuration.
"""

from django import forms


class IntegrationConfigForm(forms.Form):
    """Form for configuring third-party integrations."""

    integration_type = forms.ChoiceField(
        choices=[
            ('linkedin', 'LinkedIn'),
            ('stripe', 'Stripe'),
            ('avalara', 'Avalara'),
            ('quickbooks', 'QuickBooks'),
            ('xero', 'Xero'),
        ],
        widget=forms.Select(attrs={'class': 'form-select'}),
    )
    api_key = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-input'}),
    )
    api_secret = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={'class': 'form-input'}),
    )
    is_enabled = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
    )


class WebhookConfigForm(forms.Form):
    """Form for configuring outbound webhooks."""

    url = forms.URLField(
        widget=forms.URLInput(attrs={'class': 'form-input'}),
    )
    events = forms.MultipleChoiceField(
        choices=[
            ('job.created', 'Job Created'),
            ('candidate.applied', 'Candidate Applied'),
            ('payment.succeeded', 'Payment Succeeded'),
            ('service.completed', 'Service Completed'),
        ],
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'form-checkbox'}),
    )
    is_active = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
    )
