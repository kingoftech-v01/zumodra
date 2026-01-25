"""
Services App Forms

Forms for service listings, proposals, and contracts.
"""

from django import forms
from django.core.exceptions import ValidationError
from .models import (
    Service,
    ServiceProvider,
    ClientRequest,
    ServiceProposal,
    ServiceContract,
)


class ServiceForm(forms.ModelForm):
    """Form for creating/editing services."""

    class Meta:
        model = Service
        fields = [
            'name',
            'description',
            'category',
            'service_type',
            'price',
            'hourly_rate',
            'marketplace_enabled',
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-input'}),
            'description': forms.Textarea(attrs={'class': 'form-textarea', 'rows': 4}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'service_type': forms.Select(attrs={'class': 'form-select'}),
            'price': forms.NumberInput(attrs={'class': 'form-input', 'step': '0.01'}),
            'hourly_rate': forms.NumberInput(attrs={'class': 'form-input', 'step': '0.01'}),
            'marketplace_enabled': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        }

    def __init__(self, *args, **kwargs):
        self.tenant = kwargs.pop('tenant', None)
        super().__init__(*args, **kwargs)


class ServiceProviderForm(forms.ModelForm):
    """Form for service provider profiles."""

    class Meta:
        model = ServiceProvider
        fields = ['user', 'bio', 'hourly_rate', 'availability']
        widgets = {
            'user': forms.Select(attrs={'class': 'form-select'}),
            'bio': forms.Textarea(attrs={'class': 'form-textarea', 'rows': 4}),
            'hourly_rate': forms.NumberInput(attrs={'class': 'form-input', 'step': '0.01'}),
            'availability': forms.Select(attrs={'class': 'form-select'}),
        }


class ClientRequestForm(forms.ModelForm):
    """Form for creating client service requests."""

    class Meta:
        model = ClientRequest
        fields = ['title', 'description', 'budget', 'deadline']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-input'}),
            'description': forms.Textarea(attrs={'class': 'form-textarea', 'rows': 4}),
            'budget': forms.NumberInput(attrs={'class': 'form-input', 'step': '0.01'}),
            'deadline': forms.DateInput(attrs={'class': 'form-input', 'type': 'date'}),
        }


class ServiceProposalForm(forms.ModelForm):
    """Form for submitting service proposals."""

    class Meta:
        model = ServiceProposal
        fields = ['client_request', 'proposed_price', 'estimated_hours', 'proposal_text']
        widgets = {
            'client_request': forms.Select(attrs={'class': 'form-select'}),
            'proposed_price': forms.NumberInput(attrs={'class': 'form-input', 'step': '0.01'}),
            'estimated_hours': forms.NumberInput(attrs={'class': 'form-input', 'step': '0.5'}),
            'proposal_text': forms.Textarea(attrs={'class': 'form-textarea', 'rows': 6}),
        }


class ServiceContractForm(forms.ModelForm):
    """Form for creating service contracts."""

    class Meta:
        model = ServiceContract
        fields = ['service', 'client', 'provider', 'start_date', 'end_date', 'terms']
        widgets = {
            'service': forms.Select(attrs={'class': 'form-select'}),
            'client': forms.Select(attrs={'class': 'form-select'}),
            'provider': forms.Select(attrs={'class': 'form-select'}),
            'start_date': forms.DateInput(attrs={'class': 'form-input', 'type': 'date'}),
            'end_date': forms.DateInput(attrs={'class': 'form-input', 'type': 'date'}),
            'terms': forms.Textarea(attrs={'class': 'form-textarea', 'rows': 8}),
        }
