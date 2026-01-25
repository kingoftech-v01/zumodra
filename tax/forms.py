"""
Tax App Forms

Forms for tax configuration, calculations, and Avalara integration.
"""

from django import forms
from .models import (
    AvalaraConfig,
    TaxRate,
    TaxExemption,
    TaxRemittance,
)


class AvalaraConfigForm(forms.ModelForm):
    """Form for Avalara API configuration."""

    class Meta:
        model = AvalaraConfig
        fields = ['account_id', 'license_key', 'company_code', 'is_sandbox']
        widgets = {
            'account_id': forms.TextInput(attrs={'class': 'form-input'}),
            'license_key': forms.PasswordInput(attrs={'class': 'form-input'}),
            'company_code': forms.TextInput(attrs={'class': 'form-input'}),
            'is_sandbox': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        }


class TaxRateForm(forms.ModelForm):
    """Form for managing tax rates."""

    class Meta:
        model = TaxRate
        fields = ['jurisdiction', 'tax_type', 'rate', 'effective_date']
        widgets = {
            'jurisdiction': forms.TextInput(attrs={'class': 'form-input'}),
            'tax_type': forms.Select(attrs={'class': 'form-select'}),
            'rate': forms.NumberInput(attrs={'class': 'form-input', 'step': '0.0001'}),
            'effective_date': forms.DateInput(attrs={'class': 'form-input', 'type': 'date'}),
        }


class TaxExemptionForm(forms.ModelForm):
    """Form for managing tax exemptions."""

    class Meta:
        model = TaxExemption
        fields = ['customer', 'exemption_type', 'certificate_number', 'expiration_date']
        widgets = {
            'customer': forms.Select(attrs={'class': 'form-select'}),
            'exemption_type': forms.Select(attrs={'class': 'form-select'}),
            'certificate_number': forms.TextInput(attrs={'class': 'form-input'}),
            'expiration_date': forms.DateInput(attrs={'class': 'form-input', 'type': 'date'}),
        }
