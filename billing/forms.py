"""
Billing App Forms

Forms for platform subscription management (Zumodra charges tenants).
"""

from django import forms
from .models import (
    SubscriptionPlan,
    TenantSubscription,
)


class SubscriptionPlanForm(forms.ModelForm):
    """Form for creating subscription plans."""

    class Meta:
        model = SubscriptionPlan
        fields = [
            'name',
            'slug',
            'price_monthly',
            'price_yearly',
            'max_users',
            'max_jobs',
            'features',
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-input'}),
            'slug': forms.TextInput(attrs={'class': 'form-input'}),
            'price_monthly': forms.NumberInput(attrs={'class': 'form-input', 'step': '0.01'}),
            'price_yearly': forms.NumberInput(attrs={'class': 'form-input', 'step': '0.01'}),
            'max_users': forms.NumberInput(attrs={'class': 'form-input'}),
            'max_jobs': forms.NumberInput(attrs={'class': 'form-input'}),
            'features': forms.Textarea(attrs={'class': 'form-textarea', 'rows': 4}),
        }


class TenantSubscriptionForm(forms.ModelForm):
    """Form for managing tenant subscriptions."""

    class Meta:
        model = TenantSubscription
        fields = ['tenant', 'plan', 'billing_cycle']
        widgets = {
            'tenant': forms.Select(attrs={'class': 'form-select'}),
            'plan': forms.Select(attrs={'class': 'form-select'}),
            'billing_cycle': forms.Select(attrs={'class': 'form-select'}),
        }
