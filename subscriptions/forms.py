"""
Subscriptions App Forms

Forms for subscription products, customer subscriptions, and usage tracking.
"""

from django import forms
from django.core.exceptions import ValidationError
from .models import (
    SubscriptionProduct,
    SubscriptionTier,
    CustomerSubscription,
    SubscriptionInvoice,
    UsageRecord,
)


class SubscriptionProductForm(forms.ModelForm):
    """Form for creating subscription products."""

    class Meta:
        model = SubscriptionProduct
        fields = ['name', 'description', 'billing_period', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-input'}),
            'description': forms.Textarea(attrs={'class': 'form-textarea', 'rows': 3}),
            'billing_period': forms.Select(attrs={'class': 'form-select'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        }


class SubscriptionTierForm(forms.ModelForm):
    """Form for managing subscription tiers."""

    class Meta:
        model = SubscriptionTier
        fields = ['product', 'name', 'price', 'currency', 'features']
        widgets = {
            'product': forms.Select(attrs={'class': 'form-select'}),
            'name': forms.TextInput(attrs={'class': 'form-input'}),
            'price': forms.NumberInput(attrs={'class': 'form-input', 'step': '0.01'}),
            'currency': forms.Select(attrs={'class': 'form-select'}),
            'features': forms.Textarea(attrs={'class': 'form-textarea', 'rows': 4}),
        }


class CustomerSubscriptionForm(forms.ModelForm):
    """Form for managing customer subscriptions."""

    class Meta:
        model = CustomerSubscription
        fields = ['customer', 'tier', 'quantity', 'trial_end']
        widgets = {
            'customer': forms.Select(attrs={'class': 'form-select'}),
            'tier': forms.Select(attrs={'class': 'form-select'}),
            'quantity': forms.NumberInput(attrs={'class': 'form-input', 'min': '1'}),
            'trial_end': forms.DateInput(attrs={'class': 'form-input', 'type': 'date'}),
        }


class UsageRecordForm(forms.ModelForm):
    """Form for recording subscription usage."""

    class Meta:
        model = UsageRecord
        fields = ['subscription', 'metric_name', 'quantity', 'timestamp']
        widgets = {
            'subscription': forms.Select(attrs={'class': 'form-select'}),
            'metric_name': forms.TextInput(attrs={'class': 'form-input'}),
            'quantity': forms.NumberInput(attrs={'class': 'form-input', 'step': '0.01'}),
            'timestamp': forms.DateTimeInput(attrs={'class': 'form-input', 'type': 'datetime-local'}),
        }
