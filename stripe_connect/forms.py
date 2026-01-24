"""
Stripe Connect App Forms

Forms for connected accounts, onboarding, and platform fees.
"""

from django import forms
from .models import (
    ConnectedAccount,
    StripeConnectOnboarding,
    PlatformFee,
    PayoutSchedule,
)


class ConnectedAccountForm(forms.ModelForm):
    """Form for creating Stripe connected accounts."""

    class Meta:
        model = ConnectedAccount
        fields = ['provider', 'account_type', 'business_type']
        widgets = {
            'provider': forms.Select(attrs={'class': 'form-select'}),
            'account_type': forms.Select(attrs={'class': 'form-select'}),
            'business_type': forms.Select(attrs={'class': 'form-select'}),
        }


class PlatformFeeForm(forms.ModelForm):
    """Form for configuring platform fees."""

    class Meta:
        model = PlatformFee
        fields = ['connected_account', 'fee_type', 'percentage', 'fixed_amount']
        widgets = {
            'connected_account': forms.Select(attrs={'class': 'form-select'}),
            'fee_type': forms.Select(attrs={'class': 'form-select'}),
            'percentage': forms.NumberInput(attrs={'class': 'form-input', 'step': '0.01'}),
            'fixed_amount': forms.NumberInput(attrs={'class': 'form-input', 'step': '0.01'}),
        }


class PayoutScheduleForm(forms.ModelForm):
    """Form for managing payout schedules."""

    class Meta:
        model = PayoutSchedule
        fields = ['connected_account', 'interval', 'delay_days']
        widgets = {
            'connected_account': forms.Select(attrs={'class': 'form-select'}),
            'interval': forms.Select(attrs={'class': 'form-select'}),
            'delay_days': forms.NumberInput(attrs={'class': 'form-input', 'min': '0'}),
        }
