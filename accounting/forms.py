"""
Accounting App Forms

Forms for accounting provider integration (QuickBooks, Xero).
"""

from django import forms
from .models import (
    AccountingProvider,
    JournalEntry,
    FinancialReport,
)


class AccountingProviderForm(forms.ModelForm):
    """Form for configuring accounting provider integration."""

    class Meta:
        model = AccountingProvider
        fields = ['provider', 'realm_id']
        widgets = {
            'provider': forms.Select(attrs={'class': 'form-select'}),
            'realm_id': forms.TextInput(attrs={'class': 'form-input'}),
        }


class JournalEntryForm(forms.ModelForm):
    """Form for creating journal entries."""

    class Meta:
        model = JournalEntry
        fields = ['entry_number', 'date', 'description']
        widgets = {
            'entry_number': forms.TextInput(attrs={'class': 'form-input'}),
            'date': forms.DateInput(attrs={'class': 'form-input', 'type': 'date'}),
            'description': forms.Textarea(attrs={'class': 'form-textarea', 'rows': 2}),
        }


class FinancialReportForm(forms.ModelForm):
    """Form for generating financial reports."""

    class Meta:
        model = FinancialReport
        fields = ['report_type', 'period_start', 'period_end']
        widgets = {
            'report_type': forms.Select(attrs={'class': 'form-select'}),
            'period_start': forms.DateInput(attrs={'class': 'form-input', 'type': 'date'}),
            'period_end': forms.DateInput(attrs={'class': 'form-input', 'type': 'date'}),
        }
