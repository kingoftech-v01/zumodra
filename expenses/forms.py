"""
Expenses App Forms

Forms for expense tracking, approval workflows, and reimbursements.
"""

from django import forms
from django.core.exceptions import ValidationError
from decimal import Decimal
from .models import (
    ExpenseCategory,
    ExpenseReport,
    ExpenseLineItem,
    ExpenseApproval,
    Reimbursement,
    MileageRate,
)


class ExpenseCategoryForm(forms.ModelForm):
    """Form for managing expense categories."""

    class Meta:
        model = ExpenseCategory
        fields = ['name', 'description', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-input'}),
            'description': forms.Textarea(attrs={'class': 'form-textarea', 'rows': 2}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        }


class ExpenseReportForm(forms.ModelForm):
    """Form for creating expense reports."""

    class Meta:
        model = ExpenseReport
        fields = ['title', 'description', 'business_purpose']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'Business Trip to NYC - Jan 2026',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
            'business_purpose': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
                'placeholder': 'Client meeting and site visit',
            }),
        }

    def __init__(self, *args, **kwargs):
        self.employee = kwargs.pop('employee', None)
        super().__init__(*args, **kwargs)


class ExpenseLineItemForm(forms.ModelForm):
    """Form for adding expense line items."""

    class Meta:
        model = ExpenseLineItem
        fields = [
            'expense_report',
            'category',
            'amount',
            'currency',
            'expense_date',
            'merchant',
            'description',
            'receipt',
        ]
        widgets = {
            'expense_report': forms.Select(attrs={'class': 'form-select'}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'amount': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0.01',
            }),
            'currency': forms.Select(attrs={'class': 'form-select'}),
            'expense_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'merchant': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'Starbucks',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
            }),
            'receipt': forms.FileInput(attrs={'class': 'form-file'}),
        }

    def clean_amount(self):
        """Validate expense amount."""
        amount = self.cleaned_data.get('amount')
        if amount <= 0:
            raise ValidationError('Amount must be greater than zero')
        if amount > Decimal('10000.00'):
            raise ValidationError('Expenses over $10,000 require special approval')
        return amount


class ExpenseApprovalForm(forms.ModelForm):
    """Form for approving/rejecting expense reports."""

    class Meta:
        model = ExpenseApproval
        fields = ['expense_report', 'decision', 'notes']
        widgets = {
            'expense_report': forms.Select(attrs={'class': 'form-select'}),
            'decision': forms.RadioSelect(attrs={'class': 'form-radio'}),
            'notes': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
                'placeholder': 'Approval/rejection notes...',
            }),
        }

    def __init__(self, *args, **kwargs):
        self.approver = kwargs.pop('approver', None)
        super().__init__(*args, **kwargs)


class ReimbursementForm(forms.ModelForm):
    """Form for processing reimbursements."""

    class Meta:
        model = Reimbursement
        fields = [
            'expense_report',
            'amount',
            'payment_method',
            'payment_date',
        ]
        widgets = {
            'expense_report': forms.Select(attrs={'class': 'form-select'}),
            'amount': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'readonly': 'readonly',
            }),
            'payment_method': forms.Select(attrs={'class': 'form-select'}),
            'payment_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
        }


class MileageRateForm(forms.ModelForm):
    """Form for managing mileage reimbursement rates."""

    class Meta:
        model = MileageRate
        fields = ['vehicle_type', 'rate_per_mile', 'effective_date', 'end_date']
        widgets = {
            'vehicle_type': forms.Select(attrs={'class': 'form-select'}),
            'rate_per_mile': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.001',
            }),
            'effective_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'end_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
        }
