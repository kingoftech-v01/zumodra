"""
Payroll App Forms

Forms for payroll processing, employee payments, and tax calculations.
"""

from django import forms
from django.core.exceptions import ValidationError
from decimal import Decimal
from .models import (
    PayrollRun,
    DirectDeposit,
    EmployeePayment,
    PayrollDeduction,
    PayStub,
    PayrollTax,
)


class PayrollRunForm(forms.ModelForm):
    """Form for creating payroll runs."""

    class Meta:
        model = PayrollRun
        fields = [
            'run_number',
            'pay_period_start',
            'pay_period_end',
            'pay_date',
        ]
        widgets = {
            'run_number': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'PR-2026-01',
            }),
            'pay_period_start': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'pay_period_end': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'pay_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
        }

    def __init__(self, *args, **kwargs):
        self.tenant = kwargs.pop('tenant', None)
        self.created_by = kwargs.pop('created_by', None)
        super().__init__(*args, **kwargs)

    def clean(self):
        """Validate payroll run dates."""
        cleaned_data = super().clean()
        start = cleaned_data.get('pay_period_start')
        end = cleaned_data.get('pay_period_end')
        pay_date = cleaned_data.get('pay_date')

        if start and end:
            if end < start:
                raise ValidationError('Pay period end must be after start date')

        if pay_date and end:
            if pay_date < end:
                raise ValidationError('Pay date must be after pay period end')

        return cleaned_data


class DirectDepositForm(forms.ModelForm):
    """Form for managing employee direct deposit information."""

    class Meta:
        model = DirectDeposit
        fields = [
            'employee',
            'account_type',
            'routing_number',
            'account_number',
            'bank_name',
            'is_active',
        ]
        widgets = {
            'employee': forms.Select(attrs={'class': 'form-select'}),
            'account_type': forms.Select(attrs={'class': 'form-select'}),
            'routing_number': forms.TextInput(attrs={
                'class': 'form-input',
                'maxlength': '9',
                'placeholder': '123456789',
            }),
            'account_number': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': '****1234',
            }),
            'bank_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'Bank of America',
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }

    def clean_routing_number(self):
        """Validate routing number."""
        routing = self.cleaned_data.get('routing_number', '')
        if not routing.isdigit():
            raise ValidationError('Routing number must contain only digits')
        if len(routing) != 9:
            raise ValidationError('Routing number must be exactly 9 digits')
        return routing

    def clean_account_number(self):
        """Validate account number."""
        account = self.cleaned_data.get('account_number', '')
        if not account.isdigit():
            raise ValidationError('Account number must contain only digits')
        if len(account) < 4 or len(account) > 17:
            raise ValidationError('Account number must be between 4-17 digits')
        return account


class EmployeePaymentForm(forms.ModelForm):
    """Form for creating employee payments."""

    class Meta:
        model = EmployeePayment
        fields = [
            'payroll_run',
            'employee',
            'gross_amount',
            'federal_tax',
            'state_tax',
            'social_security',
            'medicare',
            'deductions',
        ]
        widgets = {
            'payroll_run': forms.Select(attrs={'class': 'form-select'}),
            'employee': forms.Select(attrs={'class': 'form-select'}),
            'gross_amount': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0.01',
            }),
            'federal_tax': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0.00',
            }),
            'state_tax': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0.00',
            }),
            'social_security': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0.00',
            }),
            'medicare': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0.00',
            }),
            'deductions': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
        }

    def clean_gross_amount(self):
        """Validate gross amount."""
        amount = self.cleaned_data.get('gross_amount')
        if amount <= 0:
            raise ValidationError('Gross amount must be greater than zero')
        return amount

    def clean(self):
        """Validate tax calculations."""
        cleaned_data = super().clean()
        gross = cleaned_data.get('gross_amount', Decimal('0'))
        federal = cleaned_data.get('federal_tax', Decimal('0'))
        state = cleaned_data.get('state_tax', Decimal('0'))
        ss = cleaned_data.get('social_security', Decimal('0'))
        medicare = cleaned_data.get('medicare', Decimal('0'))

        total_taxes = federal + state + ss + medicare
        if total_taxes > gross:
            raise ValidationError('Total taxes cannot exceed gross amount')

        return cleaned_data


class PayrollDeductionForm(forms.ModelForm):
    """Form for managing payroll deductions."""

    class Meta:
        model = PayrollDeduction
        fields = [
            'employee',
            'deduction_type',
            'amount',
            'is_percentage',
            'start_date',
            'end_date',
            'description',
        ]
        widgets = {
            'employee': forms.Select(attrs={'class': 'form-select'}),
            'deduction_type': forms.Select(attrs={'class': 'form-select'}),
            'amount': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0.01',
            }),
            'is_percentage': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'start_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'end_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
            }),
        }

    def clean_amount(self):
        """Validate deduction amount."""
        amount = self.cleaned_data.get('amount')
        is_percentage = self.cleaned_data.get('is_percentage')

        if is_percentage and amount > 100:
            raise ValidationError('Percentage deduction cannot exceed 100%')

        return amount

    def clean(self):
        """Validate date range."""
        cleaned_data = super().clean()
        start = cleaned_data.get('start_date')
        end = cleaned_data.get('end_date')

        if start and end and end < start:
            raise ValidationError('End date must be after start date')

        return cleaned_data


class PayStubForm(forms.ModelForm):
    """Form for generating pay stubs."""

    class Meta:
        model = PayStub
        fields = ['employee_payment']
        widgets = {
            'employee_payment': forms.Select(attrs={'class': 'form-select'}),
        }

    def __init__(self, *args, **kwargs):
        self.tenant = kwargs.pop('tenant', None)
        super().__init__(*args, **kwargs)


class PayrollTaxForm(forms.ModelForm):
    """Form for managing payroll tax records."""

    class Meta:
        model = PayrollTax
        fields = [
            'payroll_run',
            'tax_type',
            'tax_jurisdiction',
            'taxable_wages',
            'tax_rate',
            'tax_amount',
        ]
        widgets = {
            'payroll_run': forms.Select(attrs={'class': 'form-select'}),
            'tax_type': forms.Select(attrs={'class': 'form-select'}),
            'tax_jurisdiction': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'Federal, CA, NY, etc.',
            }),
            'taxable_wages': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0.00',
            }),
            'tax_rate': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.0001',
                'min': '0.0000',
                'max': '1.0000',
            }),
            'tax_amount': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0.00',
                'readonly': 'readonly',
            }),
        }

    def clean(self):
        """Calculate tax amount from rate and wages."""
        cleaned_data = super().clean()
        wages = cleaned_data.get('taxable_wages', Decimal('0'))
        rate = cleaned_data.get('tax_rate', Decimal('0'))

        if wages and rate:
            cleaned_data['tax_amount'] = wages * rate

        return cleaned_data


class BulkPayrollApprovalForm(forms.Form):
    """Form for approving multiple payroll payments at once."""

    payment_ids = forms.MultipleChoiceField(
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'form-checkbox'}),
    )
    approval_notes = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 3,
            'placeholder': 'Optional notes for approval...',
        }),
    )

    def __init__(self, *args, **kwargs):
        payroll_run = kwargs.pop('payroll_run', None)
        super().__init__(*args, **kwargs)

        if payroll_run:
            choices = [
                (payment.id, f"{payment.employee.user.get_full_name()} - ${payment.net_amount}")
                for payment in payroll_run.payments.filter(status='pending')
            ]
            self.fields['payment_ids'].choices = choices
