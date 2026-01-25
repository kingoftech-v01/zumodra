"""
Payments App Forms

Forms for payment processing, refunds, and payment methods.
Multi-currency support with validation.
"""

from django import forms
from django.core.exceptions import ValidationError
from decimal import Decimal
from .models import (
    Currency,
    ExchangeRate,
    PaymentMethod,
    PaymentTransaction,
    RefundRequest,
    PaymentIntent,
)


class CurrencyForm(forms.ModelForm):
    """Form for creating/editing supported currencies."""

    class Meta:
        model = Currency
        fields = ['code', 'name', 'symbol', 'decimal_places', 'is_active']
        widgets = {
            'code': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'USD',
                'maxlength': '3',
            }),
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'US Dollar',
            }),
            'symbol': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': '$',
            }),
            'decimal_places': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
                'max': '8',
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }

    def clean_code(self):
        """Ensure currency code is uppercase and valid."""
        code = self.cleaned_data.get('code', '').upper()
        if len(code) != 3:
            raise ValidationError('Currency code must be exactly 3 characters (ISO 4217)')
        return code


class ExchangeRateForm(forms.ModelForm):
    """Form for managing exchange rates."""

    class Meta:
        model = ExchangeRate
        fields = ['from_currency', 'to_currency', 'rate', 'date', 'source']
        widgets = {
            'from_currency': forms.Select(attrs={'class': 'form-select'}),
            'to_currency': forms.Select(attrs={'class': 'form-select'}),
            'rate': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.00000001',
                'min': '0.00000001',
            }),
            'date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'source': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'api',
            }),
        }

    def clean(self):
        """Validate exchange rate data."""
        cleaned_data = super().clean()
        from_currency = cleaned_data.get('from_currency')
        to_currency = cleaned_data.get('to_currency')
        rate = cleaned_data.get('rate')

        if from_currency and to_currency:
            if from_currency == to_currency:
                raise ValidationError('Source and target currencies must be different')

        if rate and rate <= 0:
            raise ValidationError({'rate': 'Exchange rate must be positive'})

        return cleaned_data


class PaymentMethodForm(forms.ModelForm):
    """Form for adding/editing payment methods."""

    class Meta:
        model = PaymentMethod
        fields = [
            'payment_type',
            'card_brand',
            'last4',
            'exp_month',
            'exp_year',
            'is_default',
        ]
        widgets = {
            'payment_type': forms.Select(attrs={'class': 'form-select'}),
            'card_brand': forms.Select(attrs={'class': 'form-select'}),
            'last4': forms.TextInput(attrs={
                'class': 'form-input',
                'maxlength': '4',
                'placeholder': '4242',
            }),
            'exp_month': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '1',
                'max': '12',
            }),
            'exp_year': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '2024',
            }),
            'is_default': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

    def clean_last4(self):
        """Validate last 4 digits."""
        last4 = self.cleaned_data.get('last4', '')
        if not last4.isdigit():
            raise ValidationError('Last 4 must be digits only')
        return last4

    def clean(self):
        """Validate expiration date."""
        cleaned_data = super().clean()
        exp_month = cleaned_data.get('exp_month')
        exp_year = cleaned_data.get('exp_year')

        if exp_month and exp_year:
            from datetime import date
            today = date.today()
            if exp_year < today.year:
                raise ValidationError('Card has expired')
            if exp_year == today.year and exp_month < today.month:
                raise ValidationError('Card has expired')

        return cleaned_data


class PaymentTransactionForm(forms.ModelForm):
    """Form for creating payment transactions."""

    class Meta:
        model = PaymentTransaction
        fields = [
            'amount',
            'currency',
            'payer',
            'payee',
            'payment_method',
            'description',
        ]
        widgets = {
            'amount': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0.01',
            }),
            'currency': forms.Select(attrs={'class': 'form-select'}),
            'payer': forms.Select(attrs={'class': 'form-select'}),
            'payee': forms.Select(attrs={'class': 'form-select'}),
            'payment_method': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
                'placeholder': 'Payment for services...',
            }),
        }

    def __init__(self, *args, **kwargs):
        self.tenant = kwargs.pop('tenant', None)
        super().__init__(*args, **kwargs)

    def clean_amount(self):
        """Validate payment amount."""
        amount = self.cleaned_data.get('amount')
        if amount <= 0:
            raise ValidationError('Amount must be greater than zero')
        return amount

    def clean(self):
        """Validate transaction data."""
        cleaned_data = super().clean()
        payer = cleaned_data.get('payer')
        payee = cleaned_data.get('payee')

        if payer and payee and payer == payee:
            raise ValidationError('Payer and payee must be different users')

        return cleaned_data


class RefundRequestForm(forms.ModelForm):
    """Form for requesting refunds."""

    class Meta:
        model = RefundRequest
        fields = ['payment_transaction', 'amount', 'reason', 'notes']
        widgets = {
            'payment_transaction': forms.Select(attrs={'class': 'form-select'}),
            'amount': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0.01',
            }),
            'reason': forms.Select(attrs={'class': 'form-select'}),
            'notes': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
                'placeholder': 'Additional details about refund request...',
            }),
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

    def clean_amount(self):
        """Validate refund amount against original payment."""
        amount = self.cleaned_data.get('amount')
        payment = self.cleaned_data.get('payment_transaction')

        if amount and payment:
            if amount > payment.amount:
                raise ValidationError(
                    f'Refund amount cannot exceed original payment amount '
                    f'({payment.amount} {payment.currency.code})'
                )
            if amount <= 0:
                raise ValidationError('Refund amount must be greater than zero')

        return amount


class PaymentIntentForm(forms.ModelForm):
    """Form for creating payment intents (Stripe integration)."""

    class Meta:
        model = PaymentIntent
        fields = [
            'amount',
            'currency',
            'customer',
            'payment_method',
            'description',
            'capture_method',
        ]
        widgets = {
            'amount': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0.01',
            }),
            'currency': forms.Select(attrs={'class': 'form-select'}),
            'customer': forms.Select(attrs={'class': 'form-select'}),
            'payment_method': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
            'capture_method': forms.Select(attrs={'class': 'form-select'}),
        }

    def clean_amount(self):
        """Validate payment intent amount."""
        amount = self.cleaned_data.get('amount')
        if amount <= 0:
            raise ValidationError('Amount must be greater than zero')

        # Stripe minimum amount validation (50 cents USD minimum)
        currency = self.cleaned_data.get('currency')
        if currency and currency.code == 'USD' and amount < Decimal('0.50'):
            raise ValidationError('Minimum payment amount is $0.50 USD')

        return amount


class BulkRefundForm(forms.Form):
    """Form for processing bulk refunds."""

    transaction_ids = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 5,
            'placeholder': 'Enter transaction IDs (one per line)',
        }),
        help_text='One transaction ID per line'
    )
    reason = forms.ChoiceField(
        choices=RefundRequest.REFUND_REASONS,
        widget=forms.Select(attrs={'class': 'form-select'}),
    )
    notes = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 3,
            'placeholder': 'Optional notes for all refunds...',
        }),
    )

    def clean_transaction_ids(self):
        """Parse and validate transaction IDs."""
        ids_text = self.cleaned_data.get('transaction_ids', '')
        ids = [tid.strip() for tid in ids_text.split('\n') if tid.strip()]

        if not ids:
            raise ValidationError('At least one transaction ID is required')

        if len(ids) > 100:
            raise ValidationError('Maximum 100 transactions can be refunded at once')

        return ids
