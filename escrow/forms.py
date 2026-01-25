"""
Escrow App Forms

Forms for escrow transactions, milestone payments, disputes, and releases.
"""

from django import forms
from django.core.exceptions import ValidationError
from decimal import Decimal
from .models import (
    EscrowTransaction,
    MilestonePayment,
    EscrowRelease,
    Dispute,
    EscrowPayout,
    EscrowAudit,
)


class EscrowTransactionForm(forms.ModelForm):
    """Form for creating escrow transactions."""

    class Meta:
        model = EscrowTransaction
        fields = [
            'client',
            'provider',
            'service_contract',
            'project_contract',
            'amount',
            'currency',
            'description',
            'terms',
        ]
        widgets = {
            'client': forms.Select(attrs={'class': 'form-select'}),
            'provider': forms.Select(attrs={'class': 'form-select'}),
            'service_contract': forms.Select(attrs={'class': 'form-select'}),
            'project_contract': forms.Select(attrs={'class': 'form-select'}),
            'amount': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0.01',
            }),
            'currency': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
                'placeholder': 'Describe the work to be completed...',
            }),
            'terms': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 5,
                'placeholder': 'Escrow terms and conditions...',
            }),
        }

    def __init__(self, *args, **kwargs):
        self.tenant = kwargs.pop('tenant', None)
        super().__init__(*args, **kwargs)

    def clean_amount(self):
        """Validate escrow amount."""
        amount = self.cleaned_data.get('amount')
        if amount <= 0:
            raise ValidationError('Amount must be greater than zero')
        if amount > Decimal('1000000.00'):
            raise ValidationError('Amount exceeds maximum allowed ($1,000,000)')
        return amount

    def clean(self):
        """Validate escrow transaction data."""
        cleaned_data = super().clean()
        client = cleaned_data.get('client')
        provider = cleaned_data.get('provider')
        service_contract = cleaned_data.get('service_contract')
        project_contract = cleaned_data.get('project_contract')

        # Validate client and provider are different
        if client and provider and client == provider:
            raise ValidationError('Client and provider must be different users')

        # Require either service or project contract
        if not service_contract and not project_contract:
            raise ValidationError('Either service contract or project contract is required')

        # Don't allow both contracts
        if service_contract and project_contract:
            raise ValidationError('Cannot have both service and project contract')

        return cleaned_data


class MilestonePaymentForm(forms.ModelForm):
    """Form for creating milestone payments."""

    class Meta:
        model = MilestonePayment
        fields = [
            'escrow_transaction',
            'milestone_name',
            'amount',
            'due_date',
            'description',
            'deliverables',
        ]
        widgets = {
            'escrow_transaction': forms.Select(attrs={'class': 'form-select'}),
            'milestone_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'Phase 1: Design Mockups',
            }),
            'amount': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0.01',
            }),
            'due_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
            'deliverables': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
                'placeholder': 'List of deliverables for this milestone...',
            }),
        }

    def clean_amount(self):
        """Validate milestone amount."""
        amount = self.cleaned_data.get('amount')
        escrow = self.cleaned_data.get('escrow_transaction')

        if amount and escrow:
            # Check that milestone doesn't exceed escrow balance
            total_milestones = sum(
                m.amount for m in escrow.milestone_payments.all()
                if m.pk != self.instance.pk
            )
            if total_milestones + amount > escrow.amount:
                raise ValidationError(
                    f'Total milestone payments cannot exceed escrow amount '
                    f'({escrow.amount} {escrow.currency.code})'
                )

        return amount


class EscrowReleaseForm(forms.ModelForm):
    """Form for approving escrow releases."""

    class Meta:
        model = EscrowRelease
        fields = [
            'escrow_transaction',
            'milestone_payment',
            'amount',
            'release_reason',
            'notes',
        ]
        widgets = {
            'escrow_transaction': forms.Select(attrs={'class': 'form-select'}),
            'milestone_payment': forms.Select(attrs={'class': 'form-select'}),
            'amount': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0.01',
            }),
            'release_reason': forms.Select(attrs={'class': 'form-select'}),
            'notes': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

    def clean_amount(self):
        """Validate release amount against escrow balance."""
        amount = self.cleaned_data.get('amount')
        escrow = self.cleaned_data.get('escrow_transaction')

        if amount and escrow:
            if amount > escrow.balance:
                raise ValidationError(
                    f'Release amount cannot exceed escrow balance '
                    f'({escrow.balance} {escrow.currency.code})'
                )

        return amount


class DisputeForm(forms.ModelForm):
    """Form for opening disputes."""

    class Meta:
        model = Dispute
        fields = [
            'escrow_transaction',
            'dispute_type',
            'description',
            'amount_disputed',
            'evidence',
        ]
        widgets = {
            'escrow_transaction': forms.Select(attrs={'class': 'form-select'}),
            'dispute_type': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 5,
                'placeholder': 'Describe the issue in detail...',
            }),
            'amount_disputed': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0.01',
            }),
            'evidence': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
                'placeholder': 'Provide evidence supporting your dispute...',
            }),
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

    def clean_amount_disputed(self):
        """Validate disputed amount."""
        amount = self.cleaned_data.get('amount_disputed')
        escrow = self.cleaned_data.get('escrow_transaction')

        if amount and escrow:
            if amount > escrow.amount:
                raise ValidationError(
                    f'Disputed amount cannot exceed escrow total '
                    f'({escrow.amount} {escrow.currency.code})'
                )

        return amount


class DisputeResolutionForm(forms.Form):
    """Form for resolving disputes."""

    resolution = forms.ChoiceField(
        choices=[
            ('client_favor', 'Resolve in Client Favor'),
            ('provider_favor', 'Resolve in Provider Favor'),
            ('split', 'Split Amount'),
            ('refund_all', 'Refund All to Client'),
        ],
        widget=forms.RadioSelect(attrs={'class': 'form-radio'}),
    )
    client_amount = forms.DecimalField(
        required=False,
        max_digits=12,
        decimal_places=2,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'step': '0.01',
        }),
        help_text='Amount to release to client (if split)'
    )
    provider_amount = forms.DecimalField(
        required=False,
        max_digits=12,
        decimal_places=2,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'step': '0.01',
        }),
        help_text='Amount to release to provider (if split)'
    )
    resolution_notes = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 4,
            'placeholder': 'Explain the resolution decision...',
        }),
    )

    def clean(self):
        """Validate resolution amounts."""
        cleaned_data = super().clean()
        resolution = cleaned_data.get('resolution')
        client_amount = cleaned_data.get('client_amount')
        provider_amount = cleaned_data.get('provider_amount')

        if resolution == 'split':
            if not client_amount or not provider_amount:
                raise ValidationError('Both client and provider amounts required for split resolution')

        return cleaned_data


class EscrowPayoutForm(forms.ModelForm):
    """Form for processing escrow payouts."""

    class Meta:
        model = EscrowPayout
        fields = [
            'escrow_release',
            'recipient',
            'amount',
            'payout_method',
        ]
        widgets = {
            'escrow_release': forms.Select(attrs={'class': 'form-select'}),
            'recipient': forms.Select(attrs={'class': 'form-select'}),
            'amount': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'readonly': 'readonly',
            }),
            'payout_method': forms.Select(attrs={'class': 'form-select'}),
        }

    def clean(self):
        """Validate payout data."""
        cleaned_data = super().clean()
        escrow_release = cleaned_data.get('escrow_release')
        amount = cleaned_data.get('amount')

        if escrow_release and amount:
            if amount != escrow_release.amount:
                raise ValidationError('Payout amount must match release amount')

        return cleaned_data


class MilestoneCompletionForm(forms.Form):
    """Form for marking milestones as complete."""

    milestone_payment = forms.ModelChoiceField(
        queryset=None,
        widget=forms.Select(attrs={'class': 'form-select'}),
    )
    completion_notes = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 3,
            'placeholder': 'Describe the completed work...',
        }),
    )
    deliverable_files = forms.FileField(
        required=False,
        widget=forms.ClearableFileInput(attrs={
            'class': 'form-file',
            'multiple': True,
        }),
        help_text='Upload deliverable files'
    )

    def __init__(self, *args, **kwargs):
        escrow_transaction = kwargs.pop('escrow_transaction', None)
        super().__init__(*args, **kwargs)

        if escrow_transaction:
            self.fields['milestone_payment'].queryset = (
                MilestonePayment.objects.filter(
                    escrow_transaction=escrow_transaction,
                    status='pending'
                )
            )
