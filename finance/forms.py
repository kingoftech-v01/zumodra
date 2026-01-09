"""
Finance Forms - Input validation for Payment Processing.

This module provides secure forms for:
- Payment transactions
- Refund requests
- Escrow management
- Disputes
- Payouts

All forms include:
- Input sanitization
- XSS/SQL injection prevention
- Amount validation
- Field-level validation

SECURITY NOTE: All financial operations require additional
server-side validation beyond form validation.
"""

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from decimal import Decimal

from core.validators import (
    sanitize_html,
    sanitize_plain_text,
    NoSQLInjection,
    NoXSS,
    FileValidator,
    SecureTextValidator,
)

from .models import (
    PaymentTransaction, RefundRequest, EscrowTransaction,
    Dispute, EscrowPayout, Invoice, PaymentMethod,
)


# =============================================================================
# PAYMENT FORMS
# =============================================================================

class PaymentForm(forms.Form):
    """Secure form for initiating payments."""

    amount = forms.DecimalField(
        min_value=Decimal('0.01'),
        max_value=Decimal('999999.99'),
        decimal_places=2,
    )
    currency = forms.ChoiceField(
        choices=[
            ('USD', 'US Dollar'),
            ('EUR', 'Euro'),
            ('GBP', 'British Pound'),
            ('CAD', 'Canadian Dollar'),
        ],
        initial='USD',
    )
    description = forms.CharField(
        max_length=500,
        required=False,
        validators=[NoXSS()],
    )
    payment_method_id = forms.CharField(
        max_length=100,
        required=False,
    )

    def clean_amount(self):
        amount = self.cleaned_data.get('amount')
        if amount and amount <= 0:
            raise ValidationError(_('Amount must be a positive number.'))
        return amount

    def clean_description(self):
        description = self.cleaned_data.get('description', '')
        if description:
            return sanitize_plain_text(description)
        return description


class PaymentMethodForm(forms.ModelForm):
    """Form for adding payment methods (card info goes to Stripe)."""

    # Note: Actual card details are collected via Stripe.js
    # This form handles metadata only

    class Meta:
        model = PaymentMethod
        fields = ['nickname', 'is_default']

    nickname = forms.CharField(
        max_length=50,
        required=False,
        validators=[NoXSS()],
    )

    def clean_nickname(self):
        nickname = self.cleaned_data.get('nickname', '')
        if nickname:
            return sanitize_plain_text(nickname)
        return nickname


class SetDefaultPaymentMethodForm(forms.Form):
    """Form for setting default payment method."""

    payment_method_id = forms.CharField(max_length=100)

    def clean_payment_method_id(self):
        pm_id = self.cleaned_data.get('payment_method_id', '')
        # Validate format (Stripe payment method IDs start with 'pm_')
        if pm_id and not pm_id.startswith('pm_'):
            raise ValidationError(_('Invalid payment method ID.'))
        return pm_id


# =============================================================================
# REFUND FORMS
# =============================================================================

class RefundRequestForm(forms.ModelForm):
    """Secure form for requesting refunds."""

    REASON_CHOICES = [
        ('duplicate', _('Duplicate charge')),
        ('fraudulent', _('Fraudulent charge')),
        ('product_unacceptable', _('Product/service not as described')),
        ('product_not_received', _('Product/service not received')),
        ('other', _('Other')),
    ]

    reason = forms.ChoiceField(choices=REASON_CHOICES)
    description = forms.CharField(
        max_length=2000,
        widget=forms.Textarea(attrs={'rows': 4}),
    )
    evidence = forms.FileField(
        required=False,
        validators=[FileValidator('document')],
    )

    class Meta:
        model = RefundRequest
        fields = ['reason', 'description']

    def clean_description(self):
        description = self.cleaned_data.get('description', '')
        NoXSS()(description)
        NoSQLInjection()(description)
        return sanitize_html(description)


class RefundProcessForm(forms.Form):
    """Admin form for processing refund requests."""

    ACTION_CHOICES = [
        ('approve', _('Approve Refund')),
        ('partial', _('Partial Refund')),
        ('reject', _('Reject Request')),
    ]

    action = forms.ChoiceField(choices=ACTION_CHOICES)
    refund_amount = forms.DecimalField(
        required=False,
        min_value=Decimal('0.01'),
        decimal_places=2,
    )
    admin_notes = forms.CharField(
        max_length=1000,
        required=False,
        widget=forms.Textarea(attrs={'rows': 3}),
    )

    def clean_admin_notes(self):
        notes = self.cleaned_data.get('admin_notes', '')
        if notes:
            NoXSS()(notes)
            return sanitize_plain_text(notes)
        return notes

    def clean(self):
        cleaned_data = super().clean()
        action = cleaned_data.get('action')
        refund_amount = cleaned_data.get('refund_amount')

        if action == 'partial' and not refund_amount:
            raise ValidationError({
                'refund_amount': _('Partial refund requires an amount.')
            })

        return cleaned_data


# =============================================================================
# ESCROW FORMS
# =============================================================================

class EscrowFundForm(forms.Form):
    """Form for funding an escrow transaction."""

    amount = forms.DecimalField(
        min_value=Decimal('1.00'),
        max_value=Decimal('999999.99'),
        decimal_places=2,
    )
    contract_id = forms.IntegerField()
    description = forms.CharField(
        max_length=500,
        required=False,
        validators=[NoXSS()],
    )

    def clean_amount(self):
        amount = self.cleaned_data.get('amount')
        if amount and amount <= 0:
            raise ValidationError(_('Amount must be a positive number.'))
        return amount

    def clean_description(self):
        description = self.cleaned_data.get('description', '')
        if description:
            return sanitize_plain_text(description)
        return description


class EscrowReleaseForm(forms.Form):
    """Form for releasing escrow funds."""

    RELEASE_TYPE_CHOICES = [
        ('full', _('Full Release')),
        ('partial', _('Partial Release')),
        ('milestone', _('Milestone Release')),
    ]

    release_type = forms.ChoiceField(choices=RELEASE_TYPE_CHOICES)
    amount = forms.DecimalField(
        required=False,
        min_value=Decimal('0.01'),
        decimal_places=2,
    )
    milestone_id = forms.IntegerField(required=False)
    notes = forms.CharField(
        max_length=500,
        required=False,
        validators=[NoXSS()],
    )

    def clean_notes(self):
        notes = self.cleaned_data.get('notes', '')
        if notes:
            return sanitize_plain_text(notes)
        return notes

    def clean(self):
        cleaned_data = super().clean()
        release_type = cleaned_data.get('release_type')

        if release_type == 'partial':
            if not cleaned_data.get('amount'):
                raise ValidationError({
                    'amount': _('Partial release requires an amount.')
                })
        elif release_type == 'milestone':
            if not cleaned_data.get('milestone_id'):
                raise ValidationError({
                    'milestone_id': _('Milestone release requires a milestone ID.')
                })

        return cleaned_data


class EscrowCancelForm(forms.Form):
    """Form for canceling/refunding an escrow transaction."""

    reason = forms.CharField(
        max_length=1000,
        widget=forms.Textarea(attrs={'rows': 3}),
    )
    refund_to_buyer = forms.BooleanField(
        initial=True,
        required=False,
    )

    def clean_reason(self):
        reason = self.cleaned_data.get('reason', '')
        NoXSS()(reason)
        NoSQLInjection()(reason)
        return sanitize_plain_text(reason)


# =============================================================================
# DISPUTE FORMS
# =============================================================================

class DisputeForm(forms.ModelForm):
    """Secure form for creating disputes."""

    REASON_CHOICES = [
        ('not_as_described', _('Item/service not as described')),
        ('not_received', _('Item/service not received')),
        ('quality', _('Quality issues')),
        ('incomplete', _('Incomplete work')),
        ('timeline', _('Timeline issues')),
        ('communication', _('Communication issues')),
        ('fraud', _('Suspected fraud')),
        ('other', _('Other')),
    ]

    reason = forms.ChoiceField(choices=REASON_CHOICES)
    description = forms.CharField(
        max_length=5000,
        widget=forms.Textarea(attrs={'rows': 6}),
    )
    evidence = forms.FileField(
        required=False,
        validators=[FileValidator('document')],
    )
    desired_resolution = forms.CharField(
        max_length=2000,
        widget=forms.Textarea(attrs={'rows': 3}),
    )
    requested_amount = forms.DecimalField(
        required=False,
        min_value=Decimal('0.00'),
        decimal_places=2,
    )

    class Meta:
        model = Dispute
        fields = ['reason', 'description', 'desired_resolution', 'requested_amount']

    def clean_description(self):
        description = self.cleaned_data.get('description', '')
        NoXSS()(description)
        NoSQLInjection()(description)
        return sanitize_html(description)

    def clean_desired_resolution(self):
        resolution = self.cleaned_data.get('desired_resolution', '')
        NoXSS()(resolution)
        return sanitize_plain_text(resolution)


class DisputeResponseForm(forms.Form):
    """Form for responding to a dispute."""

    response = forms.CharField(
        max_length=5000,
        widget=forms.Textarea(attrs={'rows': 6}),
    )
    evidence = forms.FileField(
        required=False,
        validators=[FileValidator('document')],
    )
    counter_offer = forms.DecimalField(
        required=False,
        min_value=Decimal('0.00'),
        decimal_places=2,
    )

    def clean_response(self):
        response = self.cleaned_data.get('response', '')
        NoXSS()(response)
        NoSQLInjection()(response)
        return sanitize_html(response)


class DisputeResolutionForm(forms.Form):
    """Admin form for resolving disputes."""

    RESOLUTION_CHOICES = [
        ('buyer_win', _('Ruled in favor of buyer')),
        ('seller_win', _('Ruled in favor of seller')),
        ('split', _('Split resolution')),
        ('dismissed', _('Dispute dismissed')),
    ]

    resolution = forms.ChoiceField(choices=RESOLUTION_CHOICES)
    buyer_amount = forms.DecimalField(
        required=False,
        min_value=Decimal('0.00'),
        decimal_places=2,
    )
    seller_amount = forms.DecimalField(
        required=False,
        min_value=Decimal('0.00'),
        decimal_places=2,
    )
    resolution_notes = forms.CharField(
        max_length=2000,
        widget=forms.Textarea(attrs={'rows': 4}),
    )

    def clean_resolution_notes(self):
        notes = self.cleaned_data.get('resolution_notes', '')
        NoXSS()(notes)
        return sanitize_html(notes)

    def clean(self):
        cleaned_data = super().clean()
        resolution = cleaned_data.get('resolution')

        if resolution == 'split':
            if not cleaned_data.get('buyer_amount'):
                raise ValidationError({
                    'buyer_amount': _('Split resolution requires buyer amount.')
                })
            if not cleaned_data.get('seller_amount'):
                raise ValidationError({
                    'seller_amount': _('Split resolution requires seller amount.')
                })

        return cleaned_data


# =============================================================================
# PAYOUT FORMS
# =============================================================================

class PayoutRequestForm(forms.Form):
    """Form for requesting a payout."""

    amount = forms.DecimalField(
        min_value=Decimal('10.00'),  # Minimum payout
        max_value=Decimal('999999.99'),
        decimal_places=2,
    )
    notes = forms.CharField(
        max_length=500,
        required=False,
        validators=[NoXSS()],
    )

    def clean_amount(self):
        amount = self.cleaned_data.get('amount')
        if amount and amount < Decimal('10.00'):
            raise ValidationError(_('Minimum payout amount is $10.00.'))
        return amount

    def clean_notes(self):
        notes = self.cleaned_data.get('notes', '')
        if notes:
            return sanitize_plain_text(notes)
        return notes


class PayoutProcessForm(forms.Form):
    """Admin form for processing payouts."""

    ACTION_CHOICES = [
        ('approve', _('Approve Payout')),
        ('reject', _('Reject Payout')),
        ('hold', _('Hold for Review')),
    ]

    action = forms.ChoiceField(choices=ACTION_CHOICES)
    admin_notes = forms.CharField(
        max_length=1000,
        required=False,
        widget=forms.Textarea(attrs={'rows': 3}),
    )
    rejection_reason = forms.CharField(
        max_length=500,
        required=False,
    )

    def clean_admin_notes(self):
        notes = self.cleaned_data.get('admin_notes', '')
        if notes:
            NoXSS()(notes)
            return sanitize_plain_text(notes)
        return notes

    def clean_rejection_reason(self):
        reason = self.cleaned_data.get('rejection_reason', '')
        if reason:
            NoXSS()(reason)
            return sanitize_plain_text(reason)
        return reason

    def clean(self):
        cleaned_data = super().clean()
        action = cleaned_data.get('action')

        if action == 'reject' and not cleaned_data.get('rejection_reason'):
            raise ValidationError({
                'rejection_reason': _('Rejection requires a reason.')
            })

        return cleaned_data


# =============================================================================
# INVOICE FORMS
# =============================================================================

class InvoiceForm(forms.ModelForm):
    """Secure form for creating invoices."""

    class Meta:
        model = Invoice
        fields = [
            'invoice_number', 'due_date', 'notes',
        ]
        widgets = {
            'due_date': forms.DateInput(attrs={'type': 'date'}),
            'notes': forms.Textarea(attrs={'rows': 3}),
        }

    def clean_invoice_number(self):
        number = self.cleaned_data.get('invoice_number', '')
        NoXSS()(number)
        return sanitize_plain_text(number)

    def clean_notes(self):
        notes = self.cleaned_data.get('notes', '')
        if notes:
            NoSQLInjection()(notes)
            return sanitize_html(notes)
        return notes


class InvoiceLineItemForm(forms.Form):
    """Form for invoice line items."""

    description = forms.CharField(
        max_length=500,
        validators=[NoXSS()],
    )
    quantity = forms.DecimalField(
        min_value=Decimal('0.01'),
        decimal_places=2,
    )
    unit_price = forms.DecimalField(
        min_value=Decimal('0.00'),
        decimal_places=2,
    )
    tax_rate = forms.DecimalField(
        required=False,
        min_value=Decimal('0.00'),
        max_value=Decimal('100.00'),
        decimal_places=2,
    )

    def clean_description(self):
        description = self.cleaned_data.get('description', '')
        return sanitize_plain_text(description)


class InvoiceSendForm(forms.Form):
    """Form for sending an invoice."""

    recipient_email = forms.EmailField()
    cc_emails = forms.CharField(
        required=False,
        max_length=500,
    )
    message = forms.CharField(
        required=False,
        max_length=2000,
        widget=forms.Textarea(attrs={'rows': 4}),
    )

    def clean_cc_emails(self):
        cc = self.cleaned_data.get('cc_emails', '')
        if cc:
            # Validate comma-separated emails
            emails = [e.strip() for e in cc.split(',') if e.strip()]
            for email in emails:
                if '@' not in email:
                    raise ValidationError(_('Invalid email in CC list: {}').format(email))
            return ','.join(emails)
        return cc

    def clean_message(self):
        message = self.cleaned_data.get('message', '')
        if message:
            NoXSS()(message)
            return sanitize_html(message)
        return message


# =============================================================================
# SUBSCRIPTION FORMS
# =============================================================================

class SubscriptionChangeForm(forms.Form):
    """Form for changing subscription plan."""

    plan_id = forms.IntegerField()
    billing_cycle = forms.ChoiceField(
        choices=[
            ('monthly', _('Monthly')),
            ('annual', _('Annual')),
        ],
        initial='monthly',
    )
    promo_code = forms.CharField(
        max_length=50,
        required=False,
        validators=[NoXSS()],
    )

    def clean_promo_code(self):
        code = self.cleaned_data.get('promo_code', '')
        if code:
            # Promo codes should be alphanumeric
            if not code.replace('-', '').replace('_', '').isalnum():
                raise ValidationError(_('Invalid promo code format.'))
            return code.upper()
        return code


class SubscriptionCancelForm(forms.Form):
    """Form for canceling subscription."""

    REASON_CHOICES = [
        ('too_expensive', _('Too expensive')),
        ('not_using', _('Not using enough')),
        ('missing_features', _('Missing features')),
        ('switching', _('Switching to competitor')),
        ('other', _('Other')),
    ]

    reason = forms.ChoiceField(choices=REASON_CHOICES)
    feedback = forms.CharField(
        required=False,
        max_length=2000,
        widget=forms.Textarea(attrs={'rows': 4}),
    )
    cancel_immediately = forms.BooleanField(
        initial=False,
        required=False,
    )

    def clean_feedback(self):
        feedback = self.cleaned_data.get('feedback', '')
        if feedback:
            NoXSS()(feedback)
            return sanitize_plain_text(feedback)
        return feedback


# =============================================================================
# STRIPE CONNECT FORMS
# =============================================================================

class ConnectedAccountForm(forms.Form):
    """Form for Stripe Connect onboarding information."""

    # Note: Most account info is collected via Stripe Connect onboarding
    # This form handles supplementary data

    business_type = forms.ChoiceField(
        choices=[
            ('individual', _('Individual')),
            ('company', _('Company')),
        ],
    )
    country = forms.CharField(max_length=2)  # ISO country code
    payout_schedule = forms.ChoiceField(
        choices=[
            ('daily', _('Daily')),
            ('weekly', _('Weekly')),
            ('monthly', _('Monthly')),
        ],
        initial='weekly',
    )

    def clean_country(self):
        country = self.cleaned_data.get('country', '').upper()
        # Validate country code (basic check)
        if len(country) != 2 or not country.isalpha():
            raise ValidationError(_('Invalid country code.'))
        return country


class BankAccountForm(forms.Form):
    """Form for adding bank account details."""

    # Note: Actual bank details go directly to Stripe
    # This form handles metadata

    account_holder_name = forms.CharField(
        max_length=100,
        validators=[NoXSS()],
    )
    account_holder_type = forms.ChoiceField(
        choices=[
            ('individual', _('Individual')),
            ('company', _('Company')),
        ],
    )
    is_default = forms.BooleanField(initial=True, required=False)

    def clean_account_holder_name(self):
        name = self.cleaned_data.get('account_holder_name', '')
        return sanitize_plain_text(name)
