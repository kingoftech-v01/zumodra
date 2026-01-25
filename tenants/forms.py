"""
Tenants App Forms

Forms for tenant management, invitations, and settings.
"""

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from .models import (
    Tenant,
    Domain,
    TenantInvitation,
    Plan,
)


class TenantForm(forms.ModelForm):
    """Form for creating/editing tenants."""

    class Meta:
        model = Tenant
        fields = [
            'name',
            'slug',
            'industry',
            'company_size',
            'logo',
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-input'}),
            'slug': forms.TextInput(attrs={'class': 'form-input'}),
            'industry': forms.TextInput(attrs={'class': 'form-input'}),
            'company_size': forms.Select(attrs={'class': 'form-select'}),
            'logo': forms.FileInput(attrs={'class': 'form-file'}),
        }

    def clean_slug(self):
        """Validate tenant slug."""
        slug = self.cleaned_data.get('slug', '').lower()
        if not slug.replace('-', '').replace('_', '').isalnum():
            raise ValidationError('Slug can only contain letters, numbers, hyphens, and underscores')
        return slug


class DomainForm(forms.ModelForm):
    """Form for managing tenant domains."""

    class Meta:
        model = Domain
        fields = ['domain', 'is_primary']
        widgets = {
            'domain': forms.TextInput(attrs={'class': 'form-input'}),
            'is_primary': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        }


class TenantInvitationForm(forms.ModelForm):
    """Form for inviting users to tenant."""

    class Meta:
        model = TenantInvitation
        fields = ['email', 'assigned_role']
        widgets = {
            'email': forms.EmailInput(attrs={'class': 'form-input'}),
            'assigned_role': forms.Select(attrs={'class': 'form-select'}),
        }

    def __init__(self, *args, **kwargs):
        self.tenant = kwargs.pop('tenant', None)
        self.invited_by = kwargs.pop('invited_by', None)
        super().__init__(*args, **kwargs)


class CompanyInfoForm(forms.Form):
    """Step 1: Company information form for signup wizard."""

    company_name = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Enter your company name')
        }),
        label=_('Company Name')
    )

    company_size = forms.ChoiceField(
        choices=[
            ('1-10', _('1-10 employees')),
            ('11-50', _('11-50 employees')),
            ('51-200', _('51-200 employees')),
            ('201-500', _('201-500 employees')),
            ('500+', _('500+ employees')),
        ],
        widget=forms.Select(attrs={'class': 'form-select'}),
        label=_('Company Size')
    )

    industry = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('e.g., Technology, Healthcare, Finance')
        }),
        label=_('Industry')
    )

    website = forms.URLField(
        required=False,
        widget=forms.URLInput(attrs={
            'class': 'form-input',
            'placeholder': _('https://example.com')
        }),
        label=_('Website (Optional)')
    )


class PlanSelectionForm(forms.Form):
    """Step 2: Plan selection form for signup wizard."""

    plan_id = forms.ChoiceField(
        widget=forms.RadioSelect(attrs={'class': 'form-radio'}),
        label=_('Select a Plan')
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Dynamically populate plan choices from active plans
        plans = Plan.objects.filter(is_active=True).order_by('price_monthly')
        self.fields['plan_id'].choices = [
            (plan.id, f"{plan.name} - ${plan.price_monthly}/month")
            for plan in plans
        ]


class StripePaymentForm(forms.Form):
    """Step 3: Payment form for signup wizard."""

    stripe_payment_method_id = forms.CharField(
        widget=forms.HiddenInput(),
        label=_('Payment Method')
    )

    cardholder_name = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Name on card')
        }),
        label=_('Cardholder Name')
    )
