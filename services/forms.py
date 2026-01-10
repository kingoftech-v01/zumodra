"""
Services Forms - Input validation for Freelance Marketplace.

This module provides secure forms for:
- Services
- Proposals
- Contracts
- Reviews
- Client Requests

All forms include:
- Input sanitization
- XSS/SQL injection prevention
- File upload validation
- Field-level validation
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
    Service, ServiceCategory, ServiceTag, ServiceImage,
    ServiceProvider, ServiceProposal, ServiceContract,
    ServiceReview, ClientRequest, ContractMessage,
    CrossTenantServiceRequest,
)


# =============================================================================
# SERVICE FORMS
# =============================================================================

class ServiceForm(forms.ModelForm):
    """Secure form for creating/editing services."""

    class Meta:
        model = Service
        fields = [
            'title', 'description', 'category', 'tags',
            'base_price', 'price_type', 'delivery_time',
            'revisions_included', 'requirements',
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 6}),
            'requirements': forms.Textarea(attrs={'rows': 4}),
        }

    def clean_title(self):
        title = self.cleaned_data.get('title', '')
        NoXSS()(title)
        NoSQLInjection()(title)
        return sanitize_plain_text(title)

    def clean_description(self):
        description = self.cleaned_data.get('description', '')
        NoSQLInjection()(description)
        return sanitize_html(description)

    def clean_requirements(self):
        requirements = self.cleaned_data.get('requirements', '')
        NoSQLInjection()(requirements)
        return sanitize_html(requirements)

    def clean_base_price(self):
        price = self.cleaned_data.get('base_price')
        if price and price < 0:
            raise ValidationError(_('Price must be a positive number.'))
        return price

    def clean_delivery_time(self):
        delivery_time = self.cleaned_data.get('delivery_time')
        if delivery_time and delivery_time < 1:
            raise ValidationError(_('Delivery time must be at least 1 day.'))
        return delivery_time


class ServiceImageForm(forms.ModelForm):
    """Form for uploading service images."""

    image = forms.ImageField(
        validators=[FileValidator('image')],
    )

    class Meta:
        model = ServiceImage
        fields = ['image', 'caption', 'is_primary']

    def clean_caption(self):
        caption = self.cleaned_data.get('caption', '')
        if caption:
            NoXSS()(caption)
            return sanitize_plain_text(caption)
        return caption


class ServiceSearchForm(forms.Form):
    """Form for searching services with secure input."""

    query = forms.CharField(
        required=False,
        max_length=200,
        validators=[NoSQLInjection(), NoXSS()],
    )
    category = forms.IntegerField(required=False)
    min_price = forms.DecimalField(required=False, min_value=0)
    max_price = forms.DecimalField(required=False, min_value=0)
    min_rating = forms.DecimalField(required=False, min_value=0, max_value=5)
    provider_location = forms.CharField(
        required=False,
        max_length=100,
        validators=[NoXSS()],
    )

    def clean(self):
        cleaned_data = super().clean()
        min_price = cleaned_data.get('min_price')
        max_price = cleaned_data.get('max_price')

        if min_price and max_price and min_price > max_price:
            raise ValidationError({
                'max_price': _('Maximum price must be greater than minimum price.')
            })

        return cleaned_data


# =============================================================================
# PROPOSAL FORMS
# =============================================================================

class ProposalForm(forms.ModelForm):
    """Secure form for creating service proposals."""

    class Meta:
        model = ServiceProposal
        fields = [
            'cover_letter', 'proposed_price', 'delivery_days',
            'milestones',
        ]
        widgets = {
            'cover_letter': forms.Textarea(attrs={'rows': 6}),
            'milestones': forms.Textarea(attrs={'rows': 4}),
        }

    def clean_cover_letter(self):
        cover_letter = self.cleaned_data.get('cover_letter', '')
        NoSQLInjection()(cover_letter)
        return sanitize_html(cover_letter)

    def clean_proposed_price(self):
        price = self.cleaned_data.get('proposed_price')
        if price and price <= 0:
            raise ValidationError(_('Price must be a positive number.'))
        return price

    def clean_delivery_days(self):
        days = self.cleaned_data.get('delivery_days')
        if days and days < 1:
            raise ValidationError(_('Delivery time must be at least 1 day.'))
        return days

    def clean_milestones(self):
        milestones = self.cleaned_data.get('milestones', '')
        if milestones:
            NoSQLInjection()(milestones)
            return sanitize_html(milestones)
        return milestones


class ProposalResponseForm(forms.Form):
    """Form for client response to a proposal."""

    ACTION_CHOICES = [
        ('accept', _('Accept Proposal')),
        ('reject', _('Reject Proposal')),
        ('counter', _('Counter Offer')),
    ]

    action = forms.ChoiceField(choices=ACTION_CHOICES)
    counter_price = forms.DecimalField(required=False, min_value=0)
    counter_days = forms.IntegerField(required=False, min_value=1)
    message = forms.CharField(
        required=False,
        max_length=2000,
        widget=forms.Textarea(attrs={'rows': 4}),
    )

    def clean_message(self):
        message = self.cleaned_data.get('message', '')
        if message:
            NoXSS()(message)
            return sanitize_plain_text(message)
        return message

    def clean(self):
        cleaned_data = super().clean()
        action = cleaned_data.get('action')

        if action == 'counter':
            if not cleaned_data.get('counter_price'):
                raise ValidationError({
                    'counter_price': _('Please provide a counter price.')
                })

        return cleaned_data


# =============================================================================
# CONTRACT FORMS
# =============================================================================

class ContractForm(forms.ModelForm):
    """Secure form for contract details."""

    class Meta:
        model = ServiceContract
        fields = [
            'title', 'description', 'total_amount',
            'payment_terms', 'deadline',
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 6}),
            'payment_terms': forms.Textarea(attrs={'rows': 3}),
            'deadline': forms.DateInput(attrs={'type': 'date'}),
        }

    def clean_title(self):
        title = self.cleaned_data.get('title', '')
        NoXSS()(title)
        NoSQLInjection()(title)
        return sanitize_plain_text(title)

    def clean_description(self):
        description = self.cleaned_data.get('description', '')
        NoSQLInjection()(description)
        return sanitize_html(description)

    def clean_payment_terms(self):
        terms = self.cleaned_data.get('payment_terms', '')
        if terms:
            NoSQLInjection()(terms)
            return sanitize_html(terms)
        return terms

    def clean_total_amount(self):
        amount = self.cleaned_data.get('total_amount')
        if amount and amount <= 0:
            raise ValidationError(_('Amount must be a positive number.'))
        return amount


class ContractMilestoneForm(forms.Form):
    """Form for adding/editing contract milestones."""

    title = forms.CharField(
        max_length=200,
        validators=[NoXSS()],
    )
    description = forms.CharField(
        required=False,
        max_length=2000,
        widget=forms.Textarea(attrs={'rows': 3}),
    )
    amount = forms.DecimalField(min_value=Decimal('0.01'))
    due_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'type': 'date'}),
    )

    def clean_title(self):
        title = self.cleaned_data.get('title', '')
        return sanitize_plain_text(title)

    def clean_description(self):
        description = self.cleaned_data.get('description', '')
        if description:
            NoSQLInjection()(description)
            return sanitize_html(description)
        return description


class ContractDeliverableForm(forms.Form):
    """Form for submitting contract deliverables."""

    message = forms.CharField(
        max_length=5000,
        widget=forms.Textarea(attrs={'rows': 4}),
    )
    files = forms.FileField(
        required=False,
        validators=[FileValidator('document')],
    )

    def clean_message(self):
        message = self.cleaned_data.get('message', '')
        NoSQLInjection()(message)
        return sanitize_html(message)


class ContractRevisionRequestForm(forms.Form):
    """Form for requesting revisions on deliverables."""

    feedback = forms.CharField(
        max_length=5000,
        widget=forms.Textarea(attrs={'rows': 4}),
    )

    def clean_feedback(self):
        feedback = self.cleaned_data.get('feedback', '')
        NoXSS()(feedback)
        NoSQLInjection()(feedback)
        return sanitize_html(feedback)


class ContractCompletionForm(forms.Form):
    """Form for completing/approving a contract."""

    rating = forms.IntegerField(min_value=1, max_value=5)
    feedback = forms.CharField(
        required=False,
        max_length=2000,
        widget=forms.Textarea(attrs={'rows': 4}),
    )
    tip_amount = forms.DecimalField(required=False, min_value=0)

    def clean_feedback(self):
        feedback = self.cleaned_data.get('feedback', '')
        if feedback:
            NoXSS()(feedback)
            return sanitize_html(feedback)
        return feedback


class ContractDisputeForm(forms.Form):
    """Form for raising a contract dispute."""

    REASON_CHOICES = [
        ('quality', _('Quality issues with deliverables')),
        ('incomplete', _('Work incomplete')),
        ('communication', _('Communication issues')),
        ('deadline', _('Missed deadline')),
        ('scope', _('Scope disagreement')),
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

    def clean_description(self):
        description = self.cleaned_data.get('description', '')
        NoXSS()(description)
        NoSQLInjection()(description)
        return sanitize_html(description)

    def clean_desired_resolution(self):
        resolution = self.cleaned_data.get('desired_resolution', '')
        NoXSS()(resolution)
        return sanitize_plain_text(resolution)


# =============================================================================
# REVIEW FORMS
# =============================================================================

class ServiceReviewForm(forms.ModelForm):
    """Secure form for submitting service reviews."""

    class Meta:
        model = ServiceReview
        fields = [
            'overall_rating', 'quality_rating', 'communication_rating',
            'timeliness_rating', 'value_rating',
            'title', 'content', 'would_recommend',
        ]
        widgets = {
            'content': forms.Textarea(attrs={'rows': 5}),
        }

    def clean_title(self):
        title = self.cleaned_data.get('title', '')
        if title:
            NoXSS()(title)
            return sanitize_plain_text(title)
        return title

    def clean_content(self):
        content = self.cleaned_data.get('content', '')
        NoXSS()(content)
        NoSQLInjection()(content)
        return sanitize_html(content)

    def clean(self):
        cleaned_data = super().clean()

        # Validate all ratings are in range
        rating_fields = [
            'overall_rating', 'quality_rating', 'communication_rating',
            'timeliness_rating', 'value_rating'
        ]

        for field in rating_fields:
            rating = cleaned_data.get(field)
            if rating is not None and (rating < 1 or rating > 5):
                raise ValidationError({
                    field: _('Rating must be between 1 and 5.')
                })

        return cleaned_data


class ReviewResponseForm(forms.Form):
    """Form for provider response to a review."""

    response = forms.CharField(
        max_length=2000,
        widget=forms.Textarea(attrs={'rows': 4}),
    )

    def clean_response(self):
        response = self.cleaned_data.get('response', '')
        NoXSS()(response)
        NoSQLInjection()(response)
        return sanitize_html(response)


# =============================================================================
# CLIENT REQUEST FORMS
# =============================================================================

class ClientRequestForm(forms.ModelForm):
    """Secure form for client service requests."""

    class Meta:
        model = ClientRequest
        fields = [
            'title', 'description', 'category',
            'budget_min', 'budget_max', 'deadline',
            'requirements', 'attachments',
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 6}),
            'requirements': forms.Textarea(attrs={'rows': 4}),
            'deadline': forms.DateInput(attrs={'type': 'date'}),
        }

    attachments = forms.FileField(
        required=False,
        validators=[FileValidator('document')],
    )

    def clean_title(self):
        title = self.cleaned_data.get('title', '')
        NoXSS()(title)
        NoSQLInjection()(title)
        return sanitize_plain_text(title)

    def clean_description(self):
        description = self.cleaned_data.get('description', '')
        NoSQLInjection()(description)
        return sanitize_html(description)

    def clean_requirements(self):
        requirements = self.cleaned_data.get('requirements', '')
        if requirements:
            NoSQLInjection()(requirements)
            return sanitize_html(requirements)
        return requirements

    def clean(self):
        cleaned_data = super().clean()

        budget_min = cleaned_data.get('budget_min')
        budget_max = cleaned_data.get('budget_max')

        if budget_min and budget_max and budget_min > budget_max:
            raise ValidationError({
                'budget_max': _('Maximum budget must be greater than minimum budget.')
            })

        return cleaned_data


# =============================================================================
# CROSS-TENANT REQUEST FORMS
# =============================================================================

class CrossTenantServiceRequestForm(forms.ModelForm):
    """
    Secure form for cross-tenant service requests.

    Supports both ORGANIZATIONAL and PERSONAL hiring contexts:
    - ORGANIZATIONAL: User hiring on behalf of their tenant/company
    - PERSONAL: User hiring for themselves
    """

    class Meta:
        model = CrossTenantServiceRequest
        fields = [
            'title', 'description', 'budget',
            'deadline', 'hiring_context', 'requirements',
        ]
        widgets = {
            'description': forms.Textarea(attrs={
                'rows': 6,
                'placeholder': _('Describe your project requirements, goals, and expectations...')
            }),
            'requirements': forms.Textarea(attrs={
                'rows': 4,
                'placeholder': _('List specific requirements, deliverables, or constraints...')
            }),
            'deadline': forms.DateInput(attrs={
                'type': 'date',
                'class': 'form-input'
            }),
            'hiring_context': forms.RadioSelect(attrs={
                'class': 'form-radio'
            }),
            'budget': forms.NumberInput(attrs={
                'placeholder': _('e.g., 5000'),
                'class': 'form-input',
                'min': '0',
                'step': '0.01'
            }),
        }
        labels = {
            'hiring_context': _('Hiring For'),
            'budget': _('Budget (CAD)'),
            'deadline': _('Desired Completion Date'),
        }
        help_texts = {
            'hiring_context': _('Choose whether this is a personal hire or on behalf of your organization'),
            'budget': _('Your maximum budget for this project'),
        }

    def __init__(self, *args, user=None, tenant=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        self.tenant = tenant

        # If user has no tenant, force PERSONAL context
        if not tenant:
            self.fields['hiring_context'].initial = CrossTenantServiceRequest.HiringContext.PERSONAL
            self.fields['hiring_context'].widget = forms.HiddenInput()

        # Add CSS classes for styling
        for field_name, field in self.fields.items():
            if field_name not in ['hiring_context']:
                if 'class' not in field.widget.attrs:
                    field.widget.attrs['class'] = 'form-input'

    def clean_title(self):
        title = self.cleaned_data.get('title', '')
        NoXSS()(title)
        NoSQLInjection()(title)
        return sanitize_plain_text(title)

    def clean_description(self):
        description = self.cleaned_data.get('description', '')
        NoSQLInjection()(description)
        return sanitize_html(description)

    def clean_requirements(self):
        requirements = self.cleaned_data.get('requirements', '')
        if requirements:
            NoSQLInjection()(requirements)
            return sanitize_html(requirements)
        return requirements

    def clean_budget(self):
        budget = self.cleaned_data.get('budget')
        if budget and budget < 0:
            raise ValidationError(_('Budget must be a positive number.'))
        return budget

    def clean(self):
        cleaned_data = super().clean()
        hiring_context = cleaned_data.get('hiring_context')

        # Validate hiring context based on user's tenant status
        if hiring_context == CrossTenantServiceRequest.HiringContext.ORGANIZATIONAL:
            if not self.tenant:
                raise ValidationError({
                    'hiring_context': _('You must be part of an organization to hire on its behalf. '
                                       'Please select "Personal" or join/create an organization.')
                })

        return cleaned_data


# =============================================================================
# MESSAGE FORMS
# =============================================================================

class ContractMessageForm(forms.ModelForm):
    """Secure form for contract messages."""

    attachment = forms.FileField(
        required=False,
        validators=[FileValidator('document')],
    )

    class Meta:
        model = ContractMessage
        fields = ['content', 'attachment']
        widgets = {
            'content': forms.Textarea(attrs={'rows': 3}),
        }

    def clean_content(self):
        content = self.cleaned_data.get('content', '')
        NoXSS()(content)
        NoSQLInjection()(content)
        return sanitize_html(content)


# =============================================================================
# PROVIDER FORMS
# =============================================================================

class ServiceProviderProfileForm(forms.ModelForm):
    """Secure form for service provider profile."""

    class Meta:
        model = ServiceProvider
        fields = [
            'headline', 'bio', 'hourly_rate',
            'availability', 'languages', 'skills',
            'portfolio_url', 'linkedin_url', 'github_url',
        ]
        widgets = {
            'bio': forms.Textarea(attrs={'rows': 6}),
            'languages': forms.Textarea(attrs={'rows': 2}),
        }

    def clean_headline(self):
        headline = self.cleaned_data.get('headline', '')
        if headline:
            NoXSS()(headline)
            return sanitize_plain_text(headline)
        return headline

    def clean_bio(self):
        bio = self.cleaned_data.get('bio', '')
        if bio:
            NoSQLInjection()(bio)
            return sanitize_html(bio)
        return bio

    def clean_hourly_rate(self):
        rate = self.cleaned_data.get('hourly_rate')
        if rate and rate < 0:
            raise ValidationError(_('Hourly rate must be a positive number.'))
        return rate

    def clean_portfolio_url(self):
        url = self.cleaned_data.get('portfolio_url', '')
        if url and not url.startswith(('http://', 'https://')):
            raise ValidationError(_('Please enter a valid URL.'))
        return url

    def clean_linkedin_url(self):
        url = self.cleaned_data.get('linkedin_url', '')
        if url and 'linkedin.com' not in url.lower():
            raise ValidationError(_('Please enter a valid LinkedIn URL.'))
        return url

    def clean_github_url(self):
        url = self.cleaned_data.get('github_url', '')
        if url and 'github.com' not in url.lower():
            raise ValidationError(_('Please enter a valid GitHub URL.'))
        return url
