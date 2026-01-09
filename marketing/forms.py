"""
Marketing Forms - Lead Management and Campaigns

This module provides forms for:
- Prospect/Lead capture and management
- Newsletter campaigns
- Subscriber management
- Conversion tracking
"""

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

from .models import (
    Prospect,
    NewsletterCampaign,
    NewsletterSubscriber,
    ConversionEvent,
)


class ProspectForm(forms.ModelForm):
    """
    Form for creating and managing prospects/leads.
    """

    class Meta:
        model = Prospect
        fields = [
            'email',
            'first_name',
            'last_name',
            'company',
            'phone',
            'source',
            'status',
        ]
        widgets = {
            'email': forms.EmailInput(attrs={
                'class': 'form-input',
                'placeholder': _('email@company.com'),
            }),
            'first_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('First Name'),
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Last Name'),
            }),
            'company': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Company Name'),
            }),
            'phone': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('+1 (555) 123-4567'),
            }),
            'source': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Lead source or campaign'),
            }),
            'status': forms.Select(attrs={
                'class': 'form-select',
            }),
        }
        help_texts = {
            'source': _('Where did this lead come from? (e.g., Website, LinkedIn, Referral)'),
        }


class LeadCaptureForm(forms.ModelForm):
    """
    Simplified form for lead capture from public-facing pages.
    """

    class Meta:
        model = Prospect
        fields = [
            'email',
            'first_name',
            'last_name',
            'company',
            'phone',
        ]
        widgets = {
            'email': forms.EmailInput(attrs={
                'class': 'form-input',
                'placeholder': _('Your email address'),
                'required': True,
            }),
            'first_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('First name'),
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Last name'),
            }),
            'company': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Company (optional)'),
            }),
            'phone': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Phone (optional)'),
            }),
        }


class ProspectStatusUpdateForm(forms.ModelForm):
    """
    Form for updating prospect status.
    """

    class Meta:
        model = Prospect
        fields = ['status']
        widgets = {
            'status': forms.Select(attrs={
                'class': 'form-select',
            }),
        }


class ProspectFilterForm(forms.Form):
    """
    Form for filtering prospects in list views.
    """

    STATUS_CHOICES = [
        ('', _('All Statuses')),
        ('new', _('New')),
        ('contacted', _('Contacted')),
        ('qualified', _('Qualified')),
        ('converted', _('Converted')),
        ('disqualified', _('Disqualified')),
    ]

    search = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Search by name, email, or company...'),
            'type': 'search',
        }),
    )
    status = forms.ChoiceField(
        choices=STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
    )
    source = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Filter by source...'),
        }),
    )
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
    )
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
    )


class NewsletterCampaignForm(forms.ModelForm):
    """
    Form for creating and editing newsletter campaigns.
    """

    class Meta:
        model = NewsletterCampaign
        fields = [
            'title',
            'subject',
            'content',
            'scheduled_for',
        ]
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Campaign Title (internal)'),
            }),
            'subject': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Email Subject Line'),
            }),
            'content': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 15,
                'placeholder': _('Email content (HTML supported)...'),
            }),
            'scheduled_for': forms.DateTimeInput(attrs={
                'class': 'form-input',
                'type': 'datetime-local',
            }),
        }
        help_texts = {
            'title': _('Internal reference name for this campaign'),
            'subject': _('Subject line recipients will see'),
            'scheduled_for': _('Leave blank to save as draft, or set a future date to schedule'),
        }

    def clean_scheduled_for(self):
        """Ensure scheduled time is in the future."""
        scheduled = self.cleaned_data.get('scheduled_for')
        if scheduled and scheduled < timezone.now():
            raise ValidationError(_('Scheduled time must be in the future.'))
        return scheduled


class QuickNewsletterForm(forms.ModelForm):
    """
    Simplified form for quick newsletter creation.
    """

    send_immediately = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Send immediately'),
    )

    class Meta:
        model = NewsletterCampaign
        fields = [
            'title',
            'subject',
            'content',
        ]
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Campaign Title'),
            }),
            'subject': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Email Subject'),
            }),
            'content': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 10,
            }),
        }


class NewsletterSubscriberForm(forms.ModelForm):
    """
    Form for managing newsletter subscribers.
    """

    class Meta:
        model = NewsletterSubscriber
        fields = [
            'email',
            'active',
        ]
        widgets = {
            'email': forms.EmailInput(attrs={
                'class': 'form-input',
                'placeholder': _('subscriber@email.com'),
            }),
            'active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class NewsletterSignupForm(forms.ModelForm):
    """
    Public-facing newsletter signup form.
    """

    class Meta:
        model = NewsletterSubscriber
        fields = ['email']
        widgets = {
            'email': forms.EmailInput(attrs={
                'class': 'form-input',
                'placeholder': _('Enter your email'),
            }),
        }

    def clean_email(self):
        """Check if email is already subscribed."""
        email = self.cleaned_data.get('email')
        if NewsletterSubscriber.objects.filter(email=email, active=True).exists():
            raise ValidationError(_('This email is already subscribed.'))
        return email


class NewsletterUnsubscribeForm(forms.Form):
    """
    Form for unsubscribing from newsletters.
    """

    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': _('Your email address'),
        }),
    )
    reason = forms.ChoiceField(
        choices=[
            ('too_many', _('Too many emails')),
            ('not_relevant', _('Content not relevant')),
            ('never_subscribed', _('Never subscribed')),
            ('other', _('Other')),
        ],
        required=False,
        widget=forms.RadioSelect(attrs={
            'class': 'form-radio',
        }),
        label=_('Reason for unsubscribing'),
    )
    feedback = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 3,
            'placeholder': _('Additional feedback (optional)'),
        }),
        label=_('Feedback'),
    )


class ConversionEventForm(forms.ModelForm):
    """
    Form for logging conversion events.
    """

    class Meta:
        model = ConversionEvent
        fields = [
            'marketing_id',
            'event_name',
            'value',
            'metadata',
        ]
        widgets = {
            'marketing_id': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Marketing ID'),
            }),
            'event_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('purchase, signup, etc.'),
            }),
            'value': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'metadata': forms.Textarea(attrs={
                'class': 'form-textarea code-editor',
                'rows': 5,
                'placeholder': _('{"product_id": "...", "campaign": "..."}'),
            }),
        }


class UTMParametersForm(forms.Form):
    """
    Form for UTM campaign tracking parameters.
    """

    utm_source = forms.CharField(
        max_length=128,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('google, facebook, newsletter'),
        }),
        label=_('UTM Source'),
        help_text=_('Where the traffic is coming from'),
    )
    utm_medium = forms.CharField(
        max_length=128,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('cpc, email, social'),
        }),
        label=_('UTM Medium'),
        help_text=_('Marketing medium (e.g., cpc, email)'),
    )
    utm_campaign = forms.CharField(
        max_length=128,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Campaign name'),
        }),
        label=_('UTM Campaign'),
        help_text=_('Specific campaign name'),
    )
    utm_content = forms.CharField(
        max_length=128,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Ad content or variant'),
        }),
        label=_('UTM Content'),
        help_text=_('Used for A/B testing'),
    )
    utm_term = forms.CharField(
        max_length=128,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Paid keywords'),
        }),
        label=_('UTM Term'),
        help_text=_('Paid search keywords'),
    )


class CampaignAnalyticsFilterForm(forms.Form):
    """
    Form for filtering campaign analytics.
    """

    date_range = forms.ChoiceField(
        choices=[
            ('7d', _('Last 7 days')),
            ('30d', _('Last 30 days')),
            ('90d', _('Last 90 days')),
            ('ytd', _('Year to date')),
            ('custom', _('Custom range')),
        ],
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        initial='30d',
    )
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
    )
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
    )
    campaign = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Filter by campaign...'),
        }),
    )
    source = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Filter by source...'),
        }),
    )


class BulkProspectImportForm(forms.Form):
    """
    Form for bulk importing prospects from CSV.
    """

    csv_file = forms.FileField(
        widget=forms.FileInput(attrs={
            'class': 'form-file',
            'accept': '.csv',
        }),
        label=_('CSV File'),
        help_text=_('CSV file with columns: email, first_name, last_name, company, phone'),
    )
    source = forms.CharField(
        max_length=256,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Import source (e.g., "Trade Show 2024")'),
        }),
        label=_('Import Source'),
    )
    skip_duplicates = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Skip duplicate emails'),
    )

    def clean_csv_file(self):
        """Validate CSV file format."""
        file = self.cleaned_data.get('csv_file')
        if file:
            if not file.name.endswith('.csv'):
                raise ValidationError(_('File must be a CSV file.'))
            if file.size > 5 * 1024 * 1024:  # 5MB limit
                raise ValidationError(_('File must be less than 5MB.'))
        return file
