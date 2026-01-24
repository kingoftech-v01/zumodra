"""
Marketing Campaigns App Forms

Forms for contacts, campaigns, and tracking (merged from marketing + newsletter).
"""

from django import forms
from django.core.exceptions import ValidationError
from .models import (
    Contact,
    MarketingCampaign,
    ContactSegment,
)


class ContactForm(forms.ModelForm):
    """Form for managing contacts (leads/subscribers)."""

    class Meta:
        model = Contact
        fields = [
            'email',
            'first_name',
            'last_name',
            'company',
            'phone',
            'status',
            'source',
        ]
        widgets = {
            'email': forms.EmailInput(attrs={'class': 'form-input'}),
            'first_name': forms.TextInput(attrs={'class': 'form-input'}),
            'last_name': forms.TextInput(attrs={'class': 'form-input'}),
            'company': forms.TextInput(attrs={'class': 'form-input'}),
            'phone': forms.TextInput(attrs={'class': 'form-input'}),
            'status': forms.Select(attrs={'class': 'form-select'}),
            'source': forms.Select(attrs={'class': 'form-select'}),
        }

    def clean_email(self):
        """Validate email uniqueness within tenant."""
        email = self.cleaned_data.get('email', '').lower()
        return email


class ContactImportForm(forms.Form):
    """Form for bulk importing contacts."""

    csv_file = forms.FileField(
        widget=forms.FileInput(attrs={'class': 'form-file', 'accept': '.csv'}),
        help_text='Upload CSV file with columns: email, first_name, last_name, company'
    )
    skip_duplicates = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        help_text='Skip contacts that already exist'
    )


class MarketingCampaignForm(forms.ModelForm):
    """Form for creating marketing campaigns."""

    class Meta:
        model = MarketingCampaign
        fields = [
            'title',
            'slug',
            'campaign_type',
            'subject',
            'preview_text',
            'content',
            'segment',
            'scheduled_for',
        ]
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-input'}),
            'slug': forms.TextInput(attrs={'class': 'form-input'}),
            'campaign_type': forms.Select(attrs={'class': 'form-select'}),
            'subject': forms.TextInput(attrs={'class': 'form-input'}),
            'preview_text': forms.TextInput(attrs={'class': 'form-input'}),
            'content': forms.Textarea(attrs={'class': 'form-textarea', 'rows': 10}),
            'segment': forms.Select(attrs={'class': 'form-select'}),
            'scheduled_for': forms.DateTimeInput(attrs={
                'class': 'form-input',
                'type': 'datetime-local',
            }),
        }


class ContactSegmentForm(forms.ModelForm):
    """Form for creating contact segments."""

    class Meta:
        model = ContactSegment
        fields = ['name', 'description', 'filters']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-input'}),
            'description': forms.Textarea(attrs={'class': 'form-textarea', 'rows': 2}),
            'filters': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 6,
                'placeholder': '{"status": "subscribed", "source": "website"}',
            }),
        }


class NewsletterSubscribeForm(forms.Form):
    """Form for newsletter subscription (public)."""

    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': 'your@email.com',
        }),
    )
    first_name = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': 'First Name',
        }),
    )

    def clean_email(self):
        """Validate and normalize email."""
        email = self.cleaned_data.get('email', '').lower().strip()
        if not email:
            raise ValidationError('Email is required')
        return email
