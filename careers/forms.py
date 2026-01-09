"""
Careers Forms - Public Career Pages and Job Applications

This module provides forms for:
- Career site configuration
- Public job application forms
- Job alert subscriptions
- Talent pool management
"""

from django import forms
from django.core.validators import FileExtensionValidator
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .models import (
    CareerSite,
    CareerPage,
    CareerPageSection,
    CareerCustomPage,
    JobListing,
    PublicApplication,
    JobAlert,
    TalentPool,
    validate_hex_color,
)


class CareerSiteForm(forms.ModelForm):
    """
    Form for configuring career site settings.
    """

    class Meta:
        model = CareerSite
        fields = [
            'company_name',
            'subdomain',
            'custom_domain',
            'tagline',
            'description',
            'logo',
            'favicon',
            'cover_image',
            'primary_color',
            'secondary_color',
            'accent_color',
            'text_color',
            'background_color',
            'is_active',
            'is_published',
            'show_salary_range',
        ]
        widgets = {
            'company_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Company Name'),
            }),
            'subdomain': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('your-company'),
            }),
            'custom_domain': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('careers.yourcompany.com'),
            }),
            'tagline': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Join our amazing team'),
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
            }),
            'logo': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': 'image/*',
            }),
            'favicon': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': 'image/*',
            }),
            'cover_image': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': 'image/*',
            }),
            'primary_color': forms.TextInput(attrs={
                'class': 'form-input',
                'type': 'color',
            }),
            'secondary_color': forms.TextInput(attrs={
                'class': 'form-input',
                'type': 'color',
            }),
            'accent_color': forms.TextInput(attrs={
                'class': 'form-input',
                'type': 'color',
            }),
            'text_color': forms.TextInput(attrs={
                'class': 'form-input',
                'type': 'color',
            }),
            'background_color': forms.TextInput(attrs={
                'class': 'form-input',
                'type': 'color',
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'is_published': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'show_salary_range': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        help_texts = {
            'subdomain': _('This will be used for your career site URL: subdomain.careers.zumodra.com'),
            'custom_domain': _('Optionally use your own domain for the career site'),
            'logo': _('Company logo (max 5MB)'),
            'cover_image': _('Hero banner image (max 10MB, recommended 1920x600)'),
        }


class CareerSiteContentForm(forms.ModelForm):
    """
    Form for editing career site content sections.
    """

    class Meta:
        model = CareerSite
        fields = [
            'hero_title',
            'hero_subtitle',
            'hero_cta_text',
            'hero_cta_url',
            'about_company',
            'company_video_url',
            'benefits_title',
            'culture_title',
            'culture_content',
            'show_team_section',
            'team_title',
            'show_testimonials',
        ]
        widgets = {
            'hero_title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Join Our Team'),
            }),
            'hero_subtitle': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Build your career with us'),
            }),
            'hero_cta_text': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('View Open Positions'),
            }),
            'hero_cta_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://...'),
            }),
            'about_company': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 6,
            }),
            'company_video_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('YouTube or Vimeo URL'),
            }),
            'benefits_title': forms.TextInput(attrs={
                'class': 'form-input',
            }),
            'culture_title': forms.TextInput(attrs={
                'class': 'form-input',
            }),
            'culture_content': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
            }),
            'show_team_section': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'team_title': forms.TextInput(attrs={
                'class': 'form-input',
            }),
            'show_testimonials': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class CareerSiteSEOForm(forms.ModelForm):
    """
    Form for career site SEO and analytics settings.
    """

    class Meta:
        model = CareerSite
        fields = [
            'meta_title',
            'meta_description',
            'meta_keywords',
            'og_image',
            'canonical_url',
            'google_analytics_id',
            'google_tag_manager_id',
            'facebook_pixel_id',
            'linkedin_insight_tag',
        ]
        widgets = {
            'meta_title': forms.TextInput(attrs={
                'class': 'form-input',
                'maxlength': '60',
            }),
            'meta_description': forms.TextInput(attrs={
                'class': 'form-input',
                'maxlength': '160',
            }),
            'meta_keywords': forms.TextInput(attrs={
                'class': 'form-input',
            }),
            'og_image': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': 'image/*',
            }),
            'canonical_url': forms.URLInput(attrs={
                'class': 'form-input',
            }),
            'google_analytics_id': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('G-XXXXXXXXXX'),
            }),
            'google_tag_manager_id': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('GTM-XXXXXX'),
            }),
            'facebook_pixel_id': forms.TextInput(attrs={
                'class': 'form-input',
            }),
            'linkedin_insight_tag': forms.TextInput(attrs={
                'class': 'form-input',
            }),
        }
        help_texts = {
            'meta_title': _('SEO title (max 60 characters)'),
            'meta_description': _('SEO description (max 160 characters)'),
            'og_image': _('Social sharing image (recommended 1200x630)'),
        }


class CareerSiteSocialForm(forms.ModelForm):
    """
    Form for career site social links.
    """

    class Meta:
        model = CareerSite
        fields = [
            'linkedin_url',
            'twitter_url',
            'facebook_url',
            'instagram_url',
            'glassdoor_url',
            'youtube_url',
        ]
        widgets = {
            'linkedin_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://linkedin.com/company/...'),
            }),
            'twitter_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://twitter.com/...'),
            }),
            'facebook_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://facebook.com/...'),
            }),
            'instagram_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://instagram.com/...'),
            }),
            'glassdoor_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://glassdoor.com/...'),
            }),
            'youtube_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://youtube.com/...'),
            }),
        }


class CareerSitePrivacyForm(forms.ModelForm):
    """
    Form for career site privacy and GDPR settings.
    """

    class Meta:
        model = CareerSite
        fields = [
            'gdpr_consent_text',
            'privacy_policy_url',
            'terms_url',
            'data_retention_days',
            'require_account',
            'allow_general_applications',
            'max_resume_size_mb',
        ]
        widgets = {
            'gdpr_consent_text': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
            }),
            'privacy_policy_url': forms.URLInput(attrs={
                'class': 'form-input',
            }),
            'terms_url': forms.URLInput(attrs={
                'class': 'form-input',
            }),
            'data_retention_days': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '30',
                'max': '730',
            }),
            'require_account': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'allow_general_applications': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'max_resume_size_mb': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '1',
                'max': '25',
            }),
        }


class CareerPageForm(forms.ModelForm):
    """
    Form for legacy career page configuration.
    """

    class Meta:
        model = CareerPage
        fields = [
            'title',
            'tagline',
            'description',
            'logo',
            'cover_image',
            'primary_color',
            'secondary_color',
            'is_active',
        ]
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-input',
            }),
            'tagline': forms.TextInput(attrs={
                'class': 'form-input',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
            }),
            'logo': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': 'image/*',
            }),
            'cover_image': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': 'image/*',
            }),
            'primary_color': forms.TextInput(attrs={
                'class': 'form-input',
                'type': 'color',
            }),
            'secondary_color': forms.TextInput(attrs={
                'class': 'form-input',
                'type': 'color',
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class CareerPageSectionForm(forms.ModelForm):
    """
    Form for adding/editing career page sections.
    """

    class Meta:
        model = CareerPageSection
        fields = [
            'title',
            'section_type',
            'content',
            'order',
            'is_visible',
        ]
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-input',
            }),
            'section_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'content': forms.Textarea(attrs={
                'class': 'form-textarea code-editor',
                'rows': 10,
            }),
            'order': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
            }),
            'is_visible': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class CareerCustomPageForm(forms.ModelForm):
    """
    Form for creating custom pages on career site.
    """

    class Meta:
        model = CareerCustomPage
        fields = [
            'title',
            'slug',
            'content',
            'meta_title',
            'meta_description',
            'is_published',
            'show_in_nav',
            'nav_order',
        ]
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-input',
            }),
            'slug': forms.TextInput(attrs={
                'class': 'form-input',
            }),
            'content': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 15,
            }),
            'meta_title': forms.TextInput(attrs={
                'class': 'form-input',
                'maxlength': '60',
            }),
            'meta_description': forms.TextInput(attrs={
                'class': 'form-input',
                'maxlength': '160',
            }),
            'is_published': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'show_in_nav': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'nav_order': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
            }),
        }


class JobListingForm(forms.ModelForm):
    """
    Form for configuring public job listing display settings.
    """

    class Meta:
        model = JobListing
        fields = [
            'custom_slug',
            'show_company_name',
            'show_department',
            'show_team_size',
            'show_application_count',
            'application_count_threshold',
            'is_featured',
            'feature_priority',
            'expires_at',
        ]
        widgets = {
            'custom_slug': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('custom-job-url'),
            }),
            'show_company_name': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'show_department': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'show_team_size': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'show_application_count': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'application_count_threshold': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '1',
            }),
            'is_featured': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'feature_priority': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
            }),
            'expires_at': forms.DateTimeInput(attrs={
                'class': 'form-input',
                'type': 'datetime-local',
            }),
        }


class PublicApplicationForm(forms.ModelForm):
    """
    Public-facing job application form.
    Used by candidates applying through the career site.
    """

    # Hidden honeypot field for spam detection
    website = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'style': 'display: none;',
            'tabindex': '-1',
            'autocomplete': 'off',
        }),
    )

    # Track submission time for spam detection
    form_started_at = forms.CharField(
        required=False,
        widget=forms.HiddenInput(),
    )

    class Meta:
        model = PublicApplication
        fields = [
            'first_name',
            'last_name',
            'email',
            'phone',
            'resume',
            'cover_letter',
            'linkedin_url',
            'portfolio_url',
            'privacy_consent',
            'marketing_consent',
        ]
        widgets = {
            'first_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('First Name'),
                'required': True,
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Last Name'),
                'required': True,
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-input',
                'placeholder': _('email@example.com'),
                'required': True,
            }),
            'phone': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('+1 (555) 123-4567'),
            }),
            'resume': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': '.pdf,.doc,.docx',
                'required': True,
            }),
            'cover_letter': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 6,
                'placeholder': _('Tell us why you are interested in this position...'),
            }),
            'linkedin_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://linkedin.com/in/...'),
            }),
            'portfolio_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://...'),
            }),
            'privacy_consent': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
                'required': True,
            }),
            'marketing_consent': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        help_texts = {
            'resume': _('Accepted formats: PDF, DOC, DOCX. Max 10MB.'),
            'privacy_consent': _('I consent to the processing of my personal data.'),
            'marketing_consent': _('I agree to receive job-related communications.'),
        }

    def clean_website(self):
        """Detect honeypot spam."""
        website = self.cleaned_data.get('website')
        if website:
            # Honeypot field was filled - likely spam
            raise ValidationError(_('Invalid submission.'))
        return website

    def clean_resume(self):
        """Validate resume file size."""
        resume = self.cleaned_data.get('resume')
        if resume and hasattr(resume, 'size'):
            if resume.size > 10 * 1024 * 1024:  # 10MB
                raise ValidationError(_('Resume must be less than 10MB.'))
        return resume

    def clean_privacy_consent(self):
        """Ensure privacy consent is given."""
        consent = self.cleaned_data.get('privacy_consent')
        if not consent:
            raise ValidationError(_('You must consent to the privacy policy to apply.'))
        return consent


class JobAlertForm(forms.ModelForm):
    """
    Form for subscribing to job alerts.
    """

    class Meta:
        model = JobAlert
        fields = [
            'email',
            'name',
            'frequency',
            'remote_only',
        ]
        widgets = {
            'email': forms.EmailInput(attrs={
                'class': 'form-input',
                'placeholder': _('your.email@example.com'),
                'required': True,
            }),
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Your name (optional)'),
            }),
            'frequency': forms.Select(attrs={
                'class': 'form-select',
            }),
            'remote_only': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class JobAlertPreferencesForm(forms.ModelForm):
    """
    Form for editing job alert preferences.
    """

    class Meta:
        model = JobAlert
        fields = [
            'frequency',
            'departments',
            'job_types',
            'locations',
            'keywords',
            'remote_only',
            'min_salary',
        ]
        widgets = {
            'frequency': forms.Select(attrs={
                'class': 'form-select',
            }),
            'departments': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
                'placeholder': _('Engineering, Marketing, Sales (one per line)'),
            }),
            'job_types': forms.CheckboxSelectMultiple(attrs={
                'class': 'form-checkbox',
            }),
            'locations': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
                'placeholder': _('New York, Remote, Europe (one per line)'),
            }),
            'keywords': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
                'placeholder': _('Python, React, DevOps (one per line)'),
            }),
            'remote_only': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'min_salary': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
                'step': '1000',
            }),
        }


class JobSearchForm(forms.Form):
    """
    Form for searching jobs on career site.
    """

    query = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Search jobs...'),
            'type': 'search',
        }),
    )
    department = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
    )
    location = forms.CharField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
    )
    job_type = forms.ChoiceField(
        required=False,
        choices=[
            ('', _('All Job Types')),
            ('full_time', _('Full-time')),
            ('part_time', _('Part-time')),
            ('contract', _('Contract')),
            ('temporary', _('Temporary')),
            ('internship', _('Internship')),
        ],
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
    )
    remote = forms.ChoiceField(
        required=False,
        choices=[
            ('', _('All')),
            ('remote', _('Remote Only')),
            ('hybrid', _('Hybrid')),
            ('onsite', _('On-site')),
        ],
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
    )


class TalentPoolForm(forms.ModelForm):
    """
    Form for creating talent pools.
    """

    class Meta:
        model = TalentPool
        fields = [
            'name',
            'description',
            'is_public',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Talent Pool Name'),
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
            'is_public': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        help_texts = {
            'is_public': _('Allow candidates to self-join this talent pool'),
        }


class JobAlertUnsubscribeForm(forms.Form):
    """
    Form for unsubscribing from job alerts.
    """

    token = forms.UUIDField(widget=forms.HiddenInput())
    reason = forms.ChoiceField(
        required=False,
        choices=[
            ('', _('Select a reason...')),
            ('found_job', _('I found a job')),
            ('too_many', _('Too many emails')),
            ('not_relevant', _('Jobs not relevant')),
            ('other', _('Other')),
        ],
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
    )
    feedback = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 3,
            'placeholder': _('Additional feedback (optional)'),
        }),
    )
