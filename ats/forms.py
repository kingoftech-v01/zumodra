"""
ATS Forms - Input validation for Applicant Tracking System.

This module provides secure forms for:
- Job postings
- Applications
- Interviews
- Offers
- Candidates

All forms include:
- Input sanitization
- XSS/SQL injection prevention
- File upload validation
- Field-level validation
"""

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from core.validators import (
    sanitize_html,
    sanitize_plain_text,
    NoSQLInjection,
    NoXSS,
    FileValidator,
    SecureTextValidator,
    PhoneValidator,
)

from .models import (
    JobPosting, Candidate, Application, Interview,
    InterviewFeedback, Offer, PipelineStage,
)


# =============================================================================
# JOB POSTING FORMS
# =============================================================================

class JobPostingForm(forms.ModelForm):
    """Secure form for creating/editing job postings."""

    class Meta:
        model = JobPosting
        fields = [
            'title', 'description', 'requirements', 'responsibilities',
            'category', 'employment_type', 'experience_level',
            'location', 'remote_policy', 'salary_min', 'salary_max',
            'application_deadline', 'pipeline',
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 6}),
            'requirements': forms.Textarea(attrs={'rows': 4}),
            'responsibilities': forms.Textarea(attrs={'rows': 4}),
            'application_deadline': forms.DateInput(attrs={'type': 'date'}),
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        self.tenant = kwargs.pop('tenant', None)
        super().__init__(*args, **kwargs)

    def clean_title(self):
        title = self.cleaned_data.get('title', '')
        # Validate and sanitize
        NoXSS()(title)
        NoSQLInjection()(title)
        return sanitize_plain_text(title)

    def clean_description(self):
        description = self.cleaned_data.get('description', '')
        # Allow some HTML formatting
        NoSQLInjection()(description)
        return sanitize_html(description)

    def clean_requirements(self):
        requirements = self.cleaned_data.get('requirements', '')
        NoSQLInjection()(requirements)
        return sanitize_html(requirements)

    def clean_responsibilities(self):
        responsibilities = self.cleaned_data.get('responsibilities', '')
        NoSQLInjection()(responsibilities)
        return sanitize_html(responsibilities)

    def clean(self):
        cleaned_data = super().clean()

        # Validate salary range
        salary_min = cleaned_data.get('salary_min')
        salary_max = cleaned_data.get('salary_max')

        if salary_min and salary_max and salary_min > salary_max:
            raise ValidationError({
                'salary_max': _('Maximum salary must be greater than minimum salary.')
            })

        return cleaned_data


class JobPostingSearchForm(forms.Form):
    """Form for searching job postings with secure input."""

    query = forms.CharField(
        required=False,
        max_length=200,
        validators=[NoSQLInjection(), NoXSS()],
    )
    category = forms.IntegerField(required=False)
    employment_type = forms.CharField(required=False, max_length=50)
    experience_level = forms.CharField(required=False, max_length=50)
    remote_only = forms.BooleanField(required=False)
    salary_min = forms.DecimalField(required=False, min_value=0)
    salary_max = forms.DecimalField(required=False, min_value=0)


# =============================================================================
# CANDIDATE FORMS
# =============================================================================

class CandidateForm(forms.ModelForm):
    """Secure form for creating/editing candidates."""

    resume = forms.FileField(
        required=False,
        validators=[FileValidator('resume')],
    )

    class Meta:
        model = Candidate
        fields = [
            'first_name', 'last_name', 'email', 'phone',
            'headline', 'location', 'resume',
            'linkedin_url', 'portfolio_url',
            'current_company', 'current_title',
            'years_experience', 'source',
        ]

    def clean_first_name(self):
        name = self.cleaned_data.get('first_name', '')
        NoXSS()(name)
        return sanitize_plain_text(name)

    def clean_last_name(self):
        name = self.cleaned_data.get('last_name', '')
        NoXSS()(name)
        return sanitize_plain_text(name)

    def clean_phone(self):
        phone = self.cleaned_data.get('phone', '')
        if phone:
            PhoneValidator()(phone)
        return phone

    def clean_headline(self):
        headline = self.cleaned_data.get('headline', '')
        NoXSS()(headline)
        NoSQLInjection()(headline)
        return sanitize_plain_text(headline)

    def clean_linkedin_url(self):
        url = self.cleaned_data.get('linkedin_url', '')
        if url and 'linkedin.com' not in url.lower():
            raise ValidationError(_('Please enter a valid LinkedIn URL.'))
        return url


class CandidateBulkImportForm(forms.Form):
    """Form for bulk importing candidates from CSV."""

    csv_file = forms.FileField(
        validators=[FileValidator(
            'document',
            allowed_extensions={'.csv'},
            allowed_mime_types={'text/csv', 'text/plain', 'application/csv'},
        )],
    )
    skip_duplicates = forms.BooleanField(required=False, initial=True)
    send_confirmation = forms.BooleanField(required=False, initial=False)


# =============================================================================
# APPLICATION FORMS
# =============================================================================

class ApplicationForm(forms.ModelForm):
    """Secure form for job applications."""

    resume = forms.FileField(
        required=False,
        validators=[FileValidator('resume')],
    )
    cover_letter = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'rows': 5}),
        max_length=5000,
    )

    class Meta:
        model = Application
        fields = ['cover_letter', 'resume']

    def clean_cover_letter(self):
        cover_letter = self.cleaned_data.get('cover_letter', '')
        NoSQLInjection()(cover_letter)
        return sanitize_html(cover_letter)


class ApplicationStageChangeForm(forms.Form):
    """Form for moving application to different stage."""

    stage = forms.ModelChoiceField(
        queryset=PipelineStage.objects.none(),
    )
    notes = forms.CharField(
        required=False,
        max_length=1000,
        widget=forms.Textarea(attrs={'rows': 3}),
    )

    def __init__(self, *args, pipeline=None, **kwargs):
        super().__init__(*args, **kwargs)
        if pipeline:
            self.fields['stage'].queryset = pipeline.stages.filter(is_active=True)

    def clean_notes(self):
        notes = self.cleaned_data.get('notes', '')
        NoXSS()(notes)
        return sanitize_plain_text(notes)


class ApplicationRejectForm(forms.Form):
    """Form for rejecting an application."""

    reason = forms.CharField(
        max_length=500,
        widget=forms.Textarea(attrs={'rows': 3}),
        validators=[NoXSS()],
    )
    send_notification = forms.BooleanField(required=False, initial=True)

    def clean_reason(self):
        reason = self.cleaned_data.get('reason', '')
        return sanitize_plain_text(reason)


class ApplicationBulkActionForm(forms.Form):
    """Form for bulk actions on applications."""

    ACTION_CHOICES = [
        ('move_stage', _('Move to Stage')),
        ('reject', _('Reject')),
        ('add_tag', _('Add Tag')),
        ('remove_tag', _('Remove Tag')),
        ('assign', _('Assign to User')),
    ]

    application_ids = forms.CharField(
        widget=forms.HiddenInput(),
    )
    action = forms.ChoiceField(choices=ACTION_CHOICES)
    target_stage = forms.ModelChoiceField(
        queryset=PipelineStage.objects.none(),
        required=False,
    )
    tag = forms.CharField(max_length=50, required=False)
    assignee = forms.IntegerField(required=False)

    def clean_application_ids(self):
        ids_str = self.cleaned_data.get('application_ids', '')
        try:
            # Expect comma-separated integers
            ids = [int(id.strip()) for id in ids_str.split(',') if id.strip()]
            return ids
        except ValueError:
            raise ValidationError(_('Invalid application IDs.'))

    def clean_tag(self):
        tag = self.cleaned_data.get('tag', '')
        NoXSS()(tag)
        return sanitize_plain_text(tag)


# =============================================================================
# INTERVIEW FORMS
# =============================================================================

class InterviewScheduleForm(forms.ModelForm):
    """Secure form for scheduling interviews."""

    class Meta:
        model = Interview
        fields = [
            'title', 'interview_type', 'scheduled_start', 'scheduled_end',
            'location', 'meeting_link', 'notes',
        ]
        widgets = {
            'scheduled_start': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
            'scheduled_end': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
            'notes': forms.Textarea(attrs={'rows': 3}),
        }

    def clean_title(self):
        title = self.cleaned_data.get('title', '')
        NoXSS()(title)
        return sanitize_plain_text(title)

    def clean_notes(self):
        notes = self.cleaned_data.get('notes', '')
        NoXSS()(notes)
        return sanitize_html(notes)

    def clean_meeting_link(self):
        link = self.cleaned_data.get('meeting_link', '')
        if link:
            # Basic URL validation
            if not link.startswith(('http://', 'https://')):
                raise ValidationError(_('Please enter a valid URL.'))
        return link

    def clean(self):
        cleaned_data = super().clean()
        start = cleaned_data.get('scheduled_start')
        end = cleaned_data.get('scheduled_end')

        if start and end and start >= end:
            raise ValidationError({
                'scheduled_end': _('End time must be after start time.')
            })

        return cleaned_data


class InterviewFeedbackForm(forms.ModelForm):
    """Form for submitting interview feedback."""

    class Meta:
        model = InterviewFeedback
        fields = [
            'overall_rating', 'recommendation',
            'strengths', 'weaknesses', 'notes',
        ]
        widgets = {
            'strengths': forms.Textarea(attrs={'rows': 3}),
            'weaknesses': forms.Textarea(attrs={'rows': 3}),
            'notes': forms.Textarea(attrs={'rows': 4}),
        }

    def clean_strengths(self):
        strengths = self.cleaned_data.get('strengths', '')
        NoXSS()(strengths)
        return sanitize_html(strengths)

    def clean_weaknesses(self):
        weaknesses = self.cleaned_data.get('weaknesses', '')
        NoXSS()(weaknesses)
        return sanitize_html(weaknesses)

    def clean_notes(self):
        notes = self.cleaned_data.get('notes', '')
        NoXSS()(notes)
        return sanitize_html(notes)


# =============================================================================
# OFFER FORMS
# =============================================================================

class OfferForm(forms.ModelForm):
    """Secure form for creating job offers."""

    class Meta:
        model = Offer
        fields = [
            'job_title', 'base_salary', 'bonus', 'equity',
            'start_date', 'expiration_date',
            'benefits_summary', 'additional_terms',
        ]
        widgets = {
            'start_date': forms.DateInput(attrs={'type': 'date'}),
            'expiration_date': forms.DateInput(attrs={'type': 'date'}),
            'benefits_summary': forms.Textarea(attrs={'rows': 3}),
            'additional_terms': forms.Textarea(attrs={'rows': 4}),
        }

    def clean_job_title(self):
        title = self.cleaned_data.get('job_title', '')
        NoXSS()(title)
        return sanitize_plain_text(title)

    def clean_benefits_summary(self):
        summary = self.cleaned_data.get('benefits_summary', '')
        NoXSS()(summary)
        return sanitize_html(summary)

    def clean_additional_terms(self):
        terms = self.cleaned_data.get('additional_terms', '')
        NoXSS()(terms)
        return sanitize_html(terms)

    def clean(self):
        cleaned_data = super().clean()
        start = cleaned_data.get('start_date')
        expiration = cleaned_data.get('expiration_date')

        if start and expiration and start < expiration:
            pass  # Valid: start date is before expiration

        # Validate salary is positive
        salary = cleaned_data.get('base_salary')
        if salary and salary < 0:
            raise ValidationError({
                'base_salary': _('Salary must be a positive number.')
            })

        return cleaned_data


class OfferResponseForm(forms.Form):
    """Form for candidate response to offer."""

    RESPONSE_CHOICES = [
        ('accept', _('Accept Offer')),
        ('decline', _('Decline Offer')),
        ('counter', _('Counter Offer')),
    ]

    response = forms.ChoiceField(choices=RESPONSE_CHOICES)
    counter_salary = forms.DecimalField(required=False, min_value=0)
    counter_start_date = forms.DateField(required=False)
    notes = forms.CharField(
        required=False,
        max_length=2000,
        widget=forms.Textarea(attrs={'rows': 4}),
    )

    def clean_notes(self):
        notes = self.cleaned_data.get('notes', '')
        NoXSS()(notes)
        return sanitize_plain_text(notes)

    def clean(self):
        cleaned_data = super().clean()
        response = cleaned_data.get('response')

        # Counter offer requires counter salary
        if response == 'counter':
            if not cleaned_data.get('counter_salary'):
                raise ValidationError({
                    'counter_salary': _('Please provide a counter salary.')
                })

        return cleaned_data
