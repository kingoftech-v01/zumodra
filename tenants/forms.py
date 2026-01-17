"""
Tenants Forms - Multi-tenant Configuration and Management

This module provides forms for:
- Tenant settings and configuration
- Domain management
- Tenant invitations
- Plan management
- Circusale (business unit) management
"""

from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
import re

from .models import (
    Plan,
    Tenant,
    TenantSettings,
    Domain,
    TenantInvitation,
    Circusale,
    CircusaleUser,
)


class TenantForm(forms.ModelForm):
    """
    Form for creating and updating tenant organizations.
    """

    class Meta:
        model = Tenant
        fields = [
            'name',
            'slug',
            'owner_email',
            'industry',
            'company_size',
            'website',
            'logo',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Organization Name'),
            }),
            'slug': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('organization-slug'),
            }),
            'owner_email': forms.EmailInput(attrs={
                'class': 'form-input',
                'placeholder': _('admin@company.com'),
            }),
            'industry': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Technology, Healthcare, etc.'),
            }),
            'company_size': forms.Select(attrs={
                'class': 'form-select',
            }),
            'website': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://www.company.com'),
            }),
            'logo': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': 'image/*',
            }),
        }
        help_texts = {
            'slug': _('URL-friendly identifier (lowercase letters, numbers, hyphens only)'),
            'logo': _('Allowed formats: JPG, PNG, GIF, SVG, WebP. Max size: 5MB'),
        }

    def clean_slug(self):
        """Validate slug format."""
        slug = self.cleaned_data.get('slug', '').lower()
        if not re.match(r'^[a-z0-9]+(?:-[a-z0-9]+)*$', slug):
            raise ValidationError(_('Slug must contain only lowercase letters, numbers, and hyphens.'))
        return slug

    def clean_logo(self):
        """Validate logo file size."""
        logo = self.cleaned_data.get('logo')
        if logo and hasattr(logo, 'size'):
            if logo.size > 5 * 1024 * 1024:  # 5MB
                raise ValidationError(_('Logo file must be less than 5MB.'))
        return logo


class TenantAddressForm(forms.ModelForm):
    """
    Form for tenant address information.
    """

    class Meta:
        model = Tenant
        fields = [
            'address_line1',
            'address_line2',
            'city',
            'state',
            'postal_code',
            'country',
        ]
        widgets = {
            'address_line1': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Street Address'),
            }),
            'address_line2': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Suite, Unit, Building (optional)'),
            }),
            'city': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('City'),
            }),
            'state': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('State/Province'),
            }),
            'postal_code': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Postal/ZIP Code'),
            }),
            'country': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Country'),
            }),
        }


class TenantSettingsForm(forms.ModelForm):
    """
    Form for tenant-specific settings.
    """

    class Meta:
        model = TenantSettings
        fields = [
            'primary_color',
            'secondary_color',
            'accent_color',
            'favicon',
            'default_language',
            'default_timezone',
            'date_format',
            'time_format',
            'currency',
        ]
        widgets = {
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
            'favicon': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': '.ico,.png,.svg',
            }),
            'default_language': forms.Select(attrs={
                'class': 'form-select',
            }, choices=[
                ('en', 'English'),
                ('fr', 'French'),
                ('es', 'Spanish'),
                ('de', 'German'),
            ]),
            'default_timezone': forms.Select(attrs={
                'class': 'form-select',
            }, choices=[
                ('America/Toronto', 'Eastern Time (Toronto)'),
                ('America/Vancouver', 'Pacific Time (Vancouver)'),
                ('America/New_York', 'Eastern Time (New York)'),
                ('America/Los_Angeles', 'Pacific Time (Los Angeles)'),
                ('America/Chicago', 'Central Time (Chicago)'),
                ('America/Denver', 'Mountain Time (Denver)'),
                ('Europe/London', 'London (GMT)'),
                ('Europe/Paris', 'Paris (CET)'),
                ('Asia/Tokyo', 'Tokyo (JST)'),
                ('UTC', 'UTC'),
            ]),
            'date_format': forms.Select(attrs={
                'class': 'form-select',
            }, choices=[
                ('YYYY-MM-DD', 'YYYY-MM-DD'),
                ('DD/MM/YYYY', 'DD/MM/YYYY'),
                ('MM/DD/YYYY', 'MM/DD/YYYY'),
            ]),
            'time_format': forms.Select(attrs={
                'class': 'form-select',
            }),
            'currency': forms.Select(attrs={
                'class': 'form-select',
            }, choices=[
                ('CAD', 'CAD - Canadian Dollar'),
                ('USD', 'USD - US Dollar'),
                ('EUR', 'EUR - Euro'),
                ('GBP', 'GBP - British Pound'),
            ]),
        }
        help_texts = {
            'favicon': _('Allowed formats: ICO, PNG, SVG. Max size: 1MB'),
        }


class TenantATSSettingsForm(forms.ModelForm):
    """
    Form for ATS-specific tenant settings.
    """

    pipeline_stages = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 4,
            'placeholder': _('New\nScreening\nInterview\nOffer\nHired'),
        }),
        label=_('Default Pipeline Stages'),
        help_text=_('One stage per line'),
    )

    class Meta:
        model = TenantSettings
        fields = [
            'require_cover_letter',
            'auto_reject_after_days',
            'send_rejection_email',
        ]
        widgets = {
            'require_cover_letter': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'auto_reject_after_days': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
                'max': '365',
            }),
            'send_rejection_email': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        help_texts = {
            'auto_reject_after_days': _('Automatically reject inactive applications after this many days (0 to disable)'),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.default_pipeline_stages:
            self.fields['pipeline_stages'].initial = '\n'.join(self.instance.default_pipeline_stages)

    def clean_pipeline_stages(self):
        """Parse stages from textarea."""
        stages_text = self.cleaned_data.get('pipeline_stages', '')
        if stages_text:
            stages = [s.strip() for s in stages_text.split('\n') if s.strip()]
            return stages
        return []

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.default_pipeline_stages = self.cleaned_data.get('pipeline_stages', [])
        if commit:
            instance.save()
        return instance


class TenantHRSettingsForm(forms.ModelForm):
    """
    Form for HR-specific tenant settings.
    """

    class Meta:
        model = TenantSettings
        fields = [
            'fiscal_year_start_month',
            'default_pto_days',
            'approval_workflow_enabled',
        ]
        widgets = {
            'fiscal_year_start_month': forms.Select(attrs={
                'class': 'form-select',
            }, choices=[
                (1, 'January'),
                (2, 'February'),
                (3, 'March'),
                (4, 'April'),
                (5, 'May'),
                (6, 'June'),
                (7, 'July'),
                (8, 'August'),
                (9, 'September'),
                (10, 'October'),
                (11, 'November'),
                (12, 'December'),
            ]),
            'default_pto_days': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
                'max': '365',
            }),
            'approval_workflow_enabled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class TenantSecuritySettingsForm(forms.ModelForm):
    """
    Form for security-related tenant settings.
    """

    email_domains = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 3,
            'placeholder': _('company.com\nsubsidiary.com'),
        }),
        label=_('Allowed Email Domains'),
        help_text=_('One domain per line. Leave blank to allow any domain.'),
    )

    ip_addresses = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 3,
            'placeholder': _('192.168.1.0\n10.0.0.0'),
        }),
        label=_('IP Whitelist'),
        help_text=_('One IP address per line for admin access restriction'),
    )

    class Meta:
        model = TenantSettings
        fields = [
            'require_2fa',
            'session_timeout_minutes',
            'password_expiry_days',
        ]
        widgets = {
            'require_2fa': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'session_timeout_minutes': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '5',
                'max': '1440',
            }),
            'password_expiry_days': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
                'max': '365',
            }),
        }
        help_texts = {
            'session_timeout_minutes': _('Session timeout (5-1440 minutes)'),
            'password_expiry_days': _('Force password change after this many days (0 to disable)'),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            if self.instance.allowed_email_domains:
                self.fields['email_domains'].initial = '\n'.join(self.instance.allowed_email_domains)
            if self.instance.ip_whitelist:
                self.fields['ip_addresses'].initial = '\n'.join(str(ip) for ip in self.instance.ip_whitelist)

    def clean_email_domains(self):
        """Parse and validate email domains."""
        domains_text = self.cleaned_data.get('email_domains', '')
        if domains_text:
            domains = [d.strip().lower() for d in domains_text.split('\n') if d.strip()]
            for domain in domains:
                if not re.match(r'^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$', domain):
                    raise ValidationError(_('Invalid domain format: %(domain)s') % {'domain': domain})
            return domains
        return []

    def clean_ip_addresses(self):
        """Parse and validate IP addresses."""
        ips_text = self.cleaned_data.get('ip_addresses', '')
        if ips_text:
            ips = [ip.strip() for ip in ips_text.split('\n') if ip.strip()]
            # Basic validation - Django's GenericIPAddressField will validate further
            for ip in ips:
                parts = ip.split('.')
                if len(parts) != 4:
                    raise ValidationError(_('Invalid IP address format: %(ip)s') % {'ip': ip})
            return ips
        return []

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.allowed_email_domains = self.cleaned_data.get('email_domains', [])
        instance.ip_whitelist = self.cleaned_data.get('ip_addresses', [])
        if commit:
            instance.save()
        return instance


class TenantCareerPageSettingsForm(forms.ModelForm):
    """
    Form for career page settings.
    """

    class Meta:
        model = TenantSettings
        fields = [
            'career_page_enabled',
            'career_page_title',
            'career_page_description',
            'career_page_custom_css',
            'show_salary_range',
        ]
        widgets = {
            'career_page_enabled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'career_page_title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Careers at Company'),
            }),
            'career_page_description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
                'placeholder': _('Join our team and help shape the future...'),
            }),
            'career_page_custom_css': forms.Textarea(attrs={
                'class': 'form-textarea code-editor',
                'rows': 8,
                'placeholder': _('/* Custom CSS styles */'),
            }),
            'show_salary_range': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class TenantNotificationSettingsForm(forms.ModelForm):
    """
    Form for notification settings.
    """

    class Meta:
        model = TenantSettings
        fields = [
            'notify_new_application',
            'notify_interview_scheduled',
            'notify_offer_accepted',
            'daily_digest_enabled',
        ]
        widgets = {
            'notify_new_application': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'notify_interview_scheduled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'notify_offer_accepted': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'daily_digest_enabled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class TenantIntegrationSettingsForm(forms.ModelForm):
    """
    Form for integration settings.
    """

    class Meta:
        model = TenantSettings
        fields = [
            'integration_slack_enabled',
            'integration_slack_webhook',
            'integration_calendar_enabled',
            'integration_calendar_provider',
        ]
        widgets = {
            'integration_slack_enabled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'integration_slack_webhook': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://hooks.slack.com/services/...'),
            }),
            'integration_calendar_enabled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'integration_calendar_provider': forms.Select(attrs={
                'class': 'form-select',
            }),
        }


class DomainForm(forms.ModelForm):
    """
    Form for managing tenant domains.
    """

    class Meta:
        model = Domain
        fields = [
            'domain',
            'is_primary',
            'is_careers_domain',
            'ssl_enabled',
        ]
        widgets = {
            'domain': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('app.company.com'),
            }),
            'is_primary': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'is_careers_domain': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'ssl_enabled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        help_texts = {
            'domain': _('Custom domain for your organization'),
            'is_primary': _('Primary domain for accessing the application'),
            'is_careers_domain': _('Use this domain for public career pages'),
        }

    def clean_domain(self):
        """Validate domain format."""
        domain = self.cleaned_data.get('domain', '').lower()
        if not re.match(r'^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$', domain):
            raise ValidationError(_('Invalid domain format.'))
        return domain


class DomainSSLForm(forms.ModelForm):
    """
    Form for custom SSL certificate configuration.
    """

    class Meta:
        model = Domain
        fields = [
            'ssl_certificate',
            'ssl_private_key',
        ]
        widgets = {
            'ssl_certificate': forms.Textarea(attrs={
                'class': 'form-textarea code-editor',
                'rows': 10,
                'placeholder': _('-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'),
            }),
            'ssl_private_key': forms.Textarea(attrs={
                'class': 'form-textarea code-editor',
                'rows': 10,
                'placeholder': _('-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----'),
            }),
        }
        help_texts = {
            'ssl_certificate': _('PEM-encoded SSL certificate'),
            'ssl_private_key': _('PEM-encoded private key (kept secure)'),
        }


class TenantInvitationForm(forms.ModelForm):
    """
    Form for inviting users to join a tenant.
    """

    ROLE_CHOICES = [
        ('viewer', _('Viewer')),
        ('member', _('Member')),
        ('recruiter', _('Recruiter')),
        ('hr_manager', _('HR Manager')),
        ('supervisor', _('Supervisor')),
        ('admin', _('Admin')),
    ]

    role = forms.ChoiceField(
        choices=ROLE_CHOICES,
        initial='member',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Role'),
    )

    class Meta:
        model = TenantInvitation
        fields = [
            'email',
            'role',
        ]
        widgets = {
            'email': forms.EmailInput(attrs={
                'class': 'form-input',
                'placeholder': _('colleague@email.com'),
            }),
        }

    def clean_email(self):
        """Validate email format."""
        email = self.cleaned_data.get('email', '').lower()
        try:
            validate_email(email)
        except ValidationError:
            raise ValidationError(_('Invalid email address.'))
        return email


class BulkInvitationForm(forms.Form):
    """
    Form for inviting multiple users at once.
    """

    emails = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 5,
            'placeholder': _('email1@company.com\nemail2@company.com\nemail3@company.com'),
        }),
        label=_('Email Addresses'),
        help_text=_('One email per line'),
    )
    role = forms.ChoiceField(
        choices=TenantInvitationForm.ROLE_CHOICES,
        initial='member',
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Role for All Invitees'),
    )

    def clean_emails(self):
        """Parse and validate email addresses."""
        emails_text = self.cleaned_data.get('emails', '')
        emails = []
        errors = []

        for line in emails_text.split('\n'):
            email = line.strip().lower()
            if email:
                try:
                    validate_email(email)
                    emails.append(email)
                except ValidationError:
                    errors.append(email)

        if errors:
            raise ValidationError(_('Invalid email addresses: %(emails)s') % {'emails': ', '.join(errors)})

        if not emails:
            raise ValidationError(_('Please enter at least one email address.'))

        return emails


class PlanForm(forms.ModelForm):
    """
    Form for creating and editing subscription plans (admin use).
    """

    class Meta:
        model = Plan
        fields = [
            'name',
            'slug',
            'plan_type',
            'description',
            'price_monthly',
            'price_yearly',
            'currency',
            'max_users',
            'max_job_postings',
            'max_candidates_per_month',
            'max_circusales',
            'storage_limit_gb',
            'is_active',
            'is_popular',
            'sort_order',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Plan Name'),
            }),
            'slug': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('plan-slug'),
            }),
            'plan_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
            'price_monthly': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'price_yearly': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'currency': forms.Select(attrs={
                'class': 'form-select',
            }, choices=[
                ('USD', 'USD'),
                ('CAD', 'CAD'),
                ('EUR', 'EUR'),
                ('GBP', 'GBP'),
            ]),
            'max_users': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '1',
            }),
            'max_job_postings': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '1',
            }),
            'max_candidates_per_month': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '1',
            }),
            'max_circusales': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '1',
            }),
            'storage_limit_gb': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '1',
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'is_popular': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'sort_order': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
            }),
        }


class PlanFeaturesForm(forms.ModelForm):
    """
    Form for configuring plan feature flags.
    """

    class Meta:
        model = Plan
        fields = [
            # Core features
            'feature_ats',
            'feature_hr_core',
            'feature_analytics',
            'feature_api_access',
            'feature_custom_pipelines',
            'feature_ai_matching',
            'feature_video_interviews',
            'feature_esignature',
            'feature_sso',
            'feature_audit_logs',
            'feature_custom_branding',
            'feature_priority_support',
            'feature_data_export',
            'feature_bulk_actions',
            'feature_advanced_filters',
            'feature_diversity_analytics',
            'feature_compliance_tools',
            # Marketplace features
            'feature_marketplace',
            'feature_escrow_payments',
            'feature_real_time_messaging',
            'feature_appointments',
            'feature_newsletter',
            'feature_crm',
            'feature_geospatial',
            # Enterprise features
            'feature_multi_circusale',
            'feature_custom_domains',
            'feature_webhooks',
            'feature_2fa_required',
            'feature_ip_whitelist',
            # Content features
            'feature_wagtail_cms',
            'feature_career_pages',
            'feature_events',
            # Integration features
            'feature_slack_integration',
            'feature_calendar_sync',
            'feature_linkedin_import',
            'feature_background_checks',
        ]
        widgets = {field: forms.CheckboxInput(attrs={'class': 'form-checkbox'}) for field in fields}


class CircusaleForm(forms.ModelForm):
    """
    Form for creating and managing business units/divisions.
    """

    class Meta:
        model = Circusale
        fields = [
            'name',
            'code',
            'parent',
            'status',
            'address_line1',
            'address_line2',
            'city',
            'state',
            'postal_code',
            'country',
            'phone',
            'email',
            'manager_name',
            'timezone',
            'is_headquarters',
            'accepts_applications',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Division/Branch Name'),
            }),
            'code': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('MTL-001'),
            }),
            'parent': forms.Select(attrs={
                'class': 'form-select',
            }),
            'status': forms.Select(attrs={
                'class': 'form-select',
            }),
            'address_line1': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Street Address'),
            }),
            'address_line2': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Suite, Unit (optional)'),
            }),
            'city': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('City'),
            }),
            'state': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('State/Province'),
            }),
            'postal_code': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Postal Code'),
            }),
            'country': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Country'),
            }),
            'phone': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('+1 (555) 123-4567'),
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-input',
                'placeholder': _('branch@company.com'),
            }),
            'manager_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Branch Manager Name'),
            }),
            'timezone': forms.Select(attrs={
                'class': 'form-select',
            }, choices=[
                ('America/Toronto', 'Eastern Time (Toronto)'),
                ('America/Vancouver', 'Pacific Time (Vancouver)'),
                ('America/New_York', 'Eastern Time (New York)'),
                ('America/Los_Angeles', 'Pacific Time (Los Angeles)'),
                ('America/Chicago', 'Central Time (Chicago)'),
                ('UTC', 'UTC'),
            ]),
            'is_headquarters': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'accepts_applications': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        help_texts = {
            'code': _('Internal code for this division (e.g., MTL-001)'),
            'parent': _('Parent division for organizational hierarchy'),
            'is_headquarters': _('Mark as main headquarters location'),
        }


class CircusaleFinanceForm(forms.ModelForm):
    """
    Form for circusale financial settings.
    """

    class Meta:
        model = Circusale
        fields = [
            'budget',
            'currency',
            'cost_center',
        ]
        widgets = {
            'budget': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'currency': forms.Select(attrs={
                'class': 'form-select',
            }, choices=[
                ('CAD', 'CAD'),
                ('USD', 'USD'),
                ('EUR', 'EUR'),
                ('GBP', 'GBP'),
            ]),
            'cost_center': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Cost Center Code'),
            }),
        }
        help_texts = {
            'budget': _('Annual budget allocation for this division'),
        }


class CircusaleLocationForm(forms.ModelForm):
    """
    Form for circusale geographic coordinates.
    """

    class Meta:
        model = Circusale
        fields = [
            'latitude',
            'longitude',
        ]
        widgets = {
            'latitude': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.000001',
                'placeholder': _('45.508888'),
            }),
            'longitude': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.000001',
                'placeholder': _('-73.561668'),
            }),
        }
        help_texts = {
            'latitude': _('Latitude coordinate for geospatial features'),
            'longitude': _('Longitude coordinate for geospatial features'),
        }


class CircusaleUserForm(forms.ModelForm):
    """
    Form for assigning users to circusales.
    """

    class Meta:
        model = CircusaleUser
        fields = [
            'user',
            'circusale',
            'role',
            'is_primary',
        ]
        widgets = {
            'user': forms.Select(attrs={
                'class': 'form-select',
            }),
            'circusale': forms.Select(attrs={
                'class': 'form-select',
            }),
            'role': forms.Select(attrs={
                'class': 'form-select',
            }),
            'is_primary': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        help_texts = {
            'is_primary': _("User's primary work location"),
        }


class TenantStatusUpdateForm(forms.Form):
    """
    Form for updating tenant status (admin use).
    """

    STATUS_CHOICES = [
        ('pending', _('Pending Setup')),
        ('active', _('Active')),
        ('suspended', _('Suspended')),
        ('cancelled', _('Cancelled')),
        ('trial', _('Trial')),
    ]

    status = forms.ChoiceField(
        choices=STATUS_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Status'),
    )
    reason = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 3,
            'placeholder': _('Reason for status change (optional)'),
        }),
        label=_('Reason'),
    )


class ExtendTrialForm(forms.Form):
    """
    Form for extending tenant trial period.
    """

    days = forms.IntegerField(
        initial=14,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'min': '1',
            'max': '90',
        }),
        label=_('Days to Extend'),
        help_text=_('Number of days to extend the trial period'),
    )
    notify_user = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Notify User'),
        help_text=_('Send email notification about trial extension'),
    )


class TenantFilterForm(forms.Form):
    """
    Form for filtering tenants in admin list view.
    """

    STATUS_CHOICES = [
        ('', _('All Statuses')),
        ('pending', _('Pending')),
        ('active', _('Active')),
        ('suspended', _('Suspended')),
        ('cancelled', _('Cancelled')),
        ('trial', _('Trial')),
    ]

    search = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Search by name or email...'),
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
    plan = forms.ModelChoiceField(
        queryset=Plan.objects.filter(is_active=True),
        required=False,
        empty_label=_('All Plans'),
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
    )
    created_after = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('Created After'),
    )
    created_before = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('Created Before'),
    )


# ==================== COMPANY SETUP WIZARD FORMS ====================

class CompanyInfoForm(forms.Form):
    """
    Step 1 of company signup wizard: Collect company information.
    """
    company_name = forms.CharField(
        max_length=255,
        label=_('Company Name'),
        widget=forms.TextInput(attrs={
            'class': 'form-control w-full mt-3 border border-line px-4 h-[50px] rounded-lg',
            'placeholder': _('Enter your company name'),
        }),
    )

    company_size = forms.ChoiceField(
        label=_('Company Size'),
        choices=[
            ('1-10', '1-10 employees'),
            ('11-50', '11-50 employees'),
            ('51-200', '51-200 employees'),
            ('201-500', '201-500 employees'),
            ('500+', '500+ employees'),
        ],
        widget=forms.Select(attrs={
            'class': 'form-control w-full mt-3 border border-line px-4 h-[50px] rounded-lg',
        }),
    )

    industry = forms.CharField(
        max_length=100,
        label=_('Industry'),
        widget=forms.TextInput(attrs={
            'class': 'form-control w-full mt-3 border border-line px-4 h-[50px] rounded-lg',
            'placeholder': _('e.g., Technology, Healthcare, Finance'),
        }),
    )

    website = forms.URLField(
        required=False,
        label=_('Website (optional)'),
        widget=forms.URLInput(attrs={
            'class': 'form-control w-full mt-3 border border-line px-4 h-[50px] rounded-lg',
            'placeholder': _('https://www.example.com'),
        }),
    )


class PlanSelectionForm(forms.Form):
    """
    Step 2 of company signup wizard: Select subscription plan.
    """
    plan_id = forms.ChoiceField(
        label=_('Select Plan'),
        widget=forms.RadioSelect(attrs={
            'class': 'form-radio',
        }),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Dynamically populate plan choices from database
        plans = Plan.objects.filter(is_active=True).order_by('price_monthly')
        self.fields['plan_id'].choices = [
            (str(plan.id), f'{plan.name} - ${plan.price_monthly}/month')
            for plan in plans
        ]


class StripePaymentForm(forms.Form):
    """
    Step 3 of company signup wizard: Payment information (for paid plans).
    """
    stripe_payment_method_id = forms.CharField(
        widget=forms.HiddenInput(),
        label='',
    )

    cardholder_name = forms.CharField(
        max_length=255,
        label=_('Name on Card'),
        widget=forms.TextInput(attrs={
            'class': 'form-control w-full mt-3 border border-line px-4 h-[50px] rounded-lg',
            'placeholder': _('Full name as it appears on card'),
        }),
    )
