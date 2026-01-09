"""
Integrations Forms - Third-Party Service Integration Management

This module provides forms for:
- Integration configuration
- Webhook endpoint management
- OAuth credential management
- Sync settings
"""

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .models import (
    Integration,
    IntegrationCredential,
    IntegrationSyncLog,
    WebhookEndpoint,
)


class IntegrationForm(forms.ModelForm):
    """
    Form for creating and configuring integrations.
    """

    class Meta:
        model = Integration
        fields = [
            'name',
            'integration_type',
            'provider',
            'description',
            'is_enabled',
            'auto_sync',
            'sync_interval_minutes',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Integration Name'),
            }),
            'integration_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'provider': forms.Select(attrs={
                'class': 'form-select',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
            'is_enabled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'auto_sync': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'sync_interval_minutes': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '5',
                'max': '1440',
            }),
        }
        help_texts = {
            'sync_interval_minutes': _('How often to sync data (5-1440 minutes)'),
        }


class IntegrationConfigForm(forms.ModelForm):
    """
    Form for integration-specific configuration settings.
    """

    class Meta:
        model = Integration
        fields = [
            'config',
        ]
        widgets = {
            'config': forms.Textarea(attrs={
                'class': 'form-textarea code-editor',
                'rows': 10,
                'placeholder': _('{"setting": "value"}'),
            }),
        }
        help_texts = {
            'config': _('JSON configuration for this integration'),
        }


class IntegrationCredentialForm(forms.ModelForm):
    """
    Form for managing OAuth credentials.
    Note: Sensitive fields are encrypted at rest.
    """

    class Meta:
        model = IntegrationCredential
        fields = [
            'auth_type',
            'api_key',
            'api_secret',
            'scope',
        ]
        widgets = {
            'auth_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'api_key': forms.PasswordInput(attrs={
                'class': 'form-input',
                'placeholder': _('API Key'),
                'autocomplete': 'off',
            }),
            'api_secret': forms.PasswordInput(attrs={
                'class': 'form-input',
                'placeholder': _('API Secret'),
                'autocomplete': 'off',
            }),
            'scope': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('read write profile'),
            }),
        }
        help_texts = {
            'scope': _('Space-separated OAuth scopes'),
        }


class APIKeyCredentialForm(forms.Form):
    """
    Simplified form for API key authentication.
    """

    api_key = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': _('Enter your API key'),
            'autocomplete': 'off',
        }),
        label=_('API Key'),
    )
    api_secret = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': _('Enter your API secret (if required)'),
            'autocomplete': 'off',
        }),
        label=_('API Secret'),
    )


class BasicAuthCredentialForm(forms.Form):
    """
    Form for basic authentication credentials.
    """

    username = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Username'),
        }),
        label=_('Username'),
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': _('Password'),
            'autocomplete': 'new-password',
        }),
        label=_('Password'),
    )


class WebhookEndpointForm(forms.ModelForm):
    """
    Form for creating and managing webhook endpoints.
    """

    class Meta:
        model = WebhookEndpoint
        fields = [
            'name',
            'subscribed_events',
            'signature_header',
            'signature_algorithm',
            'is_enabled',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Webhook Name'),
            }),
            'subscribed_events': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
                'placeholder': _('candidate.created\ncandidate.updated\napplication.submitted'),
            }),
            'signature_header': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('X-Webhook-Signature'),
            }),
            'signature_algorithm': forms.Select(attrs={
                'class': 'form-select',
            }),
            'is_enabled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        help_texts = {
            'subscribed_events': _('One event type per line'),
            'signature_header': _('HTTP header containing the webhook signature'),
        }

    def clean_subscribed_events(self):
        """Parse events from textarea to list."""
        events_text = self.cleaned_data.get('subscribed_events', '')
        if isinstance(events_text, str):
            events = [e.strip() for e in events_text.split('\n') if e.strip()]
            return events
        return events_text


class OutboundWebhookForm(forms.Form):
    """
    Form for configuring outbound webhooks.
    """

    name = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Webhook Name'),
        }),
        label=_('Name'),
    )
    url = forms.URLField(
        widget=forms.URLInput(attrs={
            'class': 'form-input',
            'placeholder': _('https://your-server.com/webhook'),
        }),
        label=_('Webhook URL'),
    )
    secret = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': _('Shared secret for signature'),
        }),
        label=_('Secret'),
        help_text=_('Used to sign webhook payloads'),
    )
    events = forms.MultipleChoiceField(
        choices=[
            ('candidate.created', _('Candidate Created')),
            ('candidate.updated', _('Candidate Updated')),
            ('application.submitted', _('Application Submitted')),
            ('application.status_changed', _('Application Status Changed')),
            ('interview.scheduled', _('Interview Scheduled')),
            ('offer.sent', _('Offer Sent')),
            ('offer.accepted', _('Offer Accepted')),
            ('employee.onboarded', _('Employee Onboarded')),
        ],
        widget=forms.CheckboxSelectMultiple(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Events to Subscribe'),
    )
    is_active = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Active'),
    )


class SyncConfigForm(forms.ModelForm):
    """
    Form for configuring sync settings.
    """

    class Meta:
        model = Integration
        fields = [
            'auto_sync',
            'sync_interval_minutes',
        ]
        widgets = {
            'auto_sync': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'sync_interval_minutes': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '5',
                'max': '1440',
            }),
        }
        labels = {
            'auto_sync': _('Enable automatic sync'),
            'sync_interval_minutes': _('Sync interval (minutes)'),
        }


class ManualSyncForm(forms.Form):
    """
    Form for triggering manual sync.
    """

    SYNC_TYPE_CHOICES = [
        ('incremental', _('Incremental (changes only)')),
        ('full', _('Full Sync (all data)')),
    ]

    DIRECTION_CHOICES = [
        ('inbound', _('Inbound (from external)')),
        ('outbound', _('Outbound (to external)')),
        ('bidirectional', _('Bidirectional')),
    ]

    sync_type = forms.ChoiceField(
        choices=SYNC_TYPE_CHOICES,
        initial='incremental',
        widget=forms.RadioSelect(attrs={
            'class': 'form-radio',
        }),
        label=_('Sync Type'),
    )
    direction = forms.ChoiceField(
        choices=DIRECTION_CHOICES,
        initial='inbound',
        widget=forms.RadioSelect(attrs={
            'class': 'form-radio',
        }),
        label=_('Direction'),
    )
    resource_type = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('e.g., contacts, events'),
        }),
        label=_('Resource Type'),
        help_text=_('Leave blank to sync all resources'),
    )


class IntegrationFilterForm(forms.Form):
    """
    Form for filtering integrations in list view.
    """

    STATUS_CHOICES = [
        ('', _('All Statuses')),
        ('active', _('Active')),
        ('inactive', _('Inactive')),
        ('error', _('Error')),
        ('pending', _('Pending')),
        ('expired', _('Expired')),
    ]

    TYPE_CHOICES = [
        ('', _('All Types')),
        ('calendar', _('Calendar')),
        ('email', _('Email')),
        ('job_board', _('Job Board')),
        ('background_check', _('Background Check')),
        ('esign', _('E-Signature')),
        ('hris', _('HRIS')),
        ('messaging', _('Messaging')),
        ('video', _('Video')),
    ]

    status = forms.ChoiceField(
        choices=STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
    )
    integration_type = forms.ChoiceField(
        choices=TYPE_CHOICES,
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
    )
    search = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Search integrations...'),
            'type': 'search',
        }),
    )


class SyncLogFilterForm(forms.Form):
    """
    Form for filtering sync logs.
    """

    STATUS_CHOICES = [
        ('', _('All')),
        ('completed', _('Completed')),
        ('failed', _('Failed')),
        ('running', _('Running')),
        ('partial', _('Partial')),
    ]

    status = forms.ChoiceField(
        choices=STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
    )
    date_from = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={
            'class': 'form-input',
            'type': 'datetime-local',
        }),
    )
    date_to = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={
            'class': 'form-input',
            'type': 'datetime-local',
        }),
    )


class CalendarIntegrationForm(forms.Form):
    """
    Form for calendar integration settings.
    """

    calendar_id = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('primary or calendar ID'),
        }),
        label=_('Calendar ID'),
        initial='primary',
    )
    sync_events = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Sync interview events'),
    )
    create_events = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Create events for scheduled interviews'),
    )
    default_duration_minutes = forms.IntegerField(
        initial=60,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'min': '15',
            'max': '480',
        }),
        label=_('Default event duration (minutes)'),
    )


class SlackIntegrationForm(forms.Form):
    """
    Form for Slack integration settings.
    """

    default_channel = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('#general or channel ID'),
        }),
        label=_('Default Channel'),
    )
    notify_new_application = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Notify on new applications'),
    )
    notify_interview_scheduled = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Notify on interview scheduled'),
    )
    notify_offer_accepted = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Notify on offer accepted'),
    )
    mention_hiring_manager = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Mention hiring manager in notifications'),
    )


class EmailIntegrationForm(forms.Form):
    """
    Form for email integration settings.
    """

    PROVIDER_CHOICES = [
        ('smtp', _('SMTP')),
        ('sendgrid', _('SendGrid')),
        ('mailgun', _('Mailgun')),
    ]

    provider = forms.ChoiceField(
        choices=PROVIDER_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Email Provider'),
    )
    from_email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': _('noreply@company.com'),
        }),
        label=_('From Email'),
    )
    from_name = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Company HR'),
        }),
        label=_('From Name'),
    )
    reply_to = forms.EmailField(
        required=False,
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': _('hr@company.com'),
        }),
        label=_('Reply-To Email'),
    )


class TestConnectionForm(forms.Form):
    """
    Form for testing integration connection.
    """

    integration_id = forms.IntegerField(widget=forms.HiddenInput())
