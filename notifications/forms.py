"""
Notifications Forms - User Notification Preferences

This module provides forms for:
- Notification preferences management
- Email notification settings
- Push notification settings
- Notification filtering and management
"""

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .models import (
    NotificationPreference,
    Notification,
    NotificationChannel,
    NotificationTemplate,
)


class NotificationPreferenceForm(forms.ModelForm):
    """
    Form for managing user notification preferences.
    Controls which notifications a user receives and through which channels.
    """

    class Meta:
        model = NotificationPreference
        fields = [
            'notification_type',
            'email_enabled',
            'push_enabled',
            'in_app_enabled',
            'sms_enabled',
            'frequency',
            'quiet_hours_start',
            'quiet_hours_end',
            'is_enabled',
        ]
        widgets = {
            'notification_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'email_enabled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'push_enabled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'in_app_enabled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'sms_enabled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'frequency': forms.Select(attrs={
                'class': 'form-select',
            }),
            'quiet_hours_start': forms.TimeInput(attrs={
                'class': 'form-input',
                'type': 'time',
            }),
            'quiet_hours_end': forms.TimeInput(attrs={
                'class': 'form-input',
                'type': 'time',
            }),
            'is_enabled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        help_texts = {
            'frequency': _('How often to receive this type of notification'),
            'quiet_hours_start': _('Start of quiet hours (no notifications)'),
            'quiet_hours_end': _('End of quiet hours'),
        }
        labels = {
            'email_enabled': _('Email'),
            'push_enabled': _('Push notifications'),
            'in_app_enabled': _('In-app notifications'),
            'sms_enabled': _('SMS'),
            'is_enabled': _('Enable this notification type'),
        }


class BulkNotificationPreferenceForm(forms.Form):
    """
    Form for bulk updating notification preferences.
    Allows users to quickly enable/disable categories of notifications.
    """

    # Email preferences
    email_marketing = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        label=_('Marketing emails'),
    )
    email_product_updates = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        label=_('Product updates'),
    )
    email_security_alerts = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        label=_('Security alerts'),
    )
    email_account_activity = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        label=_('Account activity'),
    )

    # Push preferences
    push_new_messages = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        label=_('New messages'),
    )
    push_mentions = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        label=_('Mentions and replies'),
    )
    push_reminders = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        label=_('Reminders'),
    )

    # Quiet hours
    enable_quiet_hours = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        label=_('Enable quiet hours'),
    )
    quiet_hours_start = forms.TimeField(
        required=False,
        widget=forms.TimeInput(attrs={
            'class': 'form-input',
            'type': 'time',
        }),
        label=_('Start time'),
        initial='22:00',
    )
    quiet_hours_end = forms.TimeField(
        required=False,
        widget=forms.TimeInput(attrs={
            'class': 'form-input',
            'type': 'time',
        }),
        label=_('End time'),
        initial='08:00',
    )

    # Digest settings
    daily_digest = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        label=_('Daily digest email'),
    )
    weekly_digest = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        label=_('Weekly digest email'),
    )


class NotificationChannelForm(forms.ModelForm):
    """
    Form for configuring notification channels (admin use).
    """

    class Meta:
        model = NotificationChannel
        fields = [
            'name',
            'channel_type',
            'is_enabled',
            'configuration',
            'priority',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Channel Name'),
            }),
            'channel_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'is_enabled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'configuration': forms.Textarea(attrs={
                'class': 'form-textarea code-editor',
                'rows': 5,
                'placeholder': _('{"api_key": "...", "endpoint": "..."}'),
            }),
            'priority': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
            }),
        }
        help_texts = {
            'configuration': _('JSON configuration for this channel'),
            'priority': _('Higher priority channels are used first'),
        }


class NotificationTemplateForm(forms.ModelForm):
    """
    Form for creating and editing notification templates (admin use).
    """

    class Meta:
        model = NotificationTemplate
        fields = [
            'name',
            'notification_type',
            'subject',
            'body_text',
            'body_html',
            'variables',
            'is_active',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Template Name'),
            }),
            'notification_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'subject': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Email Subject Line'),
            }),
            'body_text': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 5,
                'placeholder': _('Plain text version...'),
            }),
            'body_html': forms.Textarea(attrs={
                'class': 'form-textarea code-editor',
                'rows': 10,
                'placeholder': _('HTML version...'),
            }),
            'variables': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
                'placeholder': _('["user_name", "action", "link"]'),
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        help_texts = {
            'subject': _('Use {{variable_name}} for dynamic content'),
            'variables': _('JSON array of available template variables'),
        }


class NotificationFilterForm(forms.Form):
    """
    Form for filtering notifications in the notification center.
    """

    NOTIFICATION_STATUS_CHOICES = [
        ('', _('All')),
        ('unread', _('Unread')),
        ('read', _('Read')),
    ]

    NOTIFICATION_TYPE_CHOICES = [
        ('', _('All Types')),
        ('message', _('Messages')),
        ('mention', _('Mentions')),
        ('system', _('System')),
        ('alert', _('Alerts')),
        ('reminder', _('Reminders')),
    ]

    status = forms.ChoiceField(
        choices=NOTIFICATION_STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Status'),
    )
    notification_type = forms.ChoiceField(
        choices=NOTIFICATION_TYPE_CHOICES,
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Type'),
    )
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('From'),
    )
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('To'),
    )


class MarkNotificationsForm(forms.Form):
    """
    Form for bulk marking notifications as read/unread.
    """

    notification_ids = forms.CharField(
        widget=forms.HiddenInput(),
        help_text=_('Comma-separated list of notification IDs'),
    )
    action = forms.ChoiceField(
        choices=[
            ('read', _('Mark as Read')),
            ('unread', _('Mark as Unread')),
            ('delete', _('Delete')),
        ],
        widget=forms.HiddenInput(),
    )

    def clean_notification_ids(self):
        """Parse and validate notification IDs."""
        ids_string = self.cleaned_data.get('notification_ids', '')
        try:
            ids = [int(id.strip()) for id in ids_string.split(',') if id.strip()]
            if not ids:
                raise ValidationError(_('No notifications selected.'))
            return ids
        except ValueError:
            raise ValidationError(_('Invalid notification IDs.'))


class EmailUnsubscribeForm(forms.Form):
    """
    Form for email unsubscribe actions.
    """

    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': _('your.email@example.com'),
        }),
        label=_('Email Address'),
    )
    unsubscribe_token = forms.CharField(
        widget=forms.HiddenInput(),
        required=False,
    )
    categories = forms.MultipleChoiceField(
        choices=[
            ('all', _('All emails')),
            ('marketing', _('Marketing emails')),
            ('product', _('Product updates')),
            ('digest', _('Digest emails')),
        ],
        widget=forms.CheckboxSelectMultiple(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Unsubscribe from'),
        required=True,
    )
    reason = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 2,
            'placeholder': _('Why are you unsubscribing? (optional)'),
        }),
        label=_('Feedback'),
        required=False,
        max_length=500,
    )


class PushNotificationSubscriptionForm(forms.Form):
    """
    Form for managing push notification subscriptions.
    """

    endpoint = forms.URLField(
        widget=forms.HiddenInput(),
    )
    p256dh_key = forms.CharField(
        widget=forms.HiddenInput(),
    )
    auth_key = forms.CharField(
        widget=forms.HiddenInput(),
    )
    device_name = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Device name (optional)'),
        }),
        label=_('Device Name'),
    )


class NotificationSnoozeForm(forms.Form):
    """
    Form for snoozing notifications.
    """

    SNOOZE_DURATION_CHOICES = [
        (30, _('30 minutes')),
        (60, _('1 hour')),
        (120, _('2 hours')),
        (240, _('4 hours')),
        (480, _('8 hours')),
        (1440, _('1 day')),
        (10080, _('1 week')),
    ]

    duration = forms.ChoiceField(
        choices=SNOOZE_DURATION_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Snooze for'),
    )
    snooze_type = forms.ChoiceField(
        choices=[
            ('all', _('All notifications')),
            ('specific', _('Specific type only')),
        ],
        widget=forms.RadioSelect(attrs={
            'class': 'form-radio',
        }),
        label=_('What to snooze'),
        initial='all',
    )
    notification_type = forms.ChoiceField(
        choices=[
            ('message', _('Messages')),
            ('mention', _('Mentions')),
            ('reminder', _('Reminders')),
        ],
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Notification type'),
    )
