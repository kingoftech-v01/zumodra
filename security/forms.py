"""
Security Forms - Security Settings and Audit Management

This module provides forms for:
- Security settings management
- IP whitelist/blacklist configuration
- Session management
- Audit log filtering
- Two-factor authentication settings
"""

from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv4_address, validate_ipv6_address
from django.utils.translation import gettext_lazy as _

from .models import (
    AuditLogEntry,
    SecurityEvent,
    UserSession,
    AuditLogConfig,
)


class SecuritySettingsForm(forms.Form):
    """
    Form for managing security settings.
    """

    # Password Policy
    min_password_length = forms.IntegerField(
        min_value=8,
        max_value=128,
        initial=12,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'min': '8',
            'max': '128',
        }),
        label=_('Minimum Password Length'),
    )
    require_uppercase = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Require uppercase letters'),
    )
    require_lowercase = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Require lowercase letters'),
    )
    require_numbers = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Require numbers'),
    )
    require_special_chars = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Require special characters'),
    )
    password_expiry_days = forms.IntegerField(
        min_value=0,
        max_value=365,
        initial=90,
        required=False,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'min': '0',
            'max': '365',
        }),
        label=_('Password expiry (days)'),
        help_text=_('Set to 0 to disable password expiry'),
    )

    # Login Security
    max_login_attempts = forms.IntegerField(
        min_value=3,
        max_value=20,
        initial=5,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'min': '3',
            'max': '20',
        }),
        label=_('Max login attempts before lockout'),
    )
    lockout_duration_minutes = forms.IntegerField(
        min_value=5,
        max_value=1440,
        initial=60,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'min': '5',
            'max': '1440',
        }),
        label=_('Lockout duration (minutes)'),
    )

    # Session Security
    session_timeout_minutes = forms.IntegerField(
        min_value=5,
        max_value=1440,
        initial=30,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'min': '5',
            'max': '1440',
        }),
        label=_('Session timeout (minutes)'),
    )
    single_session_only = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Allow only one active session per user'),
    )

    # Two-Factor Authentication
    require_2fa = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Require 2FA for all users'),
    )
    require_2fa_for_admins = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Require 2FA for admin users'),
    )


class IPWhitelistForm(forms.Form):
    """
    Form for managing IP whitelist entries.
    """

    ip_address = forms.CharField(
        max_length=45,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('IP address or CIDR range'),
        }),
        label=_('IP Address'),
        help_text=_('Enter IPv4, IPv6 address or CIDR notation (e.g., 192.168.1.0/24)'),
    )
    description = forms.CharField(
        max_length=255,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Description (e.g., Office network)'),
        }),
        label=_('Description'),
    )
    is_active = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Active'),
    )

    def clean_ip_address(self):
        """Validate IP address or CIDR notation."""
        ip = self.cleaned_data.get('ip_address', '').strip()

        # Check if it's a CIDR notation
        if '/' in ip:
            ip_part, prefix = ip.rsplit('/', 1)
            try:
                prefix_int = int(prefix)
            except ValueError:
                raise ValidationError(_('Invalid CIDR prefix.'))

            # Validate the IP part
            try:
                validate_ipv4_address(ip_part)
                if not (0 <= prefix_int <= 32):
                    raise ValidationError(_('IPv4 CIDR prefix must be between 0 and 32.'))
            except ValidationError:
                try:
                    validate_ipv6_address(ip_part)
                    if not (0 <= prefix_int <= 128):
                        raise ValidationError(_('IPv6 CIDR prefix must be between 0 and 128.'))
                except ValidationError:
                    raise ValidationError(_('Invalid IP address format.'))
        else:
            # Single IP address
            try:
                validate_ipv4_address(ip)
            except ValidationError:
                try:
                    validate_ipv6_address(ip)
                except ValidationError:
                    raise ValidationError(_('Invalid IP address format.'))

        return ip


class IPBlacklistForm(forms.Form):
    """
    Form for managing IP blacklist entries.
    """

    ip_address = forms.CharField(
        max_length=45,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('IP address or CIDR range'),
        }),
        label=_('IP Address'),
    )
    reason = forms.CharField(
        max_length=500,
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 2,
            'placeholder': _('Reason for blocking'),
        }),
        label=_('Reason'),
    )
    expires_at = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={
            'class': 'form-input',
            'type': 'datetime-local',
        }),
        label=_('Expires At'),
        help_text=_('Leave blank for permanent block'),
    )
    is_active = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Active'),
    )


class AuditLogFilterForm(forms.Form):
    """
    Form for filtering audit log entries.
    """

    ACTION_CHOICES = [
        ('', _('All Actions')),
        ('create', _('Create')),
        ('update', _('Update')),
        ('delete', _('Delete')),
        ('login', _('Login')),
        ('logout', _('Logout')),
        ('failed_login', _('Failed Login')),
    ]

    search = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Search by user or object...'),
            'type': 'search',
        }),
        label=_('Search'),
    )
    action = forms.ChoiceField(
        choices=ACTION_CHOICES,
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Action'),
    )
    model_name = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Model name'),
        }),
        label=_('Model'),
    )
    user_id = forms.IntegerField(
        required=False,
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
        }),
        label=_('User ID'),
    )
    date_from = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={
            'class': 'form-input',
            'type': 'datetime-local',
        }),
        label=_('From'),
    )
    date_to = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={
            'class': 'form-input',
            'type': 'datetime-local',
        }),
        label=_('To'),
    )
    ip_address = forms.GenericIPAddressField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('IP address'),
        }),
        label=_('IP Address'),
    )


class SecurityEventFilterForm(forms.Form):
    """
    Form for filtering security events.
    """

    EVENT_TYPE_CHOICES = [
        ('', _('All Events')),
        ('password_change', _('Password Change')),
        ('account_lockout', _('Account Lockout')),
        ('failed_login', _('Failed Login')),
        ('password_reset_request', _('Password Reset Request')),
        ('2fa_enabled', _('2FA Enabled')),
        ('2fa_disabled', _('2FA Disabled')),
    ]

    event_type = forms.ChoiceField(
        choices=EVENT_TYPE_CHOICES,
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Event Type'),
    )
    user_email = forms.EmailField(
        required=False,
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': _('User email'),
        }),
        label=_('User Email'),
    )
    date_from = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={
            'class': 'form-input',
            'type': 'datetime-local',
        }),
        label=_('From'),
    )
    date_to = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={
            'class': 'form-input',
            'type': 'datetime-local',
        }),
        label=_('To'),
    )
    ip_address = forms.GenericIPAddressField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('IP address'),
        }),
        label=_('IP Address'),
    )


class SessionManagementForm(forms.Form):
    """
    Form for managing user sessions.
    """

    session_ids = forms.CharField(
        widget=forms.HiddenInput(),
        help_text=_('Comma-separated session IDs'),
    )
    action = forms.ChoiceField(
        choices=[
            ('terminate', _('Terminate Sessions')),
            ('terminate_all_except_current', _('Terminate All Except Current')),
        ],
        widget=forms.HiddenInput(),
    )

    def clean_session_ids(self):
        """Parse session IDs."""
        ids_string = self.cleaned_data.get('session_ids', '')
        return [sid.strip() for sid in ids_string.split(',') if sid.strip()]


class TwoFactorSetupForm(forms.Form):
    """
    Form for setting up two-factor authentication.
    """

    METHOD_CHOICES = [
        ('totp', _('Authenticator App (TOTP)')),
        ('sms', _('SMS Text Message')),
        ('email', _('Email')),
    ]

    method = forms.ChoiceField(
        choices=METHOD_CHOICES,
        widget=forms.RadioSelect(attrs={
            'class': 'form-radio',
        }),
        label=_('2FA Method'),
    )
    phone_number = forms.CharField(
        required=False,
        max_length=30,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('+1 (555) 123-4567'),
        }),
        label=_('Phone Number'),
        help_text=_('Required for SMS verification'),
    )

    def clean(self):
        """Validate phone number is provided for SMS method."""
        cleaned_data = super().clean()
        method = cleaned_data.get('method')
        phone_number = cleaned_data.get('phone_number')

        if method == 'sms' and not phone_number:
            raise ValidationError({
                'phone_number': _('Phone number is required for SMS verification.')
            })
        return cleaned_data


class TwoFactorVerifyForm(forms.Form):
    """
    Form for verifying 2FA code.
    """

    code = forms.CharField(
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-input text-center text-2xl tracking-widest',
            'placeholder': '000000',
            'autocomplete': 'one-time-code',
            'inputmode': 'numeric',
            'pattern': '[0-9]*',
        }),
        label=_('Verification Code'),
    )
    remember_device = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Trust this device for 30 days'),
    )

    def clean_code(self):
        """Validate code is numeric."""
        code = self.cleaned_data.get('code', '')
        if not code.isdigit():
            raise ValidationError(_('Code must contain only numbers.'))
        return code


class BackupCodesForm(forms.Form):
    """
    Form for entering backup code.
    """

    backup_code = forms.CharField(
        max_length=16,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Enter backup code'),
        }),
        label=_('Backup Code'),
    )


class AuditLogConfigForm(forms.ModelForm):
    """
    Form for managing audit log configuration.
    """

    class Meta:
        model = AuditLogConfig
        fields = ['key', 'value']
        widgets = {
            'key': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Configuration key'),
            }),
            'value': forms.Textarea(attrs={
                'class': 'form-textarea code-editor',
                'rows': 5,
                'placeholder': _('{"setting": "value"}'),
            }),
        }


class PasswordResetAdminForm(forms.Form):
    """
    Admin form for triggering password reset for users.
    """

    user_email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': _('user@email.com'),
        }),
        label=_('User Email'),
    )
    send_notification = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Send password reset email'),
    )
    force_password_change = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Force password change on next login'),
    )


class UnlockAccountForm(forms.Form):
    """
    Form for unlocking a locked account.
    """

    user_email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': _('user@email.com'),
        }),
        label=_('User Email'),
    )
    reset_failed_attempts = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Reset failed login attempts counter'),
    )
    send_notification = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Notify user their account was unlocked'),
    )


class SecurityReportForm(forms.Form):
    """
    Form for generating security reports.
    """

    REPORT_TYPE_CHOICES = [
        ('login_activity', _('Login Activity Report')),
        ('failed_logins', _('Failed Login Attempts')),
        ('security_events', _('Security Events')),
        ('session_activity', _('Session Activity')),
        ('password_changes', _('Password Changes')),
        ('audit_summary', _('Audit Log Summary')),
    ]

    report_type = forms.ChoiceField(
        choices=REPORT_TYPE_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Report Type'),
    )
    date_from = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('Start Date'),
    )
    date_to = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-input',
            'type': 'date',
        }),
        label=_('End Date'),
    )
    format = forms.ChoiceField(
        choices=[
            ('pdf', _('PDF')),
            ('csv', _('CSV')),
            ('xlsx', _('Excel')),
        ],
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Export Format'),
        initial='pdf',
    )
    include_details = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Include detailed records'),
    )

    def clean(self):
        """Validate date range."""
        cleaned_data = super().clean()
        date_from = cleaned_data.get('date_from')
        date_to = cleaned_data.get('date_to')

        if date_from and date_to and date_to < date_from:
            raise ValidationError({
                'date_to': _('End date cannot be before start date.')
            })
        return cleaned_data
