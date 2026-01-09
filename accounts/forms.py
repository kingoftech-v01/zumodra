"""
Accounts Forms - User Profile and KYC Submission

This module provides forms for:
- User profile management
- KYC document submission and verification
- Trust score display
- Profile settings
"""

from django import forms
from django.core.validators import FileExtensionValidator
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .models import User, KYCSubmission, TrustScore, Profile


class UserProfileForm(forms.ModelForm):
    """
    Form for updating user profile information.
    Handles basic user data like name, email, phone.
    """

    class Meta:
        model = User
        fields = [
            'first_name',
            'last_name',
            'email',
            'phone_number',
            'bio',
            'profile_picture',
            'timezone',
            'language',
        ]
        widgets = {
            'first_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('First Name'),
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Last Name'),
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-input',
                'placeholder': _('Email Address'),
            }),
            'phone_number': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('+1 (555) 123-4567'),
            }),
            'bio': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
                'placeholder': _('Tell us about yourself...'),
            }),
            'profile_picture': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': 'image/*',
            }),
            'timezone': forms.Select(attrs={
                'class': 'form-select',
            }),
            'language': forms.Select(attrs={
                'class': 'form-select',
            }),
        }
        help_texts = {
            'phone_number': _('Include country code for international numbers'),
            'bio': _('A brief description that will appear on your profile'),
            'profile_picture': _('Recommended size: 200x200 pixels. Max 5MB.'),
        }

    def clean_email(self):
        """Validate email uniqueness excluding current user."""
        email = self.cleaned_data.get('email')
        if email and User.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
            raise ValidationError(_('This email address is already in use.'))
        return email

    def clean_profile_picture(self):
        """Validate profile picture size and format."""
        picture = self.cleaned_data.get('profile_picture')
        if picture and hasattr(picture, 'size'):
            if picture.size > 5 * 1024 * 1024:  # 5MB limit
                raise ValidationError(_('Profile picture must be less than 5MB.'))
        return picture


class ProfileForm(forms.ModelForm):
    """
    Form for extended profile information.
    Handles address, social links, and preferences.
    """

    class Meta:
        model = Profile
        fields = [
            'title',
            'company',
            'website',
            'linkedin_url',
            'twitter_url',
            'github_url',
            'address_line1',
            'address_line2',
            'city',
            'state',
            'postal_code',
            'country',
            'date_of_birth',
            'gender',
            'receive_marketing_emails',
            'receive_notification_emails',
        ]
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Job Title'),
            }),
            'company': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Company Name'),
            }),
            'website': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://yourwebsite.com'),
            }),
            'linkedin_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://linkedin.com/in/yourprofile'),
            }),
            'twitter_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://twitter.com/yourhandle'),
            }),
            'github_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://github.com/yourusername'),
            }),
            'address_line1': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Street Address'),
            }),
            'address_line2': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Apartment, Suite, etc.'),
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
            'country': forms.Select(attrs={
                'class': 'form-select',
            }),
            'date_of_birth': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'gender': forms.Select(attrs={
                'class': 'form-select',
            }),
            'receive_marketing_emails': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'receive_notification_emails': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class KYCSubmissionForm(forms.ModelForm):
    """
    Form for KYC (Know Your Customer) document submission.
    Handles identity verification documents.
    """

    class Meta:
        model = KYCSubmission
        fields = [
            'document_type',
            'document_number',
            'document_front',
            'document_back',
            'selfie_with_document',
            'issuing_country',
            'expiry_date',
        ]
        widgets = {
            'document_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'document_number': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Document Number'),
            }),
            'document_front': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': 'image/*,.pdf',
            }),
            'document_back': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': 'image/*,.pdf',
            }),
            'selfie_with_document': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': 'image/*',
            }),
            'issuing_country': forms.Select(attrs={
                'class': 'form-select',
            }),
            'expiry_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
        }
        help_texts = {
            'document_front': _('Upload a clear photo of the front of your document. Max 10MB.'),
            'document_back': _('Upload the back of your document if applicable. Max 10MB.'),
            'selfie_with_document': _('Take a selfie while holding your document. Max 10MB.'),
            'expiry_date': _('Document expiry date (must be valid)'),
        }

    def clean_document_front(self):
        """Validate front document file size."""
        doc = self.cleaned_data.get('document_front')
        if doc and hasattr(doc, 'size'):
            if doc.size > 10 * 1024 * 1024:  # 10MB limit
                raise ValidationError(_('Document file must be less than 10MB.'))
        return doc

    def clean_document_back(self):
        """Validate back document file size."""
        doc = self.cleaned_data.get('document_back')
        if doc and hasattr(doc, 'size'):
            if doc.size > 10 * 1024 * 1024:
                raise ValidationError(_('Document file must be less than 10MB.'))
        return doc

    def clean_selfie_with_document(self):
        """Validate selfie file size."""
        selfie = self.cleaned_data.get('selfie_with_document')
        if selfie and hasattr(selfie, 'size'):
            if selfie.size > 10 * 1024 * 1024:
                raise ValidationError(_('Selfie file must be less than 10MB.'))
        return selfie

    def clean_expiry_date(self):
        """Ensure document is not expired."""
        from django.utils import timezone
        expiry = self.cleaned_data.get('expiry_date')
        if expiry and expiry < timezone.now().date():
            raise ValidationError(_('Document has expired. Please provide a valid document.'))
        return expiry


class KYCAdminReviewForm(forms.ModelForm):
    """
    Admin form for reviewing KYC submissions.
    Allows approving or rejecting submissions with notes.
    """

    class Meta:
        model = KYCSubmission
        fields = [
            'status',
            'reviewer_notes',
            'rejection_reason',
        ]
        widgets = {
            'status': forms.Select(attrs={
                'class': 'form-select',
            }),
            'reviewer_notes': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
                'placeholder': _('Internal notes about this submission...'),
            }),
            'rejection_reason': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
                'placeholder': _('Reason for rejection (will be shown to user)...'),
            }),
        }

    def clean(self):
        """Validate rejection reason is provided if rejected."""
        cleaned_data = super().clean()
        status = cleaned_data.get('status')
        rejection_reason = cleaned_data.get('rejection_reason')

        if status == 'rejected' and not rejection_reason:
            raise ValidationError({
                'rejection_reason': _('Please provide a reason for rejection.')
            })
        return cleaned_data


class TrustScoreDisplayForm(forms.ModelForm):
    """
    Read-only form for displaying trust score details.
    Used for showing trust score breakdown to users.
    """

    class Meta:
        model = TrustScore
        fields = [
            'overall_score',
            'identity_verified',
            'email_verified',
            'phone_verified',
            'profile_completeness',
            'transaction_history_score',
        ]
        widgets = {
            'overall_score': forms.NumberInput(attrs={
                'class': 'form-input',
                'readonly': True,
            }),
            'identity_verified': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
                'disabled': True,
            }),
            'email_verified': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
                'disabled': True,
            }),
            'phone_verified': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
                'disabled': True,
            }),
            'profile_completeness': forms.NumberInput(attrs={
                'class': 'form-input',
                'readonly': True,
            }),
            'transaction_history_score': forms.NumberInput(attrs={
                'class': 'form-input',
                'readonly': True,
            }),
        }


class ChangePasswordForm(forms.Form):
    """
    Form for changing user password.
    Requires current password and new password confirmation.
    """

    current_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': _('Current Password'),
            'autocomplete': 'current-password',
        }),
        label=_('Current Password'),
    )
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': _('New Password'),
            'autocomplete': 'new-password',
        }),
        label=_('New Password'),
        min_length=8,
        help_text=_('Password must be at least 8 characters long.'),
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': _('Confirm New Password'),
            'autocomplete': 'new-password',
        }),
        label=_('Confirm New Password'),
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_current_password(self):
        """Verify current password is correct."""
        current = self.cleaned_data.get('current_password')
        if current and not self.user.check_password(current):
            raise ValidationError(_('Current password is incorrect.'))
        return current

    def clean(self):
        """Validate new passwords match."""
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')

        if new_password and confirm_password:
            if new_password != confirm_password:
                raise ValidationError({
                    'confirm_password': _('Passwords do not match.')
                })
        return cleaned_data

    def save(self):
        """Set the new password."""
        new_password = self.cleaned_data.get('new_password')
        self.user.set_password(new_password)
        self.user.save()
        return self.user


class AccountSettingsForm(forms.ModelForm):
    """
    Form for account-level settings.
    Handles privacy, security, and notification preferences.
    """

    class Meta:
        model = User
        fields = [
            'is_profile_public',
            'two_factor_enabled',
            'login_notifications_enabled',
        ]
        widgets = {
            'is_profile_public': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'two_factor_enabled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'login_notifications_enabled': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        labels = {
            'is_profile_public': _('Make my profile public'),
            'two_factor_enabled': _('Enable two-factor authentication'),
            'login_notifications_enabled': _('Notify me of new login attempts'),
        }


class DeleteAccountForm(forms.Form):
    """
    Form for account deletion confirmation.
    Requires password and explicit confirmation.
    """

    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': _('Enter your password'),
        }),
        label=_('Password'),
        help_text=_('Enter your password to confirm account deletion.'),
    )
    confirm_deletion = forms.BooleanField(
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('I understand this action is permanent and cannot be undone'),
        required=True,
    )
    reason = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 3,
            'placeholder': _('Why are you leaving? (optional)'),
        }),
        label=_('Reason for leaving'),
        required=False,
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_password(self):
        """Verify password is correct."""
        password = self.cleaned_data.get('password')
        if password and not self.user.check_password(password):
            raise ValidationError(_('Password is incorrect.'))
        return password
