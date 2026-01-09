"""
Messages System Forms - Real-time Messaging

This module provides forms for:
- Message composition
- Conversation management
- Contact forms
- Message search and filtering
"""

from django import forms
from django.core.validators import FileExtensionValidator
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .models import Message, Conversation, Contact, MessageAttachment


class MessageComposeForm(forms.ModelForm):
    """
    Form for composing and sending messages.
    Supports text content and file attachments.
    """

    attachments = forms.FileField(
        required=False,
        widget=forms.ClearableFileInput(attrs={
            'class': 'form-file',
            'multiple': True,
            'accept': '.pdf,.doc,.docx,.jpg,.jpeg,.png,.gif,.xls,.xlsx,.zip',
        }),
        help_text=_('Attach files (max 10MB each)'),
    )

    class Meta:
        model = Message
        fields = [
            'content',
            'message_type',
        ]
        widgets = {
            'content': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
                'placeholder': _('Type your message...'),
                'autofocus': True,
            }),
            'message_type': forms.HiddenInput(),
        }

    def clean_content(self):
        """Validate message content is not empty."""
        content = self.cleaned_data.get('content', '').strip()
        if not content:
            raise ValidationError(_('Message content cannot be empty.'))
        if len(content) > 10000:
            raise ValidationError(_('Message cannot exceed 10,000 characters.'))
        return content

    def clean_attachments(self):
        """Validate attachment file sizes."""
        attachments = self.files.getlist('attachments')
        for attachment in attachments:
            if attachment.size > 10 * 1024 * 1024:  # 10MB
                raise ValidationError(
                    _('File "%(name)s" exceeds 10MB limit.'),
                    params={'name': attachment.name}
                )
        return attachments


class QuickMessageForm(forms.Form):
    """
    Simplified form for quick message sending (HTMX compatible).
    """

    content = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-textarea resize-none',
            'rows': 2,
            'placeholder': _('Type a message...'),
            'x-data': '',
            'x-on:keydown.enter.prevent': 'if (!$event.shiftKey) $el.form.submit()',
        }),
        max_length=5000,
    )
    recipient_id = forms.IntegerField(widget=forms.HiddenInput())


class ConversationForm(forms.ModelForm):
    """
    Form for creating and managing conversations.
    """

    class Meta:
        model = Conversation
        fields = [
            'title',
            'conversation_type',
            'participants',
        ]
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Conversation Title (optional)'),
            }),
            'conversation_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'participants': forms.SelectMultiple(attrs={
                'class': 'form-select',
            }),
        }
        help_texts = {
            'title': _('Leave blank for direct messages'),
            'participants': _('Select users to include in this conversation'),
        }

    def clean_participants(self):
        """Ensure at least one participant."""
        participants = self.cleaned_data.get('participants')
        if not participants:
            raise ValidationError(_('Select at least one participant.'))
        return participants


class GroupConversationForm(forms.ModelForm):
    """
    Form specifically for creating group conversations.
    """

    class Meta:
        model = Conversation
        fields = [
            'title',
            'description',
            'participants',
            'is_archived',
        ]
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Group Name'),
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
                'placeholder': _('Group description (optional)'),
            }),
            'participants': forms.SelectMultiple(attrs={
                'class': 'form-select',
                'size': '5',
            }),
            'is_archived': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }

    def clean_title(self):
        """Require title for group conversations."""
        title = self.cleaned_data.get('title', '').strip()
        if not title:
            raise ValidationError(_('Group name is required.'))
        return title

    def clean_participants(self):
        """Require at least 2 participants for group."""
        participants = self.cleaned_data.get('participants')
        if not participants or len(participants) < 2:
            raise ValidationError(_('Group conversations require at least 2 participants.'))
        return participants


class ContactForm(forms.ModelForm):
    """
    Form for managing contacts in the messaging system.
    """

    class Meta:
        model = Contact
        fields = [
            'contact_user',
            'nickname',
            'is_blocked',
            'is_favorite',
            'notes',
        ]
        widgets = {
            'contact_user': forms.Select(attrs={
                'class': 'form-select',
            }),
            'nickname': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Nickname (optional)'),
            }),
            'is_blocked': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'is_favorite': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
                'placeholder': _('Personal notes about this contact...'),
            }),
        }


class MessageAttachmentForm(forms.ModelForm):
    """
    Form for uploading message attachments.
    """

    class Meta:
        model = MessageAttachment
        fields = [
            'file',
            'description',
        ]
        widgets = {
            'file': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': '.pdf,.doc,.docx,.jpg,.jpeg,.png,.gif,.xls,.xlsx,.zip',
            }),
            'description': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('File description (optional)'),
            }),
        }

    def clean_file(self):
        """Validate file size and type."""
        file = self.cleaned_data.get('file')
        if file:
            if file.size > 10 * 1024 * 1024:  # 10MB
                raise ValidationError(_('File must be less than 10MB.'))
        return file


class MessageSearchForm(forms.Form):
    """
    Form for searching messages within conversations.
    """

    query = forms.CharField(
        max_length=200,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Search messages...'),
            'type': 'search',
        }),
    )
    conversation = forms.IntegerField(
        required=False,
        widget=forms.HiddenInput(),
    )
    sender = forms.IntegerField(
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
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
    has_attachments = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('Only with attachments'),
    )


class ContactUsForm(forms.Form):
    """
    Public contact form for website visitors.
    Used for inquiries, support requests, etc.
    """

    name = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Your Name'),
        }),
        label=_('Name'),
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': _('your.email@example.com'),
        }),
        label=_('Email'),
    )
    phone = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('+1 (555) 123-4567'),
        }),
        label=_('Phone (optional)'),
    )
    subject = forms.CharField(
        max_length=200,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': _('Subject'),
        }),
        label=_('Subject'),
    )
    message = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 5,
            'placeholder': _('Your message...'),
        }),
        label=_('Message'),
        max_length=5000,
    )
    category = forms.ChoiceField(
        choices=[
            ('general', _('General Inquiry')),
            ('support', _('Technical Support')),
            ('sales', _('Sales')),
            ('partnership', _('Partnership')),
            ('feedback', _('Feedback')),
            ('other', _('Other')),
        ],
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        label=_('Category'),
    )
    privacy_consent = forms.BooleanField(
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        label=_('I agree to the privacy policy'),
        required=True,
    )


class ReportMessageForm(forms.Form):
    """
    Form for reporting inappropriate messages.
    """

    REPORT_REASONS = [
        ('spam', _('Spam')),
        ('harassment', _('Harassment')),
        ('inappropriate', _('Inappropriate Content')),
        ('scam', _('Scam/Fraud')),
        ('other', _('Other')),
    ]

    reason = forms.ChoiceField(
        choices=REPORT_REASONS,
        widget=forms.RadioSelect(attrs={
            'class': 'form-radio',
        }),
        label=_('Reason for report'),
    )
    details = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 3,
            'placeholder': _('Please provide additional details...'),
        }),
        label=_('Details'),
        required=False,
        max_length=1000,
    )
    message_id = forms.IntegerField(widget=forms.HiddenInput())


class ConversationSettingsForm(forms.ModelForm):
    """
    Form for managing conversation-specific settings.
    """

    class Meta:
        model = Conversation
        fields = [
            'title',
            'is_muted',
            'is_archived',
            'is_pinned',
        ]
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-input',
            }),
            'is_muted': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'is_archived': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'is_pinned': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        labels = {
            'is_muted': _('Mute notifications'),
            'is_archived': _('Archive conversation'),
            'is_pinned': _('Pin to top'),
        }
