from django.db import models
from django.utils import timezone
# Create your models here.
import uuid
from django.db import models
from zumodra import settings
from django.core.exceptions import ValidationError
from django.core.validators import FileExtensionValidator
from django.utils.translation import gettext_lazy as _

User = settings.AUTH_USER_MODEL  # Reference your custom user model here


class Conversation(models.Model):
    """
    Represents a chat conversation which can be either:
    - A one-to-one conversation between two users
    - A group chat with multiple participants

    UUID primary key for secure reference.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, blank=True, null=True)  # Group chat name or null for direct message
    participants = models.ManyToManyField(User, related_name='conversations')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def add_participant(self, user):
        if not self.participants.filter(pk=user.pk).exists():
            self.participants.add(user)
            self.save()

    def remove_participant(self, user):
        if self.participants.filter(pk=user.pk).exists():
            self.participants.remove(user)
            if self.participants.count() == 0:
                self.delete()

    def get_last_message(self):
        return self.messages.order_by('-timestamp').first()

    def is_group(self):
        """Returns True if conversation has more than 2 participants (group chat)."""
        return self.participants.count() > 2

    def __str__(self):
        if self.is_group():
            return f"Group Chat: {self.name or 'Unnamed'} ({self.id})"
        users = self.participants.all()
        return f"Chat: {users[0]} & {users[1]}" if users.count() == 2 else f"Conversation {self.id}"

    class Meta:
        ordering = ['-updated_at']


class Message(models.Model):
    """
    Represents individual messages sent within conversations.

    Messages have content, sender, timestamp, and read/unread status.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    content = models.TextField(blank=True, null=True)
    file = models.FileField(
        upload_to='message_attachments/',
        blank=True,
        null=True,
        help_text="Document, image ou autre fichier (<= 50MB)",
        validators=[FileExtensionValidator(
            allowed_extensions=['pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx', 'mp4', 'xlsx', 'zip', 'csv', 'txt'])]  # adapte selon tes besoins !
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    voice_message = models.FileField(upload_to='voice_messages/', blank=True, null=True)
    is_voice = models.BooleanField(default=False)

    def validate_file(field_file):
        max_size = 50 * 1024 * 1024  # 50 MB
        allowed_extensions = ['pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx', 'mp4', 'xlsx', 'zip', 'csv', 'txt']

        ext = field_file.name.split('.')[-1].lower()
        if ext not in allowed_extensions:
            raise ValidationError(f"Unsupported file extension. Allowed: {allowed_extensions}")

        if field_file.size > max_size:
            raise ValidationError("File size must be 50MB or smaller.")

    def mark_as_read(self, user):
        status, created = MessageStatus.objects.get_or_create(user=user, message=self)
        if not status.read_at:
            status.read_at = timezone.now()
            status.save()

    def is_read_by(self, user):
        try:
            status = self.statuses.get(user=user)
            return status.read_at is not None
        except MessageStatus.DoesNotExist:
            return False


    def clean(self):
        super().clean()
        if self.file and self.file.size > 50 * 1024 * 1024:  # 50 MB = 50*1024*1024
            raise ValidationError("Le fichier ne doit pas dépasser 50MB.")

    def __str__(self):
        return f"From {self.sender} at {self.timestamp}: {self.content[:50]}"

    class Meta:
        ordering = ['timestamp']


class MessageStatus(models.Model):
    """
    Tracks the read status for each participant and message.
    Useful for group chats to track who has read what.

    Connects a user to a message and tracks if the message is read.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='message_statuses')
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='statuses')
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('user', 'message')  # Each user-message pair is unique

    def __str__(self):
        status = "Read" if self.read_at else "Unread"
        return f"{self.user} {status} message {self.message.id}"

class TypingStatus(models.Model):
    """
    Optional: To track which user is currently typing in which conversation.
    Can be used to display 'User X is typing...' status.
    """
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='typing_statuses')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='typing_statuses')
    is_typing = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('conversation', 'user')

    def __str__(self):
        return f"{self.user} typing in {self.conversation}: {self.is_typing}"

class Contact(models.Model):
    """
    Gère la liste de contacts entre utilisateurs.
    """
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='contacts_owner')
    contact = models.ForeignKey(User, on_delete=models.CASCADE, related_name='contacts_contact')
    created_at = models.DateTimeField(auto_now_add=True)
    is_favorite = models.BooleanField(default=False)

    def remove_contact(self, other_user):
        """Remove a contact relationship."""
        Contact.objects.filter(
            (models.Q(owner=self, contact=other_user) | models.Q(owner=other_user, contact=self))
        ).delete()


    class Meta:
        unique_together = ('owner', 'contact')

    def __str__(self):
        return f"{self.owner} has contact {self.contact}"


class FriendRequest(models.Model):
    """
    Invitation d’amitié (demande de contact).
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_friend_requests')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_friend_requests')
    created_at = models.DateTimeField(auto_now_add=True)
    accepted = models.BooleanField(default=False)
    rejected = models.BooleanField(default=False)

    def accept(self):
        if self.rejected:
            raise ValidationError("Cannot accept a rejected request.")
        if self.accepted:
            raise ValidationError("Request already accepted.")

        self.accepted = True
        self.rejected = False
        self.save()
        # Automatically create contacts for both users
        Contact.objects.get_or_create(owner=self.sender, contact=self.receiver)
        Contact.objects.get_or_create(owner=self.receiver, contact=self.sender)

    def reject(self):
        if self.accepted:
            raise ValidationError("Cannot reject an accepted request.")
        if self.rejected:
            raise ValidationError("Request already rejected.")

        self.rejected = True
        self.accepted = False
        self.save()

    def cancel(self):
        # Optionally allow sender to cancel a pending request
        if self.accepted or self.rejected:
            raise ValidationError("Cannot cancel a completed request.")
        self.delete()

    class Meta:
        unique_together = ('sender', 'receiver')

    def __str__(self):
        status = "accepted" if self.accepted else "pending" if not self.rejected else "rejected"
        return f"FriendRequest from {self.sender} to {self.receiver} ({status})"


class BlockList(models.Model):
    """
    Blocage entre utilisateurs pour gérer la confidentialité.
    """
    blocker = models.ForeignKey(User, on_delete=models.CASCADE, related_name='blocker')
    blocked = models.ForeignKey(User, on_delete=models.CASCADE, related_name='blocked_user')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('blocker', 'blocked')

    def __str__(self):
        return f"{self.blocker} blocked {self.blocked}"


class UserStatus(models.Model):
    """
    Statut en ligne/hors ligne + dernière activité utilisateur.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='status')
    is_online = models.BooleanField(default=False)
    last_seen = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        state = "Online" if self.is_online else f"Last seen: {self.last_seen}"
        return f"{self.user} - {state}"
