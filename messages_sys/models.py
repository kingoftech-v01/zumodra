from django.db import models
from django.db.models import Prefetch, Q
from django.utils import timezone
from django.core.cache import cache
import uuid
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import FileExtensionValidator
from django.utils.translation import gettext_lazy as _

User = settings.AUTH_USER_MODEL


class ConversationManager(models.Manager):
    """
    Optimized manager for Conversation queries.
    Designed for 500K concurrent users with efficient query patterns.
    """

    def for_user(self, user, limit=50):
        """
        Get conversations for a user with optimized prefetching.
        Uses select_related and prefetch_related to avoid N+1 queries.
        """
        return (
            self.get_queryset()
            .filter(participants=user)
            .prefetch_related(
                Prefetch(
                    'participants',
                    queryset=user.__class__.objects.only('id', 'email', 'first_name', 'last_name')
                ),
            )
            .order_by('-updated_at')[:limit]
        )

    def get_or_create_direct(self, user1, user2):
        """
        Get or create a direct conversation between two users.
        Uses efficient query to avoid duplicate conversations.
        """
        # Check cache first
        cache_key = f"conv_direct_{min(str(user1.id), str(user2.id))}_{max(str(user1.id), str(user2.id))}"
        cached_id = cache.get(cache_key)
        if cached_id:
            try:
                return self.get(id=cached_id), False
            except self.model.DoesNotExist:
                cache.delete(cache_key)

        # Find existing conversation with exactly these two participants
        conversations = (
            self.get_queryset()
            .filter(participants=user1)
            .filter(participants=user2)
            .annotate(participant_count=models.Count('participants'))
            .filter(participant_count=2)
        )

        if conversations.exists():
            conv = conversations.first()
            cache.set(cache_key, str(conv.id), timeout=3600)  # Cache for 1 hour
            return conv, False

        # Create new conversation
        conv = self.create()
        conv.participants.add(user1, user2)
        cache.set(cache_key, str(conv.id), timeout=3600)
        return conv, True

    def with_unread_count(self, user):
        """
        Get conversations with unread message count for efficient inbox display.
        """
        from django.db.models import Count, Case, When, IntegerField
        return (
            self.for_user(user)
            .annotate(
                unread_count=Count(
                    Case(
                        When(messages__is_read=False, messages__sender__id__ne=user.id, then=1),
                        output_field=IntegerField(),
                    )
                )
            )
        )


class Conversation(models.Model):
    """
    Represents a chat conversation which can be either:
    - A one-to-one conversation between two users
    - A group chat with multiple participants

    UUID primary key for secure reference.
    Optimized with indexes for 500K concurrent users.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, blank=True, null=True, db_index=True)
    participants = models.ManyToManyField(User, related_name='conversations')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True, db_index=True)

    # Denormalized fields for efficient queries (updated on message save)
    last_message_text = models.CharField(max_length=255, blank=True, null=True)
    last_message_at = models.DateTimeField(null=True, blank=True, db_index=True)
    last_message_sender_id = models.UUIDField(null=True, blank=True)

    objects = ConversationManager()

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
        """Get last message - uses cache for efficiency."""
        cache_key = f"conv_last_msg_{self.id}"
        cached = cache.get(cache_key)
        if cached:
            return cached
        msg = self.messages.select_related('sender').order_by('-timestamp').first()
        if msg:
            cache.set(cache_key, msg, timeout=300)  # 5 min cache
        return msg

    def is_group(self):
        """Returns True if conversation has more than 2 participants (group chat)."""
        return self.participants.count() > 2

    def is_participant(self, user):
        """Check if user is participant - uses cache for efficiency."""
        cache_key = f"conv_participant_{self.id}_{user.id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        result = self.participants.filter(pk=user.pk).exists()
        cache.set(cache_key, result, timeout=600)  # 10 min cache
        return result

    def update_last_message(self, message):
        """Update denormalized last message fields."""
        self.last_message_text = (message.content or '')[:255]
        self.last_message_at = message.timestamp
        self.last_message_sender_id = message.sender_id
        self.save(update_fields=['last_message_text', 'last_message_at', 'last_message_sender_id', 'updated_at'])
        # Invalidate cache
        cache.delete(f"conv_last_msg_{self.id}")

    def __str__(self):
        if self.is_group():
            return f"Group Chat: {self.name or 'Unnamed'} ({self.id})"
        users = self.participants.all()
        return f"Chat: {users[0]} & {users[1]}" if users.count() == 2 else f"Conversation {self.id}"

    class Meta:
        ordering = ['-updated_at']
        indexes = [
            models.Index(fields=['-updated_at']),
            models.Index(fields=['-last_message_at']),
            models.Index(fields=['created_at']),
        ]


class MessageManager(models.Manager):
    """
    Optimized manager for Message queries.
    Designed for 500K concurrent users with cursor-based pagination.
    """

    def for_conversation(self, conversation_id, limit=50, before_timestamp=None):
        """
        Get messages for a conversation with cursor-based pagination.
        More efficient than offset pagination for large datasets.
        """
        queryset = (
            self.get_queryset()
            .filter(conversation_id=conversation_id)
            .select_related('sender')
            .order_by('-timestamp')
        )

        if before_timestamp:
            queryset = queryset.filter(timestamp__lt=before_timestamp)

        return queryset[:limit]

    def unread_for_user(self, user, conversation_id=None):
        """Get unread messages for a user, optionally filtered by conversation."""
        queryset = (
            self.get_queryset()
            .filter(conversation__participants=user)
            .exclude(sender=user)
            .filter(is_read=False)
            .select_related('sender', 'conversation')
        )

        if conversation_id:
            queryset = queryset.filter(conversation_id=conversation_id)

        return queryset

    def mark_conversation_read(self, user, conversation_id):
        """Bulk mark all messages in a conversation as read for a user."""
        updated = (
            self.get_queryset()
            .filter(conversation_id=conversation_id)
            .exclude(sender=user)
            .filter(is_read=False)
            .update(is_read=True)
        )
        return updated


class Message(models.Model):
    """
    Represents individual messages sent within conversations.

    Messages have content, sender, timestamp, and read/unread status.
    Optimized with indexes for 500K concurrent users.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    conversation = models.ForeignKey(
        Conversation,
        on_delete=models.CASCADE,
        related_name='messages',
        db_index=True  # Explicit index for FK
    )
    sender = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='sent_messages',
        db_index=True  # Explicit index for FK
    )
    content = models.TextField(blank=True, null=True)
    file = models.FileField(
        upload_to='message_attachments/',
        blank=True,
        null=True,
        help_text="Document, image ou autre fichier (<= 50MB)",
        validators=[FileExtensionValidator(
            allowed_extensions=['pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx', 'mp4', 'xlsx', 'zip', 'csv', 'txt'])]
    )
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    is_read = models.BooleanField(default=False, db_index=True)
    voice_message = models.FileField(upload_to='voice_messages/', blank=True, null=True)
    is_voice = models.BooleanField(default=False)

    objects = MessageManager()

    @staticmethod
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
        if self.file and self.file.size > 50 * 1024 * 1024:
            raise ValidationError("Le fichier ne doit pas dépasser 50MB.")

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Update conversation's denormalized last message fields
        if self.conversation:
            self.conversation.update_last_message(self)

    def __str__(self):
        content_preview = (self.content or '')[:50]
        return f"From {self.sender} at {self.timestamp}: {content_preview}"

    class Meta:
        ordering = ['timestamp']
        indexes = [
            # Composite index for efficient conversation message queries
            models.Index(fields=['conversation', '-timestamp']),
            models.Index(fields=['conversation', 'timestamp']),
            # Index for unread message queries
            models.Index(fields=['conversation', 'is_read']),
            # Index for user's sent messages
            models.Index(fields=['sender', '-timestamp']),
        ]


class MessageStatus(models.Model):
    """
    Tracks the read status for each participant and message.
    Useful for group chats to track who has read what.

    Connects a user to a message and tracks if the message is read.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='message_statuses', db_index=True)
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='statuses', db_index=True)
    read_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        unique_together = ('user', 'message')
        indexes = [
            models.Index(fields=['user', 'read_at']),
            models.Index(fields=['message', 'read_at']),
        ]

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


class BlockListManager(models.Manager):
    """Optimized manager for BlockList queries."""

    def is_blocked(self, blocker, blocked):
        """Check if blocker has blocked the blocked user."""
        cache_key = f"block_{blocker.id}_{blocked.id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        result = self.filter(blocker=blocker, blocked=blocked).exists()
        cache.set(cache_key, result, timeout=300)  # 5 min cache
        return result

    def is_blocked_by(self, user, other_user):
        """Check if either user has blocked the other."""
        return self.is_blocked(user, other_user) or self.is_blocked(other_user, user)

    def blocked_user_ids(self, user):
        """Get list of user IDs that user has blocked."""
        cache_key = f"blocked_ids_{user.id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        ids = list(self.filter(blocker=user).values_list('blocked_id', flat=True))
        cache.set(cache_key, ids, timeout=300)
        return ids


class BlockList(models.Model):
    """
    Blocage entre utilisateurs pour gérer la confidentialité.
    """
    blocker = models.ForeignKey(User, on_delete=models.CASCADE, related_name='blocker', db_index=True)
    blocked = models.ForeignKey(User, on_delete=models.CASCADE, related_name='blocked_user', db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = BlockListManager()

    class Meta:
        unique_together = ('blocker', 'blocked')
        indexes = [
            models.Index(fields=['blocker', 'blocked']),
            models.Index(fields=['blocked', 'blocker']),
        ]

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Invalidate cache
        cache.delete(f"block_{self.blocker_id}_{self.blocked_id}")
        cache.delete(f"blocked_ids_{self.blocker_id}")

    def delete(self, *args, **kwargs):
        # Invalidate cache before delete
        cache.delete(f"block_{self.blocker_id}_{self.blocked_id}")
        cache.delete(f"blocked_ids_{self.blocker_id}")
        super().delete(*args, **kwargs)

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
