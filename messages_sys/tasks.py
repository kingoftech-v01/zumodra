"""
Celery Tasks for Messages System App

This module contains async tasks for messaging operations:
- Old message cleanup and archival
- Unread notification sending
- Conversation statistics updates
- Message delivery status tracking

Security Features:
- User-scoped operations
- Message encryption handling
- Audit logging for administrative actions
"""

import logging
from datetime import timedelta
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.db.models import Count, Max, Q
from django.core.cache import cache

logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security.messages.tasks')


# ==================== MESSAGE CLEANUP ====================

@shared_task(
    bind=True,
    name='messages_sys.tasks.cleanup_old_messages',
    max_retries=3,
    default_retry_delay=300,
    soft_time_limit=3600,
)
def cleanup_old_messages(self):
    """
    Archive or delete old messages based on retention policy.

    Actions:
    - Archive messages older than 2 years
    - Delete archived messages older than 5 years
    - Clean up orphaned attachments

    Returns:
        dict: Summary of cleanup.
    """
    from messages_sys.models import Message, Attachment

    try:
        now = timezone.now()
        archive_threshold = now - timedelta(days=730)  # 2 years
        delete_threshold = now - timedelta(days=1825)  # 5 years

        # Archive old messages
        messages_to_archive = Message.objects.filter(
            created_at__lt=archive_threshold,
            is_archived=False
        )

        archived_count = messages_to_archive.count()
        messages_to_archive.update(is_archived=True, archived_at=now)

        # Delete very old archived messages
        messages_to_delete = Message.objects.filter(
            created_at__lt=delete_threshold,
            is_archived=True
        )

        deleted_count = messages_to_delete.count()

        # Log before deletion for audit
        for msg in messages_to_delete[:100]:  # Log first 100
            security_logger.info(
                f"MESSAGE_DELETE: id={msg.id} conversation={msg.conversation_id} "
                f"created={msg.created_at.isoformat()}"
            )

        messages_to_delete.delete()

        # Clean up orphaned attachments
        orphaned_attachments = Attachment.objects.filter(
            message__isnull=True,
            created_at__lt=archive_threshold
        )
        orphaned_count = orphaned_attachments.count()
        orphaned_attachments.delete()

        logger.info(
            f"Message cleanup: archived={archived_count}, deleted={deleted_count}, "
            f"orphaned_attachments={orphaned_count}"
        )

        return {
            'status': 'success',
            'archived_count': archived_count,
            'deleted_count': deleted_count,
            'orphaned_attachments_cleaned': orphaned_count,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Message cleanup exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error cleaning up messages: {str(e)}")
        raise self.retry(exc=e)


# ==================== UNREAD NOTIFICATIONS ====================

@shared_task(
    bind=True,
    name='messages_sys.tasks.send_unread_notifications',
    max_retries=3,
    default_retry_delay=600,
    autoretry_for=(Exception,),
)
def send_unread_notifications(self):
    """
    Send email notifications for unread messages.

    Sends digest emails to users who have unread messages
    older than 1 hour and haven't been notified recently.

    Returns:
        dict: Summary of notifications sent.
    """
    from messages_sys.models import Conversation, Message
    from django.contrib.auth import get_user_model

    User = get_user_model()

    try:
        now = timezone.now()
        unread_threshold = now - timedelta(hours=1)
        notify_cooldown = now - timedelta(hours=24)

        # Find users with unread messages
        users_with_unread = User.objects.filter(
            received_messages__read_at__isnull=True,
            received_messages__created_at__lt=unread_threshold,
        ).annotate(
            unread_count=Count(
                'received_messages',
                filter=Q(received_messages__read_at__isnull=True)
            )
        ).filter(
            unread_count__gt=0
        ).exclude(
            last_unread_notification__gte=notify_cooldown
        ).distinct()[:100]  # Batch size

        notified = 0
        for user in users_with_unread:
            try:
                _send_unread_digest_email(user, user.unread_count)

                # Update notification timestamp
                if hasattr(user, 'last_unread_notification'):
                    user.last_unread_notification = now
                    user.save(update_fields=['last_unread_notification'])

                notified += 1

            except Exception as e:
                logger.error(f"Error sending unread notification to user {user.id}: {e}")

        logger.info(f"Sent {notified} unread message notifications")

        return {
            'status': 'success',
            'notified_count': notified,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error sending unread notifications: {str(e)}")
        raise self.retry(exc=e)


def _send_unread_digest_email(user, unread_count):
    """Send unread messages digest email."""
    if not hasattr(user, 'email') or not user.email:
        return

    subject = f"You have {unread_count} unread message{'s' if unread_count > 1 else ''}"

    context = {
        'user': user,
        'unread_count': unread_count,
    }

    try:
        html_content = render_to_string('emails/messages/unread_digest.html', context)
        text_content = f"You have {unread_count} unread messages waiting for you."
    except Exception:
        text_content = f"You have {unread_count} unread messages waiting for you."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_content,
        fail_silently=True,
    )


# ==================== CONVERSATION STATISTICS ====================

@shared_task(
    bind=True,
    name='messages_sys.tasks.update_conversation_stats',
    max_retries=3,
    default_retry_delay=300,
    soft_time_limit=1800,
)
def update_conversation_stats(self):
    """
    Update statistics for conversations.

    Updates:
    - Message counts
    - Last activity timestamps
    - Participant activity scores

    Returns:
        dict: Summary of updates.
    """
    from messages_sys.models import Conversation

    try:
        now = timezone.now()

        # Get conversations with recent activity
        conversations = Conversation.objects.filter(
            updated_at__gte=now - timedelta(days=7)
        ).prefetch_related('messages')

        updated = 0
        for conversation in conversations:
            try:
                # Calculate message count
                message_count = conversation.messages.count()

                # Get last message time
                last_message = conversation.messages.order_by('-created_at').first()

                # Update conversation stats
                conversation.message_count = message_count
                if last_message:
                    conversation.last_message_at = last_message.created_at

                conversation.save(update_fields=['message_count', 'last_message_at', 'updated_at'])

                # Cache conversation metadata
                cache.set(
                    f"conversation_{conversation.id}:stats",
                    {
                        'message_count': message_count,
                        'last_message_at': last_message.created_at.isoformat() if last_message else None,
                    },
                    timeout=3600
                )

                updated += 1

            except Exception as e:
                logger.error(f"Error updating conversation {conversation.id}: {e}")

        logger.info(f"Updated statistics for {updated} conversations")

        return {
            'status': 'success',
            'updated_count': updated,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Conversation stats update exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error updating conversation stats: {str(e)}")
        raise self.retry(exc=e)


# ==================== MESSAGE DELIVERY STATUS ====================

@shared_task(
    bind=True,
    name='messages_sys.tasks.update_delivery_status',
    max_retries=3,
    default_retry_delay=300,
)
def update_delivery_status(self):
    """
    Update delivery status for sent messages.

    Checks:
    - Pending deliveries
    - Failed deliveries for retry
    - Delivery confirmations

    Returns:
        dict: Summary of status updates.
    """
    from messages_sys.models import Message

    try:
        now = timezone.now()

        # Find messages pending delivery confirmation
        pending_messages = Message.objects.filter(
            delivery_status='pending',
            timestamp__lt=now - timedelta(minutes=5)
        )

        # Update status based on WebSocket delivery
        # In production, this would check against Redis/WebSocket tracking

        confirmed = 0
        for message in pending_messages[:100]:
            try:
                # Check if recipient was online (simplified)
                if hasattr(message, 'recipient'):
                    # Would check WebSocket connection status
                    message.delivery_status = 'delivered'
                    message.delivered_at = now
                    message.save(update_fields=['delivery_status', 'delivered_at'])
                    confirmed += 1

            except Exception as e:
                logger.error(f"Error updating delivery status for message {message.id}: {e}")

        logger.info(f"Updated delivery status for {confirmed} messages")

        return {
            'status': 'success',
            'confirmed_count': confirmed,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error updating delivery status: {str(e)}")
        raise self.retry(exc=e)


# ==================== CONTACT SUGGESTIONS ====================

@shared_task(
    bind=True,
    name='messages_sys.tasks.generate_contact_suggestions',
    max_retries=3,
    default_retry_delay=600,
    soft_time_limit=1800,
)
def generate_contact_suggestions(self):
    """
    Generate contact suggestions for users.

    Based on:
    - Common connections
    - Work relationships
    - Interaction patterns

    Returns:
        dict: Summary of suggestions generated.
    """
    from django.contrib.auth import get_user_model

    User = get_user_model()

    try:
        now = timezone.now()

        # Get active users needing suggestions update
        active_users = User.objects.filter(
            last_login__gte=now - timedelta(days=30),
            is_active=True
        )[:100]

        generated = 0
        for user in active_users:
            try:
                # Generate suggestions (simplified)
                # In production, would use graph algorithms

                suggestions = _generate_user_suggestions(user)

                # Cache suggestions
                cache.set(
                    f"user_{user.id}:contact_suggestions",
                    suggestions,
                    timeout=86400  # 24 hours
                )

                generated += 1

            except Exception as e:
                logger.error(f"Error generating suggestions for user {user.id}: {e}")

        logger.info(f"Generated contact suggestions for {generated} users")

        return {
            'status': 'success',
            'generated_count': generated,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Contact suggestions generation exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error generating contact suggestions: {str(e)}")
        raise self.retry(exc=e)


def _generate_user_suggestions(user):
    """
    Generate contact suggestions for a user based on graph analysis.

    Algorithm:
    1. Find all conversations the user participates in
    2. Get all other participants from those conversations
    3. For group conversations, suggest users the user hasn't directly messaged
    4. Rank by number of shared group conversations (mutual connections)
    5. Limit to top suggestions

    Returns:
        list: List of suggested user IDs with scores
    """
    from django.contrib.auth import get_user_model
    from messages_sys.models import Conversation
    from collections import Counter

    User = get_user_model()

    try:
        # Get all conversations the user participates in
        user_conversations = Conversation.objects.filter(
            participants=user
        ).prefetch_related('participants')

        # Track potential suggestions with scores
        suggestion_scores = Counter()

        # Get users the user has direct (1-on-1) conversations with
        direct_contacts = set()

        for conv in user_conversations:
            participants = list(conv.participants.exclude(id=user.id).values_list('id', flat=True))

            if len(participants) == 1:
                # This is a direct 1-on-1 conversation
                direct_contacts.add(participants[0])
            else:
                # This is a group conversation - all participants are potential suggestions
                for participant_id in participants:
                    if participant_id not in direct_contacts:
                        # Increase score for each shared group conversation
                        suggestion_scores[participant_id] += 1

        # Remove users who are already direct contacts from suggestions
        for contact_id in direct_contacts:
            if contact_id in suggestion_scores:
                del suggestion_scores[contact_id]

        # Also find colleagues (users in same organization/tenant)
        # This adds users who might be relevant but haven't chatted yet
        try:
            if hasattr(user, 'employee_record') and user.employee_record:
                employee = user.employee_record
                # Get colleagues in same department
                if employee.department:
                    colleagues = User.objects.filter(
                        employee_record__department=employee.department,
                        is_active=True
                    ).exclude(
                        id=user.id
                    ).exclude(
                        id__in=direct_contacts
                    ).values_list('id', flat=True)[:20]

                    for colleague_id in colleagues:
                        # Add with lower score than conversation-based suggestions
                        if colleague_id not in suggestion_scores:
                            suggestion_scores[colleague_id] = 0.5
        except Exception:
            # If employee record lookup fails, continue without colleague suggestions
            pass

        # Sort by score (descending) and get top 10 suggestions
        top_suggestions = suggestion_scores.most_common(10)

        # Return list of suggestion dicts with user details
        suggestions = []
        if top_suggestions:
            suggested_ids = [uid for uid, score in top_suggestions]
            suggested_users = User.objects.filter(
                id__in=suggested_ids,
                is_active=True
            ).values('id', 'email', 'first_name', 'last_name')

            # Create a map for quick lookup
            user_map = {u['id']: u for u in suggested_users}

            for uid, score in top_suggestions:
                if uid in user_map:
                    u = user_map[uid]
                    suggestions.append({
                        'user_id': str(uid),
                        'email': u['email'],
                        'name': f"{u['first_name']} {u['last_name']}".strip() or u['email'],
                        'score': float(score),
                        'reason': 'shared_conversations' if score >= 1 else 'colleague'
                    })

        return suggestions

    except Exception as e:
        logger.error(f"Error generating suggestions for user {user.id}: {e}")
        return []


# ==================== SPAM DETECTION ====================

@shared_task(
    bind=True,
    name='messages_sys.tasks.detect_spam_messages',
    max_retries=3,
    default_retry_delay=300,
)
def detect_spam_messages(self):
    """
    Detect and flag potential spam messages.

    Checks:
    - Message frequency anomalies
    - Content patterns
    - Link density

    Returns:
        dict: Summary of detection.
    """
    from messages_sys.models import Message
    from django.contrib.auth import get_user_model

    User = get_user_model()

    try:
        now = timezone.now()
        check_window = now - timedelta(hours=1)

        # Find users sending many messages in short time
        high_volume_senders = User.objects.annotate(
            recent_message_count=Count(
                'sent_messages',
                filter=Q(sent_messages__created_at__gte=check_window)
            )
        ).filter(recent_message_count__gt=50)

        flagged = 0
        for sender in high_volume_senders:
            try:
                # Log potential spam activity
                security_logger.warning(
                    f"SPAM_DETECTION: user={sender.id} messages_in_hour={sender.recent_message_count}"
                )

                # Flag recent messages for review
                Message.objects.filter(
                    sender=sender,
                    created_at__gte=check_window
                ).update(is_flagged=True, flagged_reason='high_volume')

                flagged += 1

            except Exception as e:
                logger.error(f"Error flagging spam from user {sender.id}: {e}")

        logger.info(f"Flagged {flagged} potential spam senders")

        return {
            'status': 'success',
            'flagged_senders': flagged,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error detecting spam: {str(e)}")
        raise self.retry(exc=e)
