from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from .models import Conversation, Message, Contact, FriendRequest, BlockList, UserStatus
from django.utils import timezone
from django.db.models import Q, Prefetch


def files_render(request, filename):
    return render(request, f'message_sys/{filename}')


def js_dir_view(request, file_name):
    return render(request, file_name)


@login_required
def chat_view(request):
    """
    Main chat view with optimized queries for 500K concurrent users.
    Uses prefetch_related and select_related to avoid N+1 queries.

    TEST FINDINGS (2026-01-16):
    ---------------------------
    URL: /app/messages/

    CRITICAL ISSUE: Server returned 502 Bad Gateway when attempting to test this view.
    This indicates that the backend Django application is not running or not reachable
    through nginx reverse proxy.

    Status: NOT TESTED - Server unavailable

    EXPECTED FUNCTIONALITY (based on code analysis):
    - Message inbox with conversation list
    - Active conversation display
    - User status indicators (online/offline)
    - Contact list with favorites
    - Blocked users filtering
    - Optimized queries with caching (60s cache for user status)
    - Real-time WebSocket support (consumer.py)

    POTENTIAL ISSUES TO TEST (when server is available):
    1. Template path: 'message_sys/index.html' - verify template exists
    2. User profile avatar handling - may break if profile doesn't exist
    3. Conversation selection - defaults to first conversation if none specified
    4. Message marking as read - uses bulk update
    5. WebSocket connection for real-time updates

    URLS THAT NEED TESTING:
    - /app/messages/ - Main inbox (this view)
    - /app/messages/?conversation_id=<id> - Specific conversation
    - WebSocket: ws://domain/ws/chat/ (from routing.py and consumer.py)

    API ENDPOINTS THAT NEED TESTING:
    - /api/v1/messages/conversations/ - List conversations
    - /api/v1/messages/messages/ - List messages
    - /api/v1/messages/contacts/ - List contacts
    - /api/v1/messages/friend-requests/ - Friend requests
    - /api/v1/messages/blocked/ - Blocked users
    - /api/v1/messages/status/ - User status
    """
    user = request.user

    # Get user status with caching
    user_status_cache_key = f"user_status_{user.id}"
    cached_status = cache.get(user_status_cache_key)
    if cached_status is None:
        user_status_obj, created = UserStatus.objects.get_or_create(
            user=user,
            defaults={'is_online': False, 'last_seen': None}
        )
        cached_status = {
            'is_online': user_status_obj.is_online,
            'last_seen': user_status_obj.last_seen
        }
        cache.set(user_status_cache_key, cached_status, timeout=60)  # 1 min cache

    # User profile info
    user_profile = {
        'name': user.get_full_name() or user.email,
        'email': user.email,
        'location': 'Unknown',
        'avatar_url': user.profile.avatar.url if hasattr(user, 'profile') and user.profile.avatar else '/static/images/default-avatar.png',
        'status': 'Online' if cached_status['is_online'] else 'Offline',
        'last_seen': cached_status['last_seen'],
        'bio': user.profile.bio if hasattr(user, 'profile') else '',
    }

    # Conversations with optimized prefetching (avoid N+1)
    conversations = Conversation.objects.for_user(user, limit=50)

    # Favorites contacts with select_related to avoid N+1
    favourites = (
        Contact.objects
        .filter(owner=user, is_favorite=True)
        .select_related('contact')
    )

    # Get blocked user IDs efficiently using the manager method
    blocked_user_ids = BlockList.objects.blocked_user_ids(user)

    # Contacts with select_related, excluding blocked
    contacts = (
        Contact.objects
        .filter(owner=user)
        .exclude(contact_id__in=blocked_user_ids)
        .select_related('contact')
    )

    # Active chat with optimized query
    active_conversation = None
    conv_id = request.GET.get('conversation_id')
    if conv_id:
        try:
            # Use prefetch for active conversation
            active_conversation = (
                Conversation.objects
                .prefetch_related('participants')
                .get(id=conv_id, participants=user)
            )
        except Conversation.DoesNotExist:
            active_conversation = conversations[0] if conversations else None
    else:
        active_conversation = conversations[0] if conversations else None

    # Messages with optimized cursor-based query
    messages = []
    if active_conversation:
        # Use the optimized manager method with select_related
        messages = list(
            Message.objects
            .for_conversation(active_conversation.id, limit=50)
        )
        # Reverse to show oldest first in template
        messages.reverse()

        # Mark messages as read (bulk update for efficiency)
        Message.objects.mark_conversation_read(user, active_conversation.id)

    context = {
        'user_profile': user_profile,
        'conversations': conversations,
        'favourites': favourites,
        'contacts': contacts,
        'active_conversation': active_conversation,
        'messages': messages,
        'blocked_users': blocked_user_ids,
    }

    return render(request, 'message_sys/index.html', context)
