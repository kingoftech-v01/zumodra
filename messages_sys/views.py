from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Conversation, Message, Contact, FriendRequest, BlockList, UserStatus
from django.utils import timezone
from django.db.models import Q

# Create your views here.

def files_render(request, filename):
    return render(request, f'message_sys/{filename}')

def js_dir_view(request, file_name):
    return render(request, file_name)

@login_required
def chat_view(request):
    user = request.user

    # User profile info
    user_profile = {
        'name': user.get_full_name() or user.username,
        'email': user.email,
        'location': 'Unknown',  # Customize if you store location
        'avatar_url': user.profile.avatar.url if hasattr(user, 'profile') and user.profile.avatar else '/static/images/default-avatar.png',
        'status': 'Online' if UserStatus.objects.filter(user=user, is_online=True).exists() else 'Offline',
        'last_seen': UserStatus.objects.filter(user=user).first().last_seen if UserStatus.objects.filter(user=user).exists() else None,
        'bio': user.profile.bio if hasattr(user, 'profile') else '',
        # Add more as needed
    }

    # Conversations (sorted by recent activity)
    conversations = Conversation.objects.filter(participants=user).order_by('-updated_at')

    # Favorites contacts (example: contacts marked favourite)
    favourites = Contact.objects.filter(owner=user, is_favorite=True)

    # Contacts - all except blocked or self
    blocked_users = BlockList.objects.filter(blocker=user).values_list('blocked', flat=True)
    contacts = Contact.objects.filter(owner=user).exclude(contact__in=blocked_users)

    # Active chat can be passed via GET parameter, else first conversation
    active_conversation = None
    conv_id = request.GET.get('conversation_id')
    if conv_id:
        try:
            active_conversation = conversations.get(id=conv_id)
        except Conversation.DoesNotExist:
            active_conversation = conversations.first()
    else:
        active_conversation = conversations.first()

    # Messages in active conversation, latest 50 messages
    messages = []
    if active_conversation:
        messages = Message.objects.filter(conversation=active_conversation).order_by('timestamp')[:50]

    # Bookmarks, pinned tabs - example, assumed model to be added

    context = {
        'user_profile': user_profile,
        'conversations': conversations,
        'favourites': favourites,
        'contacts': contacts,
        'active_conversation': active_conversation,
        'messages': messages,
        'blocked_users': blocked_users,
        # 'friend_requests': FriendRequest.objects.filter(to_user=user),
    }

    return render(request, 'message_sys/index.html', context)
