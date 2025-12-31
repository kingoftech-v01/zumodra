# import json
# import base64
# from channels.generic.websocket import AsyncWebsocketConsumer
# from channels.db import database_sync_to_async
# from django.core.files.base import ContentFile
# from django.utils import timezone

# from .models import Conversation, Message, TypingStatus, MessageStatus

# MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


# class ChatConsumer(AsyncWebsocketConsumer):
#     async def connect(self):
#         self.conversation_id = self.scope['url_route']['kwargs']['conversation_id']
#         self.user = self.scope['user']
#         self.room_group_name = f"chat_{self.conversation_id}"

#         await self.channel_layer.group_add(self.room_group_name, self.channel_name)
#         await self.accept()
#         await self.send_json({"type": "status", "message": "Connected", "is_online": True})

#     async def disconnect(self, close_code):
#         await self.channel_layer.group_discard(self.room_group_name, self.channel_name)
#         await self.send_json({"type": "status", "message": "Disconnected", "is_online": False})

#     async def receive(self, text_data=None, bytes_data=None):
#         if not text_data:
#             return
#         data = json.loads(text_data)
#         event_type = data.get('type')

#         if event_type == 'text':
#             content = data.get('content', "").strip()
#             if not content:
#                 return
#             msg = await self.save_message(content=content)
#             response = {"type": "message", "content": msg.content, "sender": str(self.user.id), "timestamp": str(msg.timestamp), "file": "", "is_voice": False}
#             await self.channel_layer.group_send(self.room_group_name, {"type": "chat_message", "message": response})

#         elif event_type == 'file':
#             file_info = data.get('file')
#             is_voice = bool(data.get('is_voice', False))
#             if not file_info:
#                 await self.send_json({"type": "error", "message": "Invalid file."})
#                 return
#             file_name = file_info.get('name')
#             file_content = file_info.get('content')
#             file_size = file_info.get('size', 0)
#             if file_size > MAX_FILE_SIZE:
#                 await self.send_json({"type": "error", "message": "File exceeds 50MB."})
#                 return
#             try:
#                 file_bytes = base64.b64decode(file_content)
#             except Exception:
#                 await self.send_json({"type": "error", "message": "File decoding failed."})
#                 return
#             django_file = ContentFile(file_bytes, name=file_name)
#             msg = await self.save_message(file=django_file, is_voice=is_voice)
#             file_url = msg.voice_message.url if is_voice else msg.file.url
#             response = {
#                 "type": "message",
#                 "content": msg.content or "",
#                 "sender": str(self.user.id),
#                 "timestamp": str(msg.timestamp),
#                 "file": file_url,
#                 "is_voice": is_voice,
#             }
#             await self.channel_layer.group_send(self.room_group_name, {"type": "chat_message", "message": response})

#         elif event_type == 'typing':
#             is_typing = bool(data.get('is_typing', False))
#             await database_sync_to_async(TypingStatus.objects.update_or_create)(
#                 conversation_id=self.conversation_id,
#                 user=self.user,
#                 defaults={"is_typing": is_typing, "updated_at": timezone.now()}
#             )
#             await self.channel_layer.group_send(
#                 self.room_group_name,
#                 {
#                     "type": "typing_status",
#                     "typing_user": str(self.user.id),
#                     "is_typing": is_typing,
#                 }
#             )

#         elif event_type == 'read':
#             message_id = data.get('message_id')
#             if message_id:
#                 message = await database_sync_to_async(Message.objects.get)(id=message_id)
#                 await database_sync_to_async(MessageStatus.objects.update_or_create)(
#                     user=self.user,
#                     message=message,
#                     defaults={'read_at': timezone.now()}
#                 )
#                 await self.channel_layer.group_send(
#                     self.room_group_name,
#                     {
#                         'type': 'message_read',
#                         'message_id': str(message_id),
#                         'user': str(self.user.id),
#                     }
#                 )

#     async def chat_message(self, event):
#         await self.send_json(event['message'])

#     async def typing_status(self, event):
#         await self.send_json({
#             "type": "typing",
#             "user": event['typing_user'],
#             "is_typing": event['is_typing'],
#         })

#     async def message_read(self, event):
#         await self.send_json({
#             'type': 'read',
#             'message_id': event['message_id'],
#             'user': event['user'],
#         })

#     async def send_json(self, content):
#         await self.send(text_data=json.dumps(content))

#     @database_sync_to_async
#     def save_message(self, content="", file=None, is_voice=False):
#         msg = Message(
#             conversation_id=self.conversation_id,
#             sender=self.user,
#             content=content,
#             is_read=False,
#             is_voice=is_voice,
#         )
#         if file:
#             if is_voice:
#                 msg.voice_message = file
#             else:
#                 msg.file = file
#         msg.save()
#         return msg


import json
import base64
import logging
import mimetypes
import os
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.core.files.base import ContentFile
from django.utils import timezone
from django.contrib.auth import get_user_model
from .models import Message, Conversation, Contact, FriendRequest, MessageStatus, BlockList

User = get_user_model()

logger = logging.getLogger(__name__)

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB max upload size

# Allowed file extensions and their MIME types for security
ALLOWED_FILE_TYPES = {
    'pdf': ['application/pdf'],
    'jpg': ['image/jpeg'],
    'jpeg': ['image/jpeg'],
    'png': ['image/png'],
    'gif': ['image/gif'],
    'doc': ['application/msword'],
    'docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    'xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
    'xls': ['application/vnd.ms-excel'],
    'txt': ['text/plain'],
    'csv': ['text/csv', 'application/csv'],
    'mp4': ['video/mp4'],
    'mp3': ['audio/mpeg'],
    'wav': ['audio/wav', 'audio/x-wav'],
    'webm': ['audio/webm', 'video/webm'],
    'ogg': ['audio/ogg'],
    'zip': ['application/zip', 'application/x-zip-compressed'],
}

# Dangerous file patterns to block
BLOCKED_EXTENSIONS = {
    'exe', 'bat', 'cmd', 'sh', 'ps1', 'vbs', 'js', 'jar', 'msi', 'dll', 'scr',
    'php', 'asp', 'aspx', 'jsp', 'cgi', 'py', 'rb', 'pl', 'htaccess', 'htpasswd'
}


def validate_file_type(filename, file_content):
    """
    Validate file type by extension and magic bytes.
    Returns (is_valid, error_message).
    """
    if not filename:
        return False, "No filename provided"

    # Get extension
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    # Block dangerous extensions
    if ext in BLOCKED_EXTENSIONS:
        return False, f"File type .{ext} is not allowed"

    # Check if extension is in allowed list
    if ext not in ALLOWED_FILE_TYPES:
        return False, f"File type .{ext} is not supported"

    # Check magic bytes for common file types (basic validation)
    magic_signatures = {
        b'%PDF': ['pdf'],
        b'\xff\xd8\xff': ['jpg', 'jpeg'],
        b'\x89PNG': ['png'],
        b'GIF87a': ['gif'],
        b'GIF89a': ['gif'],
        b'PK\x03\x04': ['zip', 'docx', 'xlsx'],
        b'\xd0\xcf\x11\xe0': ['doc', 'xls'],
        b'ID3': ['mp3'],
        b'\xff\xfb': ['mp3'],
        b'RIFF': ['wav'],
        b'\x00\x00\x00': ['mp4'],  # ftyp box (simplified)
        b'\x1a\x45\xdf\xa3': ['webm'],
        b'OggS': ['ogg'],
    }

    # Only check magic bytes if we have content
    if file_content and len(file_content) >= 4:
        header = file_content[:8]
        matched = False
        for signature, extensions in magic_signatures.items():
            if header.startswith(signature):
                if ext in extensions:
                    matched = True
                    break
                else:
                    # Extension doesn't match magic bytes
                    return False, "File content does not match file extension"

        # For text files, skip magic byte check
        if ext in ['txt', 'csv'] and not matched:
            matched = True

    return True, None


class ChatConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for real-time chat with tenant isolation and security.
    """

    async def connect(self):
        self.user = self.scope['user']
        self.conversation_id = self.scope['url_route']['kwargs']['conversation_id']
        self.tenant = None  # Will be set after validation

        # Reject unauthenticated connections
        if not self.user or not self.user.is_authenticated:
            logger.warning(f"Rejected unauthenticated WebSocket connection attempt")
            await self.close(code=4001)
            return

        # Validate user is participant in this conversation
        is_participant = await self.validate_conversation_access()
        if not is_participant:
            logger.warning(
                f"User {self.user.id} denied access to conversation {self.conversation_id}"
            )
            await self.close(code=4003)
            return

        # Get tenant context for channel namespacing
        tenant_id = await self.get_conversation_tenant_id()

        # Use tenant-namespaced channel group to prevent cross-tenant access
        if tenant_id:
            self.room_group_name = f"tenant_{tenant_id}_chat_{self.conversation_id}"
        else:
            self.room_group_name = f"chat_{self.conversation_id}"

        # Add user to group
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        await self.accept()

        logger.info(f"User {self.user.id} connected to conversation {self.conversation_id}")

        # Optionally send back connect confirmation
        await self.send_json({"type": "status", "message": "Connected", "is_online": True})

    @database_sync_to_async
    def validate_conversation_access(self):
        """
        Verify user is a participant in this conversation and not blocked.
        Uses optimized queries to minimize database hits.
        """
        try:
            conversation = Conversation.objects.prefetch_related('participants').get(id=self.conversation_id)

            # Check if user is a participant
            if not conversation.participants.filter(id=self.user.id).exists():
                return False

            # Check if user is blocked by any other participant
            other_participants = conversation.participants.exclude(id=self.user.id)
            for participant in other_participants:
                if BlockList.objects.is_blocked_by(self.user, participant):
                    logger.warning(
                        f"User {self.user.id} blocked from conversation {self.conversation_id} - block exists"
                    )
                    return False

            return True
        except Conversation.DoesNotExist:
            return False
        except Exception as e:
            logger.error(f"Error validating conversation access: {e}")
            return False

    @database_sync_to_async
    def get_conversation_tenant_id(self):
        """Get tenant ID for this conversation if applicable."""
        try:
            conversation = Conversation.objects.get(id=self.conversation_id)
            # If conversation has a tenant field, use it
            if hasattr(conversation, 'tenant_id') and conversation.tenant_id:
                return conversation.tenant_id
            # Otherwise, try to get from first participant's tenant
            if hasattr(self.user, 'tenant_users'):
                tenant_user = self.user.tenant_users.first()
                if tenant_user:
                    return tenant_user.tenant_id
            return None
        except Exception as e:
            logger.error(f"Error getting tenant ID: {e}")
            return None

    async def disconnect(self, close_code):
        # Remove from group
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        if text_data is None:
            return
        data = json.loads(text_data)
        msg_type = data.get("type")

        if msg_type == "send_message":
            await self.handle_send_message(data)
        elif msg_type == "add_contact":
            await self.handle_add_contact(data)
        elif msg_type == "create_group":
            await self.handle_create_group(data)
        elif msg_type == "typing":
            await self.handle_typing(data)
        elif msg_type == "read":
            await self.handle_read_receipt(data)

    async def handle_send_message(self, data):
        content = data.get("content", "")
        file_data = data.get("file")
        is_voice = data.get("is_voice", False)

        # Basic input sanitization for content
        if content:
            content = content.strip()
            # Limit content length to prevent abuse
            if len(content) > 10000:
                await self.send_json({"type": "error", "message": "Message too long (max 10,000 characters)"})
                return

        if content == "" and not file_data:
            await self.send_json({"type": "error", "message": "Empty message"})
            return

        # Save file if exists
        django_file = None
        if file_data:
            try:
                filename = file_data.get("name", "file")

                # Sanitize filename - remove path traversal attempts
                filename = os.path.basename(filename)
                filename = filename.replace('..', '').replace('/', '').replace('\\', '')

                # Decode file content
                file_content = base64.b64decode(file_data["content"])

                # Check file size
                if len(file_content) > MAX_FILE_SIZE:
                    await self.send_json({"type": "error", "message": "File too large (max 50MB)"})
                    return

                # Validate file type (extension + magic bytes)
                is_valid, error_msg = validate_file_type(filename, file_content)
                if not is_valid:
                    logger.warning(f"File validation failed for user {self.user.id}: {error_msg}")
                    await self.send_json({"type": "error", "message": error_msg})
                    return

                django_file = ContentFile(file_content, name=filename)
            except Exception as e:
                logger.error(f"File processing error: {e}")
                await self.send_json({"type": "error", "message": "Invalid file data"})
                return

        # Save message to DB
        message = await database_sync_to_async(self.create_message)(content, django_file, is_voice)

        # Prepare message payload
        msg_payload = {
            "type": "message",
            "id": message.id,
            "sender": str(self.user.username),
            "content": message.content,
            "timestamp": message.timestamp.isoformat(),
            "file": message.file.url if message.file else (message.voice_message.url if message.is_voice else ""),
            "is_voice": message.is_voice,
            "is_read": False,
            "conversation_id": self.conversation_id,
        }

        # Broadcast message to group
        await self.channel_layer.group_send(
            self.room_group_name,
            {"type": "chat_message", "message": msg_payload},
        )

    def create_message(self, content, django_file, is_voice):
        conversation = Conversation.objects.get(id=self.conversation_id)
        message = Message.objects.create(
            conversation=conversation,
            sender=self.user,
            content=content,
            is_voice=is_voice,
        )
        if django_file:
            if is_voice:
                message.voice_message.save(django_file.name, django_file)
            else:
                message.file.save(django_file.name, django_file)
            message.save()
        return message

    async def handle_add_contact(self, data):
        email = data.get("email")
        name = data.get("name")
        invitation_message = data.get("invitation_message", "")

        if not email or not name:
            await self.send_json({"type": "error", "message": "Missing fields in add contact"})
            return

        try:
            new_contact_user = await database_sync_to_async(User.objects.get)(email=email)
        except User.DoesNotExist:
            await self.send_json({"type": "error", "message": "User not found"})
            return

        # Add contact relation
        await database_sync_to_async(Contact.objects.get_or_create)(
            owner=self.user,
            contact=new_contact_user,
        )
        # Create friend request
        await database_sync_to_async(FriendRequest.objects.get_or_create)(
            sender=self.user,
            receiver=new_contact_user,
            message=invitation_message,
        )

        # Notify user
        await self.send_json({"type": "contact_added", "contact": {"username": new_contact_user.username}})

        # Broadcast update if needed (eg. to new contact if online)
        # This is optional depending on use case

    async def handle_create_group(self, data):
        """
        Create a group conversation (not a separate Group model).
        Uses the Conversation model with multiple participants.
        """
        group_name = data.get("group_name")
        members = data.get("members", [])

        if not group_name:
            await self.send_json({"type": "error", "message": "Group name required"})
            return

        if not members:
            await self.send_json({"type": "error", "message": "At least one member required"})
            return

        # Create group conversation in DB
        conversation = await database_sync_to_async(self.create_group_conversation)(group_name, members)

        # Notify creator via websocket
        await self.send_json({
            "type": "group_created",
            "group": {
                "name": conversation.name,
                "id": str(conversation.id),
                "participant_count": len(members) + 1
            }
        })

    def create_group_conversation(self, group_name, members):
        """Create a group conversation using the Conversation model."""
        # Check for blocked users
        for member_id in members:
            try:
                member = User.objects.get(id=member_id)
                if BlockList.objects.is_blocked_by(self.user, member):
                    raise ValueError(f"Cannot add blocked user to group")
            except User.DoesNotExist:
                continue

        # Create conversation
        conversation = Conversation.objects.create(name=group_name)
        conversation.participants.add(self.user)

        # Add valid members
        valid_members = User.objects.filter(id__in=members)
        conversation.participants.add(*valid_members)

        return conversation

    async def handle_typing(self, data):
        is_typing = data.get("is_typing", False)
        # Broadcast typing indicator to group
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                "type": "typing_status",
                "typing_user": str(self.user.username),
                "is_typing": is_typing,
            },
        )

    async def handle_read_receipt(self, data):
        message_id = data.get("message_id")
        try:
            message = await database_sync_to_async(Message.objects.get)(id=message_id)
        except Message.DoesNotExist:
            return
        # Record read receipt
        await database_sync_to_async(MessageStatus.objects.get_or_create)(
            user=self.user,
            message=message,
            defaults={"read_at": timezone.now()},
        )
        # Broadcast read receipt to group
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                "type": "message_read",
                "message_id": message_id,
                "user": str(self.user.username),
            },
        )

    # Handlers for group_send message types

    async def chat_message(self, event):
        await self.send_json(event["message"])

    async def typing_status(self, event):
        await self.send_json(
            {
                "type": "typing",
                "typing_user": event["typing_user"],
                "is_typing": event["is_typing"],
            }
        )

    async def message_read(self, event):
        await self.send_json(
            {
                "type": "read",
                "message_id": event["message_id"],
                "user": event["user"],
            }
        )

    async def send_json(self, content):
        await self.send(text_data=json.dumps(content))
