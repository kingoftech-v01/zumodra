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
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.core.files.base import ContentFile
from django.utils import timezone
from .models import Message, Conversation, Contact, Group, FriendRequest, User, MessageStatus

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB max upload size

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope['user']
        self.conversation_id = self.scope['url_route']['kwargs']['conversation_id']
        self.room_group_name = f"chat_{self.conversation_id}"

        # Add user to group
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        await self.accept()

        # Optionally send back connect confirmation
        await self.send_json({"type": "status", "message": "Connected", "is_online": True})

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

        if content == "" and not file_data:
            await self.send_json({"type": "error", "message": "Empty message"})
            return

        # Save file if exists
        django_file = None
        if file_data:
            try:
                file_content = base64.b64decode(file_data["content"])
                if len(file_content) > MAX_FILE_SIZE:
                    await self.send_json({"type": "error", "message": "File too large"})
                    return
                django_file = ContentFile(file_content, name=file_data.get("name", "file"))
            except Exception:
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
        group_name = data.get("group_name")
        group_description = data.get("group_description", "")
        members = data.get("members", [])

        if not group_name:
            await self.send_json({"type": "error", "message": "Group name required"})
            return

        # Create group in DB
        group = await database_sync_to_async(self.create_group)(group_name, group_description, members)

        # Notify creator via websocket
        await self.send_json({"type": "group_created", "group": {"name": group.name, "id": group.id}})

        # Optionally broadcast to group members (requires handling user channels)

    def create_group(self, group_name, group_description, members):
        group = Group.objects.create(name=group_name, description=group_description, owner=self.user)
        users = User.objects.filter(id__in=members)
        group.members.add(*users)
        group.save()
        return group

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
