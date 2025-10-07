from django.contrib import admin
from django.utils.html import format_html
from .models import (
    Conversation,
    Message,
    MessageStatus,
    TypingStatus,
    Contact,
    FriendRequest,
    BlockList,
    UserStatus,
)


@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'participant_count', 'created_at', 'updated_at', 'is_group')
    search_fields = ('name',)
    ordering = ('-updated_at',)
    filter_horizontal = ('participants',)

    def participant_count(self, obj):
        return obj.participants.count()
    participant_count.short_description = 'Participants'


class MessageStatusInline(admin.TabularInline):
    model = MessageStatus
    extra = 0
    readonly_fields = ('user', 'read_at')


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'short_content', 'sender', 'conversation', 'timestamp', 'file_link', 'voice_message_link', 'is_voice', 'is_read')
    list_filter = ('is_read', 'is_voice', 'timestamp')
    search_fields = ('content', 'sender__username', 'conversation__name')
    readonly_fields = ('timestamp',)
    inlines = [MessageStatusInline]

    fieldsets = (
        (None, {
            'fields': ('conversation', 'sender', 'content', 'is_voice', 'is_read')
        }),
        ('Attachments', {
            'fields': ('file', 'file_preview', 'voice_message', 'voice_message_preview'),
            'classes': ('collapse',),
        }),
        ('Meta Data', {
            'fields': ('timestamp',),
            'classes': ('collapse',),
        }),
    )

    def short_content(self, obj):
        return (obj.content[:50] + '...') if obj.content and len(obj.content) > 50 else obj.content
    short_content.short_description = 'Content'

    def file_link(self, obj):
        if obj.file:
            return format_html('<a href="{}" target="_blank">Download</a>', obj.file.url)
        return "-"
    file_link.short_description = 'File'

    def voice_message_link(self, obj):
        if obj.voice_message:
            return format_html('<audio controls src="{}"></audio>', obj.voice_message.url)
        return "-"
    voice_message_link.short_description = 'Voice Message'


@admin.register(MessageStatus)
class MessageStatusAdmin(admin.ModelAdmin):
    list_display = ('user', 'message', 'read_at')
    list_filter = ('read_at',)
    search_fields = ('user__username', 'message__content')


@admin.register(TypingStatus)
class TypingStatusAdmin(admin.ModelAdmin):
    list_display = ('user', 'conversation', 'is_typing', 'updated_at')
    list_filter = ('is_typing',)


@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ('owner', 'contact', 'is_favorite', 'created_at')
    list_filter = ('is_favorite', 'created_at')
    search_fields = ('owner__username', 'contact__username')


@admin.register(FriendRequest)
class FriendRequestAdmin(admin.ModelAdmin):
    list_display = ('sender', 'receiver', 'status', 'created_at')
    list_filter = ('accepted', 'rejected', 'created_at')
    search_fields = ('sender__username', 'receiver__username')

    def status(self, obj):
        if obj.accepted:
            return 'Accepted'
        elif obj.rejected:
            return 'Rejected'
        return 'Pending'
    status.short_description = 'Status'


@admin.register(BlockList)
class BlockListAdmin(admin.ModelAdmin):
    list_display = ('blocker', 'blocked', 'created_at')
    search_fields = ('blocker__username', 'blocked__username')
    list_filter = ('created_at',)


@admin.register(UserStatus)
class UserStatusAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_online', 'last_seen')
    list_filter = ('is_online',)
    search_fields = ('user__username',)
