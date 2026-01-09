"""
Security App Serializers.

Provides serializers for:
- Audit logs
- Security events
- Failed login attempts
- User sessions
"""

from rest_framework import serializers

from .models import (
    AuditLogEntry,
    SecurityEvent,
    FailedLoginAttempt,
    UserSession,
    PasswordResetRequest,
)


# =============================================================================
# AUDIT LOG SERIALIZERS
# =============================================================================

class AuditLogListSerializer(serializers.ModelSerializer):
    """List serializer for audit logs."""
    actor_email = serializers.CharField(source='actor.email', read_only=True)
    actor_name = serializers.SerializerMethodField()
    action_display = serializers.CharField(source='get_action_display', read_only=True)

    class Meta:
        model = AuditLogEntry
        fields = [
            'id', 'actor', 'actor_email', 'actor_name', 'action', 'action_display',
            'model_name', 'object_id', 'object_repr', 'timestamp', 'ip_address'
        ]

    def get_actor_name(self, obj):
        return obj.actor.get_full_name() if obj.actor else 'System'


class AuditLogDetailSerializer(serializers.ModelSerializer):
    """Detail serializer for audit logs."""
    actor_email = serializers.CharField(source='actor.email', read_only=True)
    actor_name = serializers.SerializerMethodField()
    action_display = serializers.CharField(source='get_action_display', read_only=True)

    class Meta:
        model = AuditLogEntry
        fields = [
            'id', 'actor', 'actor_email', 'actor_name', 'action', 'action_display',
            'model_name', 'object_id', 'object_repr', 'timestamp', 'change_message', 'ip_address'
        ]

    def get_actor_name(self, obj):
        return obj.actor.get_full_name() if obj.actor else 'System'


# =============================================================================
# SECURITY EVENT SERIALIZERS
# =============================================================================

class SecurityEventListSerializer(serializers.ModelSerializer):
    """List serializer for security events."""
    user_email = serializers.CharField(source='user.email', read_only=True)
    event_type_display = serializers.CharField(source='get_event_type_display', read_only=True)

    class Meta:
        model = SecurityEvent
        fields = [
            'id', 'user', 'user_email', 'event_type', 'event_type_display',
            'timestamp', 'ip_address'
        ]


class SecurityEventDetailSerializer(serializers.ModelSerializer):
    """Detail serializer for security events."""
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.SerializerMethodField()
    event_type_display = serializers.CharField(source='get_event_type_display', read_only=True)

    class Meta:
        model = SecurityEvent
        fields = [
            'id', 'user', 'user_email', 'user_name', 'event_type', 'event_type_display',
            'timestamp', 'ip_address', 'user_agent', 'description'
        ]

    def get_user_name(self, obj):
        return obj.user.get_full_name() if obj.user else None


# =============================================================================
# FAILED LOGIN SERIALIZERS
# =============================================================================

class FailedLoginAttemptListSerializer(serializers.ModelSerializer):
    """List serializer for failed login attempts."""
    user_email = serializers.CharField(source='user.email', read_only=True)

    class Meta:
        model = FailedLoginAttempt
        fields = [
            'id', 'user', 'user_email', 'username_entered', 'ip_address', 'attempted_at'
        ]


class FailedLoginAttemptDetailSerializer(serializers.ModelSerializer):
    """Detail serializer for failed login attempts."""
    user_email = serializers.CharField(source='user.email', read_only=True)

    class Meta:
        model = FailedLoginAttempt
        fields = [
            'id', 'user', 'user_email', 'username_entered', 'ip_address',
            'attempted_at', 'user_agent'
        ]


# =============================================================================
# USER SESSION SERIALIZERS
# =============================================================================

class UserSessionListSerializer(serializers.ModelSerializer):
    """List serializer for user sessions."""
    user_email = serializers.CharField(source='user.email', read_only=True)

    class Meta:
        model = UserSession
        fields = [
            'id', 'user', 'user_email', 'ip_address', 'login_time',
            'last_activity', 'is_active'
        ]


class UserSessionDetailSerializer(serializers.ModelSerializer):
    """Detail serializer for user sessions."""
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.SerializerMethodField()

    class Meta:
        model = UserSession
        fields = [
            'id', 'user', 'user_email', 'user_name', 'session_key', 'ip_address',
            'user_agent', 'login_time', 'last_activity', 'is_active'
        ]

    def get_user_name(self, obj):
        return obj.user.get_full_name() if obj.user else None


# =============================================================================
# PASSWORD RESET REQUEST SERIALIZERS
# =============================================================================

class PasswordResetRequestSerializer(serializers.ModelSerializer):
    """Serializer for password reset requests."""
    user_email = serializers.CharField(source='user.email', read_only=True)

    class Meta:
        model = PasswordResetRequest
        fields = [
            'id', 'user', 'user_email', 'requested_at', 'ip_address', 'used'
        ]
        # Don't expose token in API


# =============================================================================
# ANALYTICS SERIALIZERS
# =============================================================================

class SecurityAnalyticsSerializer(serializers.Serializer):
    """Serializer for security analytics summary."""
    total_audit_logs = serializers.IntegerField()
    audit_logs_today = serializers.IntegerField()
    total_security_events = serializers.IntegerField()
    security_events_today = serializers.IntegerField()
    failed_logins_today = serializers.IntegerField()
    active_sessions = serializers.IntegerField()
    pending_password_resets = serializers.IntegerField()
    account_lockouts_today = serializers.IntegerField()


class AuditLogByActionSerializer(serializers.Serializer):
    """Serializer for audit logs grouped by action."""
    action = serializers.CharField()
    count = serializers.IntegerField()


class AuditLogByModelSerializer(serializers.Serializer):
    """Serializer for audit logs grouped by model."""
    model_name = serializers.CharField()
    count = serializers.IntegerField()


class FailedLoginsByIPSerializer(serializers.Serializer):
    """Serializer for failed logins grouped by IP."""
    ip_address = serializers.IPAddressField()
    count = serializers.IntegerField()
