"""
ATS Automation - HR Automation Rules Engine

This module implements intelligent automation for ATS processes:
- AutoRejectRule: Auto-reject stale applications after configurable days
- AutoAdvanceRule: Automatically advance candidates when criteria are met
- NotificationRule: Trigger notifications to stakeholders at key events
- FollowUpRule: Schedule and manage follow-up reminders

The automation engine follows HR best practices:
- Configurable rules per job/pipeline
- Audit trail for all automated actions
- Override capabilities for manual intervention
- Integration with notification and email systems
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Any, Union
from datetime import datetime, timedelta
from enum import Enum
from abc import ABC, abstractmethod
import logging

from django.utils import timezone
from django.db import transaction
from django.conf import settings
from django.contrib.contenttypes.models import ContentType

logger = logging.getLogger(__name__)


# ==================== RULE CONDITIONS ====================

class ConditionOperator(Enum):
    """Operators for rule conditions."""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    GREATER_EQUAL = "greater_equal"
    LESS_EQUAL = "less_equal"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    IN = "in"
    NOT_IN = "not_in"
    IS_NULL = "is_null"
    IS_NOT_NULL = "is_not_null"
    DAYS_AGO_MORE_THAN = "days_ago_more_than"
    DAYS_AGO_LESS_THAN = "days_ago_less_than"


@dataclass
class RuleCondition:
    """
    Defines a condition that must be met for a rule to trigger.

    Examples:
        - status == "new"
        - days_in_stage > 7
        - ai_match_score >= 80
        - current_stage in ["screening", "in_review"]
    """

    field: str
    operator: ConditionOperator
    value: Any
    description: str = ""

    def evaluate(self, entity: Any) -> bool:
        """Evaluate the condition against an entity."""
        try:
            # Get the field value, supporting nested fields with dot notation
            actual_value = self._get_field_value(entity, self.field)

            # Handle date/datetime comparisons for days_ago operators
            if self.operator == ConditionOperator.DAYS_AGO_MORE_THAN:
                if actual_value is None:
                    return False
                days_ago = (timezone.now() - actual_value).days
                return days_ago > self.value

            if self.operator == ConditionOperator.DAYS_AGO_LESS_THAN:
                if actual_value is None:
                    return False
                days_ago = (timezone.now() - actual_value).days
                return days_ago < self.value

            # Standard operators
            if self.operator == ConditionOperator.EQUALS:
                return actual_value == self.value
            elif self.operator == ConditionOperator.NOT_EQUALS:
                return actual_value != self.value
            elif self.operator == ConditionOperator.GREATER_THAN:
                return actual_value > self.value
            elif self.operator == ConditionOperator.LESS_THAN:
                return actual_value < self.value
            elif self.operator == ConditionOperator.GREATER_EQUAL:
                return actual_value >= self.value
            elif self.operator == ConditionOperator.LESS_EQUAL:
                return actual_value <= self.value
            elif self.operator == ConditionOperator.CONTAINS:
                return self.value in actual_value
            elif self.operator == ConditionOperator.NOT_CONTAINS:
                return self.value not in actual_value
            elif self.operator == ConditionOperator.IN:
                return actual_value in self.value
            elif self.operator == ConditionOperator.NOT_IN:
                return actual_value not in self.value
            elif self.operator == ConditionOperator.IS_NULL:
                return actual_value is None
            elif self.operator == ConditionOperator.IS_NOT_NULL:
                return actual_value is not None

        except Exception as e:
            logger.warning(f"Condition evaluation error: {e}")
            return False

        return False

    def _get_field_value(self, entity: Any, field_path: str) -> Any:
        """Get a field value supporting dot notation for nested fields."""
        parts = field_path.split('.')
        value = entity

        for part in parts:
            if hasattr(value, part):
                value = getattr(value, part)
            elif isinstance(value, dict):
                value = value.get(part)
            else:
                return None

        return value


# ==================== BASE RULE CLASS ====================

class AutomationRule(ABC):
    """
    Abstract base class for all automation rules.

    Each rule defines:
    - When to trigger (conditions)
    - What action to take
    - How to log/audit the action
    """

    def __init__(
        self,
        name: str,
        description: str = "",
        is_active: bool = True,
        priority: int = 100,
        conditions: List[RuleCondition] = None,
        cooldown_hours: int = 0,
        max_executions: int = 0,
        job_ids: List[int] = None,
        pipeline_ids: List[int] = None,
    ):
        self.name = name
        self.description = description
        self.is_active = is_active
        self.priority = priority
        self.conditions = conditions or []
        self.cooldown_hours = cooldown_hours
        self.max_executions = max_executions
        self.job_ids = job_ids  # Limit to specific jobs
        self.pipeline_ids = pipeline_ids  # Limit to specific pipelines
        self._execution_count: Dict[int, int] = {}
        self._last_execution: Dict[int, datetime] = {}

    def should_trigger(self, entity: Any) -> bool:
        """
        Check if the rule should trigger for the given entity.

        Returns True if all conditions are met.
        """
        if not self.is_active:
            return False

        # Check job/pipeline restrictions
        if self.job_ids and hasattr(entity, 'job_id'):
            if entity.job_id not in self.job_ids:
                return False

        if self.pipeline_ids and hasattr(entity, 'job'):
            if entity.job.pipeline_id not in self.pipeline_ids:
                return False

        # Check cooldown
        entity_id = getattr(entity, 'id', id(entity))
        if self.cooldown_hours > 0:
            last_exec = self._last_execution.get(entity_id)
            if last_exec:
                hours_since = (timezone.now() - last_exec).total_seconds() / 3600
                if hours_since < self.cooldown_hours:
                    return False

        # Check max executions
        if self.max_executions > 0:
            exec_count = self._execution_count.get(entity_id, 0)
            if exec_count >= self.max_executions:
                return False

        # Evaluate all conditions
        return all(condition.evaluate(entity) for condition in self.conditions)

    @abstractmethod
    def execute(self, entity: Any, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute the rule action on the entity.

        Args:
            entity: The entity to act upon
            context: Additional context for the action

        Returns:
            Dict with execution result details
        """
        pass

    def run(self, entity: Any, context: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Check conditions and execute if triggered.

        Returns execution result or None if not triggered.
        """
        if not self.should_trigger(entity):
            return None

        context = context or {}
        context['rule_name'] = self.name
        context['triggered_at'] = timezone.now()

        try:
            result = self.execute(entity, context)

            # Update execution tracking
            entity_id = getattr(entity, 'id', id(entity))
            self._last_execution[entity_id] = timezone.now()
            self._execution_count[entity_id] = self._execution_count.get(entity_id, 0) + 1

            result['success'] = True
            return result

        except Exception as e:
            logger.error(f"Rule execution error ({self.name}): {e}")
            return {
                'success': False,
                'error': str(e),
                'rule_name': self.name
            }


# ==================== AUTO-REJECT RULE ====================

class AutoRejectRule(AutomationRule):
    """
    Automatically reject applications that have been in a stage too long.

    HR Best Practice: Candidates should receive timely responses.
    This rule ensures applications don't languish without feedback.

    Configuration:
    - days_threshold: Days before auto-rejection
    - target_stages: Which stages to monitor
    - rejection_reason: Standard rejection reason
    - send_notification: Whether to email the candidate
    - require_email_consent: Check candidate email consent before sending (GDPR/CCPA)
    """

    def __init__(
        self,
        name: str = "Auto-Reject Stale Applications",
        days_threshold: int = 30,
        target_stages: List[str] = None,
        rejection_reason: str = "Position filled or no longer available",
        rejection_feedback: str = "",
        send_notification: bool = True,
        exclude_shortlisted: bool = True,
        require_email_consent: bool = True,
        **kwargs
    ):
        # Set up condition for days in stage
        conditions = kwargs.pop('conditions', [])
        conditions.append(RuleCondition(
            field="last_stage_change_at",
            operator=ConditionOperator.DAYS_AGO_MORE_THAN,
            value=days_threshold,
            description=f"Application in stage for more than {days_threshold} days"
        ))

        if target_stages:
            conditions.append(RuleCondition(
                field="status",
                operator=ConditionOperator.IN,
                value=target_stages,
                description=f"Application in one of: {target_stages}"
            ))

        if exclude_shortlisted:
            conditions.append(RuleCondition(
                field="status",
                operator=ConditionOperator.NOT_IN,
                value=['shortlisted', 'interviewing', 'offer_pending', 'offer_extended'],
                description="Not in advanced stages"
            ))

        super().__init__(
            name=name,
            conditions=conditions,
            **kwargs
        )

        self.days_threshold = days_threshold
        self.target_stages = target_stages
        self.rejection_reason = rejection_reason
        self.rejection_feedback = rejection_feedback
        self.send_notification = send_notification
        self.require_email_consent = require_email_consent

    def _check_candidate_consent(self, candidate) -> Dict[str, bool]:
        """
        Check candidate consent status for GDPR/CCPA compliance.

        Returns dict with consent flags for different purposes.
        """
        return {
            'consent_to_store': getattr(candidate, 'consent_to_store', True),
            'consent_to_email': getattr(candidate, 'consent_to_email', True),
            'consent_to_process': getattr(candidate, 'consent_to_process', True),
        }

    def execute(self, application, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute auto-rejection on the application."""
        from .models import Application, ApplicationActivity

        old_status = application.status
        candidate = application.candidate

        # Check candidate consent before processing
        consent = self._check_candidate_consent(candidate)

        # Check if candidate has consented to data storage/processing
        if not consent.get('consent_to_store', True):
            logger.warning(
                f"AutoRejectRule skipped for application {application.id}: "
                f"Candidate {candidate.id} has not consented to data storage"
            )
            return {
                'action': 'auto_reject_skipped',
                'application_id': application.id,
                'reason': 'no_consent_to_store',
                'notification_sent': False
            }

        # Determine if notification should be sent based on consent
        should_send_notification = self.send_notification
        if self.require_email_consent and not consent.get('consent_to_email', True):
            should_send_notification = False
            logger.info(
                f"AutoRejectRule: Email notification disabled for application {application.id} "
                f"due to lack of email consent from candidate {candidate.id}"
            )

        with transaction.atomic():
            # Update application status
            application.status = Application.ApplicationStatus.REJECTED
            application.rejection_reason = self.rejection_reason
            application.rejection_feedback = self.rejection_feedback
            application.rejected_at = timezone.now()
            application.send_rejection_email = should_send_notification
            application.save()

            # Log activity
            ApplicationActivity.objects.create(
                application=application,
                activity_type=ApplicationActivity.ActivityType.STATUS_CHANGE,
                old_value=old_status,
                new_value=Application.ApplicationStatus.REJECTED,
                notes=f"Auto-rejected: {self.rejection_reason}",
                metadata={
                    'automation_rule': self.name,
                    'days_in_stage': (timezone.now() - application.last_stage_change_at).days
                    if application.last_stage_change_at else None
                }
            )

        return {
            'action': 'auto_reject',
            'application_id': application.id,
            'candidate_name': application.candidate.full_name,
            'old_status': old_status,
            'rejection_reason': self.rejection_reason,
            'notification_sent': should_send_notification,
            'consent_status': consent
        }


# ==================== AUTO-ADVANCE RULE ====================

class AutoAdvanceRule(AutomationRule):
    """
    Automatically advance candidates when they meet criteria.

    HR Best Practice: Streamline the hiring process by auto-advancing
    highly qualified candidates through certain stages.

    Configuration:
    - from_stage: Current stage to watch
    - to_stage: Stage to advance to
    - score_threshold: Minimum AI match score
    - rating_threshold: Minimum overall rating
    - required_feedback: Number of positive feedback required
    """

    def __init__(
        self,
        name: str = "Auto-Advance Qualified Candidates",
        from_stage: str = "screening",
        to_stage: str = "in_review",
        score_threshold: float = 85.0,
        rating_threshold: float = None,
        required_feedback_count: int = 0,
        required_feedback_sentiment: str = "positive",
        **kwargs
    ):
        conditions = kwargs.pop('conditions', [])

        # Stage condition
        conditions.append(RuleCondition(
            field="status",
            operator=ConditionOperator.EQUALS,
            value=from_stage,
            description=f"Application is in '{from_stage}' stage"
        ))

        # Score threshold condition
        if score_threshold:
            conditions.append(RuleCondition(
                field="ai_match_score",
                operator=ConditionOperator.GREATER_EQUAL,
                value=score_threshold,
                description=f"AI match score >= {score_threshold}"
            ))

        # Rating threshold condition
        if rating_threshold:
            conditions.append(RuleCondition(
                field="overall_rating",
                operator=ConditionOperator.GREATER_EQUAL,
                value=rating_threshold,
                description=f"Overall rating >= {rating_threshold}"
            ))

        super().__init__(
            name=name,
            conditions=conditions,
            **kwargs
        )

        self.from_stage = from_stage
        self.to_stage = to_stage
        self.score_threshold = score_threshold
        self.rating_threshold = rating_threshold
        self.required_feedback_count = required_feedback_count
        self.required_feedback_sentiment = required_feedback_sentiment

    def execute(self, application, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute auto-advance on the application."""
        from .models import Application, ApplicationActivity, PipelineStage

        old_status = application.status

        with transaction.atomic():
            # Find the target stage
            target_stage = None
            if application.job.pipeline:
                target_stage = PipelineStage.objects.filter(
                    pipeline=application.job.pipeline,
                    stage_type=self.to_stage
                ).first()

            # Update application
            application.status = self.to_stage
            if target_stage:
                application.current_stage = target_stage
            application.last_stage_change_at = timezone.now()
            application.save()

            # Log activity
            ApplicationActivity.objects.create(
                application=application,
                activity_type=ApplicationActivity.ActivityType.STAGE_CHANGE,
                old_value=old_status,
                new_value=self.to_stage,
                notes=f"Auto-advanced due to high score ({application.ai_match_score})",
                metadata={
                    'automation_rule': self.name,
                    'ai_match_score': float(application.ai_match_score) if application.ai_match_score else None,
                    'overall_rating': float(application.overall_rating) if application.overall_rating else None
                }
            )

        return {
            'action': 'auto_advance',
            'application_id': application.id,
            'candidate_name': application.candidate.full_name,
            'from_stage': old_status,
            'to_stage': self.to_stage,
            'trigger_score': application.ai_match_score
        }


# ==================== NOTIFICATION RULE ====================

class NotificationEventType(Enum):
    """Types of events that can trigger notifications."""
    APPLICATION_RECEIVED = "application_received"
    APPLICATION_ADVANCED = "application_advanced"
    APPLICATION_REJECTED = "application_rejected"
    INTERVIEW_SCHEDULED = "interview_scheduled"
    INTERVIEW_REMINDER = "interview_reminder"
    INTERVIEW_FEEDBACK_DUE = "interview_feedback_due"
    OFFER_PENDING_APPROVAL = "offer_pending_approval"
    OFFER_ACCEPTED = "offer_accepted"
    OFFER_DECLINED = "offer_declined"
    CANDIDATE_WITHDRAWN = "candidate_withdrawn"
    STAGE_TIMEOUT_WARNING = "stage_timeout_warning"
    HIGH_SCORE_CANDIDATE = "high_score_candidate"


class NotificationChannel(Enum):
    """Channels for sending notifications."""
    EMAIL = "email"
    IN_APP = "in_app"
    SLACK = "slack"
    WEBHOOK = "webhook"
    SMS = "sms"


@dataclass
class NotificationRecipient:
    """Defines who receives a notification."""
    type: str  # 'user', 'role', 'email', 'hiring_manager', 'recruiter', 'candidate'
    value: Optional[str] = None  # User ID, role name, or email address

    def resolve_recipients(self, entity: Any) -> List[Dict[str, Any]]:
        """Resolve actual recipients from the entity context."""
        recipients = []

        if self.type == 'hiring_manager' and hasattr(entity, 'job'):
            if entity.job.hiring_manager:
                recipients.append({
                    'user_id': entity.job.hiring_manager.id,
                    'email': entity.job.hiring_manager.email,
                    'name': entity.job.hiring_manager.get_full_name()
                })

        elif self.type == 'recruiter' and hasattr(entity, 'job'):
            if entity.job.recruiter:
                recipients.append({
                    'user_id': entity.job.recruiter.id,
                    'email': entity.job.recruiter.email,
                    'name': entity.job.recruiter.get_full_name()
                })

        elif self.type == 'candidate' and hasattr(entity, 'candidate'):
            recipients.append({
                'email': entity.candidate.email,
                'name': entity.candidate.full_name
            })

        elif self.type == 'assigned_to' and hasattr(entity, 'assigned_to'):
            if entity.assigned_to:
                recipients.append({
                    'user_id': entity.assigned_to.id,
                    'email': entity.assigned_to.email,
                    'name': entity.assigned_to.get_full_name()
                })

        elif self.type == 'email' and self.value:
            recipients.append({
                'email': self.value,
                'name': 'External Recipient'
            })

        elif self.type == 'user' and self.value:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            try:
                user = User.objects.get(id=self.value)
                recipients.append({
                    'user_id': user.id,
                    'email': user.email,
                    'name': user.get_full_name()
                })
            except User.DoesNotExist:
                pass

        return recipients


class NotificationRule(AutomationRule):
    """
    Send notifications to stakeholders at key events.

    HR Best Practice: Keep all stakeholders informed throughout
    the hiring process with timely, relevant notifications.

    Configuration:
    - event_type: Type of event that triggers notification
    - recipients: Who should receive the notification
    - channels: How to send (email, in-app, etc.)
    - template: Notification template to use
    - urgency: Priority level of notification
    - require_candidate_consent: Check consent before notifying candidates (GDPR/CCPA)
    """

    def __init__(
        self,
        name: str = "Notification Rule",
        event_type: NotificationEventType = None,
        recipients: List[NotificationRecipient] = None,
        channels: List[NotificationChannel] = None,
        template_id: str = "",
        subject_template: str = "",
        body_template: str = "",
        urgency: str = "normal",  # low, normal, high, urgent
        require_candidate_consent: bool = True,
        **kwargs
    ):
        super().__init__(name=name, **kwargs)

        self.event_type = event_type
        self.recipients = recipients or []
        self.channels = channels or [NotificationChannel.EMAIL, NotificationChannel.IN_APP]
        self.template_id = template_id
        self.subject_template = subject_template
        self.body_template = body_template
        self.urgency = urgency
        self.require_candidate_consent = require_candidate_consent

    def _check_candidate_consent(self, candidate, channel: NotificationChannel) -> bool:
        """
        Check if candidate has consented to receive notifications via the specified channel.

        Args:
            candidate: Candidate model instance
            channel: The notification channel to check consent for

        Returns:
            True if consent is granted or not required, False otherwise
        """
        if not self.require_candidate_consent:
            return True

        # Check general storage consent first
        if not getattr(candidate, 'consent_to_store', True):
            return False

        # Check channel-specific consent
        if channel == NotificationChannel.EMAIL:
            return getattr(candidate, 'consent_to_email', True)
        elif channel == NotificationChannel.SMS:
            return getattr(candidate, 'consent_to_sms', True)
        elif channel == NotificationChannel.IN_APP:
            # In-app notifications typically don't require separate consent
            return True

        # Default to consent for internal channels (Slack, webhook)
        return True

    def execute(self, entity: Any, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute notification sending."""
        context = context or {}
        sent_count = 0
        skipped_count = 0
        recipients_notified = []
        skipped_recipients = []

        # Resolve all recipients
        for recipient_def in self.recipients:
            resolved = recipient_def.resolve_recipients(entity)
            recipients_notified.extend(resolved)

        # Prepare notification data
        notification_data = self._prepare_notification(entity, context)

        # Get candidate for consent checks (if applicable)
        candidate = None
        if hasattr(entity, 'candidate'):
            candidate = entity.candidate

        # Send through each channel
        for channel in self.channels:
            for recipient in recipients_notified:
                try:
                    # Check if this is a candidate recipient and verify consent
                    is_candidate_recipient = (
                        candidate is not None and
                        recipient.get('email') == getattr(candidate, 'email', None)
                    )

                    if is_candidate_recipient and not self._check_candidate_consent(candidate, channel):
                        logger.info(
                            f"NotificationRule: Skipping {channel.value} notification to candidate "
                            f"{candidate.id} - no consent for this channel"
                        )
                        skipped_count += 1
                        skipped_recipients.append({
                            **recipient,
                            'channel': channel.value,
                            'reason': 'no_consent'
                        })
                        continue

                    if channel == NotificationChannel.EMAIL:
                        self._send_email(recipient, notification_data)
                        sent_count += 1
                    elif channel == NotificationChannel.IN_APP:
                        self._create_in_app_notification(recipient, notification_data)
                        sent_count += 1
                    elif channel == NotificationChannel.SLACK:
                        self._send_slack_notification(recipient, notification_data)
                        sent_count += 1
                except Exception as e:
                    logger.error(f"Notification send error: {e}")

        return {
            'action': 'send_notification',
            'event_type': self.event_type.value if self.event_type else 'custom',
            'recipients_count': len(recipients_notified),
            'sent_count': sent_count,
            'skipped_count': skipped_count,
            'skipped_recipients': skipped_recipients,
            'channels': [c.value for c in self.channels],
            'recipients': recipients_notified
        }

    def _prepare_notification(self, entity: Any, context: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare notification content from templates."""
        # Build context for template rendering
        template_context = {
            **context,
            'entity': entity,
            'timestamp': timezone.now(),
        }

        if hasattr(entity, 'candidate'):
            template_context['candidate'] = entity.candidate
        if hasattr(entity, 'job'):
            template_context['job'] = entity.job

        # For now, return raw templates - in production, use Django template engine
        return {
            'subject': self.subject_template,
            'body': self.body_template,
            'template_id': self.template_id,
            'context': template_context,
            'urgency': self.urgency
        }

    def _send_email(self, recipient: Dict, notification_data: Dict) -> None:
        """Send email notification."""
        # Integration point for email sending
        # In production, use Django's email or a service like SendGrid
        logger.info(f"Email notification to {recipient.get('email')}: {notification_data['subject']}")

    def _create_in_app_notification(self, recipient: Dict, notification_data: Dict) -> None:
        """Create in-app notification."""
        # Integration point for in-app notifications
        # Could create a Notification model instance
        logger.info(f"In-app notification to user {recipient.get('user_id')}")

    def _send_slack_notification(self, recipient: Dict, notification_data: Dict) -> None:
        """Send Slack notification."""
        # Integration point for Slack
        logger.info(f"Slack notification sent")


# ==================== FOLLOW-UP RULE ====================

class FollowUpType(Enum):
    """Types of follow-up actions."""
    CANDIDATE_FOLLOW_UP = "candidate_follow_up"
    INTERVIEWER_REMINDER = "interviewer_reminder"
    FEEDBACK_REMINDER = "feedback_reminder"
    OFFER_FOLLOW_UP = "offer_follow_up"
    REFERENCE_REQUEST = "reference_request"
    DOCUMENT_REQUEST = "document_request"
    STAGE_CHECK_IN = "stage_check_in"


@dataclass
class ScheduledFollowUp:
    """Represents a scheduled follow-up task."""
    id: str
    follow_up_type: FollowUpType
    entity_type: str
    entity_id: int
    scheduled_at: datetime
    message: str
    assigned_to_id: Optional[int] = None
    completed: bool = False
    completed_at: Optional[datetime] = None
    result: Optional[str] = None


class FollowUpRule(AutomationRule):
    """
    Schedule and manage follow-up reminders.

    HR Best Practice: Consistent follow-up ensures candidates
    have a positive experience and processes don't stall.

    Configuration:
    - follow_up_type: Type of follow-up
    - delay_hours: Hours after trigger to schedule follow-up
    - message_template: Template for the follow-up message
    - assign_to: Who should handle the follow-up
    - auto_escalate: Escalate if not completed
    """

    def __init__(
        self,
        name: str = "Follow-Up Rule",
        follow_up_type: FollowUpType = FollowUpType.CANDIDATE_FOLLOW_UP,
        delay_hours: int = 24,
        message_template: str = "",
        assign_to: str = "recruiter",  # recruiter, hiring_manager, assigned_to
        auto_escalate: bool = False,
        escalation_hours: int = 48,
        max_follow_ups: int = 3,
        **kwargs
    ):
        super().__init__(name=name, **kwargs)

        self.follow_up_type = follow_up_type
        self.delay_hours = delay_hours
        self.message_template = message_template
        self.assign_to = assign_to
        self.auto_escalate = auto_escalate
        self.escalation_hours = escalation_hours
        self.max_follow_ups = max_follow_ups

    def execute(self, entity: Any, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Schedule a follow-up task."""
        import uuid

        # Determine assignee
        assignee_id = None
        if self.assign_to == 'recruiter' and hasattr(entity, 'job'):
            assignee_id = entity.job.recruiter_id
        elif self.assign_to == 'hiring_manager' and hasattr(entity, 'job'):
            assignee_id = entity.job.hiring_manager_id
        elif self.assign_to == 'assigned_to' and hasattr(entity, 'assigned_to'):
            assignee_id = entity.assigned_to_id

        # Create scheduled follow-up
        scheduled_at = timezone.now() + timedelta(hours=self.delay_hours)

        follow_up = ScheduledFollowUp(
            id=str(uuid.uuid4()),
            follow_up_type=self.follow_up_type,
            entity_type=entity.__class__.__name__,
            entity_id=entity.id,
            scheduled_at=scheduled_at,
            message=self._render_message(entity, context),
            assigned_to_id=assignee_id
        )

        # In production, persist to database and schedule Celery task
        self._schedule_follow_up(follow_up)

        return {
            'action': 'schedule_follow_up',
            'follow_up_id': follow_up.id,
            'follow_up_type': self.follow_up_type.value,
            'scheduled_at': scheduled_at.isoformat(),
            'assigned_to_id': assignee_id,
            'entity_type': follow_up.entity_type,
            'entity_id': follow_up.entity_id
        }

    def _render_message(self, entity: Any, context: Dict[str, Any]) -> str:
        """Render the follow-up message from template."""
        # In production, use Django template engine
        message = self.message_template

        if hasattr(entity, 'candidate'):
            message = message.replace('{candidate_name}', entity.candidate.full_name)
        if hasattr(entity, 'job'):
            message = message.replace('{job_title}', entity.job.title)

        return message

    def _schedule_follow_up(self, follow_up: ScheduledFollowUp) -> None:
        """Schedule the follow-up task."""
        # In production, create Celery task or use Django-Q
        logger.info(f"Scheduled follow-up {follow_up.id} for {follow_up.scheduled_at}")


# ==================== RULE ENGINE ====================

class AutomationEngine:
    """
    Central engine for managing and executing automation rules.

    Provides:
    - Rule registration and management
    - Batch rule execution
    - Rule prioritization
    - Execution logging and monitoring
    """

    def __init__(self):
        self.rules: Dict[str, AutomationRule] = {}
        self.rule_groups: Dict[str, List[str]] = {}
        self.execution_log: List[Dict[str, Any]] = []

    def register_rule(self, rule: AutomationRule, groups: List[str] = None) -> None:
        """Register a new automation rule."""
        self.rules[rule.name] = rule

        if groups:
            for group in groups:
                if group not in self.rule_groups:
                    self.rule_groups[group] = []
                self.rule_groups[group].append(rule.name)

    def unregister_rule(self, rule_name: str) -> None:
        """Remove a rule from the engine."""
        if rule_name in self.rules:
            del self.rules[rule_name]

            # Remove from groups
            for group, rule_names in self.rule_groups.items():
                if rule_name in rule_names:
                    rule_names.remove(rule_name)

    def get_rule(self, rule_name: str) -> Optional[AutomationRule]:
        """Get a rule by name."""
        return self.rules.get(rule_name)

    def get_rules_by_group(self, group: str) -> List[AutomationRule]:
        """Get all rules in a group."""
        rule_names = self.rule_groups.get(group, [])
        return [self.rules[name] for name in rule_names if name in self.rules]

    def run_rules(
        self,
        entity: Any,
        rule_names: List[str] = None,
        groups: List[str] = None,
        context: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """
        Run specified rules against an entity.

        Args:
            entity: The entity to process
            rule_names: Specific rules to run (optional)
            groups: Rule groups to run (optional)
            context: Additional context

        Returns:
            List of execution results
        """
        results = []
        rules_to_run = []

        # Collect rules to run
        if rule_names:
            rules_to_run.extend([
                self.rules[name] for name in rule_names
                if name in self.rules
            ])

        if groups:
            for group in groups:
                rules_to_run.extend(self.get_rules_by_group(group))

        # If no specific rules, run all
        if not rule_names and not groups:
            rules_to_run = list(self.rules.values())

        # Remove duplicates and sort by priority
        rules_to_run = list({rule.name: rule for rule in rules_to_run}.values())
        rules_to_run.sort(key=lambda r: r.priority)

        # Execute each rule
        for rule in rules_to_run:
            result = rule.run(entity, context)
            if result:
                results.append(result)
                self._log_execution(rule, entity, result)

        return results

    def run_batch(
        self,
        entities: List[Any],
        rule_names: List[str] = None,
        groups: List[str] = None,
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Run rules against multiple entities.

        Returns summary of all executions.
        """
        all_results = []
        processed = 0
        triggered = 0

        for entity in entities:
            results = self.run_rules(entity, rule_names, groups, context)
            all_results.extend(results)
            processed += 1
            triggered += len(results)

        return {
            'processed': processed,
            'triggered': triggered,
            'results': all_results
        }

    def _log_execution(
        self,
        rule: AutomationRule,
        entity: Any,
        result: Dict[str, Any]
    ) -> None:
        """Log rule execution for monitoring."""
        log_entry = {
            'timestamp': timezone.now().isoformat(),
            'rule_name': rule.name,
            'entity_type': entity.__class__.__name__,
            'entity_id': getattr(entity, 'id', None),
            'success': result.get('success', False),
            'result': result
        }

        self.execution_log.append(log_entry)

        # Keep log bounded
        if len(self.execution_log) > 1000:
            self.execution_log = self.execution_log[-500:]

    def get_execution_stats(self) -> Dict[str, Any]:
        """Get execution statistics."""
        if not self.execution_log:
            return {'total_executions': 0}

        total = len(self.execution_log)
        successful = sum(1 for e in self.execution_log if e.get('success'))

        rule_counts = {}
        for entry in self.execution_log:
            rule = entry['rule_name']
            rule_counts[rule] = rule_counts.get(rule, 0) + 1

        return {
            'total_executions': total,
            'successful': successful,
            'failed': total - successful,
            'by_rule': rule_counts
        }


# ==================== PRE-CONFIGURED RULES ====================

def create_default_rules() -> AutomationEngine:
    """Create engine with default HR automation rules."""
    engine = AutomationEngine()

    # Auto-reject stale applications
    engine.register_rule(
        AutoRejectRule(
            name="Auto-Reject After 30 Days",
            days_threshold=30,
            target_stages=['new', 'screening'],
            rejection_reason="We have decided to move forward with other candidates",
            send_notification=True
        ),
        groups=['application', 'cleanup']
    )

    # Auto-advance high scorers
    engine.register_rule(
        AutoAdvanceRule(
            name="Auto-Advance High Scorers",
            from_stage="new",
            to_stage="screening",
            score_threshold=90.0
        ),
        groups=['application', 'advancement']
    )

    # New application notification
    engine.register_rule(
        NotificationRule(
            name="New Application Alert",
            event_type=NotificationEventType.APPLICATION_RECEIVED,
            recipients=[
                NotificationRecipient(type='recruiter'),
                NotificationRecipient(type='hiring_manager')
            ],
            channels=[NotificationChannel.EMAIL, NotificationChannel.IN_APP],
            subject_template="New Application: {candidate_name} for {job_title}",
            body_template="A new application has been received for review.",
            conditions=[
                RuleCondition(
                    field="status",
                    operator=ConditionOperator.EQUALS,
                    value="new"
                )
            ]
        ),
        groups=['notification', 'application']
    )

    # High score candidate alert
    engine.register_rule(
        NotificationRule(
            name="High Score Candidate Alert",
            event_type=NotificationEventType.HIGH_SCORE_CANDIDATE,
            recipients=[
                NotificationRecipient(type='hiring_manager')
            ],
            channels=[NotificationChannel.EMAIL, NotificationChannel.SLACK],
            subject_template="High-Quality Candidate Alert: {candidate_name}",
            body_template="A candidate with score above 85% has applied.",
            urgency="high",
            conditions=[
                RuleCondition(
                    field="ai_match_score",
                    operator=ConditionOperator.GREATER_EQUAL,
                    value=85
                )
            ]
        ),
        groups=['notification', 'application']
    )

    # Interview feedback reminder
    engine.register_rule(
        FollowUpRule(
            name="Interview Feedback Reminder",
            follow_up_type=FollowUpType.FEEDBACK_REMINDER,
            delay_hours=24,
            message_template="Please submit your feedback for the interview with {candidate_name}",
            assign_to="assigned_to",
            auto_escalate=True,
            escalation_hours=48
        ),
        groups=['follow_up', 'interview']
    )

    # Candidate follow-up after application
    engine.register_rule(
        FollowUpRule(
            name="Application Acknowledgment Follow-up",
            follow_up_type=FollowUpType.CANDIDATE_FOLLOW_UP,
            delay_hours=72,
            message_template="Follow up with {candidate_name} about their application status",
            assign_to="recruiter"
        ),
        groups=['follow_up', 'application']
    )

    return engine


# Create default automation engine instance
automation_engine = create_default_rules()
